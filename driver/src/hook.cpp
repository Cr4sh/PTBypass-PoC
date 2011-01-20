#include "stdafx.h"

#define HOOK_CODE_JMP_SIZE 6
//--------------------------------------------------------------------------------------
PVOID HookCode(PVOID Func, PVOID Handler, PULONG BytesPatched)
{
    PUCHAR CallGate = NULL;
    ULONG CallGateSize = 0, CollectedSpace = 0;     

    if (BytesPatched)
    {
        *BytesPatched = 0;
    }

    while (true)
    {
        struct xde_instr Instr;
        ULONG Size = xde_disasm((PUCHAR)Func + CollectedSpace, &Instr);
        if (Size == 0)
        {
            DbgMsg(__FILE__, __LINE__, "xde_dasm() ERROR\n");
            return NULL;
        }

        CollectedSpace += Size;

        if (CollectedSpace >= HOOK_CODE_JMP_SIZE)
        {
            break;
        }

        if (Instr.flag & C_STOP)
        {
            // function too short?
            DbgMsg(__FILE__, __LINE__, "xde_dasm() C_STOP\n");
            return NULL;
        }        
    }

    // allocate callgate
    CallGateSize = CollectedSpace + 6;
    if (CallGate = (PUCHAR)M_ALLOC(CallGateSize))
    {
        ULONG Ptr = 0;

        DbgMsg(__FILE__, __LINE__, 
            __FUNCTION__"(): Function="IFMT" Handler="IFMT" CallGate="IFMT" (size: %d)\n",
            Func, Handler, CallGate, CallGateSize
        );

        RtlFillMemory(CallGate, CallGateSize, 0x90);
        RtlCopyMemory(CallGate, Func, CollectedSpace);

        while (Ptr < CollectedSpace)
        {
            struct xde_instr Instr;
            ULONG Size = xde_disasm(CallGate + Ptr, &Instr);
            if (Size == 0)
            {
                DbgMsg(__FILE__, __LINE__, "xde_dasm() ERROR\n");
                ExFreePool(CallGate);
                return NULL;
            }

            // call, jmp, jxx?
            if (Instr.flag & C_REL)
            {                
                PUCHAR data_ptr = CallGate + Ptr + (Size - Instr.datasize);

                if (Instr.datasize == 1)
                {
                    *(PUCHAR)data_ptr += (UCHAR)((PUCHAR)Func - CallGate);
                }
                else if (Instr.datasize == 2)
                {
                    *(PUSHORT)data_ptr += (USHORT)((PUCHAR)Func - CallGate);
                }
                else
                {
                    *(PULONG)data_ptr += (ULONG)((PUCHAR)Func - CallGate);
                }
            }

            Ptr += Size;
        }

        // push imm32
        *(PUCHAR)(CallGate + CollectedSpace + 0) = 0x68;
        *(PUCHAR *)(CallGate + CollectedSpace + 1) = (PUCHAR)Func + CollectedSpace;
        
        // ret
        *(PUCHAR)(CallGate + CollectedSpace + 5) = 0xC3;

        RtlFillMemory(Func, CollectedSpace, 0x90);

        // push imm32
        *(PUCHAR)((PUCHAR)Func + 0) = 0x68;
        *(PVOID *)((PUCHAR)Func + 1) = Handler;
        
        // ret
        *(PUCHAR)((PUCHAR)Func + 5) = 0xC3;

        if (BytesPatched)
        {
            *BytesPatched = CollectedSpace;
        }
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, "M_ALLOC() ERROR\n");
    }

    return CallGate;
}
//--------------------------------------------------------------------------------------
// EoF
