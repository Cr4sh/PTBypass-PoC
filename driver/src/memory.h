typedef struct _MMPTE_SOFTWARE 
{
    ULONG Valid : 1;
    ULONG PageFileLow : 4;
    ULONG Protection : 5;
    ULONG Prototype : 1;
    ULONG Transition : 1;
    ULONG PageFileHigh : 20;

} MMPTE_SOFTWARE;

typedef struct _MMPTE_TRANSITION 
{
    ULONG Valid : 1;
    ULONG Write : 1;
    ULONG Owner : 1;
    ULONG WriteThrough : 1;
    ULONG CacheDisable : 1;
    ULONG Protection : 5;
    ULONG Prototype : 1;
    ULONG Transition : 1;
    ULONG PageFrameNumber : 20;

} MMPTE_TRANSITION;

typedef struct _MMPTE_PROTOTYPE 
{
    ULONG Valid : 1;
    ULONG ProtoAddressLow : 7;
    ULONG ReadOnly : 1; // if set allow read only access.
    ULONG WhichPool : 1;
    ULONG Prototype : 1;
    ULONG ProtoAddressHigh : 21;

} MMPTE_PROTOTYPE;

typedef struct _MMPTE_HARDWARE 
{
    ULONG Valid : 1;
    ULONG Write : 1; // UP version
    ULONG Owner : 1;
    ULONG WriteThrough : 1;
    ULONG CacheDisable : 1;
    ULONG Accessed : 1;
    ULONG Dirty : 1;
    ULONG LargePage : 1;
    ULONG Global : 1;
    ULONG CopyOnWrite : 1; // software field
    ULONG Prototype : 1; // software field
    ULONG reserved : 1; // software field
    ULONG PageFrameNumber : 20;

} MMPTE_HARDWARE, *PMMPTE_HARDWARE;

typedef struct _MMPTE 
{
    union  
    {
        ULONG Long;
        MMPTE_HARDWARE Hard;
        MMPTE_PROTOTYPE Proto;
        MMPTE_SOFTWARE Soft;
        MMPTE_TRANSITION Trans;

    } u;

} MMPTE, 
*PMMPTE;

typedef struct _MMPTE_SOFTWARE_PAE 
{
    ULONGLONG Valid : 1;
    ULONGLONG PageFileLow : 4;
    ULONGLONG Protection : 5;
    ULONGLONG Prototype : 1;
    ULONGLONG Transition : 1;
    ULONGLONG Unused : 20;
    ULONGLONG PageFileHigh : 32;

} MMPTE_SOFTWARE_PAE;

typedef struct _MMPTE_TRANSITION_PAE 
{
    ULONGLONG Valid : 1;
    ULONGLONG Write : 1;
    ULONGLONG Owner : 1;
    ULONGLONG WriteThrough : 1;
    ULONGLONG CacheDisable : 1;
    ULONGLONG Protection : 5;
    ULONGLONG Prototype : 1;
    ULONGLONG Transition : 1;
    ULONGLONG PageFrameNumber : 24;
    ULONGLONG Unused : 28;

} MMPTE_TRANSITION_PAE;

typedef struct _MMPTE_PROTOTYPE_PAE 
{
    ULONGLONG Valid : 1;
    ULONGLONG Unused0: 7;
    ULONGLONG ReadOnly : 1; // if set allow read only access.  LWFIX: remove
    ULONGLONG Unused1: 1;
    ULONGLONG Prototype : 1;
    ULONGLONG Protection : 5;
    ULONGLONG Unused: 16;
    ULONGLONG ProtoAddress: 32;

} MMPTE_PROTOTYPE_PAE;

typedef struct _MMPTE_HARDWARE_PAE 
{
    ULONGLONG Valid : 1;
    ULONGLONG Write : 1; // UP version
    ULONGLONG Owner : 1;
    ULONGLONG WriteThrough : 1;
    ULONGLONG CacheDisable : 1;
    ULONGLONG Accessed : 1;
    ULONGLONG Dirty : 1;
    ULONGLONG LargePage : 1;
    ULONGLONG Global : 1;
    ULONGLONG CopyOnWrite : 1; // software field
    ULONGLONG Prototype : 1; // software field
    ULONGLONG reserved0 : 1; // software field
    ULONGLONG PageFrameNumber : 24;
    ULONGLONG reserved1 : 28; // software field

} MMPTE_HARDWARE_PAE, 
*PMMPTE_HARDWARE_PAE;

typedef struct _MMPTE_PAE 
{
    union  
    {
        LARGE_INTEGER Long;
        MMPTE_HARDWARE_PAE Hard;
        MMPTE_PROTOTYPE_PAE Proto;
        MMPTE_SOFTWARE_PAE Soft;
        MMPTE_TRANSITION_PAE Trans;

    } u;

} MMPTE_PAE,
*PMMPTE_PAE;

#define PTE_BASE     0xC0000000
#define PDE_BASE     0xC0300000
#define PDE_BASE_PAE 0xc0600000

#define MiGetPdeAddress(va) ((MMPTE *)(((((ULONG)(va)) >> 22) << 2) + PDE_BASE))
#define MiGetPteAddress(va) ((MMPTE *)(((((ULONG)(va)) >> 12) << 2) + PTE_BASE))

#define MiGetPdeAddressPae(va) ((PMMPTE_PAE)(PDE_BASE_PAE + ((((ULONG)(va)) >> 21) << 3)))
#define MiGetPteAddressPae(va) ((PMMPTE_PAE)(PTE_BASE + ((((ULONG)(va)) >> 12) << 3)))

//++
//
// ULONG
// BYTE_OFFSET (
//     IN PVOID Va
//     )
//
// Routine Description:
//
//     The BYTE_OFFSET macro takes a virtual address and returns the byte offset
//     of that address within the page.
//
// Arguments:
//
//     Va - Virtual address.
//
// Return Value:
//
//     Returns the byte offset portion of the virtual address.
//
//--

#define BYTE_OFFSET(Va) ((ULONG)((LONG_PTR)(Va) & (PAGE_SIZE - 1)))

//++
// ULONG
// MiGetPteOffset (
//    IN PVOID va
//    );
//
// Routine Description:
//
//    MiGetPteOffset returns the offset into a page table page
//    for a given virtual address.
//
// Arguments
//
//    Va - Supplies the virtual address to locate the offset for.
//
// Return Value:
//
//    The offset into the page table page table the corresponding PTE is at.
//
//--

#define MiGetPteOffset(va) ((((ULONG)(va)) << 10) >> 22)

#define PAGE_SHIFT 12L

#define PAE_ON (1 << 5)
