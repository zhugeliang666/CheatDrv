#pragma once
#include <fltkernel.h>
//0x8 bytes (sizeof)

struct __EX_FAST_REF
{
    union
    {
        VOID* Object;                                                       //0x0
        ULONGLONG RefCnt : 4;                                                 //0x0
        ULONGLONG Value;                                                    //0x0
    };
};

//0x8 bytes (sizeof)
struct __EX_PUSH_LOCK
{
    union
    {
        struct
        {
            ULONGLONG Locked : 1;                                             //0x0
            ULONGLONG Waiting : 1;                                            //0x0
            ULONGLONG Waking : 1;                                             //0x0
            ULONGLONG MultipleShared : 1;                                     //0x0
            ULONGLONG Shared : 60;                                            //0x0
        };
        ULONGLONG Value;                                                    //0x0
        VOID* Ptr;                                                          //0x0
    };
};
//0x4 bytes (sizeof)
struct _SEGMENT_FLAGS
{
    union
    {
        struct
        {
            USHORT TotalNumberOfPtes4132 : 10;                                //0x0
            USHORT Spare0 : 2;                                                //0x0
            USHORT LargePages : 1;                                            //0x0
            USHORT DebugSymbolsLoaded : 1;                                    //0x0
            USHORT WriteCombined : 1;                                         //0x0
            USHORT NoCache : 1;                                               //0x0
        };
        USHORT Short0;                                                      //0x0
    };
    union
    {
        struct
        {
            UCHAR Unused : 1;                                                 //0x2
            UCHAR DefaultProtectionMask : 5;                                  //0x2
            UCHAR Binary32 : 1;                                               //0x2
            UCHAR ContainsDebug : 1;                                          //0x2
        };
        UCHAR UChar1;                                                       //0x2
    };
    union
    {
        struct
        {
            UCHAR ForceCollision : 1;                                         //0x3
            UCHAR ImageSigningType : 3;                                       //0x3
            UCHAR ImageSigningLevel : 4;                                      //0x3
        };
        UCHAR UChar2;                                                       //0x3
    };
};

//0x48 bytes (sizeof)
struct __SEGMENT
{
    struct _CONTROL_AREA* ControlArea;                                      //0x0
    ULONG TotalNumberOfPtes;                                                //0x8
    struct _SEGMENT_FLAGS SegmentFlags;                                     //0xc
    ULONGLONG NumberOfCommittedPages;                                       //0x10
    ULONGLONG SizeOfSegment;                                                //0x18
    union
    {
        struct _MMEXTEND_INFO* ExtendInfo;                                  //0x20
        VOID* BasedAddress;                                                 //0x20
    };
    __EX_PUSH_LOCK SegmentLock;                                       //0x28
    union
    {
        ULONGLONG ImageCommitment;                                          //0x30
        ULONG CreatingProcessId;                                            //0x30
    } u1;                                                                   //0x30
    union
    {
        struct _MI_SECTION_IMAGE_INFORMATION* ImageInformation;             //0x38
        VOID* FirstMappedVa;                                                //0x38
    } u2;                                                                   //0x38
    struct _MMPTE* PrototypePte;                                            //0x40
};


//0x4 bytes (sizeof)
struct __MMSECTION_FLAGS
{
    ULONG BeingDeleted : 1;                                                   //0x0
    ULONG BeingCreated : 1;                                                   //0x0
    ULONG BeingPurged : 1;                                                    //0x0
    ULONG NoModifiedWriting : 1;                                              //0x0
    ULONG FailAllIo : 1;                                                      //0x0
    ULONG Image : 1;                                                          //0x0
    ULONG Based : 1;                                                          //0x0
    ULONG File : 1;                                                           //0x0
    ULONG AttemptingDelete : 1;                                               //0x0
    ULONG PrefetchCreated : 1;                                                //0x0
    ULONG PhysicalMemory : 1;                                                 //0x0
    ULONG ImageControlAreaOnRemovableMedia : 1;                               //0x0
    ULONG Reserve : 1;                                                        //0x0
    ULONG Commit : 1;                                                         //0x0
    ULONG NoChange : 1;                                                       //0x0
    ULONG WasPurged : 1;                                                      //0x0
    ULONG UserReference : 1;                                                  //0x0
    ULONG GlobalMemory : 1;                                                   //0x0
    ULONG DeleteOnClose : 1;                                                  //0x0
    ULONG FilePointerNull : 1;                                                //0x0
    ULONG PreferredNode : 6;                                                  //0x0
    ULONG GlobalOnlyPerSession : 1;                                           //0x0
    ULONG UserWritable : 1;                                                   //0x0
    ULONG SystemVaAllocated : 1;                                              //0x0
    ULONG PreferredFsCompressionBoundary : 1;                                 //0x0
    ULONG UsingFileExtents : 1;                                               //0x0
    ULONG PageSize64K : 1;                                                    //0x0
};


//0x4 bytes (sizeof)
struct _MMSECTION_FLAGS2
{
    USHORT PartitionId : 10;                                                  //0x0
    UCHAR NoCrossPartitionAccess : 1;                                         //0x2
    UCHAR SubsectionCrossPartitionReferenceOverflow : 1;                      //0x2
};

//0x28 bytes (sizeof)
struct _MI_CONTROL_AREA_WAIT_BLOCK
{
    struct _MI_CONTROL_AREA_WAIT_BLOCK* Next;                               //0x0
    ULONG WaitReason;                                                       //0x8
    ULONG WaitResponse;                                                     //0xc
    struct _KGATE Gate;                                                     //0x10
};

//0x8 bytes (sizeof)
extern struct _EX_FAST_REF;

//0x80 bytes (sizeof)
struct __CONTROL_AREA
{
    struct __SEGMENT* Segment;                                               //0x0
    struct _LIST_ENTRY ListHead;                                            //0x8
    ULONGLONG NumberOfSectionReferences;                                    //0x18
    ULONGLONG NumberOfPfnReferences;                                        //0x20
    ULONGLONG NumberOfMappedViews;                                          //0x28
    ULONGLONG NumberOfUserReferences;                                       //0x30
    union
    {
        ULONG LongFlags;                                                    //0x38
        struct __MMSECTION_FLAGS Flags;                                      //0x38
    } u;                                                                    //0x38
    union
    {
        ULONG LongFlags;                                                    //0x3c
        struct _MMSECTION_FLAGS2 Flags;                                     //0x3c
    } u1;                                                                   //0x3c
    struct __EX_FAST_REF FilePointer;                                        //0x40
    volatile LONG ControlAreaLock;                                          //0x48
    ULONG ModifiedWriteCount;                                               //0x4c
    struct _MI_CONTROL_AREA_WAIT_BLOCK* WaitList;                           //0x50
    union
    {
        struct
        {
            union
            {
                ULONG NumberOfSystemCacheViews;                             //0x58
                ULONG ImageRelocationStartBit;                              //0x58
            };
            union
            {
                volatile LONG WritableUserReferences;                       //0x5c
                struct
                {
                    ULONG ImageRelocationSizeIn64k : 16;                      //0x5c
                    ULONG LargePage : 1;                                      //0x5c
                    ULONG SystemImage : 1;                                    //0x5c
                    ULONG StrongCode : 2;                                     //0x5c
                    ULONG CantMove : 1;                                       //0x5c
                    ULONG BitMap : 2;                                         //0x5c
                    ULONG ImageActive : 1;                                    //0x5c
                };
            };
            union
            {
                ULONG FlushInProgressCount;                                 //0x60
                ULONG NumberOfSubsections;                                  //0x60
                struct _MI_IMAGE_SECURITY_REFERENCE* SeImageStub;           //0x60
            };
        } e2;                                                               //0x58
    } u2;                                                                   //0x58
    struct __EX_PUSH_LOCK FileObjectLock;                                    //0x68
    volatile ULONGLONG LockedPages;                                         //0x70
    union
    {
        ULONGLONG IoAttributionContext : 61;                                  //0x78
        ULONGLONG Spare : 3;                                                  //0x78
        ULONGLONG ImageCrossPartitionCharge;                                //0x78
        ULONGLONG CommittedPageCount : 36;                                    //0x78
    } u3;                                                                   //0x78
};

//0xa0 bytes (sizeof)
typedef struct _KLDR_DATA_TABLE_ENTRY
{
    struct _LIST_ENTRY InLoadOrderLinks;                                    //0x0
    VOID* ExceptionTable;                                                   //0x10
    ULONG ExceptionTableSize;                                               //0x18
    VOID* GpValue;                                                          //0x20
    struct _NON_PAGED_DEBUG_INFO* NonPagedDebugInfo;                        //0x28
    VOID* DllBase;                                                          //0x30
    VOID* EntryPoint;                                                       //0x38
    ULONG SizeOfImage;                                                      //0x40
    struct _UNICODE_STRING FullDllName;                                     //0x48
    struct _UNICODE_STRING BaseDllName;                                     //0x58
    ULONG Flags;                                                            //0x68
    USHORT LoadCount;                                                       //0x6c
    union
    {
        USHORT SignatureLevel : 4;                                            //0x6e
        USHORT SignatureType : 3;                                             //0x6e
        USHORT Unused : 9;                                                    //0x6e
        USHORT EntireField;                                                 //0x6e
    } u1;                                                                   //0x6e
    VOID* SectionPointer;                                                   //0x70
    ULONG CheckSum;                                                         //0x78
    ULONG CoverageSectionSize;                                              //0x7c
    VOID* CoverageSection;                                                  //0x80
    VOID* LoadedImports;                                                    //0x88
    VOID* Spare;                                                            //0x90
    ULONG SizeOfImageNotRounded;                                            //0x98
    ULONG TimeDateStamp;                                                    //0x9c
}KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;


// 设置完成例程
NTSTATUS FD_SetFileCompletion(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context);

//打开文件返回句柄
HANDLE  FD_OpenFile(WCHAR szFileName[]);

//去除只读属性
bool FD_StripFileAttributes(HANDLE FileHandle);

// 删除文件 
bool FD_DeleteFile(HANDLE FileHandle);

//强制删除文件
bool FD_ForceDeleteFile(WCHAR szFileName[]);

//强写文件
NTSTATUS FD_WriteFile(HANDLE FileHandle, PVOID Buffer, ULONG BytesToWrite);

//隐藏驱动文件
VOID HideDriverFile(PDRIVER_OBJECT pDriver, PUCHAR data, size_t size);

//强制删除驱动文件
VOID DeleteDriverFile(PDRIVER_OBJECT pDriver);