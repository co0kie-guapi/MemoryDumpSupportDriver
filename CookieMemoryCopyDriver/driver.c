#include <ntddk.h>
#include <wdf.h>
#include <windef.h>




DRIVER_INITIALIZE DriverEntry;


/// <summary>
/// ����Ԥ���庯��
/// </summary>
/// <param name="pDevObj"></param>
/// <param name="pIrp"></param>
/// <returns></returns>
NTSTATUS DispatchFunction(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp);
NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(HANDLE ProcessId, PEPROCESS* Process);
NTSTATUS NTAPI MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);



/// <summary>
/// ��ǲ����
/// </summary>
/// <param name="DriverObject"></param>
/// <param name="RegistryPath"></param>
/// <returns></returns>
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT     DriverObject,
    _In_ PUNICODE_STRING    RegistryPath
)
{
	NTSTATUS status = STATUS_SUCCESS;
	WDF_DRIVER_CONFIG config;


    DriverObject->MajorFunction[IRP_MJ_READ] = DispatchFunction;
    DriverObject->MajorFunction[IRP_MJ_WRITE] = DispatchFunction;

    DbgPrint("cookie driver entry \n");
    return STATUS_SUCCESS;
}




/// <summary>
/// irp �е��û��ռ�ṹ�����
/// </summary>
struct IRP_USER_PARAM {
	PVOID SourceAddress;

	PVOID TargetAddress;

	SIZE_T Size;

	DWORD pid;

};


// ��Ŀ���ַд���ַ
NTSTATUS KeReadProcessMemory(PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size, IN PEPROCESS process)
{
	PEPROCESS SourceProcess = PsGetCurrentProcess();
	PEPROCESS TargetProcess = process;
	SIZE_T Result;
	//������Ϊ��Ҫ������ȥ�����ʷ�������vulnPoint��
	if (NT_SUCCESS(MmCopyVirtualMemory(TargetProcess, TargetAddress, SourceProcess, SourceAddress, Size, KernelMode, &Result)))
		return STATUS_SUCCESS;
	else
		return STATUS_ACCESS_DENIED;
}



/// <summary>
/// ��ǲ����
/// </summary>
/// <param name="pDevObj"></param>
/// <param name="pIrp"></param>
/// <returns></returns>
NTSTATUS DispatchFunction(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp)
{
	// ��ȡIRP�������ͺ�������  
	UCHAR MajorFunction = NULL;
	UCHAR MinorFunction = NULL;
	pIrp->Flags &= ~0x80;
	NTSTATUS status = IoGetFunctionCodeFromCtlCode(pIrp->Flags, &MajorFunction, &MinorFunction);
	if (!NT_SUCCESS(status)) {
		// �������
		pIrp->IoStatus.Status = status;
		IoCompleteRequest(pIrp, IO_NO_INCREMENT);
		return status;
	}
	if (MajorFunction == NULL)
	{
		return STATUS_ACCESS_DENIED;
	}
	
	switch (MajorFunction) {
		case IRP_MJ_READ: {
		//todo ��irp�ϻ�ò���
			struct IRP_USER_PARAM* irpParam = pIrp->AssociatedIrp.SystemBuffer;
			PEPROCESS Perocess = NULL;
			PsLookupProcessByProcessId((HANDLE)irpParam->pid, &Perocess);
			if (!NT_SUCCESS(KeReadProcessMemory(irpParam->SourceAddress, irpParam->TargetAddress, irpParam->Size, Perocess)))
				return STATUS_ACCESS_DENIED;
			break;
		}
	}

	return STATUS_SUCCESS;
}




