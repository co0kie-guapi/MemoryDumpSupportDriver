#include <ntddk.h>
#include <wdf.h>
#include <windef.h>




DRIVER_INITIALIZE DriverEntry;


/// <summary>
/// 这里预定义函数
/// </summary>
/// <param name="pDevObj"></param>
/// <param name="pIrp"></param>
/// <returns></returns>
NTSTATUS DispatchFunction(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp);
NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(HANDLE ProcessId, PEPROCESS* Process);
NTSTATUS NTAPI MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);



/// <summary>
/// 派遣函数
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
/// irp 中的用户空间结构体参数
/// </summary>
struct IRP_USER_PARAM {
	PVOID SourceAddress;

	PVOID TargetAddress;

	SIZE_T Size;

	DWORD pid;

};


// 将目标地址写入地址
NTSTATUS KeReadProcessMemory(PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size, IN PEPROCESS process)
{
	PEPROCESS SourceProcess = PsGetCurrentProcess();
	PEPROCESS TargetProcess = process;
	SIZE_T Result;
	//这里因为是要反过来去读，故反过来（vulnPoint）
	if (NT_SUCCESS(MmCopyVirtualMemory(TargetProcess, TargetAddress, SourceProcess, SourceAddress, Size, KernelMode, &Result)))
		return STATUS_SUCCESS;
	else
		return STATUS_ACCESS_DENIED;
}



/// <summary>
/// 派遣函数
/// </summary>
/// <param name="pDevObj"></param>
/// <param name="pIrp"></param>
/// <returns></returns>
NTSTATUS DispatchFunction(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp)
{
	// 获取IRP的主类型和子类型  
	UCHAR MajorFunction = NULL;
	UCHAR MinorFunction = NULL;
	pIrp->Flags &= ~0x80;
	NTSTATUS status = IoGetFunctionCodeFromCtlCode(pIrp->Flags, &MajorFunction, &MinorFunction);
	if (!NT_SUCCESS(status)) {
		// 处理错误
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
		//todo 从irp上获得参数
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




