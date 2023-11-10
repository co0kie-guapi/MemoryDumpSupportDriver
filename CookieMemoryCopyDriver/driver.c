#include <ntddk.h>
#include <wdf.h>
#include <windef.h>
#include <initguid.h>




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


// GUID
DEFINE_GUID(GUID_YOUR_DEVICE_INTERFACE,
	0x12345678, 0x1234, 0x1234, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef);

UNICODE_STRING deviceName;
UNICODE_STRING deviceSymLink;
UNICODE_STRING deviceInterfaceName;


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
	PDEVICE_OBJECT DeviceObject = NULL;


	// �����豸����
	RtlInitUnicodeString(&deviceName, L"\\Device\\CookieMemoryCpyDevice");

	// �����豸����
	status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);
	if (!NT_SUCCESS(status)) {
		// ������
		return status;
	}

	// ����������������
	RtlInitUnicodeString(&deviceSymLink, L"\\??\\CookieMemoryCpySym");
	status = IoCreateSymbolicLink(&deviceSymLink, &deviceName);
	if (!NT_SUCCESS(status)) {
		IoDeleteDevice(DeviceObject);
		return status;
	}


	RtlInitUnicodeString(&deviceInterfaceName, L"\\CookieMemoryCpyInterface");
	// ע���豸�ӿ�
	status = IoRegisterDeviceInterface(DeviceObject, &GUID_YOUR_DEVICE_INTERFACE, NULL, &deviceInterfaceName);
	if (!NT_SUCCESS(status)) {
		IoDeleteSymbolicLink(&deviceSymLink);
		IoDeleteDevice(DeviceObject);
		return status;
	}

	// �����豸�ӿ�
	status = IoSetDeviceInterfaceState(&deviceInterfaceName, TRUE);
	if (!NT_SUCCESS(status)) {
		IoDeleteSymbolicLink(&deviceSymLink);
		IoDeleteDevice(DeviceObject);
		return status;
	}

	// ����������������ص�����ɳ�ʼ��...
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
	UCHAR MajorFunction = 0;
	UCHAR MinorFunction = 0;
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
			if (irpParam == NULL) {
				pIrp->IoStatus.Status = STATUS_INVALID_PARAMETER;
				pIrp->IoStatus.Information = 0;
				IoCompleteRequest(pIrp, IO_NO_INCREMENT);
				return STATUS_INVALID_PARAMETER;
			}
			__try {
				// ����֤�û�ģʽ�µ�ָ��
				ProbeForRead(irpParam->SourceAddress, irpParam->Size, 1);
				ProbeForWrite(irpParam->TargetAddress, irpParam->Size, 1);
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				return GetExceptionCode();
			}
			PEPROCESS Perocess = NULL;
			PsLookupProcessByProcessId((HANDLE)irpParam->pid, &Perocess);
			if (!NT_SUCCESS(KeReadProcessMemory(irpParam->SourceAddress, irpParam->TargetAddress, irpParam->Size, Perocess)))
				ObDereferenceObject(Perocess);
				return STATUS_ACCESS_DENIED;
			ObDereferenceObject(Perocess);
			SIZE_T bytesTransferred = irpParam->Size;
			pIrp->IoStatus.Status = STATUS_SUCCESS;
			pIrp->IoStatus.Information = bytesTransferred;
			// �������
			IoCompleteRequest(pIrp, IO_NO_INCREMENT);
			break;
		}
	}
	
	return STATUS_SUCCESS;
}

VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
	PDEVICE_OBJECT deviceObject = DriverObject->DeviceObject;


	// ѭ���������е��豸����
	while (deviceObject != NULL)
	{
		// ��ȡ��һ���豸������ΪIoDeleteDevice��ɾ����ǰ���豸����
		PDEVICE_OBJECT nextDeviceObject = deviceObject->NextDevice;

		// ע���豸�ӿ�
		IoSetDeviceInterfaceState(&deviceInterfaceName, FALSE);

		// ɾ����������
		IoDeleteSymbolicLink(&deviceSymLink);


		// ɾ���豸����
		IoDeleteDevice(deviceObject);


		deviceObject = nextDeviceObject;
	}
}


