#include "mouse.h"

#pragma data_seg(".vm2data")



#pragma data_seg()

EXTERN_C VOID MouseClassServiceCallback_rewrite(
	PDEVICE_OBJECT DeviceObject,
	PMOUSE_INPUT_DATA InputDataStart,
	PMOUSE_INPUT_DATA InputDataEnd,
	PULONG InputDataConsumed
);

namespace mouse {


#pragma data_seg(".vm2data")

	MOUSE_OBJECT mouse_obj = { 0 };
	UINT64 _KeAcquireSpinLockAtDpcLevel = 0;
	UINT64 _KeReleaseSpinLockFromDpcLevel = 0;
	UINT64 _IofCompleteRequest = 0;
	UINT64 _IoReleaseRemoveLockEx = 0;

#pragma data_seg()


#pragma code_seg(".vm")

	NTSTATUS init_mouse(PMOUSE_OBJECT mouse_obj)
	{
		if (!mouse_obj)
			return STATUS_INVALID_PARAMETER;

		mouse_obj->mouse_device = nullptr;
		mouse_obj->service_callback = nullptr;
		mouse_obj->hid_driver_base = 0;
		mouse_obj->hid_driver_size = 0;
		mouse_obj->hidclass_driver_base = 0;
		mouse_obj->hidclass_driver_size = 0;
		mouse_obj->hidusb_driver_base = 0;
		mouse_obj->hidusb_driver_size = 0;
		mouse_obj->use_mouse = false;


		_KeAcquireSpinLockAtDpcLevel = (UINT64)KeAcquireSpinLockAtDpcLevel;
		_KeReleaseSpinLockFromDpcLevel = (UINT64)KeReleaseSpinLockFromDpcLevel;
		_IofCompleteRequest = (UINT64)IofCompleteRequest;
		_IoReleaseRemoveLockEx = (UINT64)IoReleaseRemoveLockEx;


		UNICODE_STRING class_string;
		RtlInitUnicodeString(&class_string, _XOR_(L"\\Driver\\MouClass"));

		PDRIVER_OBJECT class_driver_object = NULL;
		NTSTATUS status = ObReferenceObjectByName(&class_string, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, (PVOID*)&class_driver_object);
		if (!NT_SUCCESS(status)) { return status; }

		UNICODE_STRING hid_string;
		RtlInitUnicodeString(&hid_string, _XOR_(L"\\Driver\\MouHID"));

		PDRIVER_OBJECT hid_driver_object = NULL;
		status = ObReferenceObjectByName(&hid_string, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, (PVOID*)&hid_driver_object);
		if (!NT_SUCCESS(status))
		{
			if (class_driver_object) { ObDereferenceObject(class_driver_object); }
			return status;
		}

		ULONG_PTR class_driver_base = (ULONG_PTR)class_driver_object->DriverStart;
		ULONG_PTR class_driver_end = class_driver_base + class_driver_object->DriverSize;
		mouse_obj->hid_driver_base = (ULONG_PTR)hid_driver_object->DriverStart;
		mouse_obj->hid_driver_size = (ULONG_PTR)hid_driver_object->DriverSize;

		// Optional bases for read-only lower-layer probes. Do not fail mouse
		// init if one of these drivers is not currently loaded on a non-USB
		// path; the overlay will show base=0 / install not attempted.
		{
			UNICODE_STRING hidclass_string;
			RtlInitUnicodeString(&hidclass_string, _XOR_(L"\\Driver\\HidClass"));
			PDRIVER_OBJECT hidclass_driver_object = NULL;
			if (NT_SUCCESS(ObReferenceObjectByName(&hidclass_string, OBJ_CASE_INSENSITIVE, NULL, 0,
				*IoDriverObjectType, KernelMode, NULL, (PVOID*)&hidclass_driver_object)))
			{
				mouse_obj->hidclass_driver_base = (ULONG_PTR)hidclass_driver_object->DriverStart;
				mouse_obj->hidclass_driver_size = (ULONG_PTR)hidclass_driver_object->DriverSize;
				ObDereferenceObject(hidclass_driver_object);
			}
		}

		{
			UNICODE_STRING hidusb_string;
			RtlInitUnicodeString(&hidusb_string, _XOR_(L"\\Driver\\HidUsb"));
			PDRIVER_OBJECT hidusb_driver_object = NULL;
			if (NT_SUCCESS(ObReferenceObjectByName(&hidusb_string, OBJ_CASE_INSENSITIVE, NULL, 0,
				*IoDriverObjectType, KernelMode, NULL, (PVOID*)&hidusb_driver_object)))
			{
				mouse_obj->hidusb_driver_base = (ULONG_PTR)hidusb_driver_object->DriverStart;
				mouse_obj->hidusb_driver_size = (ULONG_PTR)hidusb_driver_object->DriverSize;
				ObDereferenceObject(hidusb_driver_object);
			}
		}

		PDEVICE_OBJECT hid_device_object = hid_driver_object->DeviceObject;
		while (hid_device_object && !mouse_obj->service_callback)
		{
			PDEVICE_OBJECT class_device_object = class_driver_object->DeviceObject;
			while (class_device_object && !mouse_obj->service_callback)
			{
				if (!class_device_object->NextDevice && !mouse_obj->mouse_device)
				{
					mouse_obj->mouse_device = class_device_object;
				}

				PULONG_PTR device_extension = (PULONG_PTR)hid_device_object->DeviceExtension;
				ULONG_PTR device_ext_size = ((ULONG_PTR)hid_device_object->DeviceObjectExtension - (ULONG_PTR)hid_device_object->DeviceExtension) / sizeof(ULONG_PTR);
				for (ULONG_PTR i = 0; i + 1 < device_ext_size; i++)
				{
					ULONG_PTR callback = device_extension[i + 1];
					if (device_extension[i] == (ULONG_PTR)class_device_object &&
						callback >= class_driver_base &&
						callback < class_driver_end)
					{
						mouse_obj->service_callback = (MouseClassServiceCallback)callback;
						break;
					}
				}
				class_device_object = class_device_object->NextDevice;
			}
			hid_device_object = hid_device_object->AttachedDevice;
		}

		if (!mouse_obj->mouse_device)
		{
			PDEVICE_OBJECT target_device_object = class_driver_object->DeviceObject;
			while (target_device_object)
			{
				if (!target_device_object->NextDevice)
				{
					mouse_obj->mouse_device = target_device_object;
					break;
				}
				target_device_object = target_device_object->NextDevice;
			}
		}

		ObDereferenceObject(class_driver_object);
		ObDereferenceObject(hid_driver_object);


		if (!mouse_obj->mouse_device || !mouse_obj->service_callback)
			return STATUS_NOT_FOUND;

		mouse_obj->use_mouse = true;
		return STATUS_SUCCESS;


	}
#pragma code_seg()

#pragma code_seg(".vm2")

	void mouse_event( long x, long y, unsigned short button_flags)
	{


		ULONG input_data;
		KIRQL irql;
		MOUSE_INPUT_DATA mid = { 0 };

		mid.LastX = x;
		mid.LastY = y;
		mid.ButtonFlags = button_flags;

		KeRaiseIrql(DISPATCH_LEVEL, &irql);

		MouseClassServiceCallback_rewrite(mouse_obj.mouse_device, &mid, (PMOUSE_INPUT_DATA)&mid + 1, &input_data);
		
		KeLowerIrql(irql);

	}

#pragma code_seg()
}
