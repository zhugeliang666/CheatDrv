#pragma once
#include "fltKernel.h"
#include <ntifs.h>
#include <ntddmou.h>
#include "../xorstr.h"

#define MOUSE_MOVE_RELATIVE         0
#define MOUSE_MOVE_ABSOLUTE         1

#define MOUSE_LEFT_BUTTON_DOWN   0x0001  // Left Button changed to down.
#define MOUSE_LEFT_BUTTON_UP     0x0002  // Left Button changed to up.
#define MOUSE_RIGHT_BUTTON_DOWN  0x0004  // Right Button changed to down.
#define MOUSE_RIGHT_BUTTON_UP    0x0008  // Right Button changed to up.
#define MOUSE_MIDDLE_BUTTON_DOWN 0x0010  // Middle Button changed to down.
#define MOUSE_MIDDLE_BUTTON_UP   0x0020  // Middle Button changed to up.



EXTERN_C POBJECT_TYPE* IoDriverObjectType;


namespace mouse {


	EXTERN_C

	NTSTATUS
		NTAPI
		ObReferenceObjectByName(
			_In_ PUNICODE_STRING ObjectName,
			_In_ ULONG Attributes,
			_In_opt_ PACCESS_STATE AccessState,
			_In_opt_ ACCESS_MASK DesiredAccess,
			_In_ POBJECT_TYPE ObjectType,
			_In_ KPROCESSOR_MODE AccessMode,
			_Inout_opt_ PVOID ParseContext,
			_Out_ PVOID* Object
		);


	typedef struct _NF_MOUSE_REQUEST
	{
		long x;
		long y;
		unsigned short button_flags;
	}NF_MOUSE_REQUEST, * PNF_MOUSE_REQUEST;




	typedef VOID
	(*MouseClassServiceCallback)(
		PDEVICE_OBJECT DeviceObject,
		PMOUSE_INPUT_DATA InputDataStart,
		PMOUSE_INPUT_DATA InputDataEnd,
		PULONG InputDataConsumed
		);

	typedef struct _MOUSE_OBJECT
	{
		PDEVICE_OBJECT              mouse_device;
		MouseClassServiceCallback service_callback;
		ULONG_PTR                   hid_driver_base;
		ULONG_PTR                   hid_driver_size;
		ULONG_PTR                   hidclass_driver_base;
		ULONG_PTR                   hidclass_driver_size;
		ULONG_PTR                   hidusb_driver_base;
		ULONG_PTR                   hidusb_driver_size;
		bool                        use_mouse;
	} MOUSE_OBJECT, * PMOUSE_OBJECT;


	extern MOUSE_OBJECT mouse_obj;

	NTSTATUS init_mouse(PMOUSE_OBJECT mouse_obj);
	void mouse_event( long x, long y, unsigned short button_flags);

}
