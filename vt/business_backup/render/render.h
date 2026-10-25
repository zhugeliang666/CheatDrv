#pragma once
#include <fltKernel.h>

namespace hv {

	struct vcpu;

	extern PVOID swapChain;
	extern PVOID context;
	extern PVOID surface;
	extern PVOID device;
	extern  bool isFinish;
	extern PVOID d2dRenderTarget;
	extern PVOID colorBrush;
	extern PVOID TextFormat;
	extern PVOID BigTextFormat;
	extern PVOID descBuffer;  // user-mode VirtualAlloc'd 4KB scratch buffer, usable
	                          // as commit-page dummy dest in hv::Call(ReadProcessMemory).


	typedef struct RENDERINFO {

		PVOID swapChain = nullptr;
		PVOID context;
		PVOID surface;
		PVOID device;
		PVOID d2dRenderTarget;
		PVOID colorBrush;
		PVOID TextFormat;
		PVOID BigTextFormat;

	}RenderInfo;


	void init(vcpu* cpu);

	extern INT64 perf_frequency;

	void tick(vcpu* cpu);

	void reset(vcpu* cpu);

	PVOID CreateTexture();

	// Anti-screenshot: read fakeTexture without consuming or counting.
	// Used by Present / CopyResource / AcquireNextFrame alien handlers.
	PVOID GetFakeTexture();

	// Anti-screenshot: pre-magenta-cleared texture handed to alien GetBuffer
	// callers in place of NULL. Captured frame = solid magenta → hook worked.
	PVOID GetMarkerTexture();

	void CreateTexture2();

}
