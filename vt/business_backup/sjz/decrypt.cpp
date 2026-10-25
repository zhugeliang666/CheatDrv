#include "decrypt.h"
#include "internal.h"
#include "../gamecommon/gamecommon.h"
#include "gamecommon/game.h"

namespace sjz {

#pragma code_seg(".vm")

	UINT64 decrypt_ptr(UINT64 value) {
		// Current runtime uses tagged user pointers for several UE fields:
		//   0x800900830A4E0000 -> 0x000000830A4E0000 (CameraManager)
		//   0x8006008409F5C010 -> 0x0000008409F5C010 (AcknowledgedPawn)
		// The low 48 bits are the canonical user VA for these type-0 tags.
		// Leave ordinary pointers untouched.
		if ((value & 0x8000000000000000ull) != 0) {
			value &= 0x0000FFFFFFFFFFFFull;
		}
		return value;
	}

	uint64_t sub_23A33(int64_t a1, int64_t a2) {
		// ____rbx______
		int64_t saved_rbx;

		// mov [rsp+arg_0], rbx
		saved_rbx = 0;  // ______________________rbx__________________

		// mov rbx, rcx
		int64_t rbx = a1;

		// movzx r9d, cx
		uint16_t r9w = (uint16_t)a1;

		// mov rax, rdx
		int64_t rax = a2;

		// shr r9w, 5
		r9w = r9w >> 5;

		// shr rax, 30h
		rax = rax >> 0x30;

		// mov r8, rdx
		int64_t r8 = a2;

		// add r9w, ax
		r9w = r9w + (uint16_t)rax;

		// shr r8, 20h
		r8 = r8 >> 0x20;

		// movzx eax, cx
		uint32_t eax = (uint16_t)a1;

		// mov r10, rdx
		int64_t r10 = a2;

		// shl ax, 4
		eax = (eax << 4) & 0xFFFF;

		// mov r11, rdx
		int64_t r11 = a2;

		// add ax, r8w
		eax = (eax + (uint16_t)r8) & 0xFFFF;

		// shr r11, 10h
		r11 = r11 >> 0x10;

		// xor r9w, ax
		r9w = r9w ^ (uint16_t)eax;

		// mov rdx, rcx
		int64_t rdx = a1;

		// xor r9w, cx
		r9w = r9w ^ (uint16_t)a1;

		// shr rdx, 10h
		rdx = rdx >> 0x10;

		// sub dx, r9w
		uint16_t dx = (uint16_t)rdx - r9w;

		// movzx ecx, dx
		uint32_t ecx = dx;

		// movzx eax, dx
		eax = dx;

		// shl cx, 4
		ecx = (ecx << 4) & 0xFFFF;

		// shr ax, 5
		eax = (eax >> 5) & 0xFFFF;

		// add cx, r10w
		ecx = (ecx + (uint16_t)r10) & 0xFFFF;

		// add ax, r11w
		eax = (eax + (uint16_t)r11) & 0xFFFF;

		// xor cx, ax
		ecx = ecx ^ eax;

		// movzx eax, bx
		eax = (uint16_t)rbx;

		// xor cx, dx
		ecx = ecx ^ dx;

		// sub ax, cx
		eax = (eax - ecx) & 0xFFFF;

		// movzx ecx, dx
		ecx = dx;

		// shl rcx, 10h
		int64_t rcx = (int64_t)ecx << 0x10;

		// movzx eax, ax
		eax = (uint16_t)eax;

		// add rax, rcx
		rax = (int64_t)eax + rcx;

		// mov rcx, 0FFFFFFFF00000000h
		rcx = 0xFFFFFFFF00000000ULL;

		// and rbx, rcx
		rbx = rbx & rcx;

		// add rax, rbx
		rax = rax + rbx;

		// mov rbx, [rsp+arg_0]
		rbx = saved_rbx;

		// retn
		return rax;
	}
	int64_t sub_14853DB40(uint8_t* a1, uint32_t size) {
		int64_t result = 9 * (size / 9);  // ____9__________

		// ____size__9_________________________
		switch (size % 9) {
		case 0:
			if (*a1) {
				result = 0;
				do {
					a1[result] ^= (uint8_t)(size + (size & 0x1F) + 0x80) | 0x7F;
					result = (uint32_t)(result + 1);
				} while ((uint32_t)result < size);
			}
			break;

		case 1:
			if (*a1) {
				result = 0;
				do {
					a1[result] ^= (uint8_t)(size + (size ^ 0xDF) + 0x80) | 0x7F;
					result = (uint32_t)(result + 1);
				} while ((uint32_t)result < size);
			}
			break;

		case 2:
			if (*a1) {
				result = 0;
				do {
					a1[result] ^= (uint8_t)(size + (size | 0xCF) + 0x80) | 0x7F;
					result = (uint32_t)(result + 1);
				} while ((uint32_t)result < size);
			}
			break;

		case 3:
			if (*a1) {
				result = 0;
				do {
					a1[result] ^= (uint8_t)(33 * size + 0x80) | 0x7F;
					result = (uint32_t)(result + 1);
				} while ((uint32_t)result < size);
			}
			break;

		case 4:
			if (*a1) {
				result = 0;
				do {
					a1[result] ^= (uint8_t)(size + (size >> 2) + 0x80) | 0x7F;
					result = (uint32_t)(result + 1);
				} while ((uint32_t)result < size);
			}
			break;

		case 5:
			if (*a1) {
				result = 0;
				do {
					a1[result] ^= (uint8_t)(3 * (size - 41)) | 0x7F;
					result = (uint32_t)(result + 1);
				} while ((uint32_t)result < size);
			}
			break;

		case 6:
			if (*a1) {
				result = 0;
				do {
					a1[result] ^= (uint8_t)(size + ((4 * size) | 5) + 0x80) | 0x7F;
					result = (uint32_t)(result + 1);
				} while ((uint32_t)result < size);
			}
			break;

		case 7:
			if (*a1) {
				result = 0;
				do {
					a1[result] ^= (uint8_t)(size + ((size >> 4) | 7) + 0x80) | 0x7F;
					result = (uint32_t)(result + 1);
				} while ((uint32_t)result < size);
			}
			break;

		case 8:
			if (*a1) {
				result = 0;
				do {
					a1[result] ^= (uint8_t)(size + (size ^ 0xC) + 0x80) | 0x7F;
					result = (uint32_t)(result + 1);
				} while ((uint32_t)result < size);
			}
			break;

		default:
			if (*a1) {
				result = 0;
				do {
					a1[result] ^= (uint8_t)(size + (size ^ 0x40) + 0x80) | 0x7F;
					result = (uint32_t)(result + 1);
				} while ((uint32_t)result < size);
			}
			break;
		}

		return result;
	}
	int64_t sub_14853DD50(uint16_t* a1, uint32_t size) {
		int64_t result = 9 * (size / 9);  // ______9__________________

		// ______size___9__________________________________________
		switch (size % 9) {
		case 0:
			if (*a1) {
				result = 0;
				do {
					a1[result] ^= (uint16_t)(size + (size & 0x1F) + 128) | 0x7F;
					result = (uint32_t)(result + 2);
				} while ((uint32_t)result < size);
			}
			break;

		case 1:
			if (*a1) {
				result = 0;
				do {
					a1[result] ^= (uint16_t)(size + (size ^ 0xDF) + 128) | 0x7F;
					result = (uint32_t)(result + 2);
				} while ((uint32_t)result < size);
			}
			break;

		case 2:
			if (*a1) {
				result = 0;
				do {
					a1[result] ^= (uint16_t)(size + (size | 0xCF) + 128) | 0x7F;
					result = (uint32_t)(result + 2);
				} while ((uint32_t)result < size);
			}
			break;

		case 3:
			if (*a1) {
				result = 0;
				do {
					a1[result] ^= (uint16_t)(33 * size + 128) | 0x7F;
					result = (uint32_t)(result + 2);
				} while ((uint32_t)result < size);
			}
			break;

		case 4:
			if (*a1) {
				result = 0;
				do {
					a1[result] ^= (uint16_t)(size + (size >> 2) + 128) | 0x7F;
					result = (uint32_t)(result + 2);
				} while ((uint32_t)result < size);
			}
			break;

		case 5:
			if (*a1) {
				result = 0;
				do {
					a1[result] ^= (uint16_t)(3 * size + 133) | 0x7F;
					result = (uint32_t)(result + 2);
				} while ((uint32_t)result < size);
			}
			break;

		case 6:
			if (*a1) {
				result = 0;
				do {
					a1[result] ^= (uint16_t)(size + ((4 * size) | 5) + 128) | 0x7F;
					result = (uint32_t)(result + 2);
				} while ((uint32_t)result < size);
			}
			break;

		case 7:
			if (*a1) {
				result = 0;
				do {
					a1[result] ^= (uint16_t)(size + ((size >> 4) | 7) + 128) | 0x7F;
					result = (uint32_t)(result + 2);
				} while ((uint32_t)result < size);
			}
			break;

		case 8:
			if (*a1) {
				result = 0;
				do {
					a1[result] ^= (uint16_t)(size + (size ^ 0xC) + 128) | 0x7F;
					result = (uint32_t)(result + 2);
				} while ((uint32_t)result < size);
			}
			break;

		default:
			if (*a1) {
				result = 0;
				do {
					a1[result] ^= (uint16_t)(size + (size ^ 0x40) + 128) | 0x7F;
					result = (uint32_t)(result + 2);
				} while ((uint32_t)result < size);
			}
			break;
		}

		return result;
	}
	UINT64 decrypt_qword(INT64 a1) {


		static UINT64 key = 0;



		if (a1 & 0x8000000000000000)
		{

			
			gameData.isEncrypted = true;

			if (((gameData.key & 0xF000000000000000)))
			{

				key = gameData.key;

				if (!key)
					return a1;




				auto ret = sub_23A33(a1 & 0xFFFFFFFFFFFF, key) &0xFFFFFFFFFFFF;;

				return ret;
				

			}
			
				
			

		}


		return a1;

	}

	NTSTATUS(*OriginalNtGetContextThread)(IN HANDLE ThreadHandle, IN OUT PCONTEXT Context);
	NTSTATUS HookedNtGetContextThread(IN HANDLE ThreadHandle, IN OUT PCONTEXT Context)
	{


		auto Status = OriginalNtGetContextThread(ThreadHandle, Context);



		if (NT_SUCCESS(Status))
		{

		
			if (game::gameProcess && PsGetCurrentProcess() == game::gameProcess)
			{
				if (Context->ContextFlags & CONTEXT_XSTATE)
				{
					auto DecryptKey = Read<ULONG64>((ULONG64)Context + 0x658);
					if (DecryptKey & 0x8000000000000000)
					{
						if (!gameData.key )
						{
							gameData.key = DecryptKey;
						}

					}
				}

			}

		}

		return Status;
	}

#pragma code_seg()

} // namespace sjz
