#include "world.h"
#include "decrypt.h"
#include "reader.h"
#include "../gamecommon/gamecommon.h"
#include "gamecommon/game.h"

namespace sjz {

#pragma code_seg(".vm")

	GameData gameData;

	static bool IsFiniteFloat(float v) {
		return (v == v) && (v > -3.4e38f) && (v < 3.4e38f);
	}

	static bool IsFiniteVector(const math_rust::Vector3& v) {
		return IsFiniteFloat(v.x) && IsFiniteFloat(v.y) && IsFiniteFloat(v.z);
	}

	static bool IsPlausibleWorldVector(const math_rust::Vector3& v) {
		if (!IsFiniteVector(v)) return false;
		if (v.x > -0.01f && v.x < 0.01f &&
			v.y > -0.01f && v.y < 0.01f &&
			v.z > -0.01f && v.z < 0.01f) return false;
		return (v.x > -10000000.0f && v.x < 10000000.0f &&
			v.y > -10000000.0f && v.y < 10000000.0f &&
			v.z > -10000000.0f && v.z < 10000000.0f);
	}

	static bool IsPlausibleWorldVector(const FVector& v) {
		return IsPlausibleWorldVector(math_rust::Vector3(v.x, v.y, v.z));
	}

	static float Dot3(const math_rust::Vector3& a, const math_rust::Vector3& b) {
		return a.x * b.x + a.y * b.y + a.z * b.z;
	}

	static bool IsValidCameraView(const FMinimalViewInfo& view) {
		if (!IsPlausibleWorldVector(view.Location)) return false;
		if (!IsFiniteFloat(view.Rotation.pitch) ||
			!IsFiniteFloat(view.Rotation.yaw) ||
			!IsFiniteFloat(view.Rotation.roll)) {
			return false;
		}
		if (!IsFiniteFloat(view.FOV) || view.FOV < 1.0f || view.FOV > 179.0f) return false;
		return true;
	}

	static bool RefreshCameraView() {
		UINT64 playerController = decrypt_ptr(decrypt(gameData.PlayerController));
		if (!isValidPtr(playerController) && isValidPtr(gameData.LocalPlayer)) {
			playerController = decrypt_ptr(Read<UINT64>(gameData.LocalPlayer + Offsets.PlayerController));
		}
		if (!isValidPtr(playerController))
			return IsValidCameraView(gameData.viewInfo);

		UINT64 cameraManager = decrypt_ptr(Read<UINT64>(playerController + Offsets.PlayerCameraManager));
		if (!isValidPtr(cameraManager)) return false;

		// Current runtime: CameraCachePrivate has usable rot/FOV but Location can
		// be encrypted/stale. ViewTarget.POV is plaintext and matches VT reads.
		const UINT64 pov = cameraManager + Offsets.CameraViewTarget + Offsets.ViewTargetPOV;

		FMinimalViewInfo view{};
		view.Location = Read<math_rust::Vector3>(pov + Offsets.MinimalViewInfoLocation);
		view.Rotation = Read<FRotator>(pov + Offsets.MinimalViewInfoRotation);
		view.FOV = Read<float>(pov + Offsets.MinimalViewInfoFOV);

		if (!IsValidCameraView(view)) return false;

		gameData.viewInfo = view;
		gameData.Martix = cameraManager; // legacy debug field; now stores CameraManager
		return true;
	}

	static Matrix4x4 BuildCameraMatrix(const FMinimalViewInfo& view) {
		Matrix4x4 matrix{};

		const float screenWidth = (float)game::GameCenterW;
		const float screenHeight = (float)game::GameCenterH;
		if (screenWidth <= 1.0f || screenHeight <= 1.0f) return matrix;

		constexpr float kPi = 3.14159265358979323846f;
		const float pitch = view.Rotation.pitch * kPi / 180.0f;
		const float yaw = view.Rotation.yaw * kPi / 180.0f;
		const float roll = view.Rotation.roll * kPi / 180.0f;

		const float sp = sinf(pitch);
		const float cp = cosf(pitch);
		const float sy = sinf(yaw);
		const float cy = cosf(yaw);
		const float sr = sinf(roll);
		const float cr = cosf(roll);

		const math_rust::Vector3 axisX(cp * cy, cp * sy, sp);
		const math_rust::Vector3 axisY(
			sr * sp * cy - cr * sy,
			sr * sp * sy + cr * cy,
			-sr * cp);
		const math_rust::Vector3 axisZ(
			-(cr * sp * cy + sr * sy),
			cy * sr - cr * sp * sy,
			cr * cp);

		const float tanHalfFov = tanf(view.FOV * kPi / 360.0f);
		if (tanHalfFov <= 0.0001f || !IsFiniteFloat(tanHalfFov)) return matrix;

		const float sx = 1.0f / tanHalfFov;
		const float syScale = (screenWidth / screenHeight) / tanHalfFov;
		const math_rust::Vector3 cam = view.Location;

		// Layout intentionally matches the legacy WorldToScreen multiply below:
		// x = wx*m[0] + wy*m[4] + wz*m[8]  + m[12]
		// y = wx*m[1] + wy*m[5] + wz*m[9]  + m[13]
		// w = wx*m[3] + wy*m[7] + wz*m[11] + m[15]
		matrix.m[0][0] = axisY.x * sx;
		matrix.m[1][0] = axisY.y * sx;
		matrix.m[2][0] = axisY.z * sx;
		matrix.m[3][0] = -Dot3(cam, axisY) * sx;

		matrix.m[0][1] = axisZ.x * syScale;
		matrix.m[1][1] = axisZ.y * syScale;
		matrix.m[2][1] = axisZ.z * syScale;
		matrix.m[3][1] = -Dot3(cam, axisZ) * syScale;

		// Debug depth column. The existing W2S does not use column 2.
		matrix.m[0][2] = axisX.x;
		matrix.m[1][2] = axisX.y;
		matrix.m[2][2] = axisX.z;
		matrix.m[3][2] = -Dot3(cam, axisX);

		matrix.m[0][3] = axisX.x;
		matrix.m[1][3] = axisX.y;
		matrix.m[2][3] = axisX.z;
		matrix.m[3][3] = -Dot3(cam, axisX);

		return matrix;
	}

	Matrix4x4  get_matrix() {

		if (game::GameNULL == 0)
			return Matrix4x4{};

		if (!IsValidCameraView(gameData.viewInfo)) {
			if (!RefreshCameraView()) return Matrix4x4{};
		}

		return BuildCameraMatrix(gameData.viewInfo);


	}
	bool WorldToScreen(FVector WorldPos, math_rust::Vector2& ScreenPos) {

		if (WorldPos.x != WorldPos.x || WorldPos.y != WorldPos.y || WorldPos.z != WorldPos.z) return false;
		if(ScreenPos.x!= ScreenPos.x || ScreenPos.y!= ScreenPos.y) return false;
		// _______________g_matrix
		Matrix4x4 viewMatrix = get_matrix();
		const float* matrix = (float*)viewMatrix.m;

		if (matrix[3] == 0.0f && matrix[7] == 0.0f && matrix[11] == 0.0f && matrix[15] == 0.0f)
			return false;

		// 1. ___________
		float x = WorldPos.x * matrix[0] +
			WorldPos.y * matrix[4] +
			WorldPos.z * matrix[8] +
			matrix[12];

		float y = WorldPos.x * matrix[1] +
			WorldPos.y * matrix[5] +
			WorldPos.z * matrix[9] +
			matrix[13];

		float w = WorldPos.x * matrix[3] +
			WorldPos.y * matrix[7] +
			WorldPos.z * matrix[11] +
			matrix[15];

		// 2. ___W__
		if (w < 0.001f) {
			return false;
		}

		// 3. ________
		float invW = 1.0f / w;
		x *= invW;
		y *= invW;

		// 4. ______________
		float screenWidth = (float)game::GameCenterW;
		float screenHeight = (float)game::GameCenterH;

		ScreenPos.x = (screenWidth * 0.5f) * (1.0f + x);
		ScreenPos.y = (screenHeight * 0.5f) * (1.0f - y);

		// 5. ___________
		if (ScreenPos.x < 0.0f || ScreenPos.x > screenWidth ||
			ScreenPos.y < 0.0f || ScreenPos.y > screenHeight) {
			return false;
		}

		return true;
	}
	void GetName(int objectId, char* result, size_t maxSize, bool& isWide) {
		if (!result || maxSize == 0) {
			return;
		}

		// _________________________________
		union {
			char narrow[256];
			wchar_t wide[128];
		} buffer = {0};

		ULONG ChunkIndex = objectId >> 0x12;
		ULONG NameIndex = objectId & 0x3FFFF;
		ULONG64 NamePoolBase = Read<ULONG64>(game::GameNULL + Offsets.Gname + ChunkIndex * 0x8 + 0x8);
		ULONG64 NamePoolAddress = NamePoolBase + (NameIndex * 2);

		if (!isValidPtr(NamePoolBase)) {
			strcpy_s(result, maxSize, "Unknown");
			return;
		}

		USHORT NameEntry = Read<USHORT>(NamePoolAddress);
		ULONG NameLength = NameEntry >> 0x6;

		if (NameLength <= 0 || NameLength >= 128) {
			strcpy_s(result, maxSize, "Unknown");
			return;
		}

		// ___________________________________________________
		if (!(NameEntry & 0x1)) {
			// _______________
			if (!ReadMemoryt((NamePoolAddress + 0x2), buffer.narrow, NameLength)) {
				strcpy_s(result, maxSize, "Unknown");
				return;
			}
			sub_14853DB40((uint8_t*)buffer.narrow, NameLength);
			isWide = false;
			// ___________________________
			buffer.narrow[NameLength] = 0;
			// ______________________________
			strcpy_s(result, maxSize, buffer.narrow);
		}
		else {
			// _______________
			//if (!ReadMemoryt((NamePoolAddress + 0x2), buffer.wide, NameLength * sizeof(wchar_t))) {
			//	strcpy_s(result, maxSize, "Unknown");
			//	return;
			//}
			//sub_14853DD50((uint16_t*)buffer.wide, NameLength);
			//isWide = true;
			//// ___________________________
			//buffer.wide[NameLength] = 0;
			//// ___________________________________________________isWide______
			//memcpy(result, buffer.wide, min(maxSize, NameLength * sizeof(wchar_t)));
		}
	}
	bool InScreen(math_rust::Vector2 pos) {
		
		if (pos.x <= 2 ||
			pos.y <= 2 ||
			pos.x >= (game::GameCenterW-2) ||
			pos.y >= (game::GameCenterH-2))
		{
			return false;
		};
		return true;
	}
	bool update_addr(ULONG64& engine)
	{

		gameData.Uworld = encrypt(Read<ULONG64>((ULONG64)game::GameNULL + Offsets.Uworld));

		const ULONG64 uworld = decrypt(gameData.Uworld);
		if (isValidPtr(uworld)) {
			gameData.ULevels = Read<ULONG64>(uworld + Offsets.ULevels);
			gameData.levelCount = Read<int>(uworld + Offsets.LevelCount);

			if (isValidPtr(gameData.ULevels)) {
				gameData.ULevel = Read<ULONG64>((ULONG64)gameData.ULevels);
			}
			else {
				gameData.ULevel = 0;
			}

			if (isValidPtr(gameData.ULevel)) {
				gameData.Count = Read<int>(gameData.ULevel + Offsets.Count);
				gameData.Actor = decrypt_qword(Read<ULONG64>(gameData.ULevel + Offsets.Actor));
				if (!isValidPtr(gameData.Actor))
					gameData.Actor = 0;
			}
			else {
				gameData.Count = 0;
				gameData.Actor = 0;
			}
		}
		else {
			// Do not let UWorld / actor-array encryption kill the draw path.
			// The hook-only fallback only needs a valid camera and recent
			// plaintext coords captured by the EPT probe.
			gameData.ULevels = 0;
			gameData.ULevel = 0;
			gameData.levelCount = 0;
			gameData.Count = 0;
			gameData.Actor = 0;
		}

		//gameData.GameInstance = encrypt(Read<ULONG64>((ULONG64)decrypt(gameData.Uworld) + Offsets.OwningGameInstance));

		//if (!isValidPtr(decrypt(gameData.GameInstance))) return false;

		//gameData.LocalPlayers = Read<ULONG64>(decrypt(gameData.GameInstance) + Offsets.LocalPlayers);

		//if (!isValidPtr(gameData.LocalPlayers)) return false;

		//gameData.LocalPlayer = Read<ULONG64>(gameData.LocalPlayers);

		gameData.LocalPlayer = Read<ULONG64>((ULONG64)game::GameNULL + Offsets.DecryptLocalPlayers);


		if (!isValidPtr(gameData.LocalPlayer)) {
			gameData.PlayerController = 0;
			gameData.AcknowledgedPawn = 0;
			gameData.PlayerRootComponent = 0;
			gameData.PlayerPawnMesh = 0;
			gameData.PlayerTeam = 0;
			gameData.PlayerRotator = FRotator();
			gameData.localPlayerPos = FVector();
			return IsValidCameraView(gameData.viewInfo);
		}

		gameData.PlayerController = encrypt(decrypt_ptr(Read<ULONG64>(gameData.LocalPlayer + Offsets.PlayerController)));

		ULONG64 controller = decrypt_ptr(decrypt(gameData.PlayerController));
		if (!isValidPtr(controller)) {
			gameData.PlayerController = 0;
			gameData.AcknowledgedPawn = 0;
			gameData.PlayerRootComponent = 0;
			gameData.PlayerPawnMesh = 0;
			gameData.PlayerTeam = 0;
			gameData.PlayerRotator = FRotator();
			controller = 0;
		}

		gameData.AcknowledgedPawn = controller ? encrypt(decrypt_ptr(Read<ULONG64>(controller + Offsets.AcknowledgedPawn))) : 0;

		const ULONG64 localPawn = decrypt_ptr(decrypt(gameData.AcknowledgedPawn));
		if (isValidPtr(localPawn)) {
			gameData.objId = Read<ULONG>(localPawn + Offsets.GObjcetID);
			gameData.PlayerRootComponent = decrypt_ptr(Read<ULONG64>(localPawn + Offsets.RootComponent));
			gameData.PlayerPawnMesh = decrypt_ptr(Read<ULONG64>(localPawn + Offsets.PlayerPawnMesh));
			gameData.PlayerTeam = GetTeamId(localPawn);
			gameData.PlayerRotator = Read<FRotator>(controller + Offsets.ControlRotation);
		}
		else {
			// Local pawn/root/mesh are not required for first-pass ESP when
			// entity coordinates come from the EPT coord hook.  Keep them
			// optional so a missing/tagged local chain does not block drawing.
			gameData.objId = 0;
			gameData.PlayerRootComponent = 0;
			gameData.PlayerPawnMesh = 0;
			gameData.PlayerTeam = 0;
			gameData.PlayerRotator = FRotator();
		}


		if (!RefreshCameraView() && !IsValidCameraView(gameData.viewInfo)) return false;

		gameData.localPlayerPos = isValidPtr(localPawn) ? GetWorldLocation(localPawn) : FVector();

		// Local RootComponent position can be encrypted in this build. Distance
		// and radar filters only need a sane local origin, so fall back to the
		// plaintext camera ViewTarget location when the root value is implausible.
		if (!IsPlausibleWorldVector(gameData.localPlayerPos) && IsValidCameraView(gameData.viewInfo)) {
			gameData.localPlayerPos = FVector(
				gameData.viewInfo.Location.x,
				gameData.viewInfo.Location.y,
				gameData.viewInfo.Location.z);
		}

		gameData.camp = isValidPtr(localPawn) ? getCamp(localPawn) : 0;

		return true;
	}
	size_t UTF8ToUTF16(const char* utf8, wchar_t* utf16, size_t utf16Size) {
		if (!utf8 || !utf16 || utf16Size == 0) return 0;

		size_t utf8Len = strlen(utf8);
		size_t utf16Index = 0;

		for (size_t i = 0; i < utf8Len && utf16Index < utf16Size - 1; i++) {
			unsigned char c = utf8[i];

			if (c < 0x80) {
				// ASCII ______
				utf16[utf16Index++] = c;
			}
			else if (c < 0xE0) {
				// 2______ UTF-8
				if (i + 1 >= utf8Len) break;
				unsigned char c2 = utf8[++i];
				if ((c2 & 0xC0) != 0x80) break;

				utf16[utf16Index++] = ((c & 0x1F) << 6) | (c2 & 0x3F);
			}
			else if (c < 0xF0) {
				// 3______ UTF-8
				if (i + 2 >= utf8Len) break;
				unsigned char c2 = utf8[++i];
				unsigned char c3 = utf8[++i];
				if ((c2 & 0xC0) != 0x80 || (c3 & 0xC0) != 0x80) break;

				utf16[utf16Index++] = ((c & 0x0F) << 12) | ((c2 & 0x3F) << 6) | (c3 & 0x3F);
			}
			else {
				// 4______ UTF-8 (__________________)
				if (i + 3 >= utf8Len) break;
				unsigned char c2 = utf8[++i];
				unsigned char c3 = utf8[++i];
				unsigned char c4 = utf8[++i];
				if ((c2 & 0xC0) != 0x80 || (c3 & 0xC0) != 0x80 || (c4 & 0xC0) != 0x80) break;

				unsigned int codePoint = ((c & 0x07) << 18) | ((c2 & 0x3F) << 12) | ((c3 & 0x3F) << 6) | (c4 & 0x3F);

				if (codePoint > 0x10FFFF) break;

				if (utf16Index + 1 >= utf16Size - 1) break;

				codePoint -= 0x10000;
				utf16[utf16Index++] = 0xD800 | ((codePoint >> 10) & 0x3FF);
				utf16[utf16Index++] = 0xDC00 | (codePoint & 0x3FF);
			}
		}

		utf16[utf16Index] = L'\0';
		return utf16Index;
	}
	int MultiByteToWideChar(const char* mbStr, wchar_t* wcStr, size_t wcStrSize) {
		if (!mbStr || !wcStr || wcStrSize == 0) return 0;

		size_t len = UTF8ToUTF16(mbStr, wcStr, wcStrSize);
		return (int)len;
	}

#pragma code_seg()

} // namespace sjz
