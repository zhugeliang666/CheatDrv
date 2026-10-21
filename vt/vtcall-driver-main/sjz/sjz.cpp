#include "sjz.h"
#include "world.h"
#include "decrypt.h"
#include "coord_cache.h"
#include "../vt/hv.h"
#include "../vt/ept-probe.h"
#include "../gamecommon/gamecommon.h"
#include "gamecommon/game.h"

namespace sjz {

#pragma code_seg(".vm")

	// Module-global frame state. `engine` is the legacy persistent input
	// to update_addr(); `currentTime` is captured by ReadData() and read
	// by aim.cpp for elapsed-time math.
	ULONG64 engine;
	UINT64  currentTime = 0;
	ULONG64 lastReadContainerTime = 0;

	// Stats counters surfaced to render.cpp's debug overlay.
	UINT64 screenCount  = 0;
	UINT64 screenCount2 = 0;
	bool   isMoving     = false;
	UINT64 diagPipelineStage = 0;
	UINT64 diagPackedCounts = 0;
	UINT64 diagDrawMainTicks = 0;
	UINT64 diagDrawPlayerCalls = 0;
	PmoValidationState pmoValidation = {};
	PmoDebugRequest    pmoDebugRequest = {};
	PmoDebugResult     pmoDebugResult = {};
	static UINT64 autoCoordProbeCr3 = 0;
	static UINT64 autoCoordProbeId = 0;
	static volatile LONG64 autoCoordProbeInstalledMask = 0;

	// Module-private menu-namespace settings (referenced via internal.h).
	namespace menu {
		bool isHead = false;
		bool isSkeleton = false;
		bool isBox = true;
		bool isAim = false;
		bool isBattleMode = false;
		bool isShowDebugInfo = false;
		bool isHealth = true;
		bool isShowContainer = true;
		bool isShowBox = true;
		bool isShowItem = true;
		bool isItemList = true;
		bool isCenter = true;
		bool isDistance = true;
		bool isShowNpc = true;
	}

	// Legacy declared-but-never-defined hook entry; kept as no-op.
	void hook() {}

	// Tick forwarders kept on the public facade. They route to scan/.
	void GetData()      {
		if (!isStart) return;
		ReadData();
	}

	void GetOtherData() {
		// kept as no-op ___ original implementation was fully commented out.
	}

	static UINT64 AutoCoordProbeFullMask() {
		const ULONG count = hv::g_ghv->vcpu_count;
		if (!count)
			return 0;
		if (count >= 64)
			return ~0ull;
		return (1ull << count) - 1ull;
	}

	static void AutoCoordProbeDisarmAll(hv::vcpu* cpu) {
		if (!cpu || !autoCoordProbeCr3)
			return;

		UINT64 removedMask = 0;
		hv::ept_probe_remove_all(
			cpu,
			autoCoordProbeCr3,
			kCoordProbeDecryptRet,
			0,
			&removedMask);

		autoCoordProbeCr3 = 0;
		autoCoordProbeId = 0;
		_InterlockedExchange64(&autoCoordProbeInstalledMask, 0);
	}

	void AutoCoordProbeTick(hv::vcpu* cpu) {
		if (!cpu)
			return;

		const bool shouldArm =
			isStart &&
			game::GameCr3 &&
			game::GameNULL;

		if (!shouldArm) {
			AutoCoordProbeDisarmAll(cpu);
			return;
		}

		if (autoCoordProbeCr3 && autoCoordProbeCr3 != game::GameCr3) {
			AutoCoordProbeDisarmAll(cpu);
			ClearCoordHookCache();
		}

		const UINT64 fullMask = AutoCoordProbeFullMask();
		if (!fullMask)
			return;

		const UINT64 installedMaskSnapshot = (UINT64)autoCoordProbeInstalledMask;
		if (autoCoordProbeCr3 == game::GameCr3 &&
			((installedMaskSnapshot & fullMask) == fullMask)) {
			return;
		}

		UINT64 installedMask = 0;
		const UINT64 id = hv::ept_probe_install_all(
			cpu,
			game::GameCr3,
			kCoordProbeDecryptRet,
			0,
			0,
			&installedMask);

		if (id) {
			autoCoordProbeCr3 = game::GameCr3;
			autoCoordProbeId = id;
			if (installedMask)
				_InterlockedOr64(&autoCoordProbeInstalledMask, (LONG64)installedMask);
		}
	}

	template <typename T>
	static bool PmoRead(ULONG64 address, T& out) {
		RtlZeroMemory(&out, sizeof(T));
		if (!isValidPtr(address))
			return false;
		return ReadMemoryt(address, &out, sizeof(T));
	}

	static bool PmoFail(UINT64 stage) {
		pmoValidation.failStage = stage;
		pmoValidation.lastOk = 0;
		return false;
	}

	bool PmoValidateOnce() {
		pmoValidation.validateRuns++;
		pmoValidation.failStage = 0;
		pmoValidation.lastOk = 0;

		pmoValidation.pid  = game::GamePid;
		pmoValidation.cr3  = game::GameCr3;
		pmoValidation.base = game::GameNULL;
		pmoValidation.key  = gameData.key;

		if (!isStart)
			return PmoFail(1);     // F2 has not armed sjz yet.

		if (!game::gameProcess || !game::GamePid || !game::GameCr3 || !game::GameNULL)
			return PmoFail(2);     // GameInit has not resolved process / CR3 / base.

		ULONG64 gworld = 0;
		if (!PmoRead(game::GameNULL + Offsets.Uworld, gworld))
			return PmoFail(10);
		pmoValidation.gworld = gworld;
		if (!isValidPtr(gworld))
			return PmoFail(11);

		ULONG64 ulevels = 0;
		if (!PmoRead(gworld + Offsets.ULevels, ulevels))
			return PmoFail(20);
		pmoValidation.ulevels = ulevels;
		if (!isValidPtr(ulevels))
			return PmoFail(21);

		int levelCount = 0;
		if (!PmoRead(gworld + Offsets.LevelCount, levelCount))
			return PmoFail(22);
		pmoValidation.levelCount = levelCount;

		ULONG64 ulevel = 0;
		if (!PmoRead(ulevels, ulevel))
			return PmoFail(23);
		pmoValidation.ulevel = ulevel;
		if (!isValidPtr(ulevel))
			return PmoFail(24);

		int actorCount = 0;
		if (!PmoRead(ulevel + Offsets.Count, actorCount))
			return PmoFail(30);
		pmoValidation.actorCount = actorCount;
		if (actorCount <= 0 || actorCount > 0x20000)
			return PmoFail(31);

		ULONG64 actorArrayRaw = 0;
		if (!PmoRead(ulevel + Offsets.Actor, actorArrayRaw))
			return PmoFail(32);
		pmoValidation.actorArrayRaw = actorArrayRaw;
		pmoValidation.actorArray = decrypt_qword((INT64)actorArrayRaw);
		if ((actorArrayRaw & 0x8000000000000000ull) && !gameData.key)
			return PmoFail(33);    // Actor array is encrypted, key not captured yet.
		if (!isValidPtr(pmoValidation.actorArray))
			return PmoFail(34);

		ULONG64 localPlayer = 0;
		if (PmoRead(game::GameNULL + Offsets.DecryptLocalPlayers, localPlayer))
			pmoValidation.localPlayer = localPlayer;

		ULONG64 gnamesChunk0 = 0;
		if (PmoRead(game::GameNULL + Offsets.Gname + 0x8, gnamesChunk0))
			pmoValidation.gnamesChunk0 = gnamesChunk0;

		ULONG64 globalActors = 0;
		if (PmoRead(game::GameNULL + Offsets.GlobalActors, globalActors))
			pmoValidation.globalActors = globalActors;

		// Commit the verified minimal world snapshot. Full local-player /
		// entity scanning stays disabled for this phase; this is just a PMO
		// thread read-chain proof.
		gameData.Uworld     = gworld;
		gameData.ULevels    = ulevels;
		gameData.levelCount = levelCount;
		gameData.ULevel     = ulevel;
		gameData.Count      = actorCount;
		gameData.Actor      = pmoValidation.actorArray;
		gameData.LocalPlayer = localPlayer;

		pmoValidation.okRuns++;
		pmoValidation.lastOk = 1;
		// Surface the render/scan pipeline checkpoint through the existing
		// vtcall.exe pmo output without changing the host tool ABI:
		//   stage=<diagPipelineStage>
		//   key=0xD1SSCC11CC33CC55CC66CC77
		// where each byte is saturated.  If a real decrypt key is present keep
		// showing it; current coord-hook path normally runs with key==0.
		pmoValidation.failStage = diagPipelineStage;
		if (!gameData.key && diagPackedCounts)
			pmoValidation.key = diagPackedCounts;
		return true;
	}

	void PmoValidateTick() {
		pmoValidation.pmoHits++;

		// PMO can be 60+ Hz. Keep this as a low-frequency proof path so a
		// bad offset or paged-out chain does not stall the compositor thread.
		if ((pmoValidation.pmoHits & 0x0F) != 0)
			return;

		PmoValidateOnce();
	}

	void PmoDebugConsume() {
		UINT64 seq = pmoDebugRequest.seq;
		if (!seq || seq == pmoDebugResult.seq)
			return;

		PmoDebugResult result = {};
		result.seq = seq;
		result.command = pmoDebugRequest.command;
		result.address = pmoDebugRequest.address;
		result.requested = pmoDebugRequest.size;

		if (pmoDebugRequest.command != PmoDebugRead) {
			result.status = 2; // unsupported command
			pmoDebugResult = result;
			return;
		}

		if (!game::GameCr3 || !isValidPtr(pmoDebugRequest.address) ||
			!pmoDebugRequest.size) {
			result.status = 3; // not ready / bad args
			pmoDebugResult = result;
			return;
		}

		ULONG size = (ULONG)pmoDebugRequest.size;
		if (size > sizeof(result.bytes))
			size = sizeof(result.bytes);

		if (!ReadMemoryt(pmoDebugRequest.address, result.bytes, size)) {
			result.status = 4; // read failed in PMO context
			result.got = 0;
			pmoDebugResult = result;
			return;
		}

		result.status = 1;
		result.got = size;
		pmoDebugResult = result;
	}

#pragma code_seg()

} // namespace sjz
