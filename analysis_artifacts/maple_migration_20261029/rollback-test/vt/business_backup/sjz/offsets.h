#pragma once
#include <cstdint>
#pragma code_seg(".vm")


static struct Offsets {
	// 2026-05-29 IDA/MCP xref-signature refreshed globals for the current UE4 dump.
	// Full VA in IDA:
	//   GWorld/全_Uworld   = 0x1591F8CA8
	//   GNames/NamePool    = 0x159CF46C0
	//   LocalPlayer/本人地址 = 0x159E5C1C0
	//   Global actor array = 0x159BA5218
	//   GUObjectArray      = 0x159CF0458
	// Stored here as RVA because the runtime code adds game::GameNULL.
	static const uintptr_t Gname = 0x19CF46C0; //x
	static const uintptr_t Matrix = 0x1263C520; //x
	static const uintptr_t Uworld = 0x191F8CA8; //x
	static const uintptr_t DecryptLocalPlayers = 0x19E5C1C0; //x
	static const uintptr_t GlobalActors = 0x19BA5218; //x
	static const uintptr_t GUObjectArray = 0x19CF0458; //x
	static const uintptr_t Matrix0 = 0x20;    //x
	static const uintptr_t Matrix1 = 0x280;  //x
	static const uintptr_t ULevels = 0x158; // docs/sjz Offset.OffSet_UWorld_Levels
	static const uintptr_t LevelCount = 0x160; // TArray ULevels+8
	static const uintptr_t PlayerController = 0x30; // docs/sjz Offset.OffSet_UPlayer_PlayerController
	static const uintptr_t AcknowledgedPawn = 0x3F0;// docs/sjz Offset.OffSet_APlayerController_AcknowledgedPawn
	static const uintptr_t PlayerCameraManager = 0x408; // docs/sjz Offset.OffSet_APlayerController_PlayerCameraManager
	static const uintptr_t CameraViewTarget = 0x2DEC0; // docs/sjz Offset.OffSet_APlayerCameraManager_ViewTarget
	static const uintptr_t ViewTargetPOV = 0x10; // docs/sjz Offset.OffSet_FTViewTarget_POV
	static const uintptr_t CameraCachePrivate = 0x2F2E0; // docs/sjz Offset.OffSet_APlayerCameraManager_CameraCachePrivate
	static const uintptr_t CameraCachePOV = 0x10; // docs/sjz Offset.OffSet_FCameraCacheEntry_POV
	static const uintptr_t MinimalViewInfoLocation = 0x00; // docs/sjz Offset.OffSet_FMinimalViewInfo_Location
	static const uintptr_t MinimalViewInfoRotation = 0x10; // docs/sjz Offset.OffSet_FMinimalViewInfo_Rotation
	static const uintptr_t MinimalViewInfoFOV = 0x1C; // docs/sjz Offset.OffSet_FMinimalViewInfo_FOV
	static const uintptr_t GObjcetID = 0x1C; // docs/sjz Offset.OffSet_AActor_ObjectID
	static const uintptr_t Count = 0xA0; // ULevel actor TArray count
	static const uintptr_t Actor = 0x98; // docs/sjz OffSet_ULevel_Tarray = Level_OwningWorld - sizeof(TArray)
	static const uintptr_t PlayerState = 0x390; // docs/sjz Offset.OffSet_APawn_PlayerState
	static const uintptr_t ExitState = 0x0D60;//x struct ADFMPlayerState : AGPPlayerState ->enum class EExitState ExitState
	static const uintptr_t RootComponent = 0x180;// docs/sjz Offset.OffSet_AActor_RootComponent
	static const uintptr_t PlayerPawnMesh = 0x3D0; // docs/sjz Offset.OffSet_ACHARACTER_Mesh
	static const uintptr_t TeamId = 0x0660;// docs/sjz Offset.OffSet_AGPPlayerState_TeamId
	static const uintptr_t ControlRotation = 0x03D8;// docs/sjz Offset.OffSet_AController_ControlRotation
	static const uintptr_t RelativeLocation = 0x168;// docs/sjz Offset.OffSet_USceneComponent_RelativeLocation
	static const uintptr_t MarkingItemType = 0x072A; //x struct AInteractorBase -> class EMarkingItemType MarkingItemType
	static const uintptr_t HealthComp = 0x2328;// docs/sjz Offset.OffSet_ADFMCharacter_DFMHealthDataComponent
	static const uintptr_t HealthSet = 0x0280; // docs/sjz Offset.OffSet_UGPHealthDataComponent_HealthSet
	static const uintptr_t Health = 0x030; // docs/sjz Offset.OffSet_UGPAttributeSetHealth_Health
	static const uintptr_t PickupItemInfo = 0x0E40;//x struct AInventoryPickup -> struct FPickupAttachActorInfo AttachInfo上面char pad_DB8
	static const uintptr_t InitialGuidePrice = 0x00D8;//x struct FDFMCommonItemRow ->int32_t InitialGuidePrice
	static const uintptr_t Quality = 0x0068;//x struct FDFMCommonItemRow ->int32_t Quality
	static const uintptr_t Length = 0x0074; //x struct FDFMCommonItemRow ->int32_t Length
	static const uintptr_t Width = 0x0078; //x struct FDFMCommonItemRow ->int32_t Width
	static const uintptr_t BonearrayA = 0x720;//x  struct UWidgetComponent3DUI : UMeshComponent -> struct UBodySetup* BodySetup;
	static const uintptr_t ComponentToWorld = 0x210; //x struct UMeshComponent : UPrimitiveComponent ->struct UPrimitiveComponent : USceneComponent -> struct USceneComponent : UActorComponent -> char pad_1A2[0x9e];
	static const uintptr_t bHasOpened = 0x233C; // docs/sjz Offset.OffSet_AInventoryPickup_OpenBox_bHasOpened
	static const uintptr_t CharacterEquipComponentCache = 0x2320;  // docs/sjz Offset.OffSet_ADFMCharacter_CharacterEquipComponentCache
	static const uintptr_t EquipmentInfoArray = 0x1D8;  // docs/sjz Offset.OffSet_UCharacterEquipComponent_EquipmentInfoArray
	static const uintptr_t HeroID = 0x9F8; // docs/sjz Offset.OffSet_ADFMPlayerState_HeroID
	static const uintptr_t CacheCurWeapon = 0x1708;  // docs/sjz Offset.OffSet_AGPCharacterBase_CacheCurWeapon
	static const uintptr_t WeaponID = 0x0838;  // docs/sjz Offset.OffSet_AWeaponBase_WeaponID
	static const uintptr_t Camp = 0x0664;  // docs/sjz Offset.OffSet_AGPPlayerState_Camp

}Offsets;
