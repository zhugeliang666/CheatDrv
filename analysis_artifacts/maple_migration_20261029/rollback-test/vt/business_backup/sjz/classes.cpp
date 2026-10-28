#include "classes.h"
#include "../xor.h"
#include "offsets.h"



namespace sjz {


#pragma code_seg(".vm")

//void UObject::ProcessEvent(void* Function, void* Args,uint64_t argSize)
//{
//		RtlZeroMemory((PVOID)(game::GameNULL + Offsets.blackmemory), argSize);
//
//		RtlCopyMemory((PVOID)(game::GameNULL + Offsets.blackmemory), Args, argSize);
//		auto vt = Read<UINT64>((UINT64)this);
//		auto  fun = Read<UINT64>(vt + 68 * 8);
//		Call(fun, (UINT64)this, Function, game::GameNULL + Offsets.blackmemory);
//
//		RtlCopyMemory(Args, (PVOID)(game::GameNULL + Offsets.blackmemory),  argSize);
//
//		RtlZeroMemory((PVOID)(game::GameNULL + Offsets.blackmemory), argSize);
//}
//
//UObject* UObject::StaticFindObject(void* ObjectClass, UObject* InObjectPackage, const WCHAR* OrigInName, bool ExactClass)
//{
//	static void* Function = NULL;
//
//	if (!Function) {
//		Function = (void*)(game::GameNULL + Offsets.call_staticfindobject);
//	}
//	auto len = (wcslen(OrigInName) + 1) * 2;
//
//	RtlCopyMemory((char*)game::GameNULL + Offsets.blackmemory, OrigInName, len);
//	UObject* ret = (UObject*)Call(Function, (UINT64)NULL, (UINT64)NULL, (UINT64)game::GameNULL + Offsets.blackmemory, (UINT64)false);
//	RtlZeroMemory((char*)game::GameNULL + Offsets.blackmemory, len);
//
//	return ret;
//
//
//
//}
////
//FString UKismetStringLibrary::Conv_NameToString(uint64_t InName)
//{
//	FString str;
//
//
//	*(ULONG64*)(game::GameNULL + Offsets.blackmemory) = InName;
//
//	Call(game::GameNULL + Offsets.call_Conv_NameToString, (ULONG64)game::GameNULL + Offsets.blackmemory, (ULONG64)game::GameNULL + Offsets.blackmemory+0x100);
//
//	RtlCopyMemory(&str, (char*)game::GameNULL  + Offsets.blackmemory+0x100, sizeof(FString));
//	RtlZeroMemory((char*)game::GameNULL+ Offsets.blackmemory+0x100, sizeof(FString));
//	RtlZeroMemory((char*)game::GameNULL + Offsets.blackmemory, sizeof(UINT64));
//
//	return str;
//}
//FString UKismetStringLibrary::GetDisplayName(UObject* object)
//{
//
//	
//	FString str;
//	Call(game::GameNULL + Offsets.call_getdisplayname, (ULONG64)object, (ULONG64)game::GameNULL + Offsets.blackmemory);
//	RtlCopyMemory(&str, (char*)game::GameNULL + Offsets.blackmemory + Offsets.blackmemory, sizeof(FString));
//	RtlZeroMemory((char*)game::GameNULL + Offsets.blackmemory + Offsets.blackmemory, sizeof(FString));
//	return str;
//}
// 
// 
//FVector UKismetStringLibrary::GetForwardVector(const FRotator* InRo)
//{
//	const float PitchNoWinding = Utils::Fmod(InRo->pitch, 360.0f);
//	const float YawNoWinding = Utils::Fmod(InRo->yaw, 360.0f);
//	float SP, CP, SY, CY;
//	Utils::SinCos(&SP, &CP, DegreesToRadians(PitchNoWinding));
//	Utils::SinCos(&SY, &CY, DegreesToRadians(YawNoWinding));
//	FVector V = { CP * CY,CP * SY,SP};
//	if (Utils::ContainsNaN(V))
//	{
//		return FVector();
//	}
//
//	return V;
//}
//
//void* UObject::GetIteamClass()
//{
//	static void* PlayerClass = NULL;
//
//	if (!PlayerClass) {
//		PlayerClass = UObject::StaticFindObject(NULL, NULL, L"DFMGameplay.InventoryPickup", false);
//	}
//
//	return PlayerClass;
//
//}
//
//void UObject::Free(void* Addr)
//{
//	static void* Free = NULL;
//	using FuncType = void(__fastcall*)(void*);
//	if (!Free) {
//		ULONG64 TempFree = (ULONG64)(GetModuleHandleA(NULL));
//		//48 85 C9 74 ? 53 48 83 EC ? 48 8B D9 48 8B 0D
//		Free = (void*)(TempFree + +0x07E9940);
//	}
//	FuncType pFree = reinterpret_cast<FuncType>(Free);
//	spoof_call(pFree, Addr);
//}
//
//void* UObject::GetPlayerClass()
//{
//	static void* PlayerClass = NULL;
//
//	if (!PlayerClass) {
//		PlayerClass = UObject::StaticFindObject(NULL, NULL, L"GPGameplay.IntCharacter", false);
//	}
//
//	return PlayerClass;
//
//}
//
//APlayerController* UObject::GetLocalPlayerController(UWorld* WorldContextObject)
//{
//	static void* Function = NULL;
//	if (!Function) {
//		Function = StaticFindObject(NULL, NULL, L"GPNetModeUtils.GetLocalPlayerController", false);
//	}
//
//	struct {
//		APlayerController* ReturnValue;
//	} Params = {};
//
//	WorldContextObject->ProcessEvent(Function, &Params);
//
//	return Params.ReturnValue;
//}
//
//
//
//UFont* UObject::GetRoboto()
//{
//	static UFont* Roboto = NULL;
//
//	if (!Roboto) {
//		Roboto = (UFont*)StaticFindObject(NULL, NULL, L"/Game/UI/Fonts/FZLTZHJW_ZH_Font.FZLTZHJW_ZH_Font", false);
//	}
//
//	return Roboto;
//}
//
//
//
//
//wstring UObject::GetName()
//{
//	FString Name = UKismetStringLibrary::Conv_NameToString(*(uint64_t*)((uint8_t*)this + 0x24));
//	wstring NamesPtr = Name.Data;
//	size_t Pos = NamesPtr.rfind(L"/");
//	if (Pos != std::string::npos)
//	{
//		NamesPtr = NamesPtr.substr(Pos + 1);
//	}
//	return NamesPtr;
//}
//
//void UGameplayStatics::GetAllActorsOfClass(UWorld* WorldContextObject, void* ActorClass, TArray<ASolarCharacter*>* OutActors)
//{
//	static void* Function = NULL;
//	if (!Function) {
//		Function = StaticFindObject(NULL, NULL, _XOR_(L"GameplayStatics.GetAllActorsOfClass"), NULL);
//	}
//
//	struct
//	{
//		UWorld* WorldContextObject;
//		void* ActorClass;
//		TArray<ASolarCharacter*> OutActors;
//	}Params{ WorldContextObject,ActorClass,TArray<ASolarCharacter*>() };
//
//
//
//
//	WorldContextObject->ProcessEvent(Function, &Params,sizeof(Params));
//
//	*OutActors = Params.OutActors;
//}
//
//void UGameplayStatics::GetAllIteamsOfClass(UWorld* WorldContextObject, void* ActorClass, TArray<AActor*>* OutActors)
//{
//	static void* Function = NULL;
//	if (!Function) {
//		Function = StaticFindObject(NULL, NULL, L"GameplayStatics.GetAllActorsOfClass", NULL);
//	}
//
//	struct
//	{
//		UWorld* WorldContextObject;
//		void* ActorClass;
//		TArray<AActor*> OutActors;
//	}Params{ WorldContextObject,ActorClass,TArray<AActor*>() };
//
//	WorldContextObject->ProcessEvent(Function, &Params);
//
//	*OutActors = Params.OutActors;
//}
//
//
//
//void UCanvas::K2_DrawBox(FVector2D ScreenPosition, FVector2D ScreenSize, float Thickness, FLinearColor RenderColor)
//{
//	static void* Function = NULL; // UFuntion
//
//	if (!Function) {
//		Function = StaticFindObject(NULL, NULL, L"Canvas.K2_DrawBox", false);
//	}
//
//	struct {
//		FVector2D ScreenPosition;
//		FVector2D ScreenSize;
//		float Thickness;
//		FLinearColor RenderColor;
//	}Params{ ScreenPosition,ScreenSize,Thickness,RenderColor };
//
//	ProcessEvent(Function, &Params);
//}
//
//void UCanvas::K2_DrawLine(FVector2D ScreenPositionA, FVector2D ScreenPositionB, float Thickness, FLinearColor RenderColor)
//{
//	static void* Function = NULL; // UFuntion
//
//	if (!Function) {
//		Function = StaticFindObject(NULL, NULL, L"Engine.Canvas.K2_DrawLine", false);
//	}
//	struct {
//		FVector2D ScreenPositionA;
//		FVector2D ScreenPositionB;
//		float Thickness;
//		FLinearColor RenderColor;
//	}Params{ ScreenPositionA,ScreenPositionB,Thickness,RenderColor };
//
//	ProcessEvent(Function, &Params);
//}
//
//void UCanvas::K2_DrawText(void* RenderFont, FString RenderText, FVector2D ScreenPosition, FVector2D Scale, FLinearColor RenderColor, float Kerning, FLinearColor ShadowColor, FVector2D ShadowOffset, bool bCentreX, bool bCentreY, bool bOutlined, FLinearColor OutlineColor)
//{
//	static void* Function = NULL; // UFuntion
//
//	if (!Function) {
//		Function = StaticFindObject(NULL, NULL, L"Canvas.K2_DrawText", false);
//	}
//
//	struct {
//		void* RenderFont;
//		FString RenderText;
//		FVector2D ScreenPosition;
//		FVector2D Scale;
//		FLinearColor RenderColor;
//		float Kerning;
//		FLinearColor ShadowColor;
//		FVector2D ShadowOffset;
//		bool bCentreX;
//		bool bCentreY;
//		bool bOutlined;
//		FLinearColor OutlineColor;
//	}Params{ RenderFont,RenderText,ScreenPosition,Scale,RenderColor,Kerning,ShadowColor,ShadowOffset,bCentreX,bCentreY,bOutlined,OutlineColor };
//
//	ProcessEvent(Function, &Params);
//}
//
//void UCanvas::K2_DrawTexture(void* RenderTexture, FVector2D ScreenPosition, FVector2D ScreenSize, FLinearColor RenderColor)
//{
//	static void* Function = NULL; // UFuntion
//
//	if (!Function) {
//		Function = StaticFindObject(NULL, NULL, L"Canvas.K2_DrawTexture", false);
//	}
//
//	struct {
//		void* RenderTexture;
//		FVector2D ScreenPosition;
//		FVector2D ScreenSize;
//		FVector2D CoordinatePosition;
//		FVector2D CoordinateSize;
//		FLinearColor RenderColor;
//		int BlendMode;
//		float Rotation;
//		FVector2D PivotPoint;
//	}Params{ RenderTexture,ScreenPosition,ScreenSize,{0,0},{0,0},RenderColor,0,0,{0,0} };
//
//	ProcessEvent(Function, &Params);
//}
//
//void UCanvas::K2_DrawPolygon(FVector2D ScreenPosition, FVector2D Radius, int32_t NumberOfSides, FLinearColor RenderColor, float Thickness)
//{
//	float TwoPI = 2.f * 3.1415926f;
//
//	for (int32_t i = 0; i < NumberOfSides; i++)
//	{
//		float AngleA = (float)i / (float)NumberOfSides * TwoPI; // 求出开始绘制的点A弧度
//		float AngleB = (float)(i + 1) / (float)NumberOfSides * TwoPI; //  求出绘制的点B弧度
//
//		FVector2D PointA = FVector2D(cos(AngleA) * Radius.x, sin(AngleA) * Radius.y);
//		FVector2D PointB = FVector2D(cos(AngleB) * Radius.x, sin(AngleB) * Radius.y);
//
//		PointA.x += ScreenPosition.x;
//		PointA.y += ScreenPosition.y;
//		PointB.x += ScreenPosition.x;
//		PointB.y += ScreenPosition.y;
//
//		K2_DrawLine(PointA, PointB, Thickness, RenderColor);
//	}
//}
//
//FVector2D UCanvas::K2_TextSize(void* RenderFont, FString RenderText, FVector2D Scale)
//{
//	static void* Function = NULL; // UFuntion
//
//	if (!Function) {
//		Function = StaticFindObject(NULL, NULL, L"Canvas.K2_TextSize", false);
//	}
//
//	struct {
//		void* RenderFont;
//		FString RenderText;
//		FVector2D Scale;
//		FVector2D ReturnValue;
//	}Params{ RenderFont,RenderText,Scale };
//
//	ProcessEvent(Function, &Params);
//	return Params.ReturnValue;
//}
//
//APlayerController* UGameInstance::GetPlayerController()
//{
//	uint8_t* Player = **(uint8_t***)((uint8_t*)this + 0x58);
//	if (MmIsAddressValid(Player))
//		return *(APlayerController**)(Player + 0x38);
//
//	return NULL;
//}
////playerpawn
//ASolarCharacter* UGameInstance::GetPlayerPawn()
//{
//	uint8_t* PlayerController = (uint8_t*)GetPlayerController();
//	if (MmIsAddressValid(PlayerController))
//		return *(ASolarCharacter**)(PlayerController + 0x410);
//	return NULL;
//
//}
//
//BoneIndex* USkeletalMeshComponent::GetBoneIndex(uint32_t NumBones)
//{
//	static vector<BoneIndex*> BoneIdxArray;
//
//	for (size_t i = 0; i < BoneIdxArray.size(); i++)
//	{
//		if (BoneIdxArray[i]->NumBones == NumBones)
//			return BoneIdxArray[i]; 
//	}
//
//	BoneIndex* NewBoneIdx = new BoneIndex;
//	NewBoneIdx->NumBones = NumBones;
//	BoneIdxArray.push_back(NewBoneIdx);
//
//	TArray<uint64_t> BoneNames = GetAllSocketNames();
//	for (uint32_t i = 0; i < NumBones; i++)
//	{  
//		FString BonePtr = UKismetStringLibrary::Conv_NameToString(BoneNames.Data[i]);
//		wstring BoneName = BonePtr.Data;
//		transform(BoneName.begin(), BoneName.end(), BoneName.begin(), ::tolower); 
//
//		if (BoneName == L"head") { NewBoneIdx->head = i; }
//		else if (BoneName == L"lefthand") { NewBoneIdx->hand_l = i; }
//		else if (BoneName == L"righthand") { NewBoneIdx->hand_r = i; }
//
//		else if (BoneName == L"leftshoulder") { NewBoneIdx->clavicle_l = i; }  
//		else if (BoneName == L"rightshoulder") { NewBoneIdx->clavicle_r = i; } 
//
//		else if (BoneName == L"leftfoot") { NewBoneIdx->foot_l = i; }
//		else if (BoneName == L"leftleg") { NewBoneIdx->calf_l = i; }
//
//		else if (BoneName == L"rightleg") { NewBoneIdx->calf_r = i; }
//		else if (BoneName == L"rightfoot") { NewBoneIdx->foot_r = i; }
//
//		else if (BoneName == L"hips") { NewBoneIdx->pelvis = i; }
//		else if (BoneName == L"neck") { NewBoneIdx->neck_01 = i; }
//
//		else if (BoneName == L"leftupleg") { NewBoneIdx->thigh_l = i; }
//		else if (BoneName == L"rightupleg") { NewBoneIdx->thigh_r = i; }
//
//		else if (BoneName == L"spine2") { NewBoneIdx->spine_03 = i; }
//		else if (BoneName == L"spine1") { NewBoneIdx->spine_02 = i; }
//
//		else if (BoneName == L"spine") { NewBoneIdx->spine_01 = i; }
//		else if (BoneName == L"leftforearm") { NewBoneIdx->lowerarm_l = i; }
//
//		else if (BoneName == L"rightforearm") { NewBoneIdx->lowerarm_r = i; }
//		else if (BoneName == L"leftarm") { NewBoneIdx->upperarm_l = i; }
//
//		else if (BoneName == L"rightarm") { NewBoneIdx->upperarm_r = i; }
//
//	}
//
//	return NewBoneIdx;
//}
//
//TArray<uint64_t> USkeletalMeshComponent::GetAllSocketNames()
//{
//	static void* Function = NULL;
//	if (!Function) {
//		Function = StaticFindObject(NULL, NULL, _XOR_(L"SceneComponent.GetAllSocketNames"), false);
//	}
//
//	struct
//	{
//		TArray<uint64_t> ReturnValue;
//	}Params{};
//
//	ProcessEvent(Function, &Params,sizeof(Params));
//
//	return Params.ReturnValue;
//}
//
//FVector USkeletalMeshComponent::GetSocketTransform(uint64_t InSocketName)
//{
//	static void* Function = NULL;
//	if (!Function) {
//		Function = StaticFindObject(NULL, NULL, L"SceneComponent.GetSocketTransform", false);
//	}
//
//	struct
//	{
//		uint64_t InSocketName;
//		uint32_t TransformSpace;
//		bool bDoParallel;
//		FTransform ReturnValue;
//	}Params{ InSocketName,0,false };
//
//	ProcessEvent(Function, &Params);
//
//	return Params.ReturnValue.Translation;
//}
//
//FRotator ASolarCharacter::GetBaseAimRotation()
//{
//	static void* Function = NULL;
//	if (!Function) {
//		Function = StaticFindObject(NULL, NULL, L"Pawn.GetBaseAimRotation", false);
//	}
//
//	struct {
//		FRotator ReturnValue;
//	} Params = {};
//
//	ProcessEvent(Function, &Params);
//
//	return Params.ReturnValue;
//}
//APlayerController* ASolarCharacter::GetController()
//{
//	static void* Function = NULL;
//	if (!Function) {
//		Function = StaticFindObject(NULL, NULL, L"Pawn.GetController", false);
//	}
//
//	struct {
//		APlayerController* ReturnValue;
//	} Params = {};
//
//	ProcessEvent(Function, &Params);
//
//	return Params.ReturnValue;
//}
//
//FRotator APlayerCameraManager::GetCameraRotation()
//{
//	static void* Function = NULL;
//	if (!Function) {
//		Function = StaticFindObject(NULL, NULL, _XOR_(L"PlayerCameraManager.GetCameraRotation"), false);
//	}
//
//	struct
//	{
//		FRotator ReturnValue;
//	}Params{};
//
//	ProcessEvent(Function, &Params,sizeof(Params));
//
//	return Params.ReturnValue;
//}
////
//FVector APlayerCameraManager::GetCameraLocation()
//{
//	static void* Function = NULL;
//	if (!Function) {
//		Function = StaticFindObject(NULL, NULL, _XOR_(L"PlayerCameraManager.GetCameraLocation"), false);
//	}
//
//	struct
//	{
//		FVector ReturnValue;
//	}Params{};
//
//	ProcessEvent(Function, &Params,sizeof(Params));
//
//	return Params.ReturnValue;
//}
////
//bool APlayerController::WorldToScreen(FVector WorldLocation, FVector2D& ScreenLocation)
//{
//	static void* Function = NULL;
//
//	if (!Function)
//	{
//		Function = StaticFindObject(NULL, NULL, _XOR_(L"PlayerController.ProjectWorldLocationToScreen"), false);
//	}
//
//	struct
//	{
//		FVector WorldLocation;
//		FVector2D ScreenLocation;
//		bool bPlayerViewportRelative;
//		bool ReturnValue;
//	}Params{ WorldLocation,FVector2D(),false };
//
//
//
//	ProcessEvent(Function, &Params,sizeof(Params));
//
//
//	ScreenLocation = Params.ScreenLocation;
//
//
//	return Params.ReturnValue;
//}
//char APlayerController::LineOfSightTo(ASolarCharacter* Other, FVector ViewPoint)
//{
//	static void* Function = NULL;
//	if (!Function) {
//		Function = StaticFindObject(NULL, NULL, L"Controller.LineOfSightTo", false);
//	}
//
//	struct
//	{
//		ASolarCharacter* Other;
//		FVector ViewPoint;
//		char bAlternateChecks;
//		char ReturnValue;
//	}Params{ Other,ViewPoint,0 };
//
//	ProcessEvent(Function, &Params);
//
//	return Params.ReturnValue;
//}
//
//int32_t ASolarPlayerState::GetCamp()
//{
//	static void* Function = NULL;
//	if (!Function) {
//		Function = StaticFindObject(NULL, NULL, L"GPPlayerState.GetCamp", false);
//	}
//	struct
//	{
//		int32_t ReturnValue;
//	}Params{};
//
//	ProcessEvent(Function, &Params);
//
//	return Params.ReturnValue;
//}
//
//FString ASolarPlayerState::GetPlayerName()
//{
//	static void* Function = NULL;
//	if (!Function) {
//		Function = StaticFindObject(NULL, NULL, L"PlayerState.GetPlayerName", false);
//	}
//
//	struct
//	{
//		FString ReturnValue;
//	}Params{};
//
//	ProcessEvent(Function, &Params);
//
//	return Params.ReturnValue;
//}
//
//int32_t ASolarPlayerState::GetTeamID()
//{
//	static void* Function = NULL;
//	if (!Function) {
//		Function = StaticFindObject(NULL, NULL, L"GPPlayerState.GetTeamID", false);
//	}
//
//	struct
//	{
//		int32_t ReturnValue;
//	}Params{};
//
//	ProcessEvent(Function, &Params);
//
//	return Params.ReturnValue;
//}
//
//float ASolarCharacter::GetHealth()
//{
//	static void* Function = NULL;
//	if (!Function) {
//		Function = StaticFindObject(NULL, NULL, L"GPCharacterBase.GetHealth", false);
//	}
//	struct
//	{
//		float ReturnValue;
//	}Params{};
//
//	ProcessEvent(Function, &Params);
//
//	return Params.ReturnValue;
//}
//
//float ASolarCharacter::GetHealthMax()
//{
//	static void* Function = NULL;
//	if (!Function) {
//		Function = StaticFindObject(NULL, NULL, L"GPCharacterBase.GetHealthMax", false);
//	}
//
//	struct
//	{
//		float ReturnValue;
//	}Params{};
//
//	ProcessEvent(Function, &Params);
//
//	return Params.ReturnValue;
//
//}
//
//char ASolarCharacter::IsPlayerAI()
//{
//	static void* Function = NULL;
//	if (!Function) {
//		Function = StaticFindObject(NULL, NULL, L"GPCharacterBase.IsAI", false);
//	}
//
//	struct
//	{
//		char ReturnValue;
//	}Params{};
//
//	ProcessEvent(Function, &Params);
//
//	return Params.ReturnValue;
//}
//
//
//void UCanvas::K2_StrokeText(FString RenderText, FLinearColor Color, const FVector2D& Pos)
//{
//	const FLinearColor OutlineColor = FLinearColor(0.12f, 0.12f, 0.12f, 0.5f);  
//	const FLinearColor SoftShadowColor = FLinearColor(0.05f, 0.05f, 0.05f, 0.25f); 
//	for (int x = -1; x <= 1; x++) {
//		for (int y = -1; y <= 1; y++) {
//			if (x == 0 && y == 0) continue;
//			K2_DrawText(UObject::GetRoboto(), RenderText, { Pos.x + x * 0.5f, Pos.y + y * 0.5f }, // X
//				{ 1.f,1.f }, OutlineColor, 1.f, FLinearColor(), FVector2D(), true, true, false, FLinearColor());
//		}
//	}
//
//	for (int x = -1; x <= 1; x++) {
//		for (int y = -1; y <= 1; y++) {
//			if (x == 0 && y == 0) continue;
//			K2_DrawText(UObject::GetRoboto(), RenderText, { Pos.x + x * 0.8f, Pos.y + y * 0.8f }, // X
//				{ 1.f,1.f }, SoftShadowColor, 1.f, FLinearColor(), FVector2D(), true, true, false, FLinearColor());
//		}
//	}
//
//	FLinearColor AdjustedColor = FLinearColor(std::clamp(Color.r * 1.3f, 0.0f, 1.0f),std::clamp(Color.g * 1.3f, 0.0f, 1.0f),std::clamp(Color.b * 1.3f, 0.0f, 1.0f),	Color.a);
//
//	K2_DrawText(UObject::GetRoboto(), RenderText, Pos, { 1.f,1.f }, AdjustedColor,
//		1.f, FLinearColor(), FVector2D(), true, true, false, FLinearColor());
//
//}
//
//void UCanvas::K2_StroKeLine(const FVector2D& P1, const FVector2D& P2, FLinearColor Color)
//{
//	const float LineThickness = 1.0f;
//	const FLinearColor OutlineColor1(0.1f, 0.1f, 0.1f, 0.3f);
//	const FLinearColor OutlineColor2(0.1f, 0.1f, 0.1f, 0.2f);
//	K2_DrawLine(P1, P2, LineThickness + 0.8f, OutlineColor1);
//	K2_DrawLine(P1, P2, LineThickness + 1.2f, OutlineColor2);
//	K2_DrawLine(P1, P2, LineThickness, Color);
//}
//
//FString AActor::GetActorsName()
//{
//	FString Name = UKismetStringLibrary::Conv_NameToString(*(uint64_t*)((uint8_t*)this + 0x24));
//	return Name;
//}
//
//FText AActor::GetItemName()
//{
//	static void* Function = NULL;
//	if (!Function) {
//		Function = StaticFindObject(NULL, NULL, L"PickupBase.GetItemName", false);
//	}
//
//	struct {
//		FText ReturnValue;
//	} Params = {};
//
//	ProcessEvent(Function, &Params);
//
//     return Params.ReturnValue;
//}
//
//void APlayerController::SetControlRotation(FRotator& NewRotation)
//{
//	static void* Function = NULL;
//	if (!Function) {
//		Function = StaticFindObject(NULL, NULL, L"Controller.SetControlRotation", false);
//	}
//
//	struct {
//		FRotator ReturnValue;
//	} Params = {};
//
//	ProcessEvent(Function, &Params);
//
//	NewRotation = Params.ReturnValue;
//}
//
//bool APlayerController::GetMousePosition(FVector2D& MousePosition)
//{
//	static void* Function = NULL;
//	if (!Function) {
//		Function = StaticFindObject(NULL, NULL, L"PlayerController.GetMousePosition", false);
//	}
//
//	struct {
//		float LocationX;
//		float LocationY;
//		bool ReturnValue;
//	} Params = {};
//
//	ProcessEvent(Function, &Params);
//
//	MousePosition = FVector2D(Params.LocationX, Params.LocationY);
//	return Params.ReturnValue;
//}


#pragma code_seg()

}



