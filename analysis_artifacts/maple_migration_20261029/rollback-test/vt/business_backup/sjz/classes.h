#pragma once
#include"../base.h"
#include <cstdint>
#include <corecrt_math.h>
#include <string>
#include "math_rust.h"
#include <vector>

#pragma code_seg(".vm")
namespace sjz {
	class APlayerState;
	class AGameStateBase;
	class ASolarCharacter;
	class APlayerController;
	class FBaseTeamComponent;
	class UWorld;
	class UFont;
	class FTextData;
	template<class T>
	struct TArray
	{
		TArray() {
			RtlZeroMemory(this, sizeof(TArray));
		};

		T* Data;
		uint32_t Count;
		uint32_t Max;
	};


	struct FRotator
	{
		FRotator() {
			RtlZeroMemory(this, sizeof(FRotator));
		}

		FRotator(float Pitch, float Yaw, float Roll) : pitch(Pitch), yaw(Yaw), roll(Roll) {}

		FRotator operator+(FRotator In) { return FRotator(this->pitch + In.pitch, this->yaw + In.yaw, this->roll + In.roll); }
		FRotator operator-(FRotator In) { return FRotator(this->pitch - In.pitch, this->yaw - In.yaw, this->roll - In.roll); }

		float pitch, yaw, roll;
	};

	class BoneIndex
	{
	public:
		BoneIndex() {
			RtlZeroMemory(this, sizeof(BoneIndex));
		}

		uint32_t head, neck_01, spine_03, spine_02, spine_01, pelvis;
		uint32_t hand_l, lowerarm_l, upperarm_l, clavicle_l, clavicle_r, upperarm_r, lowerarm_r, hand_r;
		uint32_t foot_l, calf_l, thigh_l, thigh_r, calf_r, foot_r;
		uint32_t NumBones;
	};

	class FVector2D
	{
	public:
		float x, y;
	public:
		inline FVector2D() : x(0.0), y(0.0) {}
		inline FVector2D(float x, float y) : x(x), y(y) {}
		inline FVector2D operator +(const FVector2D& other) const { return FVector2D(x + other.x, y + other.y); }
		inline FVector2D operator +(float scalar) const { return FVector2D(x + scalar, y + scalar); }
		inline FVector2D operator -(float scalar) const { return FVector2D(x - scalar, y - scalar); }
		inline FVector2D operator -(const FVector2D& other) const { return FVector2D(x - other.x, y - other.y); }
		inline FVector2D operator *(float scalar) const { return FVector2D(x * scalar, y * scalar); }
		inline FVector2D operator *(const FVector2D& other) const { return FVector2D(x * other.x, y * other.y); }
		inline FVector2D operator /(float scalar) const { return FVector2D(x / scalar, y / scalar); }
		inline FVector2D operator /(const FVector2D& other) const { return FVector2D(x / other.x, y / other.y); }
		inline FVector2D& operator =(const FVector2D& other) { x = other.x; y = other.y; return *this; }
		inline FVector2D& operator +=(float scalar) { x += scalar; y += scalar; return *this; }
		inline FVector2D& operator +=(const FVector2D& other) { x += other.x; y += other.y; return *this; }
		inline FVector2D& operator -=(float scalar) { x -= scalar; y -= scalar; return *this; }
		inline FVector2D& operator -=(const FVector2D& other) { x -= other.x; y -= other.y; return *this; }
		inline FVector2D& operator *=(float scalar) { x *= scalar; y *= scalar; return *this; }
		inline FVector2D& operator *=(const FVector2D& other) { x *= other.x; y *= other.y; return *this; }
		inline FVector2D& operator /=(const FVector2D& other) { x /= other.x; y /= other.y; return *this; }
		inline FVector2D& operator /=(const float other) { x /= other; y /= other; return *this; }
		inline bool operator==(const FVector2D& other) const { return x == other.x && y == other.y; }
	};

	struct FVector
	{
		float x, y, z;

		FVector() {
			RtlZeroMemory(this, sizeof FVector);
		}

		static float Distance(FVector HeadPos, FVector CameraPos)
		{
			if (&HeadPos == nullptr || &CameraPos == nullptr) {
				return 0.0f;
			}
			const float deltaX = static_cast<float>(HeadPos.x) - static_cast<float>(CameraPos.x);
			const float deltaY = static_cast<float>(HeadPos.y) - static_cast<float>(CameraPos.y);
			const float deltaZ = static_cast<float>(CameraPos.z) - static_cast<float>(CameraPos.z);

			const float dxSq = deltaX * deltaX;
			const float dySq = deltaY * deltaY;
			const float dzSq = deltaZ * deltaZ;

			if (dxSq < 0.0f || dySq < 0.0f || dzSq < 0.0f) {
				return 0.0f;
			}

			const float distanceSquared = dxSq + dySq + dzSq;
			const float distance = sqrt(distanceSquared);
			return distance;
		}

		FVector(float X, float Y, float Z) : x(X), y(Y), z(Z) {};


	};
	struct FQuat
	{
		float X;
		float Y;
		float Z;
		float W;
	};

	typedef struct _D3DMATRIX {
		union {
			struct {
				float        _11, _12, _13, _14;
				float        _21, _22, _23, _24;
				float        _31, _32, _33, _34;
				float        _41, _42, _43, _44;
			};
			float m[4][4];
		};
	} D3DMATRIX;

	enum  EMarkingItemType
	{
		None = 0,                         // 无标记
		CommonItem = 1,                   // 普通物品
		LootingItem = 2,                  // 物资
		Container = 3,                    // 容器
		DyingTeammate = 4,                // 濒死队友
		DeadBody = 5,                     // 死尸
		Weapon = 6,                       // 武器
		EngineerSonicTrap = 7,            // 陷阱
		Vehicle = 8,                      // 车辆
		TacticalEquip = 9,                // 战术装备
		PendingDeathCharacter = 10,       // 即将死亡
		SectorAnchor = 11,                // 区域锚点
		MandelBrickInteractor = 12,       // 交互器
		MandelBrickDecipherDevice = 13,   // 解码装置
		COUNT = 14,                       // 项目数量
		EMarkingItemType_MAX = 15         // 最大值，通常用于验证和范围检查
	};


	struct FGPGameplayAttributeData
	{
		char pa_0000[0x000C];  // 0x0000(0x000C)：占位符，可能是为了对齐或填充空白区域
		float BaseValue;        // 0x000C(0x0004)：属性的基础值，通常是该属性的初始值或最大值（如最大生命值）
		float CurrentValue;     // 0x0010(0x0004)：当前属性值，表示当前实际值（如当前生命值，可能会随游戏进程变化）
		char pa_0014[0x0004];   // 0x0014(0x0004)：占位符，可能是为了对齐或填充空白区域
	};


	// 定义骨骼的各个部位
	enum BoneType : int
	{
		//---------//
		Head = 15,        // 头部
		Neck = 31,        // 颈部
		//---------//
		LeftShoulder = 34, // 左肩
		RightShoulder = 6, // 右肩
		//---------//
		LeftElbow = 35,    // 左肘
		RightElbow = 7,    // 右肘
		//---------//
		LeftHand = 36,     // 左手
		RightHand = 8,     // 右手
		//---------//
		Pelvis = 1,        // 骨盆
		//---------//
		LeftLeg = 58,      // 左腿
		RightLeg = 62,     // 右腿
		//---------//
		LeftKnee = 59,     // 左膝
		RightKnee = 63,    // 右膝
		//---------//
		LeftHeel = 60,     // 左脚跟
		LeftFoot = 64,     // 左脚前
		RightHeel = 64,    // 右脚跟
		RightFoot = 175,   // 右脚前
		//---------//
		Sole = 193,        // 脚底
		Body = 4,          // 身体
	};






	struct FTransform
	{
	public:
		math_rust::Vector4 Rotation;
		math_rust::Vector3 Translation;
		char Pad_1[4];
		math_rust::Vector3 Scale3D;
		char Pad_2[4];
		D3DMATRIX ToMatrixWithScale()
		{
			D3DMATRIX m;
			m._41 = Translation.x;
			m._42 = Translation.y;
			m._43 = Translation.z;

			float x2 = Rotation.x + Rotation.x;
			float y2 = Rotation.y + Rotation.y;
			float z2 = Rotation.z + Rotation.z;

			float xx2 = Rotation.x * x2;
			float yy2 = Rotation.y * y2;
			float zz2 = Rotation.z * z2;
			m._11 = (1.0f - (yy2 + zz2)) * Scale3D.x;
			m._22 = (1.0f - (xx2 + zz2)) * Scale3D.y;
			m._33 = (1.0f - (xx2 + yy2)) * Scale3D.z;

			float yz2 = Rotation.y * z2;
			float wx2 = Rotation.w * x2;
			m._32 = (yz2 - wx2) * Scale3D.z;
			m._23 = (yz2 + wx2) * Scale3D.y;

			float xy2 = Rotation.x * y2;
			float wz2 = Rotation.w * z2;
			m._21 = (xy2 - wz2) * Scale3D.y;
			m._12 = (xy2 + wz2) * Scale3D.x;

			float xz2 = Rotation.x * z2;
			float wy2 = Rotation.w * y2;
			m._31 = (xz2 + wy2) * Scale3D.z;
			m._13 = (xz2 - wy2) * Scale3D.x;

			m._14 = 0.0f;
			m._24 = 0.0f;
			m._34 = 0.0f;
			m._44 = 1.0f;

			return m;
		}
	};

	struct FLinearColor
	{
		float r;
		float g;
		float b;
		float a;

		FLinearColor() {
			RtlZeroMemory(this, sizeof FLinearColor);
		}

		FLinearColor(float R, float G, float B, float A = 255.f)
		{
			r = R;
			g = G;
			b = B;
			a = A;
		}
	};


	class FColor
	{
	public:
		uint8_t B;
		uint8_t G;
		uint8_t R;
		uint8_t A;
	public:
		inline FColor() : R(0), G(0), B(0), A(0) {}
		inline FColor(uint8_t r, uint8_t g, uint8_t b, uint8_t a = 255) { R = r; G = g; B = b; A = a; }
		class FLinearColor ToLinearColor() const
		{
			return FLinearColor(GammaToLinear(R), GammaToLinear(G), GammaToLinear(B), A / 255.f);
		}
	private:
		inline static float GammaToLinear(int Value)
		{
			const float InvGamma = 1.0f / 1.5f;
			float LinearValue = static_cast<float>(Value) / 255.0f; // 显式转换为浮点数
			LinearValue = LinearValue <= 0.04045f ? LinearValue / 12.92f : pow((LinearValue + 0.055f) / 1.055f, 2.4f);
			return LinearValue * InvGamma;  // 使用 InvGamma 进行反校正
		}
	};

	class FText
	{
	public:
		FTextData* TextData;
		char Pad_8[0x10];
	};

	struct FString
	{
		wchar_t* Data;
		uint32_t Count;
		uint32_t Max;
		FString() {
			RtlZeroMemory(this, sizeof FString);
		};


		FString(wchar_t* X, uint32_t Y, uint32_t Max) : Data(X), Count(Y), Max(Max) {};

		FString(const wchar_t* other) { Max = Count = *other ? static_cast<uint32_t>(wcslen(other)) + 1 : 0; if (Count) Data = const_cast<wchar_t*>(other); }

	};
	class FTextData
	{
	public:
		char pad[0x28];
		struct FString DisplayString;
	};
	struct MagicCircle
	{
	public:
		MagicCircle()
		{
			RtlZeroMemory(this, sizeof MagicCircle);
		}
		uint32_t MagicCircleTime = 0;
		float MagicCircleAngle = 0.f;
		float Rad = 0.f;
		FLinearColor Color = FLinearColor(0.0f, 1.0f, 0.0f, 1.0f);

	};
	struct FUObjectIem
	{
		class UObject* Object;
		char Buff[0x10];
	};

	class UObject
	{
	public:

		std::wstring GetName();

		static void* GetPlayerClass();

		static void* GetIteamClass();

		static void Free(void* Addr);


		static UFont* GetRoboto();

		static APlayerController* GetLocalPlayerController(UWorld* WorldContextObject);

		void ProcessEvent(void* Function, void* Args,UINT64 argSize);

		static UObject* StaticFindObject(void* ObjectClass, UObject* InObjectPackage, const WCHAR* OrigInName, bool ExactClass);
	};
	class FGameViewportClient : public UObject
	{
	public:
		char pad_0000[0x88];
		UWorld* World;
	};
	class UFont : public UObject
	{
	public:
		char pad_0000[0x144];
		uint32_t LegacyFontSize;
	};
	class UEngine : public UObject
	{
	public:
		char pad_0000[0x80];
		UFont* MediumFont;
		char pad_0730[0x888];
		FGameViewportClient* GameViewport;
		char pad_0731[0x16C];
		float DisplayGamma;
	};
	class UCanvas : public UObject
	{
	public:
		static inline UCanvas* Canvas = nullptr;
		void K2_DrawBox(FVector2D ScreenPosition, FVector2D ScreenSize, float Thickness, FLinearColor RenderColor);

		void K2_DrawLine(FVector2D ScreenPositionA, FVector2D ScreenPositionB, float Thickness, FLinearColor RenderColor);

		void K2_DrawText(void* RenderFont, FString RenderText, FVector2D ScreenPosition, FVector2D Scale, FLinearColor RenderColor, float Kerning, FLinearColor ShadowColor, FVector2D ShadowOffset, bool bCentreX, bool bCentreY, bool bOutlined, FLinearColor OutlineColor);

		void K2_DrawTexture(void* RenderTexture, FVector2D ScreenPosition, FVector2D ScreenSize, FLinearColor RenderColor);

		void K2_DrawPolygon(FVector2D ScreenPosition, FVector2D Radius, int32_t NumberOfSides, FLinearColor RenderColor, float Thickness);

		FVector2D K2_TextSize(void* RenderFont, FString RenderText, FVector2D Scale);

		void K2_StrokeText(FString RenderText, FLinearColor Color, const FVector2D& Pos);

		void K2_StroKeLine(const FVector2D& P1, const FVector2D&, FLinearColor Color);
	};




	class USceneComponent
	{
	public:
		char pad_0000[0x220];
		FVector Pos;
	};

	class UGameInstance : public UObject
	{
	public:
		ASolarCharacter* GetPlayerPawn();

		APlayerController* GetPlayerController();
	};
	class ItemComponent
	{
	public:
		char padd[0x68];
		uint32_t Quality;

		char pad[0x6C];
		uint32_t ItemValue;
	};
	class AActor : public UObject
	{
	private:
		char pad_0000[0x188];
	public:
		USceneComponent* RootComponent;
	private:
		char pad_0010[0xBD0];
	public:
		ItemComponent* ItemData;

		FString GetActorsName();

		FText GetItemName();


	};
	class ULevel : public UObject
	{
	public:
		char pad_0000[0xA8];
		AActor** Actors;
		uint32_t Count;
		uint32_t Max;


	};
	class UWorld : public UObject
	{
	private:
		char pad_0000[0x108];
	public:
		ULevel* PersistentLevel;
	private:
		char pad_A000[0x40];
	public:
		AGameStateBase* GameState;
	private:
		char pad_0270[0x48];
	public:
		UGameInstance* OwningGameInstance;



	};

	class AGameStateBase
	{
	public:
		char pad_0000[0x398];
		APlayerState** PlayerArray;
		uint32_t Count;
		uint32_t Max;


	};
	class APlayerState
	{
	public:
		char pad_0000[0x400];
		ASolarCharacter* PawnPrivate;

	};
	class USkeletalMeshComponent : public UObject
	{
	public:

		BoneIndex* GetBoneIndex(uint32_t NumBones);

		TArray<uint64_t> GetAllSocketNames();

		FVector GetSocketTransform(uint64_t InSocketName);
	};

	class ASolarPlayerState : public UObject
	{
	public:
		FString GetPlayerName();

		int32_t GetTeamID();
		int32_t GetCamp();

	};
	class UCharacterEquipComponent : public UObject
	{
		//TArray<FEquipmentInfo> GetEquipmentInfoArray();
	};
	class ASolarCharacter : public UObject
	{
	private:
		char pad_0000[0x188];
	public:
		USceneComponent* RootComponent;
	private:
		char pad_198[0x208];
	public:
		ASolarPlayerState* PlayerState;//398
	private:
		char pad_[0x40];
	public:
		USkeletalMeshComponent* Mesh;



		float GetHealth();

		float GetHealthMax();

		char IsPlayerAI();



		FRotator GetBaseAimRotation();

		APlayerController* GetController();



	};
	class APlayerCameraManager : public UObject
	{
	public:

		FRotator GetCameraRotation();

		FVector GetCameraLocation();
	};

	class APlayerController : public UObject
	{
	public:
		char pad_00[0x3E0];
		float Yaw;
		float Pitch;

		char pad_0000[0x30];
		APlayerCameraManager* PlayerCameraManager;

		char LineOfSightTo(ASolarCharacter* Other, FVector ViewPoint = FVector());

		bool WorldToScreen(FVector WorldLocation, FVector2D& ScreenLocation);

		void SetControlRotation(FRotator& NewRotation);

		bool GetMousePosition(FVector2D& MousePosition);
	};
	class FItemArray : public AActor
	{
	public:

	};
	class UGameplayStatics : public UObject
	{
	public:
		static void GetAllActorsOfClass(UWorld* WorldContxetObject, void* ActorClass, TArray<ASolarCharacter*>* OutActors);

		static void GetAllIteamsOfClass(UWorld* WorldContextObject, void* ActorClass, TArray<AActor*>* OutActors);
	};



	class UKismetStringLibrary : public UObject
	{
	public:

		static FString Conv_NameToString(uint64_t InName);

		static FVector GetForwardVector(const FRotator* InRo);

		static FString GetDisplayName(UObject* object);

	};







};

