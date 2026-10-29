#pragma once

typedef struct _TArray {
    ULONG64 Data;
    LONG ArrayNum;
    LONG ArrayMax;
}TArray;

typedef struct _FQuat {
    float X; // 0x00(0x04)
    float Y; // 0x04(0x04)
    float Z; // 0x08(0x04)
    float W; // 0x0c(0x04)
}FQuat;

typedef struct _FRotator {
    float Pitch; // 0x00(0x04)
    float Yaw; // 0x04(0x04)
    float Roll; // 0x08(0x04)
}FRotator;

struct FEncHandler
{
    unsigned short Index;
    char bEncrypted;
    unsigned char bDynamic : 1;
    unsigned char bShareKey : 1;
    unsigned char bBitwiseCopyable : 1;
};

typedef struct _FEncVector {
    float X; // 0x00(0x04)
    float Y; // 0x04(0x04)
    float Z; // 0x08(0x04)
    FEncHandler EncHandler;
}FEncVector;

typedef struct _FVector {
    float X;
    float Y;
    float Z;
}FVector;

typedef struct _FTransform {
    FQuat Rotation;
    FVector Translation;
    UCHAR Pad_1C[0x4];
    FVector Scale3D;
    UCHAR Pad_2C[0x4];
}FTransform;

typedef struct _FEncTransform {
    FQuat Rotation;
    FVector Translation;
    UCHAR Pad_1C[0x4];
    FVector Scale3D;
    UCHAR Pad_2C[0x4];
    FEncHandler EncHandler;
    UCHAR Pad_34[0xC];
}FEncTransform;
