#pragma once
#include <fltKernel.h>
#include "imgui.h"

//#define PACKET
#define D2D

//extern ImVec4 黑背景;


//#define 红色 0xFF0000 
//#define 黄色 0xFFFF00 
//#define 黑色 0xFFFFFF
//#define 深青 0x008080 
//#define 橙黄 0xFF8000 
//#define 天蓝 0x0088FF 
//#define 蓝色 0x0000FF 
//#define 绿色 0x00FF00 
//#define 白色 0xFFFFFF 
//#define 桃红 0xFF5080
//#define 嫩黄 0xD8D800
//#define 灰色 0x808080

extern PVOID buffer0;
extern PVOID buffer1;
extern PVOID buffer0_hva;
extern PVOID buffer1_hva;






int _vsnwprintf_new(wchar_t* buffer, size_t count, const wchar_t* format, ...);
void DrawNewTextDebug(int X, int Y, ImVec4 Color, wchar_t* txt, ...);
void DrawNewText(int X, int Y, ImVec4 Color, wchar_t* txt);




void DrawCenterText(int X, int Y, ImVec4 Color, wchar_t* txt);

ImVec2 CalaTextSize(const wchar_t* txt);

void DrawAddTriangle(ImVec2 P1, ImVec2 P2, ImVec2 P3, ImVec4 Color);

void DrawCircleFilled(int X, int Y, float Radius, ImVec4 Color, int Segments = 0, int tmz = 0);

void DrawCircle(int X, int Y, float Radius, ImVec4 Color, int Segments = 0, float thickness = 1.0f);

void DrawRect(int X, int Y, int W, int H, ImVec4 Color, float thickness = 1.0f, float rounding = 0);

void DrawFilledRect(int X, int Y, int W, int H, ImVec4 Color, int tmz, float rounding);

void DrawFilledMultiColor(float X, float Y, float W, float H, ImU32 rgb, ImU32 rgb2, ImU32 rgb3, ImU32 rgb4);

void DrawLine(int X1, int Y1, int X2, int Y2, ImVec4 Color, float thickness);

void DrawBox_S(const ImVec2& pos, const ImVec2& headPosition, ImVec4 color, float Siz);