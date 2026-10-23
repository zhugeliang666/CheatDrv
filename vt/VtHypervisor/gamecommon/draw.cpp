#include "draw.h"
#include <stdio.h>
#include "../common/Utils.h"
#include <common/ntutils.h>
#include "game.h"
#include "dx.h"
#include <render/render.h>


ImVec4 黑背景 = ImVec4(0.3f, 0.3f, 0.3f, 0.8f);

#define D2D

#pragma code_seg(".vm")

void DrawPicture() {
	//ImGui::GetForegroundDrawList()->AddImage(ImGui::GetIO().Fonts->TexID, ImVec2(0, 0), ImVec2(1920, 1080), ImVec2(0, 0), ImVec2(1, 1), ImGui::ColorConvertFloat4ToU32(ImVec4(1, 1, 1, 1)));

}



// 辅助函数：将宽字符数字转换为字符串
static wchar_t* wide_itoa(int value, wchar_t* str, int base) {
	wchar_t* ptr = str;
	wchar_t* ptr1 = str;
	wchar_t tmp_char;
	int tmp_value;

	if (base < 2 || base > 36) {
		*ptr = L'\0';
		return str;
	}

	do {
		tmp_value = value;
		value /= base;
		*ptr++ = L"zyxwvutsrqponmlkjihgfedcba9876543210123456789abcdefghijklmnopqrstuvwxyz"[35 + (tmp_value - value * base)];
	} while (value);

	if (tmp_value < 0 && base == 10) {
		*ptr++ = L'-';
	}

	*ptr-- = L'\0';

	// 反转字符串
	while (ptr1 < ptr) {
		tmp_char = *ptr;
		*ptr-- = *ptr1;
		*ptr1++ = tmp_char;
	}

	return str;
}




#ifdef  TEST


// 实现一个完全不依赖库函数的_vsnwprintf
int _vsnwprintf_new_interal(wchar_t* buffer, size_t count, const wchar_t* format, va_list args) {
	if (!buffer || !format || count == 0) return -1;

	size_t pos = 0;  // 当前写入位置
	const wchar_t* p = format;  // 当前处理的格式字符串位置

	while (*p && pos < count - 1) {  // 留一个位置给null终止符
		if (*p != L'%') {
			buffer[pos++] = *p++;
			continue;
		}

		// 处理%格式
		p++;  // 跳过%
		if (!*p) break;  // 格式字符串结束

		switch (*p) {
		case L'%':  // 转义%
			buffer[pos++] = L'%';
			break;

		case L'd':  // 整数
		case L'i': {
			int value = va_arg(args, int);
			wchar_t num[32];
			int numPos = 0;
			int isNeg = value < 0;

			// 处理负数
			if (isNeg) {
				value = -value;
			}

			// 转换为字符串（反向）
			do {
				num[numPos++] = L'0' + (value % 10);
				value /= 10;
			} while (value > 0);

			// 检查是否有足够空间
			if (pos + numPos + (isNeg ? 1 : 0) >= count - 1) {
				buffer[pos] = L'\0';
				return -1;
			}

			// 添加负号
			if (isNeg) {
				buffer[pos++] = L'-';
			}

			// 复制数字（反向）
			while (numPos > 0) {
				buffer[pos++] = num[--numPos];
			}
			break;
		}

		case L'p': {  // 指针
			void* value = va_arg(args, void*);
			wchar_t hex[32];
			int hexPos = 0;
			uintptr_t ptr = (uintptr_t)value;

			// 转换为16进制字符串（反向）
			do {
				wchar_t digit = ptr & 0xF;
				hex[hexPos++] = digit < 10 ? L'0' + digit : L'A' + (digit - 10);
				ptr >>= 4;
			} while (ptr > 0);

			// 检查是否有足够空间
			if (pos + hexPos + 2 >= count - 1) {  // +2 for "0x"
				buffer[pos] = L'\0';
				return -1;
			}

			// 添加"0x"前缀
			buffer[pos++] = L'0';
			buffer[pos++] = L'x';

			// 复制16进制数（反向）
			while (hexPos > 0) {
				buffer[pos++] = hex[--hexPos];
			}
			break;
		}

		case L's': {  // 字符串
			const wchar_t* str = va_arg(args, const wchar_t*);
			if (!str) str = L"(null)";

			// 计算字符串长度
			const wchar_t* s = str;
			while (*s) s++;
			size_t len = s - str;

			// 检查是否有足够空间
			if (pos + len >= count - 1) {
				buffer[pos] = L'\0';
				return -1;
			}

			// 复制字符串
			while (*str) {
				buffer[pos++] = *str++;
			}
			break;
		}

		case L'l': {  // long / long long modifier: %lu, %llu, %ld, %lld
			// peek one or two more chars
			p++;  // skip first 'l'
			bool longlong = (*p == L'l');
			if (longlong) p++;  // skip second 'l'

			wchar_t suffix = *p;
			bool isHex = false;
			bool isSigned = (suffix == L'd' || suffix == L'i');
			bool isUnsigned = (suffix == L'u');
			if (suffix == L'x' || suffix == L'X') { isHex = true; isUnsigned = true; }
			if (!isSigned && !isUnsigned) {
				// unknown — emit literally and stop format processing for this token
				buffer[pos++] = L'%';
				buffer[pos++] = L'l';
				if (longlong && pos < count - 1) buffer[pos++] = L'l';
				if (pos < count - 1) buffer[pos++] = suffix;
				break;
			}

			uint64_t uvalue;
			bool isNeg = false;
			if (isSigned) {
				int64_t sv = longlong ? va_arg(args, long long) : (int64_t)va_arg(args, long);
				if (sv < 0) { isNeg = true; uvalue = (uint64_t)(-sv); }
				else        { uvalue = (uint64_t)sv; }
			} else {
				uvalue = longlong ? (uint64_t)va_arg(args, unsigned long long)
				                  : (uint64_t)va_arg(args, unsigned long);
			}

			wchar_t num[32];
			int numPos = 0;
			if (uvalue == 0) {
				num[numPos++] = L'0';
			} else if (isHex) {
				while (uvalue > 0) {
					wchar_t d = uvalue & 0xF;
					num[numPos++] = d < 10 ? L'0' + d : L'A' + (d - 10);
					uvalue >>= 4;
				}
			} else {
				while (uvalue > 0) {
					num[numPos++] = L'0' + (wchar_t)(uvalue % 10);
					uvalue /= 10;
				}
			}

			if (pos + numPos + (isNeg ? 1 : 0) >= count - 1) {
				buffer[pos] = L'\0';
				return -1;
			}
			if (isNeg) buffer[pos++] = L'-';
			while (numPos > 0) buffer[pos++] = num[--numPos];
			break;
		}

		case L'u': {  // unsigned int (decimal)
			unsigned int value = va_arg(args, unsigned int);
			wchar_t num[16];
			int numPos = 0;
			if (value == 0) num[numPos++] = L'0';
			else while (value > 0) {
				num[numPos++] = L'0' + (value % 10);
				value /= 10;
			}
			if (pos + numPos >= count - 1) {
				buffer[pos] = L'\0';
				return -1;
			}
			while (numPos > 0) buffer[pos++] = num[--numPos];
			break;
		}

		case L'x':
		case L'X': {  // 32-bit hex
			unsigned int value = va_arg(args, unsigned int);
			wchar_t hex[16];
			int hexPos = 0;
			if (value == 0) hex[hexPos++] = L'0';
			else while (value > 0) {
				wchar_t d = value & 0xF;
				hex[hexPos++] = d < 10 ? L'0' + d : L'A' + (d - 10);
				value >>= 4;
			}
			if (pos + hexPos >= count - 1) {
				buffer[pos] = L'\0';
				return -1;
			}
			while (hexPos > 0) buffer[pos++] = hex[--hexPos];
			break;
		}

		default:  // 未知格式
			buffer[pos++] = L'%';
			buffer[pos++] = *p;
			break;
		}
		p++;
	}

	// 添加null终止符
	buffer[pos] = L'\0';
	return (int)pos;
}



// 方便使用的包装函数
int _vsnwprintf_new(wchar_t* buffer, size_t count, const wchar_t* format, ...) {
	va_list args;
	va_start(args, format);
	int result = _vsnwprintf_new_interal(buffer, count, format, args);
	va_end(args);
	return result;
}


void DrawNewTextDebug(int X, int Y, ImVec4 Color,wchar_t* txt, ...)
{
	wchar_t str[256] = { 0 };
	memset(str, 0, 256);
	va_list va_alist;
	va_start(va_alist, txt);
	_vsnwprintf_new_interal(str, sizeof(str) / sizeof(wchar_t), txt, va_alist);
	va_end(va_alist);


	auto color = ColorF(Color.x, Color.y, Color.z, Color.w);
	memcpy(buffer0_hva, &color, sizeof(color));
	hv::Call(hv::GetVFunc(hv::colorBrush, 8), hv::colorBrush, buffer0);
	memset(buffer0_hva, 0, 0x1000);



	auto rect = RectF(X , Y, FLT_MAX, FLT_MAX);
	wcscpy_s((wchar_t*)buffer0_hva,256 , str);
	memcpy((char*)buffer0_hva+0x300, &rect, sizeof(rect));
	hv::Call(hv::GetVFunc(hv::d2dRenderTarget, 27), hv::d2dRenderTarget, buffer0, (ULONG64)wcslen(str), hv::TextFormat,(CHAR*)buffer0+0x300, hv::colorBrush,(ULONG64)0,(ULONG64)0);


}

#endif //  TEST




void DrawNewText(int X, int Y, ImVec4 Color, wchar_t* txt)
{


	auto color = ColorF(Color.x, Color.y, Color.z, Color.w);
	memset(buffer0_hva, 0, 0x1000);
	memcpy(buffer0_hva, &color, sizeof(color));
	hv::Call(hv::GetVFunc(hv::colorBrush, 8), hv::colorBrush, buffer0);
	memset(buffer0_hva, 0, 0x1000);



	auto rect = RectF(X, Y, FLT_MAX, FLT_MAX);
	wcscpy_s((wchar_t*)buffer0_hva, 256, txt);
	memcpy((char*)buffer0_hva + 0x300, &rect, sizeof(rect));
	hv::Call(hv::GetVFunc(hv::d2dRenderTarget, 27), hv::d2dRenderTarget, buffer0, (ULONG64)wcslen(txt), hv::TextFormat, (CHAR*)buffer0 + 0x300, hv::colorBrush, (ULONG64)0, (ULONG64)0);


}




void DrawCenterText(int X, int Y, ImVec4 Color, wchar_t* txt)
{

	auto color = ColorF(Color.x, Color.y, Color.z, Color.w);
	memcpy(buffer0_hva, &color, sizeof(color));
	hv::Call(hv::GetVFunc(hv::colorBrush, 8), hv::colorBrush, buffer0);
	memset(buffer0_hva, 0, 0x1000);



	auto rect = RectF(X - wcslen(txt) * 10.f / 2, Y - 8, FLT_MAX, FLT_MAX);
	wcscpy_s((wchar_t*)buffer0_hva, 256, txt);
	memcpy((char*)buffer0_hva + 0x300, &rect, sizeof(rect));
	hv::Call(hv::GetVFunc(hv::d2dRenderTarget, 27), hv::d2dRenderTarget, buffer0, (ULONG64)wcslen(txt), hv::TextFormat, (CHAR*)buffer0 + 0x300, hv::colorBrush, (ULONG64)0, (ULONG64)0);


}

//void DrawCenterText(int X, int Y, ImVec4 Color, wchar_t* txt, ...)
//{
//	wchar_t str[256];
//	memset(str, 0, 256);
//	va_list va_alist;
//	va_start(va_alist, txt);
//
//	_vsnwprintf_new_interal(str, sizeof(str) / sizeof(wchar_t), txt, va_alist);
//	va_end(va_alist);
//
//
//	auto color = ColorF(Color.x, Color.y, Color.z, Color.w);
//	memcpy(buffer0_hva, &color, sizeof(color));
//	hv::Call(hv::GetVFunc(hv::colorBrush, 8), hv::colorBrush, buffer0);
//	memset(buffer0_hva, 0, 0x1000);
//
//
//
//	auto rect = RectF(X - wcslen(str) * 10.f / 2, Y - 8, FLT_MAX, FLT_MAX);
//	memcpy((wchar_t*)buffer0_hva, str, 256);
//	memcpy((char*)buffer0_hva + 0x300, &rect, sizeof(rect));
//	hv::Call(hv::GetVFunc(hv::d2dRenderTarget, 27), hv::d2dRenderTarget, buffer0, (ULONG64)wcslen(str), hv::TextFormat, (CHAR*)buffer0 + 0x300, hv::colorBrush, (ULONG64)0, (ULONG64)0);
//
//
//}



void DrawAddTriangle(ImVec2 P1, ImVec2 P2, ImVec2 P3, ImVec4 Color)
{

	

#ifdef PACKET


	ImGui::GetForegroundDrawList()->AddTriangleFilled(P1, P2, P3, ImGui::ColorConvertFloat4ToU32(Color));
#elif defined(D2D)


#else

	render::DrawAddTriangleWrap(P1, P2, P3, Color);


#endif
}

void DrawCircleFilled(int X, int Y, float Radius, ImVec4 Color, int Segments, int tmz)
{


#ifdef PACKET


	ImGui::GetForegroundDrawList()->AddCircle(ImVec2(X, Y), Radius, ImGui::ColorConvertFloat4ToU32(Color), Segments, Radius*2);
#elif defined(D2D)

	auto color = ColorF(Color.x, Color.y, Color.z, Color.w);
	memcpy(buffer0_hva, &color, sizeof(color));
	hv::Call(hv::GetVFunc(hv::colorBrush, 8), hv::colorBrush, buffer0);
	memset(buffer0_hva, 0, 0x1000);

	D2D1_ELLIPSE ellipse = Ellipse(Point2F(X, Y), Radius, Radius);

	memcpy(buffer0_hva, &ellipse, sizeof(ellipse));
	hv::Call(hv::GetVFunc(hv::d2dRenderTarget, 21), hv::d2dRenderTarget, buffer0, hv::colorBrush);

#else

	render::DrawCircleFilledWrap(X, Y, Radius, Color, Segments, tmz);


#endif
}

void DrawCircle(int X, int Y, float Radius, ImVec4 Color, int Segments, float thickness)
{


#ifdef PACKET


	ImGui::GetForegroundDrawList()->AddCircle(ImVec2(X, Y), Radius, ImGui::ColorConvertFloat4ToU32(Color), Segments, thickness);
#elif defined(D2D)
	//a->DrawEllipse(D2D1::Ellipse(D2D1::Point2F(200, 200), 50, 50), g_pD2DBrush, 1.0f, nullptr);
	auto color = ColorF(Color.x, Color.y, Color.z, Color.w);
	memcpy(buffer0_hva, &color, sizeof(color));
	hv::Call(hv::GetVFunc(hv::colorBrush, 8), hv::colorBrush, buffer0);
	memset(buffer0_hva, 0, 0x1000);

	D2D1_ELLIPSE ellipse = Ellipse(Point2F(X, Y), Radius, Radius);
	
	memcpy(buffer0_hva, &ellipse, sizeof(ellipse));
	hv::Call(hv::GetVFunc(hv::d2dRenderTarget, 20), hv::d2dRenderTarget, buffer0, hv::colorBrush, thickness, nullptr);
#else

	render::DrawCircleWrap(X, Y, Radius, Color, Segments, thickness);


#endif
}

void DrawRect(int X, int Y, int W, int H, ImVec4 Color, float thickness, float rounding)
{
#ifdef PACKET


	ImGui::GetForegroundDrawList()->AddRect(ImVec2(X, Y), ImVec2(X + W, Y + H), ImGui::ColorConvertFloat4ToU32(Color), rounding, 15, thickness);

#elif defined(D2D)

	auto color = ColorF(Color.x, Color.y, Color.z, Color.w);
	memcpy(buffer0_hva, &color, sizeof(color));
	hv::Call(hv::GetVFunc(hv::colorBrush, 8), hv::colorBrush, buffer0);
	memset(buffer0_hva, 0, 0x1000);
	auto rect = RectF(X, Y, X + W, Y + H);
	memcpy(buffer0_hva, &rect, sizeof(rect));
	hv::Call(hv::GetVFunc(hv::d2dRenderTarget, 16), hv::d2dRenderTarget, buffer0, hv::colorBrush,thickness,nullptr);
	

#else

	render::DrawFilledRectWrap(X, Y, W, H, Color, tmz, rounding);

#endif
}

void DrawFilledRect(int X, int Y, int W, int H, ImVec4 Color, int tmz, float rounding)
{
	

#ifdef PACKET

	ImGui::GetForegroundDrawList()->AddRectFilled(ImVec2(X, Y), ImVec2(X + W, Y + H), ImGui::ColorConvertFloat4ToU32(Color), rounding);

#elif defined(D2D)

	auto color = ColorF(Color.x, Color.y, Color.z, Color.w);
	memcpy(buffer0_hva, &color, sizeof(color));
	hv::Call(hv::GetVFunc(hv::colorBrush, 8), hv::colorBrush, buffer0);
	memset(buffer0_hva, 0, 0x1000);
	D2D1_RECT_F rect  = RectF(X, Y, X + W, Y + H);
	memcpy(buffer0_hva, &rect, sizeof(D2D1_RECT_F));
	hv::Call(hv::GetVFunc(hv::d2dRenderTarget, 17), hv::d2dRenderTarget, buffer0, hv::colorBrush);
	


#else

	render::DrawFilledRectWrap(X, Y, W, H, Color, tmz, rounding);

#endif
}

void DrawFilledMultiColor(float X, float Y, float W, float H, ImU32 rgb, ImU32 rgb2, ImU32 rgb3, ImU32 rgb4)
{
#ifdef PACKET

	ImGui::GetForegroundDrawList()->AddRectFilledMultiColor(ImVec2(X, Y), ImVec2(X + W, Y + H),
		rgb, rgb2, rgb3, rgb4);//多色彩填充
#elif defined(D2D)


#else

	render::DrawFilledMultiColorWrap(X, Y, W, H, rgb, rgb2, rgb3, rgb4);

#endif
}


void DrawLine(int X1, int Y1, int X2, int Y2, ImVec4 Color, float thickness)
{

#ifdef PACKET

	ImGui::GetForegroundDrawList()->AddLine(ImVec2(X1, Y1), ImVec2(X2, Y2), ImGui::ColorConvertFloat4ToU32(Color), thickness);
#elif defined(D2D)

	auto color = ColorF(Color.x, Color.y, Color.z, Color.w);
	memcpy(buffer0_hva, &color, sizeof(color));
	hv::Call(hv::GetVFunc(hv::colorBrush, 8), hv::colorBrush, buffer0);
	memset(buffer0_hva, 0, 0x1000);
	D2D1_POINT_2F startPoint = Point2F(X1, Y1);
	D2D1_POINT_2F endPoint = Point2F(X2, Y2);
	hv::Call(hv::GetVFunc(hv::d2dRenderTarget, 15), hv::d2dRenderTarget, startPoint, endPoint,hv::colorBrush,thickness, nullptr);

#else

	render::DrawLine((X1, Y1, X2, Y2, Color, thickness);

#endif
	
}

void DrawBox_S(const ImVec2& pos, const ImVec2& headPosition, ImVec4 color, float Siz)
{
	DrawLine(pos.x, pos.y, pos.x + (headPosition.x / 2.f / 1.2f), pos.y, color, Siz);//上左右--
	DrawLine(pos.x + (headPosition.x / 2.f * 1.2f), pos.y, pos.x + headPosition.x, pos.y, color, Siz);//上左右--


	DrawLine(pos.x, pos.y, pos.x, pos.y + (headPosition.y / 2.f / 1.4f), color, Siz);//左上下|
	DrawLine(pos.x, pos.y + (headPosition.y / 2.f * 1.4f), pos.x, pos.y + headPosition.y, color, Siz);//左上下|

	DrawLine(pos.x, pos.y + headPosition.y, pos.x + (headPosition.x / 2.f / 1.2f), pos.y + headPosition.y, color, Siz);//下左右
	DrawLine(pos.x + (headPosition.x / 2.f * 1.2f), pos.y + headPosition.y, pos.x + headPosition.x, pos.y + headPosition.y, color, Siz);//下左右

	DrawLine(pos.x + headPosition.x, pos.y, pos.x + headPosition.x, pos.y + (headPosition.y / 2.f / 1.4f), color, Siz);
	DrawLine(pos.x + headPosition.x, pos.y + (headPosition.y / 2.f * 1.4f), pos.x + headPosition.x, pos.y + headPosition.y, color, Siz);
}

// 计算宽字符文本的像素宽高，简单实现（单行，等宽字体近似）
ImVec2 CalaTextSize(const wchar_t* txt) {
	if (!txt) return ImVec2(0, 0);
	size_t len = wcslen(txt);
	// 这里假设每个字符宽度为 7.8，高度为 16（与 DrawCenterText 里的 7.8f/2 对齐）
	return ImVec2(len * 10.f, 16.0f);
}

#pragma code_seg()
