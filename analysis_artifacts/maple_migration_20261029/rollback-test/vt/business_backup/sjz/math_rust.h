#pragma once
#include <corecrt_math.h>
#include <complex>
#include <algorithm>

#pragma code_seg(".vm")

namespace math_rust {


	class Vector3;
	class Vector2;


	class Vector3
	{
	public:
		float x, y, z;

		inline Vector3() {
			x = y = z = 0.0f;
		}

		inline Vector3(float var) {
			x = y = z = var;
		}

		inline Vector3(float X, float Y, float Z) {
			x = X; y = Y; z = Z;
		}

		inline float operator[](int i) const {
			return ((float*)this)[i];
		}

		inline Vector3& operator-=(float v) {
			x -= v; y -= v; z -= v; return *this;
		}

		inline Vector3 operator*(float v) const {
			return Vector3(x * v, y * v, z * v);
		}

		inline Vector3 operator/(float v) const
		{
			return Vector3(x / v, y / v, z / v);
		}

		inline Vector3& operator+=(const Vector3& v) {
			x += v.x; y += v.y; z += v.z; return *this;
		}

		inline Vector3 operator-(const Vector3& v) const {
			return Vector3(x - v.x, y - v.y, z - v.z);
		}

		inline Vector3 operator+(const Vector3& v) const {
			return Vector3(x + v.x, y + v.y, z + v.z);
		}

		inline float Length() {
			return sqrtf(x * x + y * y + z * z);
		}

		inline float dot(Vector3 input) const {
			return (x * input.x) + (y * input.y) + (z * input.z);
		}

		inline bool IsZero() const {
			return (x==0.0f && y== 0.0f && z ==0.0f);
		}

		inline Vector3 Cross(Vector3 rhs)
		{
			return Vector3(y * rhs.z - z * rhs.y, z * rhs.x - x * rhs.z, x * rhs.y - y * rhs.x);
		}

		//inline bool IsValid() const {
		//	return !std::isnan(x) && !std::isnan(y) && !std::isnan(z);
		//}

		inline float unity_magnitude()
		{
			return (float)sqrt((double)(x * x + y * y + z * z));
		}

		inline Vector3 unity_Normalize()
		{
			float num = unity_magnitude();
			if (num > 1E-05f)
			{
				x /= num;
				y /= num;
				z /= num;
			}
			else
			{
				x = 0;
				y = 0;
				z = 0;
			}

			return { x,y,z };
		}

		inline float length_sqr() const
		{
			return (x * x) + (y * y) + (z * z);
		}

		inline float length() const
		{
			return std::sqrt(length_sqr());
		}

		inline Vector3 normalize()
		{
			Vector3 out = *this;
			auto l = length();
			if (l == 0)
				return *this;
			;
			out.x /= l;
			out.y /= l;
			out.z /= l;
			return out;
		}
	};

	class Vector2
	{
	public:
		float x, y;

		inline Vector2() {
			x = y = 0.0f;
		}

		inline Vector2 operator/(float v) const {
			return Vector2(x / v, y / v);
		}
		inline Vector2(float X, float Y) {
			x = X; y = Y;
		}

		inline Vector2 operator-(const Vector2& v) const {
			return Vector2(x - v.x, y - v.y);
		}

		inline Vector2 operator+(const Vector2& v) const {
			return Vector2(x + v.x, y + v.y);
		}

		inline Vector2 operator*(float input) const
		{
			return Vector2{ x * input, y * input };
		}

		inline Vector2& operator+=(const Vector2& v) {
			x += v.x; y += v.y; return *this;
		}
		inline Vector2& operator*= (float v)
		{

			x *= v;
			y *= v;
			return *this;
		}


		inline bool Zero() const {
			return (x > -0.1f && x < 0.1f && y > -0.1f && y < 0.1f);
		}

		inline float Length()
		{
			return sqrtf(x * x + y * y);
		}


		inline Vector2 Normalize()
		{
			return { x / Length(),y / Length() };
		}

		inline float Distance(Vector2 v)
		{
			return (*this - v).Length();
		}
	};

	struct Matrix4x4
	{
		union
		{
			struct
			{
				float _11, _12, _13, _14;
				float _21, _22, _23, _24;
				float _31, _32, _33, _34;
				float _41, _42, _43, _44;
			};
			float m[4][4];
		};
	};


	class Vector4
	{
	public:
		Vector4()
		{
			x = y = z = w = 0.f;
		}

		Vector4(float fx, float fy, float fz, float fw)
		{
			x = fx;
			y = fy;
			z = fz;
			w = fw;
		}

		float x, y, z, w;

		Vector4 operator+(const Vector4& input) const
		{
			return Vector4{ x + input.x, y + input.y, z + input.z, w + input.w };
		}

		Vector4 operator-(const Vector4& input) const
		{
			return Vector4{ x - input.x, y - input.y, z - input.z, w - input.w };
		}

		Vector4 operator/(float input) const
		{
			return Vector4{ x / input, y / input, z / input, w / input };
		}

		Vector4 operator*(float input) const
		{
			return Vector4{ x * input, y * input, z * input, w * input };
		}

		Vector4& operator-=(const Vector4& v)
		{
			x -= v.x;
			y -= v.y;
			z -= v.z;
			w -= v.w;

			return *this;
		}

		Vector4& operator/=(float input)
		{
			x /= input;
			y /= input;
			z /= input;
			w /= input;
			return *this;
		}

		Vector4& operator*=(float input)
		{
			x *= input;
			y *= input;
			z *= input;
			w *= input;
			return *this;
		}

		bool operator==(const Vector4& input) const
		{
			return x == input.x && y == input.y && z == input.z && w == input.w;
		}

		void make_absolute()
		{
			x = std::abs(x);
			y = std::abs(y);
			z = std::abs(z);
			w = std::abs(w);
		}

		float length_sqr() const
		{
			return (x * x) + (y * y) + (z * z) + (w * w);
		}

		float length() const
		{
			return std::sqrt(length_sqr());
		}

		float length_2d() const
		{
			return std::sqrt((x * x) + (y * y));
		}

		Vector4 normalized() const
		{
			return { x / length(), y / length(), z / length(), w / length() };
		}

		float dot_product(Vector4 input) const
		{
			return (x * input.x) + (y * input.y) + (z * input.z) + (w * input.w);
		}

		float distance(Vector4 input) const
		{
			return (*this - input).length();
		}

		float distance_2d(Vector4 input) const
		{
			return (*this - input).length_2d();
		}
		void clamp()
		{
			static_cast<void>(std::clamp(x, -89.f, 89.f));
			static_cast<void>(std::clamp(y, -180.f, 180.f));

			z = 0.f;
			w = 0.f;
		}

		bool empty() const
		{
			return x == 0.f && y == 0.f && z == 0.f && w == 0.f;
		}

		static Vector4 QuaternionLookRotation(Vector3 forward, Vector3 up)
		{
			Vector3 vector = forward.unity_Normalize();
			Vector3 vector2 = (up).Cross(vector).unity_Normalize();
			Vector3 vector3 = (vector).Cross(vector2);
			auto m00 = vector2.x;
			auto m01 = vector2.y;
			auto m02 = vector2.z;
			auto m10 = vector3.x;
			auto m11 = vector3.y;
			auto m12 = vector3.z;
			auto m20 = vector.x;
			auto m21 = vector.y;
			auto m22 = vector.z;


			float num8 = (m00 + m11) + m22;
			auto quaternion = Vector4();
			if (num8 > 0.f)
			{
				auto num = (float)sqrt(num8 + 1.f);
				quaternion.w = num * 0.5f;
				num = 0.5f / num;
				quaternion.x = (m12 - m21) * num;
				quaternion.y = (m20 - m02) * num;
				quaternion.z = (m01 - m10) * num;
				return quaternion;
			}
			if ((m00 >= m11) && (m00 >= m22))
			{
				auto num7 = (float)sqrt(((1.f + m00) - m11) - m22);
				auto num4 = 0.5f / num7;
				quaternion.x = 0.5f * num7;
				quaternion.y = (m01 + m10) * num4;
				quaternion.z = (m02 + m20) * num4;
				quaternion.w = (m12 - m21) * num4;
				return quaternion;
			}
			if (m11 > m22)
			{
				auto num6 = (float)sqrt(((1.f + m11) - m00) - m22);
				auto num3 = 0.5f / num6;
				quaternion.x = (m10 + m01) * num3;
				quaternion.y = 0.5f * num6;
				quaternion.z = (m21 + m12) * num3;
				quaternion.w = (m20 - m02) * num3;
				return quaternion;
			}
			auto num5 = (float)sqrt(((1.f + m22) - m00) - m11);
			auto num2 = 0.5f / num5;
			quaternion.x = (m20 + m02) * num2;
			quaternion.y = (m21 + m12) * num2;
			quaternion.z = 0.5f * num5;
			quaternion.w = (m01 - m10) * num2;
			return quaternion;
		}



	};

#define M_PI 3.14159265358979323846f
#define M_RADPI 57.295779513082f
#define M_PI_F ((float)(M_PI))
#define RAD2DEG(x) ((float)(x) * (float)(180.f / M_PI_F))
#define DEG2RAD(x) ((float)(x) * (float)(M_PI_F / 180.f))
#define atan2(a, b) ((float)atan2((double)(a), (double)(b)))
	static volatile const double Tiny = 0x1p-1022;
	static volatile const double Infinity = INFINITY;
	typedef struct { double d0, d1; } double2;

	static inline double2 Mul112(double a, double b)
	{
		static const double c = 0x1p27 + 1;

		double
			ap = a * c, bp = b * c,
			a0 = (a - ap) + ap, b0 = (b - bp) + bp,
			a1 = a - a0, b1 = b - b0,
			d0 = a * b,
			d1 = a0 * b0 - d0 + a0 * b1 + a1 * b0 + a1 * b1;
		return double2{ d0, d1 };
	}

	static inline double2 Mul222(double2 a, double2 b)
	{
		static const double c = 0x1p27 + 1;

		double
			ap = a.d0 * c, bp = b.d0 * c,
			a0 = (a.d0 - ap) + ap, b0 = (b.d0 - bp) + bp,
			a1 = a.d0 - a0, b1 = b.d0 - b0,
			m0 = a.d0 * b.d0,
			m1 = a0 * b0 - m0 + a0 * b1 + a1 * b0 + a1 * b1 + (a.d0 * b.d1 + a.d1 * b.d0),
			d0 = m0 + m1,
			d1 = m0 - d0 + m1;
		return double2{ d0, d1 };
	}

	static inline double Mul121Special(double a, double2 b)
	{
		static const double c = 0x1p27 + 1;

		double
			ap = a * c, bp = b.d0 * c,
			a0 = (a - ap) + ap, b0 = (b.d0 - bp) + bp,
			a1 = a - a0, b1 = b.d0 - b0,
			m1 = a0 * b0 - 1 + a0 * b1 + a1 * b0 + a1 * b1 + a * b.d1;
		return m1;
	}

	static inline double2 Add212RightSmaller(double2 a, double b)
	{
		double
			c0 = a.d0 + b,
			c1 = a.d0 - c0 + b + a.d1,
			d0 = c0 + c1,
			d1 = c0 - d0 + c1;
		return double2{ d0, d1 };
	}

	static inline double Add221RightSmaller(double2 a, double2 b)
	{
		double
			c0 = a.d0 + b.d0,
			c1 = a.d0 - c0 + b.d0 + b.d1 + a.d1,
			d0 = c0 + c1;
		return d0;
	}

	static double Tail(double x)
	{
		if (1 <= x)
			return 1 == x
			// If x is 1, generate inexact and return Pi/2 rounded down.
			? 0x3.243f6a8885a308d313198a2e03707344ap-1 + Tiny
			// If x is outside the domain, generate invalid and return NaN.
			: Infinity - Infinity;

		static const double p01 = 0.2145993335526539017488949;
		static const double p02 = -0.0890259194305537131666744;
		static const double p03 = 0.0506659694457588602631748;
		static const double p04 = -0.0331919619444009606270380;
		static const double p05 = 0.0229883479552557203133368;
		static const double p06 = -0.0156746038587246716524035;
		static const double p07 = 0.0097868293573384001221447;
		static const double p08 = -0.0052049731575223952626203;
		static const double p09 = 0.0021912255981979442677477;
		static const double p10 = -0.0006702485124770180942917;
		static const double p11 = 0.0001307564187657962919394;
		static const double p12 = -0.0000121189820098929624806;

		double polynomial = ((((((((((((
			+p12) * x
			+ p11) * x
			+ p10) * x
			+ p09) * x
			+ p08) * x
			+ p07) * x
			+ p06) * x
			+ p05) * x
			+ p04) * x
			+ p03) * x
			+ p02) * x
			+ p01) * x;

#if UseLongDouble
		static const long double HalfPi = 0x3.243f6a8885a308d313198a2ep-1L;
		static const long double p00 = -1.5707961988153774692344105L;

		return HalfPi + sqrtl(1 - x) * (polynomial + p00);
#else	// #if UseLongDouble
		static const double2
			HalfPi = { 0x1.921fb54442d18p+0, 0x1.1a62633145c07p-54 },
			p00 = { -0x1.921fb31e97d96p0, +0x1.eab77149ad27cp-54 };

		// Estimate 1 / sqrt(1-x).
		double e = 1 / sqrt(1 - x);

		double2 ex = Mul112(e, 1 - x);		// e * x.
		double e2x = Mul121Special(e, ex);	// e**2 * x - 1.

		// Set t0 to an improved approximation of sqrt(1-x) with Newton-Raphson.
		double2 t0 = Add212RightSmaller(ex, ex.d0 * -.5 * e2x);

		// Calculate pi/2 + sqrt(1-x) * p(x).
		return Add221RightSmaller(HalfPi, Mul222(
			t0,
			Add212RightSmaller(p00, polynomial)));
#endif	// #if UseLongDouble
	}

	static float abs(float a) {
		if (a < 0.f) return -a;
		else return a;
	}

	static float asin(float x) {
		float negate = float(x < 0);
		x = abs(x);
		double ret = -0.0187293;
		ret *= x;
		ret += 0.0742610;
		ret *= x;
		ret -= 0.2121144;
		ret *= x;
		ret += 1.5707288;
		ret = 3.14159265358979 * 0.5 - sqrt(1.0 - x) * ret;
		return (ret - 2 * negate * ret);
	}

	__forceinline float Dot(const Vector3& Vec1, const Vector3& Vec2) {
		return Vec1[0] * Vec2[0] + Vec1[1] * Vec2[1] + Vec1[2] * Vec2[2];
	}

	__forceinline float Calc3D_Dist(const Vector3& Src, const Vector3& Dst) {
		return sqrtf(pow((Src.x - Dst.x), 2) + pow((Src.y - Dst.y), 2) + pow((Src.z - Dst.z), 2));
	}

	__forceinline float Calc2D_Dist(const Vector2& Src, const Vector2& Dst) {
		return sqrt(powf(Src.x - Dst.x, 2) + powf(Src.y - Dst.y, 2));
	}

	__forceinline Vector2 CalcAngle(const Vector3& Src, const Vector3& Dst) {
		Vector3 dir = Src - Dst;
		return Vector2{ RAD2DEG(asin(dir.y / dir.Length())), RAD2DEG(-atan2(dir.x, -dir.z)) };
	}

}



