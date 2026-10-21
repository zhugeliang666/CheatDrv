//need enable AVX
#include <algorithm>

#define M_PI 3.14159265358979323846
#define M_PI_F ((float)(M_PI))
#define DEG2RAD(x) ((float)(x) * (float)(M_PI_F / 180.f))
#define RAD2DEG(x) ((float)(x) * (float)(180.f / M_PI_F))


namespace  math{

	//vector 3d
	class Vector3
	{
	public:
		float x = 0, y = 0, z = 0;

		Vector3()
		{
			x = y = z = 0.0f;
		}

		Vector3(float X, float Y, float Z)
		{
			x = X; y = Y; z = Z;
		}

		Vector3(float XYZ)
		{
			x = XYZ; y = XYZ; z = XYZ;
		}

		Vector3(float* v)
		{
			x = v[0]; y = v[1]; z = v[2];
		}

		Vector3(const float* v)
		{
			x = v[0]; y = v[1]; z = v[2];
		}

		inline Vector3& operator=(const Vector3& v)
		{
			x = v.x; y = v.y; z = v.z; return *this;
		}

		inline Vector3& operator=(const float* v)
		{
			x = v[0]; y = v[1]; z = v[2]; return *this;
		}

		inline float& operator[](int i)
		{
			return ((float*)this)[i];
		}

		inline float operator[](int i) const
		{
			return ((float*)this)[i];
		}

		void Vectorf(volatile float* v)
		{
			x = v[0];
			y = v[1];
			z = v[2];
		}

		inline Vector3 Normalize() {
			Vector3 vector;
			float length = this->Length();

			if (length != 0) {
				vector.x = x / length;
				vector.y = y / length;
				vector.z = z / length;
			}
			else {
				vector.x = vector.y = 0.0f;
				vector.z = 1.0f;
			}
			return vector;
		}

		inline Vector3& operator+=(const Vector3& v)
		{
			x += v.x; y += v.y; z += v.z; return *this;
		}

		inline Vector3& operator-=(const Vector3& v)
		{
			x -= v.x; y -= v.y; z -= v.z; return *this;
		}

		inline Vector3& operator*=(const Vector3& v)
		{
			x *= v.x; y *= v.y; z *= v.z; return *this;
		}

		inline Vector3& operator/=(const Vector3& v)
		{
			x /= v.x; y /= v.y; z /= v.z; return *this;
		}

		inline Vector3& operator+=(float v)
		{
			x += v; y += v; z += v; return *this;
		}

		inline Vector3& operator-=(float v)
		{
			x -= v; y -= v; z -= v; return *this;
		}

		inline Vector3& operator*=(float v)
		{
			x *= v; y *= v; z *= v; return *this;
		}

		inline Vector3& operator/=(float v)
		{
			x /= v; y /= v; z /= v; return *this;
		}

		inline Vector3 operator-() const
		{
			return Vector3(-x, -y, -z);
		}

		inline Vector3 operator+(const Vector3& v) const
		{
			return Vector3(x + v.x, y + v.y, z + v.z);
		}

		inline Vector3 operator-(const Vector3& v) const
		{
			return Vector3(x - v.x, y - v.y, z - v.z);
		}

		inline Vector3 operator*(const Vector3& v) const
		{
			return Vector3(x * v.x, y * v.y, z * v.z);
		}

		inline Vector3 operator/(const Vector3& v) const
		{
			return Vector3(x / v.x, y / v.y, z / v.z);
		}

		inline Vector3 operator+(float v) const
		{
			return Vector3(x + v, y + v, z + v);
		}

		inline Vector3 operator-(float v) const
		{
			return Vector3(x - v, y - v, z - v);
		}

		inline Vector3 operator*(float v) const
		{
			return Vector3(x * v, y * v, z * v);
		}

		inline Vector3 operator/(float v) const
		{
			return Vector3(x / v, y / v, z / v);
		}

		inline float Length() const
		{
			return (float)sqrtf(x * x + y * y + z * z);
		}

		float LengthXY() const {
			return sqrtf(x * x + y * y);
		}

		auto ClampAngle()
		{
			//clamp x
			x = std::clamp(x, -89.f, 89.f);

			//clamp y
			while ((y > 180.f) || (y < -180.f)) {
				if (y > 180.f) y -= 360.f;
				if (y < -180.f) y += 360.f;
			}

			//clamp z
			z = 0.f;

			//ret
			return *this;
		}

	};

	class Vector2
	{
	public:
		float x = 0, y = 0;

		Vector2()
		{
			x = y = 0.0f;
		}

		Vector2(float X, float Y)
		{
			x = X; y = Y;
		}

		Vector2(float XYZ)
		{
			x = XYZ; y = XYZ;
		}

		Vector2(float* v)
		{
			x = v[0]; y = v[1];
		}

		Vector2(const float* v)
		{
			x = v[0]; y = v[1];
		}

		inline Vector2& operator=(const Vector2& v)
		{
			x = v.x; y = v.y; return *this;
		}

		inline Vector2& operator=(const float* v)
		{
			x = v[0]; y = v[1]; return *this;
		}

		inline float& operator[](int i)
		{
			return ((float*)this)[i];
		}

		inline float operator[](int i) const
		{
			return ((float*)this)[i];
		}

		void Vectorf(volatile float* v)
		{
			x = v[0];
			y = v[1];
		}

		inline Vector2& operator+=(const Vector2& v)
		{
			x += v.x; y += v.y; return *this;
		}

		inline Vector2& operator-=(const Vector2& v)
		{
			x -= v.x; y -= v.y; return *this;
		}

		inline Vector2& operator*=(const Vector2& v)
		{
			x *= v.x; y *= v.y; return *this;
		}

		inline Vector2& operator/=(const Vector2& v)
		{
			x /= v.x; y /= v.y; return *this;
		}

		inline Vector2& operator+=(float v)
		{
			x += v; y += v; return *this;
		}

		inline Vector2& operator-=(float v)
		{
			x -= v; y -= v; return *this;
		}

		inline Vector2& operator*=(float v)
		{
			x *= v; y *= v; return *this;
		}

		inline Vector2& operator/=(float v)
		{
			x /= v; y /= v; return *this;
		}

		inline Vector2 operator-() const
		{
			return Vector2(-x, -y);
		}

		inline Vector2 operator+(const Vector2& v) const
		{
			return Vector2(x + v.x, y + v.y);
		}

		inline Vector2 operator-(const Vector2& v) const
		{
			return Vector2(x - v.x, y - v.y);
		}

		inline Vector2 operator*(const Vector2& v) const
		{
			return Vector2(x * v.x, y * v.y);
		}

		inline Vector2 operator/(const Vector2& v) const
		{
			return Vector2(x / v.x, y / v.y);
		}

		inline Vector2 operator+(float v) const
		{
			return Vector2(x + v, y + v);
		}

		inline Vector2 operator-(float v) const
		{
			return Vector2(x - v, y - v);
		}

		inline Vector2 operator*(float v) const
		{
			return Vector2(x * v, y * v);
		}

		inline Vector2 operator/(float v) const
		{
			return Vector2(x / v, y / v);
		}

		inline float Length() const
		{
			return (float)sqrtf(x * x + y * y);
		}

		__forceinline float FastDist2D(const Vector2& Src, const Vector2& Dst) {
			return sqrtf(powf(Src.x - Dst.x, 2.f) + powf(Src.y - Dst.y, 2.f));
		}

		float LengthXY() const {
			return sqrtf(x * x + y * y);
		}

		auto ClampAngle()
		{
			//clamp x
			x = std::clamp(x, -89.f, 89.f);

			//clamp y
			while ((y > 180.f) || (y < -180.f)) {
				if (y > 180.f) y -= 360.f;
				if (y < -180.f) y += 360.f;
			}

			//clamp z
			//z = 0.f;

			//ret
			return *this;
		}

	};


	//matrix
	class matrix3x4_t {
	public:
		float m_flMatVal[3][4];
		const float* operator[](int i) const {
			return m_flMatVal[i];
		}
	};

	//base math
	class Math
	{
	public:
		static float Dot(const Vector3& v1, Vector3& v2) {
			return v1[0] * v2[0] + v1[1] * v2[1] + v1[2] * v2[2];
		}


		static void SmoothAngle(Vector3 ViewAngle, Vector3& DestAngles, const float smooth) {
			auto vecDelta = (ViewAngle - DestAngles).ClampAngle();
			DestAngles = ViewAngle - vecDelta / 100.0f * smooth;
		}

		static void VectorTransform(const Vector3& in1, const matrix3x4_t& in2, Vector3& out) {
			out.x = in1.x * in2[0][0] + in1.y * in2[0][1] + in1.z * in2[0][2] + in2[0][3];
			out.y = in1.x * in2[1][0] + in1.y * in2[1][1] + in1.z * in2[1][2] + in2[1][3];
			out.z = in1.x * in2[2][0] + in1.y * in2[2][1] + in1.z * in2[2][2] + in2[2][3];
		}
	};



}
