#pragma warning(disable : 5033)
#ifndef DYNAMICXOR_h
#define DYNAMICXOR_h

typedef void (*XorStrFuncTypeDef_RtlZeroMemory)(void *Destination, unsigned __int64 Length);

namespace
{

namespace DynamicXor
{

namespace DynamicXorSeed
{

#define CompilerTimePrefixSize (sizeof("<CompilerTime>") - sizeof('\0'))
#define GetTimeXX(_X_, _Y_) "<CompilerTime>"##_X_##" "##_Y_##"</CompilerTime>"
constexpr char time[] = GetTimeXX(__DATE__, __TIME__);
#pragma warning(disable : 4307)
#define hashseed_1 (static_cast<unsigned int>(time[CompilerTimePrefixSize + 0]))
#define hashseed_2                                                                                                     \
    (static_cast<unsigned int>(hashseed_1 * 0x1003Fui32) + static_cast<unsigned int>(time[CompilerTimePrefixSize + 1]))
#define hashseed_3                                                                                                     \
    (static_cast<unsigned int>(hashseed_2 * 0x1003Fui32) + static_cast<unsigned int>(time[CompilerTimePrefixSize + 2]))
#define hashseed_4                                                                                                     \
    (static_cast<unsigned int>(hashseed_3 * 0x1003Fui32) + static_cast<unsigned int>(time[CompilerTimePrefixSize + 4]))
#define hashseed_5                                                                                                     \
    (static_cast<unsigned int>(hashseed_4 * 0x1003Fui32) + static_cast<unsigned int>(time[CompilerTimePrefixSize + 5]))
#define hashseed_6                                                                                                     \
    (static_cast<unsigned int>(hashseed_5 * 0x1003Fui32) + static_cast<unsigned int>(time[CompilerTimePrefixSize + 7]))
#define hashseed_7                                                                                                     \
    (static_cast<unsigned int>(hashseed_6 * 0x1003Fui32) + static_cast<unsigned int>(time[CompilerTimePrefixSize + 8]))
#define hashseed_8                                                                                                     \
    (static_cast<unsigned int>(hashseed_7 * 0x1003Fui32) + static_cast<unsigned int>(time[CompilerTimePrefixSize + 9]))
#define hashseed_9                                                                                                     \
    (static_cast<unsigned int>(hashseed_8 * 0x1003Fui32) + static_cast<unsigned int>(time[CompilerTimePrefixSize + 10]))
#define hashseed_10                                                                                                    \
    (static_cast<unsigned int>(hashseed_9 * 0x1003Fui32) + static_cast<unsigned int>(time[CompilerTimePrefixSize + 12]))
#define hashseed_11                                                                                                    \
    (static_cast<unsigned int>(hashseed_10 * 0x1003Fui32) +                                                            \
     static_cast<unsigned int>(time[CompilerTimePrefixSize + 13]))
#define hashseed_12                                                                                                    \
    (static_cast<unsigned int>(hashseed_11 * 0x1003Fui32) +                                                            \
     static_cast<unsigned int>(time[CompilerTimePrefixSize + 15]))
#define hashseed_13                                                                                                    \
    (static_cast<unsigned int>(hashseed_12 * 0x1003Fui32) +                                                            \
     static_cast<unsigned int>(time[CompilerTimePrefixSize + 16]))
#define hashseed_14                                                                                                    \
    (static_cast<unsigned int>(hashseed_13 * 0x1003Fui32) +                                                            \
     static_cast<unsigned int>(time[CompilerTimePrefixSize + 18]))
#define hashseed_15                                                                                                    \
    (static_cast<unsigned int>(hashseed_14 * 0x1003Fui32) +                                                            \
     static_cast<unsigned int>(time[CompilerTimePrefixSize + 19]))
constexpr unsigned int hashseed = hashseed_15 + __COUNTER__;
#pragma warning(default : 4307)
constexpr unsigned int seed = (static_cast<unsigned int>(time[CompilerTimePrefixSize + 12 + 7]) +
                               static_cast<unsigned int>(time[CompilerTimePrefixSize + 12 + 6]) * 10 +
                               static_cast<unsigned int>(time[CompilerTimePrefixSize + 12 + 4]) * 60 +
                               static_cast<unsigned int>(time[CompilerTimePrefixSize + 12 + 3]) * 600 +
                               static_cast<unsigned int>(time[CompilerTimePrefixSize + 12 + 1]) * 3600 +
                               static_cast<unsigned int>(time[CompilerTimePrefixSize + 12 + 0]) * 36000) +
                              hashseed;
}

template <unsigned __int64 N> struct RandomGenerator64
{
private:
    static constexpr unsigned __int64 a = 16807;
    static constexpr unsigned __int64 m = 9223372036854775807;
    static constexpr unsigned __int64 s = RandomGenerator64<N - 1>::value;
    static constexpr unsigned __int64 lo = a * (s & 0xFFFFFFFF);
    static constexpr unsigned __int64 hi = a * (s >> 32);
    static constexpr unsigned __int64 lo2 = lo + ((hi & 0x7FFFFFFF) << 32);
    static constexpr unsigned __int64 hi2 = hi >> 31;
    static constexpr unsigned __int64 lo3 = lo2 + hi;

public:
    static constexpr unsigned __int64 max = m;
    static constexpr unsigned __int64 value = lo3 > m ? lo3 - m : lo3;
};

template <> struct RandomGenerator64<0>
{
    static constexpr unsigned __int64 value = static_cast<unsigned __int64>(DynamicXorSeed::hashseed) |
                                              (static_cast<unsigned __int64>(DynamicXorSeed::seed) << 32);
};

template <unsigned __int64 N, unsigned __int64 M> struct RandomRangeUI64
{
    static constexpr auto value = RandomGenerator64<N + 1>::value % M;
};

template <unsigned __int64 N> struct RandomUI16
{
    static const unsigned __int64 value = static_cast<unsigned __int64>(1 + RandomRangeUI64<N, 0xFFFF - 1>::value);
};

template <unsigned __int64 N> struct RandomUI32
{
    static const unsigned __int64 value = static_cast<unsigned __int64>(1 + RandomRangeUI64<N, 0xFFFFFFFF - 1>::value);
};

template <unsigned __int64 N> struct RandomUI64
{
    static const unsigned __int64 value =
        static_cast<unsigned __int64>(1 + RandomRangeUI64<N, 0xFFFFFFFF'FFFFFFFF - 1>::value);
};

template <unsigned short N, unsigned short K> struct Xor_U16
{
private:
    unsigned short _key;
    volatile unsigned short _encrypted;

    constexpr __forceinline unsigned short _Encrypt(unsigned short value) const
    {
        return value ^ _key;
    }

    __forceinline unsigned short _Decrypt(unsigned short value) const
    {
        return value ^ _key;
    }

public:
    constexpr __forceinline Xor_U16(unsigned short OriginalValue, unsigned short unk)
        : _key((unsigned short)RandomUI16<K>::value), _encrypted{_Encrypt(OriginalValue)}
    {
    }

    __forceinline decltype(auto) MacroDecrypt(void)
    {
        return _Decrypt(_encrypted);
    }
};

template <unsigned int N, unsigned int K> struct Xor_U32
{
private:
    unsigned int _key;
    volatile unsigned int _encrypted;

    constexpr __forceinline unsigned int _Encrypt(unsigned int value) const
    {
        return value ^ _key;
    }

    __forceinline unsigned int _Decrypt(unsigned int value) const
    {
        return value ^ _key;
    }

public:
    constexpr __forceinline Xor_U32(unsigned int OriginalValue, unsigned int unk)
        : _key((unsigned int)RandomUI32<K>::value), _encrypted{_Encrypt(OriginalValue)}
    {
        UNREFERENCED_PARAMETER(unk);
    }

    __forceinline decltype(auto) MacroDecrypt(void)
    {
        return _Decrypt(_encrypted);
    }
};

template <unsigned __int64 N, unsigned __int64 K> struct Xor_U64
{
private:
    unsigned __int64 _key;
    volatile unsigned __int64 _encrypted;

    constexpr __forceinline unsigned __int64 _Encrypt(unsigned __int64 value) const
    {
        return value ^ _key;
    }

    __forceinline unsigned __int64 _Decrypt(unsigned __int64 value) const
    {
        return value ^ _key;
    }

public:
    constexpr __forceinline Xor_U64(unsigned __int64 OriginalValue, unsigned __int64 unk)
        : _key(RandomUI64<K>::value), _encrypted{_Encrypt(OriginalValue)}
    {
    }

    __forceinline decltype(auto) MacroDecrypt(void)
    {
        return _Decrypt(_encrypted);
    }
};

#define XorU16(_Value_)                                                                                                \
    (DynamicXor::Xor_U16<sizeof(unsigned short), 0>(static_cast<unsigned short>(_Value_), sizeof(unsigned short))      \
         .MacroDecrypt())
#define XorU32(_Value_)                                                                                                \
    (DynamicXor::Xor_U32<sizeof(unsigned int), 0>(static_cast<unsigned int>(_Value_), sizeof(unsigned int))            \
         .MacroDecrypt())
#define XorU64(_Value_)                                                                                                \
    (DynamicXor::Xor_U64<sizeof(unsigned __int64), 0>(static_cast<unsigned __int64>(_Value_),                          \
                                                      sizeof(unsigned __int64))                                        \
         .MacroDecrypt())
#define Xor16(_Value_) (static_cast<short>(XorU16(static_cast<unsigned short>(_Value_))))
#define Xor32(_Value_) (static_cast<int>(XorU32(static_cast<unsigned int>(_Value_))))
#define Xor64(_Value_) (static_cast<__int64>(XorU64(static_cast<unsigned __int64>(_Value_))))
#define XorP64(_Value_) ((void *)(XorU64(static_cast<unsigned __int64>((unsigned __int64)_Value_))))

template <int... I> struct Indexes
{
    using type = Indexes<I..., sizeof...(I)>;
};

template <int N> struct Make_Indexes
{
    using type = typename Make_Indexes<N - 1>::type::type;
};

template <> struct Make_Indexes<0>
{
    using type = Indexes<>;
};

template <unsigned int N, unsigned int Key, typename Indexes> struct MetaString;

template <unsigned int K, unsigned int... I> struct MetaString<0, K, Indexes<I...>>
{
private:
    volatile unsigned int _buffer[1 + sizeof...(I)];
    constexpr unsigned int __forceinline _Encrypt(unsigned int c) const
    {
        return c ^ K;
    }
    constexpr unsigned int _Decrypt(unsigned int c) const
    {
        return c ^ K;
    }

public:
    constexpr __forceinline MetaString(unsigned int *str) : _buffer{sizeof(_buffer), _Encrypt(str[I])...}
    {
    }
#ifdef _DYNAMIC_XOR_VAR_COMPILE_AS_SHELLCODE_
    __forceinline char *MacroDecryptA()
#else
    inline char *MacroDecryptA()
#endif
    {
        if (sizeof...(I) == 1)
        {
            unsigned int i = 0;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
        }
        else if (sizeof...(I) == 2)
        {
            unsigned int i = 0;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
        }
        else if (sizeof...(I) == 3)
        {
            unsigned int i = 0;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
        }
        else if (sizeof...(I) == 4)
        {
            unsigned int i = 0;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
        }
        else if (sizeof...(I) == 5)
        {
            unsigned int i = 0;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
        }
        else if (sizeof...(I) == 6)
        {
            unsigned int i = 0;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
        }
        else if (sizeof...(I) == 7)
        {
            unsigned int i = 0;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
        }
        else if (sizeof...(I) == 8)
        {
            unsigned int i = 0;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
        }
        else if (sizeof...(I) == 9)
        {
            unsigned int i = 0;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
        }
        else if (sizeof...(I) == 10)
        {
            unsigned int i = 0;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
        }
        else if (sizeof...(I) == 11)
        {
            unsigned int i = 0;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
        }
        else if (sizeof...(I) == 12)
        {
            unsigned int i = 0;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
        }
        else
        {
            for (unsigned int i = 0; i < sizeof...(I); i++)
                _buffer[i + 1] = _Decrypt(_buffer[i + 1]);

        }
        return (char *)(&_buffer[1]);
    }
#ifdef _DYNAMIC_XOR_VAR_COMPILE_AS_SHELLCODE_
    __forceinline wchar_t *MacroDecryptW()
#else
    inline wchar_t *MacroDecryptW()
#endif
    {
        return (wchar_t *)MacroDecryptA();
    }
};

template <unsigned int K, unsigned int... I> struct MetaString<1, K, Indexes<I...>>
{
private:
    volatile unsigned int _buffer[1 + sizeof...(I)];
    constexpr unsigned int __forceinline _Encrypt(unsigned int c) const
    {
        return c + K;
    }
    constexpr unsigned int _Decrypt(unsigned int c) const
    {
        return c - K;
    }

public:
    constexpr __forceinline MetaString(unsigned int *str) : _buffer{sizeof(_buffer), _Encrypt(str[I])...}
    {
    }
#ifdef _DYNAMIC_XOR_VAR_COMPILE_AS_SHELLCODE_
    __forceinline char *MacroDecryptA()
#else
    inline char *MacroDecryptA()
#endif
    {
        if (sizeof...(I) == 1)
        {
            unsigned int i = 0;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
        }
        else if (sizeof...(I) == 2)
        {
            unsigned int i = 0;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
        }
        else if (sizeof...(I) == 3)
        {
            unsigned int i = 0;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
        }
        else if (sizeof...(I) == 4)
        {
            unsigned int i = 0;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
        }
        else if (sizeof...(I) == 5)
        {
            unsigned int i = 0;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
        }
        else if (sizeof...(I) == 6)
        {
            unsigned int i = 0;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
        }
        else if (sizeof...(I) == 7)
        {
            unsigned int i = 0;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
        }
        else if (sizeof...(I) == 8)
        {
            unsigned int i = 0;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
        }
        else if (sizeof...(I) == 9)
        {
            unsigned int i = 0;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
        }
        else if (sizeof...(I) == 10)
        {
            unsigned int i = 0;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
        }
        else if (sizeof...(I) == 11)
        {
            unsigned int i = 0;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
        }
        else if (sizeof...(I) == 12)
        {
            unsigned int i = 0;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
            i++;
            _buffer[i + 1] = _Decrypt(_buffer[i + 1]);
        }
        else
        {
            for (unsigned int i = 0; i < sizeof...(I); i++)
                _buffer[i + 1] = _Decrypt(_buffer[i + 1]);

        }
        return (char *)(&_buffer[1]);
    }
#ifdef _DYNAMIC_XOR_VAR_COMPILE_AS_SHELLCODE_
    __forceinline wchar_t *MacroDecryptW()
#else
    inline wchar_t *MacroDecryptW()
#endif
    {
        return (wchar_t *)MacroDecryptA();
    }
};

#ifndef __INTELLISENSE__
#define _XorStr(str)                                                                                                   \
    DynamicXor::MetaString<                                                                                            \
        (DynamicXor::RandomUI32<__COUNTER__>::value % 2 == 0) ? 0 : 1, DynamicXor::RandomUI32<__COUNTER__>::value,     \
        DynamicXor::Make_Indexes<((sizeof(str) - 4) % 4) == 0 ? ((sizeof(str) - 4) / 4) : (sizeof(str) / 4)>::type>(   \
        (unsigned int *)(str))

#define XorStrA(str) (_XorStr(str##"\0\0\0\0").MacroDecryptA())
#define XorStrW(str) (_XorStr(str##"\0\0").MacroDecryptW())
#else
#define _XorStr(str)                                                                                                   \
    DynamicXor::MetaString<                                                                                            \
        (DynamicXor::RandomUI32<0>::value % 2 == 0) ? 0 : 1, DynamicXor::RandomUI32<0>::value,                         \
        DynamicXor::Make_Indexes<((sizeof(str) - 4) % 4) == 0 ? ((sizeof(str) - 4) / 4) : (sizeof(str) / 4)>::type>(   \
        (unsigned int *)(str))

#define XorStrA(str) (PCHAR) str
#define XorStrW(str) (PWCHAR) str
#endif

#define XorStrBufferSize(str)                                                                                          \
    (DrvPrint("[Dbg] [%s] BufferSize[%u] \r\n", __FUNCTION__,                                                          \
              *(unsigned int *)((unsigned char *)str - sizeof(unsigned int))))
#define XorStrClean(str)                                                                                               \
    (RtlZeroMemory(str, *(unsigned int *)((unsigned char *)str - sizeof(unsigned int)) - sizeof(unsigned int)))
#define XorStrClean_RtlZeroMemory(fnRtlZeroMemory, str)                                                                \
    (((XorStrFuncTypeDef_RtlZeroMemory)fnRtlZeroMemory)(                                                               \
        str, *(unsigned int *)((unsigned char *)str - sizeof(unsigned int)) - sizeof(unsigned int)))

}
}

#ifndef KI_USER_SHARED_DATA
#define KI_USER_SHARED_DATA 0xFFFFF78000000000UI64
#define SharedInterruptTime (KI_USER_SHARED_DATA + 0x8)
#define SharedSystemTime (KI_USER_SHARED_DATA + 0x14)
#define SharedTickCount (KI_USER_SHARED_DATA + 0x320)
#endif

#ifndef USER_SHARED_DATA
#define USER_SHARED_DATA 0x7FFE0000UI64
#define USER_SHARED_DATA_InterruptTime_LowPart (USER_SHARED_DATA + 0x8)
#define USER_SHARED_DATA_SystemTime_LowPart (USER_SHARED_DATA + 0x14)
#define SER_SHARED_DATA_SharedTickCount_LowPart (USER_SHARED_DATA + 0x320)
#endif

extern "C" unsigned __int64 __rdtsc(void);
#pragma intrinsic(__rdtsc)

extern "C" long _InterlockedCompareExchange(long volatile *Destination, long ExChange, long Comperand);
#pragma intrinsic(_InterlockedCompareExchange)

extern "C" __int64 _InterlockedCompareExchange64(__int64 volatile *Destination, __int64 ExChange, __int64 Comperand);
#pragma intrinsic(_InterlockedCompareExchange64)

__forceinline unsigned int DynamicXorVarRol32(unsigned int x, int i)
{
    int BitSize = Xor32(31);
    return (x << static_cast<unsigned int>(i & BitSize)) |
           (x >> static_cast<unsigned int>(((BitSize + 1) - (i & BitSize)) & BitSize));
}

__forceinline unsigned int DynamicXorVarRor32(unsigned int x, int i)
{
    int BitSize = Xor32(31);
    return (x >> static_cast<unsigned int>(i & BitSize)) |
           (x << static_cast<unsigned int>(((BitSize + 1) - (i & BitSize)) & BitSize));
}

__forceinline unsigned __int64 DynamicXorVarRol64(unsigned __int64 x, int i)
{
    int BitSize = Xor32(63);
    return (x << static_cast<unsigned __int64>(i & BitSize)) |
           (x >> static_cast<unsigned __int64>(((BitSize + 1) - (i & BitSize)) & BitSize));
}

__forceinline unsigned __int64 DynamicXorVarRor64(unsigned __int64 x, int i)
{
    int BitSize = Xor32(63);
    return (x >> static_cast<unsigned __int64>(i & BitSize)) |
           (x << static_cast<unsigned __int64>(((BitSize + 1) - (i & BitSize)) & BitSize));
}

typedef struct _S_GLOBAL_DYNAMIC_XOR
{
    unsigned int EncryptedVarU32XorKey;
    unsigned __int64 EncryptedVarU64XorKey;
} S_GLOBAL_DYNAMIC_XOR, *PS_GLOBAL_DYNAMIC_XOR;

extern S_GLOBAL_DYNAMIC_XOR g_SGlobalDynamicXor;
#define DefineSGlobalDynamicXor                                                                                        \
    volatile PS_GLOBAL_DYNAMIC_XOR __SGlobalDynamicXor = &g_SGlobalDynamicXor;                                         \
    PS_GLOBAL_DYNAMIC_XOR _SGlobalDynamicXor = __SGlobalDynamicXor;
#define gSGlobalDynamicXor _SGlobalDynamicXor[0]

#if defined(_DYNAMIC_XOR_VAR_USER_)
#define DynamicXorVarSystem (*((volatile unsigned __int64 *)(XorU64(USER_SHARED_DATA_SystemTime_LowPart))))
#define DynamicXorVarUser                                                                                              \
    (*((volatile unsigned int *)(XorU64(USER_SHARED_DATA_InterruptTime_LowPart))) *                                    \
     *((volatile unsigned int *)(XorU64(USER_SHARED_DATA_SystemTime_LowPart))))
#elif defined(_DYNAMIC_XOR_VAR_KERNEL_)
#define DynamicXorVarSystem (*((volatile unsigned __int64 *)(XorU64(SharedSystemTime))))
#define DynamicXorVarKernel                                                                                            \
    (*((volatile unsigned int *)(XorU64(SharedInterruptTime))) * *((volatile unsigned int *)(XorU64(SharedSystemTime))))
#endif

#ifdef _DYNAMIC_XOR_VAR_RORL_
#define _Rol32(_X_, _Y_) (DynamicXorVarRol32(_X_, _Y_))
#define _Ror32(_X_, _Y_) (DynamicXorVarRor32(_X_, _Y_))
#define _Rol64(_X_, _Y_) (DynamicXorVarRol64(_X_, _Y_))
#define _Ror64(_X_, _Y_) (DynamicXorVarRor64(_X_, _Y_))
#else
#define _Rol32(_X_, _Y_) (_X_)
#define _Ror32(_X_, _Y_) (_X_)
#define _Rol64(_X_, _Y_) (_X_)
#define _Ror64(_X_, _Y_) (_X_)
#endif

#ifdef _DYNAMIC_XOR_VAR_BYTE_SWAP_
#define _BYTE_SWAP_U32(_X_) (_byteswap_ulong(_X_))
#define _BYTE_SWAP_U64(_X_) (_byteswap_uint64(_X_))
#else
#define _BYTE_SWAP_U32(_X_) (_X_)
#define _BYTE_SWAP_U64(_X_) (_X_)
#endif

struct _EncryptedU32
{
private:
    unsigned int _key;
    unsigned char _rorlkey;
    unsigned int _encrypted;

#ifdef _DYNAMIC_XOR_VAR_DEBUG_MONITOR_MODE_
    __forceinline unsigned int _Encrypt(volatile unsigned int value)
    {
        return value;
    }
    __forceinline unsigned int _Decrypt(volatile unsigned int value)
    {
        return value;
    }
#else
    __forceinline unsigned int _Encrypt(volatile unsigned int value)
    {
#ifdef _DYNAMIC_XOR_VAR_RDTSC_
        unsigned __int64 rdtsc = __rdtsc();
        _InterlockedCompareExchange((volatile long *)&this->_key, (unsigned int)(rdtsc * rdtsc), 0);
#elif defined(_DYNAMIC_XOR_VAR_USER_)
        _InterlockedCompareExchange((volatile long *)&this->_key, (unsigned int)(DynamicXorVarUser), 0);
#elif defined(_DYNAMIC_XOR_VAR_KERNEL_)
        _InterlockedCompareExchange((volatile long *)&this->_key, (unsigned int)(DynamicXorVarKernel), 0);
#else
        DefineSGlobalDynamicXor;
        _InterlockedCompareExchange((volatile long *)&this->_key,
                                    (unsigned int)(gSGlobalDynamicXor.EncryptedVarU32XorKey), 0);
#endif
#ifdef _DYNAMIC_XOR_VAR_RORL_
        this->_rorlkey = (this->_key | 1ui32) & XorU32(31);
#endif
        register unsigned int valuetemp = (value ^ this->_key);
        return _Ror32(_BYTE_SWAP_U32(value == this->_key ? 0 : valuetemp), this->_rorlkey);
    }
    __forceinline unsigned int _Decrypt(volatile unsigned int value)
    {
        unsigned int _decrypted = _BYTE_SWAP_U32(_Rol32(value, this->_rorlkey)) ^ this->_key;
        return _decrypted;
    }
#endif

public:
    __forceinline _EncryptedU32()
    {
        this->_encrypted = _Encrypt(0);
    }
    __forceinline _EncryptedU32(int Value)
    {
        this->_encrypted = _Encrypt(Value);
    }
    __forceinline _EncryptedU32(unsigned int Value)
    {
        this->_encrypted = _Encrypt(Value);
    }
    __forceinline _EncryptedU32(unsigned long Value)
    {
        this->_encrypted = _Encrypt(Value);
    }
    __forceinline unsigned int v()
    {
        return _Decrypt(this->_encrypted);
    }
    __forceinline unsigned int in_v()
    {
        return _Decrypt(this->_encrypted);
    }
    __forceinline void c()
    {
        this->_encrypted = _Encrypt(0);
    }
    __forceinline _EncryptedU32 &operator=(unsigned int Value)
    {
        this->_encrypted = _Encrypt(Value);
        return *this;
    }
    __forceinline _EncryptedU32 &operator=(_EncryptedU32 &Value)
    {
        this->_encrypted = _Encrypt(Value.v());
        return *this;
    }
    __forceinline unsigned int operator+(int Value)
    {
        return this->v() + Value;
    }
    __forceinline unsigned int operator+(unsigned int Value)
    {
        return this->v() + Value;
    }
    __forceinline unsigned int operator+(unsigned long Value)
    {
        return this->v() + Value;
    }
    __forceinline unsigned int operator+(_EncryptedU32 &Value)
    {
        return this->v() + Value.v();
    }
    __forceinline unsigned int operator-(int Value)
    {
        return this->v() - Value;
    }
    __forceinline unsigned int operator-(unsigned int Value)
    {
        return this->v() - Value;
    }
    __forceinline unsigned int operator-(unsigned long Value)
    {
        return this->v() - Value;
    }
    __forceinline unsigned int operator-(_EncryptedU32 &Value)
    {
        return this->v() - Value.v();
    }
};
typedef _EncryptedU32 EncryptedU32, *PEncryptedU32;

struct _Encrypted32
{
private:
    unsigned int _key;
    unsigned char _rorlkey;
    int _encrypted;

#ifdef _DYNAMIC_XOR_VAR_DEBUG_MONITOR_MODE_
    __forceinline int _Encrypt(volatile int value)
    {
        return value;
    }
    __forceinline int _Decrypt(volatile int value)
    {
        return value;
    }
#else
    __forceinline int _Encrypt(volatile int value)
    {
#ifdef _DYNAMIC_XOR_VAR_RDTSC_
        unsigned __int64 rdtsc = __rdtsc();
        _InterlockedCompareExchange((volatile long *)&this->_key, (unsigned int)(rdtsc * rdtsc), 0);
#elif defined(_DYNAMIC_XOR_VAR_USER_)
        _InterlockedCompareExchange((volatile long *)&this->_key, (unsigned int)(DynamicXorVarUser), 0);
#elif defined(_DYNAMIC_XOR_VAR_KERNEL_)
        _InterlockedCompareExchange((volatile long *)&this->_key, (unsigned int)(DynamicXorVarKernel), 0);
#else
        DefineSGlobalDynamicXor;
        _InterlockedCompareExchange((volatile long *)&this->_key,
                                    (unsigned int)(gSGlobalDynamicXor.EncryptedVarU32XorKey), 0);
#endif
#ifdef _DYNAMIC_XOR_VAR_RORL_
        this->_rorlkey = (this->_key | 1ui32) & XorU32(31);
#endif
        register int valuetemp = (value ^ this->_key);
        return (int)(_Ror32(_BYTE_SWAP_U32((unsigned int)value == this->_key ? 0 : valuetemp), this->_rorlkey));
    }
    __forceinline int _Decrypt(volatile int value)
    {
        unsigned int _decrypted = _BYTE_SWAP_U32(_Rol32((unsigned int)value, this->_rorlkey)) ^ this->_key;
        return (int)(_decrypted);
    }
#endif

public:
    _Encrypted32()
    {
        this->_encrypted = _Encrypt(0);
    }
    __forceinline _Encrypted32(int Value)
    {
        this->_encrypted = _Encrypt(Value);
    }
    __forceinline _Encrypted32(unsigned int Value)
    {
        this->_encrypted = _Encrypt((int)Value);
    }
    __forceinline _Encrypted32(unsigned long Value)
    {
        this->_encrypted = _Encrypt((int)Value);
    }
    __forceinline int v()
    {
        return _Decrypt(this->_encrypted);
    }
    __forceinline int in_v()
    {
        return _Decrypt(this->_encrypted);
    }
    __forceinline void c()
    {
        this->_encrypted = _Encrypt(0);
    }
    __forceinline _Encrypted32 &operator=(int Value)
    {
        this->_encrypted = _Encrypt(Value);
        return *this;
    }
    __forceinline _Encrypted32 &operator=(_Encrypted32 &Value)
    {
        this->_encrypted = _Encrypt(Value.v());
        return *this;
    }
    __forceinline int operator+(int Value)
    {
        return this->v() + Value;
    }
    __forceinline int operator+(_Encrypted32 &Value)
    {
        return this->v() + Value.v();
    }
    __forceinline int operator-(int Value)
    {
        return this->v() - Value;
    }
    __forceinline int operator-(_Encrypted32 &Value)
    {
        return this->v() - Value.v();
    }
};
typedef _Encrypted32 Encrypted32, *PEncrypted32;

struct _EncryptedU64
{
private:
    unsigned __int64 _key;
    unsigned char _rorlkey;
    unsigned __int64 _encrypted;

#ifdef _DYNAMIC_XOR_VAR_DEBUG_MONITOR_MODE_
    __forceinline unsigned __int64 _Encrypt(volatile unsigned __int64 value)
    {
        return value;
    }
    __forceinline unsigned __int64 _Decrypt(volatile unsigned __int64 value)
    {
        return value;
    }
#else
    __forceinline unsigned __int64 _Encrypt(volatile unsigned __int64 value)
    {
#ifdef _DYNAMIC_XOR_VAR_RDTSC_
        unsigned __int64 rdtsc = __rdtsc();
        _InterlockedCompareExchange64((volatile __int64 *)&this->_key, rdtsc * rdtsc, 0);
#elif defined(_DYNAMIC_XOR_VAR_USER_)
        _InterlockedCompareExchange64((volatile __int64 *)&this->_key, DynamicXorVarUser, 0);
#elif defined(_DYNAMIC_XOR_VAR_KERNEL_)
        _InterlockedCompareExchange64((volatile __int64 *)&this->_key, DynamicXorVarKernel, 0);
#else
        DefineSGlobalDynamicXor;
        _InterlockedCompareExchange64((volatile __int64 *)&this->_key, gSGlobalDynamicXor.EncryptedVarU64XorKey, 0);
#endif
#ifdef _DYNAMIC_XOR_VAR_RORL_
        this->_rorlkey = (unsigned char)((this->_key | 1ui32) & XorU32(63));
#endif
        register unsigned __int64 valuetemp = (value ^ this->_key);
        return _Ror64(_BYTE_SWAP_U64(value == this->_key ? 0 : valuetemp), this->_rorlkey);
    }
    __forceinline unsigned __int64 _Decrypt(volatile unsigned __int64 value)
    {
        unsigned __int64 _decrypted = _BYTE_SWAP_U64(_Rol64(value, this->_rorlkey)) ^ this->_key;
        return _decrypted;
    }
#endif

public:
    _EncryptedU64()
    {
        this->_encrypted = _Encrypt(0);
    }
    __forceinline _EncryptedU64(int Value)
    {
        this->_encrypted = _Encrypt((unsigned __int64)(unsigned int)Value);
    }
    __forceinline _EncryptedU64(unsigned int Value)
    {
        this->_encrypted = _Encrypt((unsigned __int64)Value);
    }
    __forceinline _EncryptedU64(unsigned __int64 Value)
    {
        this->_encrypted = _Encrypt(Value);
    }
    __forceinline unsigned __int64 v()
    {
        return _Decrypt(this->_encrypted);
    }
    __forceinline unsigned __int64 in_v()
    {
        return _Decrypt(this->_encrypted);
    }
    __forceinline void c()
    {
        this->_encrypted = _Encrypt(0);
    }
    __forceinline _EncryptedU64 &operator=(unsigned __int64 Value)
    {
        this->_encrypted = _Encrypt(Value);
        return *this;
    }
    __forceinline _EncryptedU64 &operator=(_EncryptedU64 &Value)
    {
        this->_encrypted = _Encrypt(Value.v());
        return *this;
    }
    __forceinline unsigned __int64 operator+(int Value)
    {
        return this->v() + Value;
    }
    __forceinline unsigned __int64 operator+(unsigned __int64 Value)
    {
        return this->v() + Value;
    }
    __forceinline unsigned __int64 operator+(_EncryptedU64 &Value)
    {
        return this->v() + Value.v();
    }
    __forceinline unsigned __int64 operator-(unsigned __int64 Value)
    {
        return this->v() - Value;
    }
    __forceinline unsigned __int64 operator-(_EncryptedU64 &Value)
    {
        return this->v() - Value.v();
    }
    __forceinline operator unsigned __int64()
    {
        return this->v();
    }
};
typedef _EncryptedU64 EncryptedU64, *PEncryptedU64;

struct _EncryptedPU8
{
private:
    unsigned __int64 _key;
    unsigned char _rorlkey;
    unsigned __int64 _encrypted;

#ifdef _DYNAMIC_XOR_VAR_DEBUG_MONITOR_MODE_
    __forceinline unsigned __int64 _Encrypt(volatile unsigned __int64 value)
    {
        return value;
    }
    __forceinline unsigned __int64 _Decrypt(volatile unsigned __int64 value)
    {
        return value;
    }
#else
    __forceinline unsigned __int64 _Encrypt(volatile unsigned __int64 value)
    {
#ifdef _DYNAMIC_XOR_VAR_RDTSC_
        unsigned __int64 rdtsc = __rdtsc();
        _InterlockedCompareExchange64((volatile __int64 *)&this->_key, rdtsc * rdtsc, 0);
#elif defined(_DYNAMIC_XOR_VAR_USER_)
        _InterlockedCompareExchange64((volatile __int64 *)&this->_key, DynamicXorVarUser, 0);
#elif defined(_DYNAMIC_XOR_VAR_KERNEL_)
        _InterlockedCompareExchange64((volatile __int64 *)&this->_key, DynamicXorVarKernel, 0);
#else
        DefineSGlobalDynamicXor;
        _InterlockedCompareExchange64((volatile __int64 *)&this->_key, gSGlobalDynamicXor.EncryptedVarU64XorKey, 0);
#endif
#ifdef _DYNAMIC_XOR_VAR_RORL_
        this->_rorlkey = (unsigned char)((this->_key | 1ui64) & XorU32(63));
#endif
        register unsigned __int64 valuetemp = (value ^ this->_key);
        return _Ror64(_BYTE_SWAP_U64(value == this->_key ? 0 : valuetemp), this->_rorlkey);
    }
    __forceinline unsigned __int64 _Decrypt(volatile unsigned __int64 value)
    {
        unsigned __int64 _decrypted = _BYTE_SWAP_U64(_Rol64(value, this->_rorlkey)) ^ this->_key;
        return _decrypted;
    }
#endif

public:
    _EncryptedPU8()
    {
        this->_encrypted = _Encrypt(0);
    }
    __forceinline _EncryptedPU8(int Value)
    {
        this->_encrypted = _Decrypt((unsigned __int64)(unsigned int)Value);
    }
    __forceinline _EncryptedPU8(unsigned int Value)
    {
        this->_encrypted = _Encrypt((unsigned __int64)Value);
    }
    __forceinline _EncryptedPU8(unsigned __int64 Value)
    {
        this->_encrypted = _Encrypt(Value);
    }
    __forceinline unsigned char *v()
    {
        return (unsigned char *)_Decrypt(this->_encrypted);
    }
    __forceinline unsigned char *in_v()
    {
        return (unsigned char *)_Decrypt(this->_encrypted);
    }
    __forceinline void c()
    {
        this->_encrypted = _Encrypt(0);
    }
    __forceinline _EncryptedPU8 &operator=(unsigned char *Value)
    {
        this->_encrypted = _Encrypt((unsigned __int64)Value);
        return *this;
    }
    __forceinline _EncryptedPU8 &operator=(_EncryptedPU8 &Value)
    {
        this->_encrypted = _Encrypt((unsigned __int64)Value.v());
        return *this;
    }
    __forceinline unsigned char *operator+(unsigned char Value)
    {
        return this->v() + Value;
    }
    __forceinline unsigned char *operator+(unsigned int Value)
    {
        return this->v() + Value;
    }
    __forceinline unsigned char *operator+(unsigned long Value)
    {
        return this->v() + Value;
    }
    __forceinline unsigned char *operator+(unsigned __int64 Value)
    {
        return this->v() + Value;
    }
    __forceinline unsigned char *operator+(char Value)
    {
        return this->v() + Value;
    }
    __forceinline unsigned char *operator+(int Value)
    {
        return this->v() + Value;
    }
    __forceinline unsigned char *operator+(long Value)
    {
        return this->v() + Value;
    }
    __forceinline unsigned char *operator+(__int64 Value)
    {
        return this->v() + Value;
    }
    __forceinline operator unsigned char *()
    {
        return this->v();
    }
    __forceinline operator void *()
    {
        return (void *)this->v();
    }
    __forceinline operator unsigned __int64()
    {
        return (unsigned __int64)this->v();
    }
};
typedef _EncryptedPU8 EncryptedPU8, *PEncryptedPU8;

struct _EncryptedPU32
{
private:
    unsigned __int64 _key;
    unsigned char _rorlkey;
    unsigned __int64 _encrypted;

#ifdef _DYNAMIC_XOR_VAR_DEBUG_MONITOR_MODE_
    __forceinline unsigned __int64 _Encrypt(volatile unsigned __int64 value)
    {
        return value;
    }
    __forceinline unsigned __int64 _Decrypt(volatile unsigned __int64 value)
    {
        return value;
    }
#else
    __forceinline unsigned __int64 _Encrypt(volatile unsigned __int64 value)
    {
#ifdef _DYNAMIC_XOR_VAR_RDTSC_
        unsigned __int64 rdtsc = __rdtsc();
        _InterlockedCompareExchange64((volatile __int64 *)&this->_key, rdtsc * rdtsc, 0);
#elif defined(_DYNAMIC_XOR_VAR_USER_)
        _InterlockedCompareExchange64((volatile __int64 *)&this->_key, DynamicXorVarUser, 0);
#elif defined(_DYNAMIC_XOR_VAR_KERNEL_)
        _InterlockedCompareExchange64((volatile __int64 *)&this->_key, DynamicXorVarKernel, 0);
#else
        DefineSGlobalDynamicXor;
        _InterlockedCompareExchange64((volatile __int64 *)&this->_key, gSGlobalDynamicXor.EncryptedVarU64XorKey, 0);
#endif
#ifdef _DYNAMIC_XOR_VAR_RORL_
        this->_rorlkey = (unsigned char)((this->_key | 1ui64) & XorU32(63));
#endif
        register unsigned __int64 valuetemp = (value ^ this->_key);
        return _Ror64(_BYTE_SWAP_U64(value == this->_key ? 0 : valuetemp), this->_rorlkey);
    }
    __forceinline unsigned __int64 _Decrypt(volatile unsigned __int64 value)
    {
        unsigned __int64 _decrypted = _BYTE_SWAP_U64(_Rol64(value, this->_rorlkey)) ^ this->_key;
        return _decrypted;
    }
#endif

public:
    _EncryptedPU32()
    {
        this->_encrypted = _Encrypt(0);
    }
    __forceinline _EncryptedPU32(int Value)
    {
        this->_encrypted = _Encrypt((unsigned __int64)(unsigned int)Value);
    }
    __forceinline _EncryptedPU32(unsigned int Value)
    {
        this->_encrypted = _Encrypt((unsigned __int64)Value);
    }
    __forceinline _EncryptedPU32(unsigned __int64 Value)
    {
        this->_encrypted = _Encrypt(Value);
    }
    __forceinline unsigned int *v()
    {
        return (unsigned int *)_Decrypt(this->_encrypted);
    }
    __forceinline unsigned int *in_v()
    {
        return (unsigned int *)_Decrypt(this->_encrypted);
    }
    __forceinline void c()
    {
        this->_encrypted = _Encrypt(0);
    }
    __forceinline _EncryptedPU32 &operator=(unsigned int *Value)
    {
        this->_encrypted = _Encrypt((unsigned __int64)Value);
        return *this;
    }
    __forceinline _EncryptedPU32 &operator=(unsigned long *Value)
    {
        this->_encrypted = _Encrypt((unsigned __int64)Value);
        return *this;
    }
    __forceinline _EncryptedPU32 &operator=(_EncryptedPU32 &Value)
    {
        this->_encrypted = _Encrypt((unsigned __int64)Value.v());
        return *this;
    }
    __forceinline unsigned int *operator+(unsigned int Value)
    {
        return this->v() + Value;
    }
    __forceinline unsigned int *operator+(unsigned __int64 Value)
    {
        return this->v() + Value;
    }
};
typedef _EncryptedPU32 EncryptedPU32, *PEncryptedPU32;

struct _EncryptedPU64
{
private:
    unsigned __int64 _key;
    unsigned char _rorlkey;
    unsigned __int64 _encrypted;

#ifdef _DYNAMIC_XOR_VAR_DEBUG_MONITOR_MODE_
    __forceinline unsigned __int64 _Encrypt(volatile unsigned __int64 value)
    {
        return value;
    }
    __forceinline unsigned __int64 _Decrypt(volatile unsigned __int64 value)
    {
        return value;
    }
#else
    __forceinline unsigned __int64 _Encrypt(volatile unsigned __int64 value)
    {
#ifdef _DYNAMIC_XOR_VAR_RDTSC_
        unsigned __int64 rdtsc = __rdtsc();
        _InterlockedCompareExchange64((volatile __int64 *)&this->_key, rdtsc * rdtsc, 0);
#elif defined(_DYNAMIC_XOR_VAR_USER_)
        _InterlockedCompareExchange64((volatile __int64 *)&this->_key, DynamicXorVarUser, 0);
#elif defined(_DYNAMIC_XOR_VAR_KERNEL_)
        _InterlockedCompareExchange64((volatile __int64 *)&this->_key, DynamicXorVarKernel, 0);
#else
        DefineSGlobalDynamicXor;
        _InterlockedCompareExchange64((volatile __int64 *)&this->_key, gSGlobalDynamicXor.EncryptedVarU64XorKey, 0);
#endif
#ifdef _DYNAMIC_XOR_VAR_RORL_
        this->_rorlkey = (unsigned char)((this->_key | 1ui64) & XorU32(63));
#endif
        register unsigned __int64 valuetemp = (value ^ this->_key);
        return _Ror64(_BYTE_SWAP_U64(value == this->_key ? 0 : valuetemp), this->_rorlkey);
    }
    __forceinline unsigned __int64 _Decrypt(volatile unsigned __int64 value)
    {
        unsigned __int64 _decrypted = _BYTE_SWAP_U64(_Rol64(value, this->_rorlkey)) ^ this->_key;
        return _decrypted;
    }
#endif

public:
    _EncryptedPU64()
    {
        this->_encrypted = _Encrypt(0);
    }
    __forceinline _EncryptedPU64(int Value)
    {
        this->_encrypted = _Encrypt((unsigned __int64)(unsigned int)Value);
    }
    __forceinline _EncryptedPU64(unsigned int Value)
    {
        this->_encrypted = _Encrypt((unsigned __int64)Value);
    }
    __forceinline _EncryptedPU64(unsigned __int64 Value)
    {
        this->_encrypted = _Encrypt(Value);
    }
    __forceinline unsigned __int64 *v()
    {
        return (unsigned __int64 *)_Decrypt(this->_encrypted);
    }
    __forceinline unsigned __int64 *in_v()
    {
        return (unsigned __int64 *)_Decrypt(this->_encrypted);
    }
    __forceinline void c()
    {
        this->_encrypted = _Encrypt(0);
    }
    __forceinline _EncryptedPU64 &operator=(unsigned __int64 *Value)
    {
        this->_encrypted = _Encrypt((unsigned __int64)Value);
        return *this;
    }
    __forceinline _EncryptedPU64 &operator=(_EncryptedPU64 &Value)
    {
        this->_encrypted = _Encrypt((unsigned __int64)Value.v());
        return *this;
    }
    __forceinline unsigned __int64 *operator+(unsigned int Value)
    {
        return this->v() + Value;
    }
    __forceinline unsigned __int64 *operator+(unsigned __int64 Value)
    {
        return this->v() + Value;
    }
};
typedef _EncryptedPU64 EncryptedPU64, *PEncryptedPU64;

struct _EncryptedFLOAT
{
private:
    unsigned int _key;
    unsigned char _rorlkey;
    unsigned int _encrypted;

#ifdef _DYNAMIC_XOR_VAR_DEBUG_MONITOR_MODE_
    __forceinline unsigned int _Encrypt(volatile unsigned int value)
    {
        return value;
    }
    __forceinline unsigned int _Decrypt(volatile unsigned int value)
    {
        return value;
    }
#else
    __forceinline unsigned int _Encrypt(volatile unsigned int value)
    {
#ifdef _DYNAMIC_XOR_VAR_RDTSC_
        unsigned __int64 rdtsc = __rdtsc();
        _InterlockedCompareExchange((volatile long *)&this->_key, (unsigned int)(rdtsc * rdtsc), 0);
#elif defined(_DYNAMIC_XOR_VAR_USER_)
        _InterlockedCompareExchange((volatile long *)&this->_key, (unsigned int)(DynamicXorVarUser), 0);
#elif defined(_DYNAMIC_XOR_VAR_KERNEL_)
        _InterlockedCompareExchange((volatile long *)&this->_key, (unsigned int)(DynamicXorVarKernel), 0);
#else
        DefineSGlobalDynamicXor;
        _InterlockedCompareExchange((volatile long *)&this->_key,
                                    (unsigned int)(gSGlobalDynamicXor.EncryptedVarU32XorKey), 0);
#endif
#ifdef _DYNAMIC_XOR_VAR_RORL_
        this->_rorlkey = (unsigned char)((this->_key | 1ui32) & XorU32(31));
#endif
        register unsigned int valuetemp = (value ^ this->_key);
        return _Ror32(_BYTE_SWAP_U32(value == this->_key ? 0 : valuetemp), this->_rorlkey);
    }
    __forceinline unsigned int _Decrypt(volatile unsigned int value)
    {
        unsigned int _decrypted = _BYTE_SWAP_U32(_Rol32(value, this->_rorlkey)) ^ this->_key;
        return _decrypted;
    }
#endif

    __forceinline unsigned int uv()
    {
        return _Decrypt(this->_encrypted);
    }

public:
    _EncryptedFLOAT()
    {
        this->_encrypted = _Encrypt(0);
    }
    __forceinline _EncryptedFLOAT(int Value)
    {
        this->_encrypted = _Encrypt((unsigned int)Value);
    }
    __forceinline _EncryptedFLOAT(unsigned int Value)
    {
        this->_encrypted = _Encrypt(Value);
    }
    __forceinline float v()
    {
        volatile unsigned int f = 0;
        f = _Decrypt(this->_encrypted);
        return *(float *)&f;
    }
    __forceinline float in_v()
    {
        volatile unsigned int f = 0;
        f = _Decrypt(this->_encrypted);
        return *(float *)&f;
    }
    __forceinline void c()
    {
        this->_encrypted = _Encrypt(0);
    }
    __forceinline _EncryptedFLOAT &operator=(unsigned int Value)
    {
        this->_encrypted = _Encrypt(Value);
        return *this;
    }
    __forceinline _EncryptedFLOAT &operator=(float Value)
    {
        this->_encrypted = _Encrypt(*(unsigned int *)&Value);
        return *this;
    }
    __forceinline _EncryptedFLOAT &operator=(_EncryptedFLOAT &Value)
    {
        this->_encrypted = _Encrypt(Value.uv());
        return *this;
    }
    __forceinline float operator+(float Value)
    {
        return this->v() + Value;
    }
    __forceinline float operator+(_EncryptedFLOAT &Value)
    {
        return this->v() + Value.v();
    }
    __forceinline float operator-(float Value)
    {
        return this->v() - Value;
    }
    __forceinline float operator-(_EncryptedFLOAT &Value)
    {
        return this->v() - Value.v();
    }
    __forceinline float operator*(float Value)
    {
        return this->v() * Value;
    }
    __forceinline float operator*(_EncryptedFLOAT &Value)
    {
        return this->v() * Value.v();
    }
    __forceinline float operator/(float Value)
    {
        return this->v() / Value;
    }
    __forceinline float operator/(_EncryptedFLOAT &Value)
    {
        return this->v() / Value.v();
    }
    __forceinline operator float()
    {
        return this->v();
    }
};
typedef _EncryptedFLOAT EncryptedFLOAT, *PEncryptedFLOAT;

__forceinline static float operator+(float a, _EncryptedFLOAT &b)
{
    return a + b.v();
}
__forceinline static float operator-(float a, _EncryptedFLOAT &b)
{
    return a - b.v();
}
__forceinline static float operator+=(float a, _EncryptedFLOAT &b)
{
    return a + b.v();
}
__forceinline static float operator-=(float a, _EncryptedFLOAT &b)
{
    return a - b.v();
}
__forceinline static float operator/(float a, _EncryptedFLOAT &b)
{
    return a / b.v();
}
__forceinline static bool operator>(float a, _EncryptedFLOAT &b)
{
    return a > b.v();
}
__forceinline static unsigned char *operator+(unsigned char *a, _EncryptedU64 &b)
{
    return a + b.v();
}
__forceinline static unsigned char *operator+(_EncryptedPU8 &a, _EncryptedU64 &b)
{
    return a.v() + b.v();
}
__forceinline static unsigned __int64 operator-(_EncryptedPU8 &a, _EncryptedPU8 &b)
{
    return a.v() - b.v();
}

#endif

#pragma warning(default : 5033)
