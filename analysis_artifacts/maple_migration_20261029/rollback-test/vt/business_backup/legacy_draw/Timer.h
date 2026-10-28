#pragma once

extern "C" {
    NTSYSAPI VOID NTAPI RtlQueryPerformanceCounter(PLARGE_INTEGER PerformanceCounter OPTIONAL, PLARGE_INTEGER PerformanceFrequency OPTIONAL);
}

struct TimerTick {
    LARGE_INTEGER startTick;
    LARGE_INTEGER freq;
};

inline void TimerStart(TimerTick& timer) {
    RtlQueryPerformanceCounter(&timer.startTick, &timer.freq);
}

inline unsigned long TimerElapsedMs(const TimerTick& timer) {
    LARGE_INTEGER now;
    RtlQueryPerformanceCounter(&now, nullptr);
    LONGLONG delta = now.QuadPart - timer.startTick.QuadPart;
    // 频率为每秒tick数，毫秒=1000*delta/freq
    return (unsigned long)(delta * 1000 / timer.freq.QuadPart);
} 