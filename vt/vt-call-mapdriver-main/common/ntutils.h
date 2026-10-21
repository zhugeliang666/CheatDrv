#pragma once
#include "fltKernel.h"
#include "./ntapi.h"
#include "./ntstructs.h"

struct MODULE_INFO
{
    uint64_t imageBase;
    uint64_t imageSize;
};

class YVT
{
public:
    YVT();
    void InitNtSymbol();

    MODULE_INFO ntosInfo;
};

extern YVT g_yvt;
