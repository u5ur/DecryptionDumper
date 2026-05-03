// Common.h
#pragma once
#include <Windows.h>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>
#include <memory>
#include <utility>
#include <algorithm>
#include <cmath>

#define LOG(format, ...) printf(format, ##__VA_ARGS__)
#ifdef _DEBUG
#define DEBUG(format, ...) printf(format, ##__VA_ARGS__)
#else
#define DEBUG(format, ...) ((void)0)
#endif