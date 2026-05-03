// Config.h
#pragma once
#include <Common.h>

/* if define OUTPUT_FILE it will output to file instead of printing*/
#define OUTPUT_FILE "output.txt"
#define DUMP_PATH "cod.bin"

#ifdef OUTPUT_FILE
inline FILE* g_output_file = nullptr;
inline void output_write(const char* format, ...) {
    if (!g_output_file)
        fopen_s(&g_output_file, OUTPUT_FILE, "a");
    if (!g_output_file)
        return;
    va_list args;
    va_start(args, format);
    vfprintf(g_output_file, format, args);
    va_end(args);
    fflush(g_output_file);
}
#define OUTPUT(format, ...) output_write(format, ##__VA_ARGS__)
#else
#define OUTPUT(format, ...) LOG(format, ##__VA_ARGS__)
#endif