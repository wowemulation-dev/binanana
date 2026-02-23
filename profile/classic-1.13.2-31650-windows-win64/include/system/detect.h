// Platform and tool detection for conditional compilation.

#ifndef BINANANA_SYSTEM_DETECT_H
#define BINANANA_SYSTEM_DETECT_H

// Tool detection
// Define GHIDRA when importing into Ghidra
// Define IDA when importing into IDA
// Define BINANANA_GENERATOR when running binanana tools

#include <stdint.h>
#include <stddef.h>

// x64 pointer size
#ifdef GHIDRA
typedef unsigned long long uintptr_t;
#endif

#endif // BINANANA_SYSTEM_DETECT_H
