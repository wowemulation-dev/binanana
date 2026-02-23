// Blizzard custom string type (replaces std::string in Classic clients).
//
// blz::basic_string<char> with SSO (Small String Optimization).
// Layout inferred from RTTI entries and decompilation patterns.
// Exact size TBD -- this is a placeholder based on MSVC std::string
// layout which blz::basic_string appears to mirror.

#ifndef BINANANA_COMMON_BLZ_STRING_H
#define BINANANA_COMMON_BLZ_STRING_H

#include "system/detect.h"

typedef struct blz_string {
    union {
        char buf[16];           // 0x00 SSO buffer (size: 0x10)
        char* ptr;              // 0x00 heap pointer (when len >= 16)
    } data;
    uint64_t length;            // 0x10 (size: 0x08)
    uint64_t capacity;          // 0x18 (size: 0x08)
} blz_string;                   // total: 0x20

#endif // BINANANA_COMMON_BLZ_STRING_H
