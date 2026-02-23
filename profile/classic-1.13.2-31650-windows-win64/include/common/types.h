// Common types used across the WoW Classic client.

#ifndef BINANANA_COMMON_TYPES_H
#define BINANANA_COMMON_TYPES_H

#include "system/detect.h"

// GUID type (128-bit object identifier)
typedef struct WOWGUID {
    uint64_t lo;    // 0x00 (size: 0x08)
    uint64_t hi;    // 0x08 (size: 0x08)
} WOWGUID;          // total: 0x10

// ARGB color
typedef struct CArgb {
    uint8_t b;      // 0x00
    uint8_t g;      // 0x01
    uint8_t r;      // 0x02
    uint8_t a;      // 0x03
} CArgb;            // total: 0x04

#endif // BINANANA_COMMON_TYPES_H
