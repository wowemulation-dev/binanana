// Tempest math library vector types.

#ifndef BINANANA_TEMPEST_VECTOR_H
#define BINANANA_TEMPEST_VECTOR_H

#include "system/detect.h"

typedef struct C2Vector {
    float x;    // 0x00
    float y;    // 0x04
} C2Vector;     // total: 0x08

typedef struct C3Vector {
    float x;    // 0x00
    float y;    // 0x04
    float z;    // 0x08
} C3Vector;     // total: 0x0C

typedef struct C4Vector {
    float x;    // 0x00
    float y;    // 0x04
    float z;    // 0x08
    float w;    // 0x0C
} C4Vector;     // total: 0x10

#endif // BINANANA_TEMPEST_VECTOR_H
