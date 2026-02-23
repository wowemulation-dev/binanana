// Blizzard container template library types.
//
// The Classic client uses TS* container templates extensively.
// These are placeholder definitions -- exact layouts need verification
// from decompilation.
//
// Template types present in RTTI:
//   TSFixedArray<T,N>       - Fixed-size array
//   TSGrowableArray<T>      - Dynamic array (like std::vector)
//   TSHashTable<V,K>        - Hash table with typed keys
//   TSList<T,LinkAccessor>  - Intrusive linked list
//   TSExplicitList<T>       - Bucket list for hash table chains
//
// Hash key types:
//   HASHKEY_DWORD           - Integer key
//   HASHKEY_STRI            - Case-insensitive string key
//   HASHKEY_CONSTSTRI       - Const string key
//   CHashKeyGUID            - WOWGUID key

#ifndef BINANANA_COMMON_CONTAINERS_H
#define BINANANA_COMMON_CONTAINERS_H

#include "system/detect.h"

// TSGrowableArray<T> - dynamic array
// Layout inferred from decompilation patterns.
typedef struct TSGrowableArray_void_ptr {
    void** data;        // 0x00 pointer to element array
    uint32_t count;     // 0x08 current element count
    uint32_t capacity;  // 0x0C allocated capacity
} TSGrowableArray_void_ptr; // total: 0x10

#endif // BINANANA_COMMON_CONTAINERS_H
