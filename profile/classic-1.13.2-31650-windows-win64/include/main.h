// binanana - WoW Classic 1.13.2 (build 31650) type definitions
//
// Master header file. Include this in Ghidra via File -> Parse C Source.
// Add the parent include/ directory to include paths.
// Add -DGHIDRA to parse options.

#ifndef BINANANA_MAIN_H
#define BINANANA_MAIN_H

#include "system/detect.h"

// Common types
#include "common/types.h"
#include "common/blz_string.h"

// Math types (Tempest library)
#include "tempest/vector.h"

// Container library
#include "common/containers.h"

// Console
#include "console/cvar.h"

// UI frame system
#include "ui/layoutframe.h"
#include "ui/simpleframe.h"

// Game objects
#include "object/object.h"

#endif // BINANANA_MAIN_H
