// Console variable (CVar) system.
//
// CVars are client configuration variables registered with a name,
// default value, and optional constraints. Each has a callback
// invoked when the value changes.

#ifndef BINANANA_CONSOLE_CVAR_H
#define BINANANA_CONSOLE_CVAR_H

#include "system/detect.h"
#include "common/blz_string.h"

// CVar struct - layout TBD from decompilation
// RTTI confirms CVar is a polymorphic class.

// CONSOLECOMMAND - registered console command
// RTTI entry: .?AVCONSOLECOMMAND@@

// CONSOLELINE - console output line
// RTTI entry: .?AVCONSOLELINE@@

#endif // BINANANA_CONSOLE_CVAR_H
