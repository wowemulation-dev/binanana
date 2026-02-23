// Game object hierarchy.
//
// CG* classes are client-side game object representations:
//   CGObject_C -> CGItem_C, CGContainer_C
//   CGObject_C -> CGUnit_C -> CGPlayer_C -> CGActivePlayer_C
//   CGObject_C -> CGGameObject_C
//   CGObject_C -> CGDynamicObject_C
//   CGObject_C -> CGAreaTrigger_C
//   CGObject_C -> CGCorpse_C
//
// Source: wow\source\object\objectclient\ (~50 files)
// Source: wow\source\objectmgrclient\objectmgrclient.cpp

#ifndef BINANANA_OBJECT_OBJECT_H
#define BINANANA_OBJECT_OBJECT_H

#include "system/detect.h"
#include "common/types.h"

// All CG* types are polymorphic (RTTI present).
// Exact layouts TBD from decompilation.
//
// Known update field types (from compilation-artifacts.md):
//   CGObjectData: Guid, Type, EntryID, DynamicFlags (4 fields)
//   CGUnitData: Health, Power, Level, Auras, Stats (117 fields)
//   CGPlayerData: DuelArbiter, GuildRank, HairColor (33 fields)
//   CGActivePlayerData: InvSlots, QuestLog, Skills (105 fields)
//   CGItemData: Owner, ContainedIn, Enchantment, Durability (18 fields)
//   CGGameObjectData: CreatedBy, DisplayID, Flags, Level (17 fields)

#endif // BINANANA_OBJECT_OBJECT_H
