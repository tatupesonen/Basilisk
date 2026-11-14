/* Basilisk console extension: the state dump (`bk dump state`, format
 * bkstate 1, docs/features/decomp-oracle.md 4.4). The sections are written
 * by three files: bk_state.cc (function, actions, spaces, varnodes, orders,
 * ops, op lists, blocks, structure), bk_state_proto.cc (prototype, call
 * specs, jump tables) and bk_state_misc.cc (scope, heritage, highs, types,
 * C). */
#ifndef BK_STATE_HH
#define BK_STATE_HH

#include "bk_ids.hh"

namespace bk {

/// Everything one dump needs.
struct StateDump {
  Funcdata *fd;
  Architecture *glb;
  IfaceStatus *status;
  DumpIds ids;
  SectionWriter w;
  StateDump(Funcdata *f, IfaceStatus *st, std::ostream &o)
    : fd(f), glb(f->getArch()), status(st), ids(f), w(o) {}
};

/// One record from fields, joined by tabs.
std::string record(const std::vector<std::string> &fields);

/// `<space>:0x<first>-0x<last>` items of a RangeList, comma-joined (`-` when empty).
std::string rangeListText(const RangeList &rl);

/// 0 or 1.
inline std::string flag(bool b) { return b ? "1" : "0"; }

void writeProtoSection(StateDump &d);
void writeCallSpecSection(StateDump &d);
void writeJumpTableSection(StateDump &d);
/// Register the symbols the @highs section will name, so @scope can list
/// the foreign ones first.
void preRegisterHighSymbols(StateDump &d);
void writeScopeSection(StateDump &d);
void writeHeritageSection(StateDump &d);
void writeHighSection(StateDump &d);
void writeTypeSection(StateDump &d);
void writeCSection(StateDump &d);

} // namespace bk

#endif
