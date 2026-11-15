/* Basilisk console extension: `bk dump state <file>` (bk_state.hh) — the
 * header and the sections up to @structure. */
#include "bk_state.hh"
#include "bk_cfg.hh"
#include "bk_commands.hh"

#include <algorithm>

#ifndef BK_GHIDRA_COMMIT
#define BK_GHIDRA_COMMIT "unknown"
#endif

namespace bk {

std::string record(const std::vector<std::string> &fields)
{
  std::string s;
  for (size_t i = 0; i < fields.size(); ++i) {
    if (i != 0) s += '\t';
    s += fields[i];
  }
  return s;
}

std::string rangeListText(const RangeList &rl)
{
  std::vector<std::string> items;
  for (set<Range>::const_iterator it = rl.begin(); it != rl.end(); ++it)
    items.push_back((*it).getSpace()->getName() + ":" + hx((*it).getFirst()) + "-" + hx((*it).getLast()));
  return joinList(items);
}

static void writeFunction(StateDump &d)
{
  Funcdata *fd = d.fd;
  d.w.begin("function");
  d.w.add(record({"F", escape(fd->name), escape(fd->displayName), addrText(fd->baseaddr), num(fd->size),
                  hx(fd->flags), hx(fd->clean_up_index), hx(fd->high_level_index), hx(fd->cast_phase_index),
                  num(fd->minLanedSize)}));
  d.w.add(record({"K", hx(fd->vbank.create_index), hx(fd->vbank.uniqbase), hx(fd->vbank.uniqid),
                  hx(fd->obank.uniqid)}));
  CommentDatabase *db = d.glb->commentdb;
  if (db != (CommentDatabase *)0) {
    CommentSet::const_iterator it = db->beginComment(fd->baseaddr), end = db->endComment(fd->baseaddr);
    for (; it != end; ++it)
      d.w.add(record({"W", hx((*it)->getType()), addrText((*it)->getAddr()), num((*it)->getUniq()),
                      escape((*it)->getText())}));
  }
  std::ostringstream ov;
  XmlEncode enc(ov, false);
  fd->localoverride.encode(enc, d.glb);
  if (!ov.str().empty()) d.w.add(record({"O", escape(ov.str())}));
  for (map<VarnodeData, const LanedRegister *>::const_iterator it = fd->lanedMap.begin(); it != fd->lanedMap.end(); ++it)
    d.w.add(record({"X", addrText(Address((*it).first.space, (*it).first.offset)), num((*it).first.size),
                    num((*it).second->getWholeSize()), hx((*it).second->getSizeBitMask())}));
  for (map<ResolveEdge, ResolvedUnion>::const_iterator it = fd->unionMap.begin(); it != fd->unionMap.end(); ++it)
    d.w.add(record({"U", hx((*it).first.typeId), hx((*it).first.opTime), num((*it).first.encoding),
                    d.ids.type((*it).second.baseType), d.ids.type((*it).second.resolve),
                    num((*it).second.fieldNum), flag((*it).second.lock)}));
  d.w.end();
}

/// The `state` field of an action: where a restart group, group or pool
/// stands mid-way (ActionRestartGroup::curstart, ActionGroup::state,
/// ActionPool::op_state and rule_index).
static std::string actionState(const ActionEntry &e, Funcdata *fd)
{
  std::vector<std::string> parts;
  Action *act = e.action;
  ActionRestartGroup *restart = dynamic_cast<ActionRestartGroup *>(act);
  // curstart is set by reset(); an action never started may not have had one.
  bool started = act->status != Action::status_start || act->count_tests > 0;
  if (restart != (ActionRestartGroup *)0 && started) parts.push_back("restart:" + num(restart->curstart));
  if (act->status == Action::status_mid) {
    ActionGroup *group = dynamic_cast<ActionGroup *>(act);
    if (group != (ActionGroup *)0 && group->state != group->list.end())
      parts.push_back("child:" + num((intb)(group->state - group->list.begin())));
    ActionPool *pool = dynamic_cast<ActionPool *>(act);
    if (pool != (ActionPool *)0) {
      std::string at = "end";
      if (pool->op_state != fd->endOpMain()) at = DumpIds::seq((*pool->op_state).second->getSeqNum());
      parts.push_back("op:" + at + "/" + num(pool->rule_index));
    }
  }
  return joinList(parts);
}

static void writeActions(StateDump &d)
{
  std::vector<ActionEntry> entries;
  collectActions(d.glb->allacts.getCurrent(), entries);
  d.w.begin("actions");
  for (size_t i = 0; i < entries.size(); ++i) {
    const ActionEntry &e(entries[i]);
    if (e.rule != (Rule *)0) {
      Rule *r = e.rule;
      d.w.add(record({"R", num(e.position), escape(e.path), hx(r->flags), num(r->count_tests), num(r->count_apply),
                      hx(r->breakpoint)}));
      continue;
    }
    Action *a = e.action;
    // Action's constructor leaves count and lcount uninitialised (action.cc);
    // perform sets count at every start and lcount when it goes on from a
    // start, so before that they are written as `-`.
    bool counted = a->status != Action::status_start || a->count_tests > 0;
    bool lcounted = a->count_tests > 0 ||
                    (a->status != Action::status_start && a->status != Action::status_breakstarthit);
    d.w.add(record({"A", num(e.position), escape(e.path), hx(a->status), counted ? num(a->count) : "-",
                    lcounted ? num(a->lcount) : "-",
                    num(a->count_tests), num(a->count_apply), hx(a->flags), hx(a->breakpoint),
                    actionState(e, d.fd)}));
  }
  d.w.end();
}

static void writeSpaces(StateDump &d)
{
  d.w.begin("spaces");
  for (int4 i = 0; i < d.glb->numSpaces(); ++i) {
    AddrSpace *spc = d.glb->getSpace(i);
    if (spc == (AddrSpace *)0) continue;
    char shortcut = spc->getShortcut();
    d.w.add(record({"P", num(spc->getIndex()), escape(spc->getName()), num(spc->getType()),
                    shortcut == 0 ? std::string("-") : std::string(1, shortcut), num(spc->getWordSize()),
                    num(spc->getAddrSize()), hx(spc->flags), num(spc->getDelay()), num(spc->getDeadcodeDelay())}));
  }
  d.w.end();
}

/// The non-zero mask; a pointer-valued constant's mask is its value
/// (Varnode::nzm of a constant), so it is written as the canonical key too.
static std::string nzmText(StateDump &d, const Varnode *v)
{
  if (d.ids.isPointerValued(v) && v->nzm == v->getOffset()) return hx(d.ids.canonicalOffset(v));
  return hx(v->nzm);
}

static bool byCreate(const Varnode *a, const Varnode *b) { return a->getCreateIndex() < b->getCreateIndex(); }

static void writeVarnodes(StateDump &d)
{
  std::vector<Varnode *> vns(d.fd->vbank.loc_tree.begin(), d.fd->vbank.loc_tree.end());
  std::sort(vns.begin(), vns.end(), byCreate);
  d.w.begin("varnodes");
  for (size_t i = 0; i < vns.size(); ++i) {
    Varnode *v = vns[i];
    std::vector<std::string> readers;
    for (list<PcodeOp *>::const_iterator it = v->descend.begin(); it != v->descend.end(); ++it)
      readers.push_back(d.ids.op(*it));
    std::string entry = "-";
    if (v->mapentry != (SymbolEntry *)0) {
      Symbol *sym = v->mapentry->getSymbol();
      int4 pos = -1;
      for (size_t k = 0; k < sym->mapentry.size(); ++k)
        if (sym->mapentry[k] == v->mapentry) pos = (int4)k;
      entry = d.ids.symbol(sym) + ":" + num(pos);
    }
    d.w.add(record({"V", DumpIds::vn(v), escape(v->getSpace()->getName()), d.ids.offsetText(v), num(v->getSize()),
                    hx(v->flags), hx(v->addlflags), num(v->mergegroup), d.ids.op(v->def), joinList(readers),
                    d.ids.type(v->type), hx(v->consumed), nzmText(d, v), d.ids.high(v->high), entry}));
  }
  d.w.end();
  std::vector<Varnode *> order;
  std::vector<std::string> names;
  d.ids.locOrder(order);
  for (size_t i = 0; i < order.size(); ++i) names.push_back(DumpIds::vn(order[i]));
  d.w.begin("locorder");
  d.w.add(record({"O", joinList(names)}));
  d.w.end();
  names.clear();
  d.ids.defOrder(order);
  for (size_t i = 0; i < order.size(); ++i) names.push_back(DumpIds::vn(order[i]));
  d.w.begin("deforder");
  d.w.add(record({"O", joinList(names)}));
  d.w.end();
}

static bool bySeq(const PcodeOp *a, const PcodeOp *b) { return a->getSeqNum() < b->getSeqNum(); }

/// An op as `print raw` prints it (BlockBasic::printRaw), in a fresh stream.
static std::string opText(const PcodeOp *op)
{
  std::ostringstream s;
  s << op->getSeqNum() << ":\t";
  size_t prefix = s.str().size();
  op->printRaw(s);
  return s.str().substr(prefix);
}

static std::string opList(StateDump &d, const list<PcodeOp *> &l)
{
  std::vector<std::string> items;
  for (list<PcodeOp *>::const_iterator it = l.begin(); it != l.end(); ++it) items.push_back(d.ids.op(*it));
  return joinList(items);
}

static void writeOps(StateDump &d)
{
  PcodeOpBank &bank(d.fd->obank);
  std::vector<PcodeOp *> ops;
  std::set<const PcodeOp *> alt;
  for (PcodeOpTree::const_iterator it = bank.optree.begin(); it != bank.optree.end(); ++it) ops.push_back((*it).second);
  for (PcodeOpTree::const_iterator it = bank.alttree.begin(); it != bank.alttree.end(); ++it) {
    ops.push_back((*it).second);
    alt.insert((*it).second);
  }
  std::sort(ops.begin(), ops.end(), bySeq);
  d.w.begin("ops");
  for (size_t i = 0; i < ops.size(); ++i) {
    PcodeOp *op = ops[i];
    std::vector<std::string> ins;
    for (int4 k = 0; k < op->numInput(); ++k) ins.push_back(DumpIds::vn(op->getIn(k)));
    d.w.add(record({"O", d.ids.op(op), num(op->getSeqNum().getOrder()), get_opname(op->code()), hx(op->flags),
                    hx(op->addlflags), DumpIds::vn(op->getOut()), joinList(ins), DumpIds::block(op->getParent()),
                    op->isDead() ? "dead" : "alive", alt.count(op) ? "alt" : "main", escape(opText(op))}));
  }
  d.w.end();
  d.w.begin("oplists");
  d.w.add(record({"L", "alive", opList(d, bank.alivelist)}));
  d.w.add(record({"L", "dead", opList(d, bank.deadlist)}));
  d.w.add(record({"L", "store", opList(d, bank.storelist)}));
  d.w.add(record({"L", "load", opList(d, bank.loadlist)}));
  d.w.add(record({"L", "return", opList(d, bank.returnlist)}));
  d.w.add(record({"L", "userop", opList(d, bank.useroplist)}));
  d.w.end();
}

static void writeBlocks(StateDump &d)
{
  const BlockGraph &g(d.fd->bblocks);
  d.w.begin("blocks");
  for (int4 i = 0; i < g.getSize(); ++i) {
    const BlockBasic *bb = (const BlockBasic *)g.getBlock(i);
    std::vector<std::string> ops;
    for (list<PcodeOp *>::const_iterator it = bb->op.begin(); it != bb->op.end(); ++it) ops.push_back(d.ids.op(*it));
    d.w.add(record({"B", DumpIds::block(bb), num(i), hx(bb->getFlags()), DumpIds::block(bb->getImmedDom()),
                    num(bb->numdesc), rangeListText(bb->cover), joinList(ops)}));
    for (int4 k = 0; k < bb->sizeIn(); ++k)
      d.w.add(record({"E", DumpIds::block(bb->getIn(k)), num(bb->getInRevIndex(k)), hx(bb->intothis[k].label)}));
  }
  d.w.end();
  d.w.begin("structure");
  const BlockGraph &s(d.fd->sblocks);
  if (s.getSize() != 0) {
    PositionMap pos;
    buildPositions(g, pos);
    NodeNames names;
    names.build(s, copiedPosition, &pos);
    std::ostringstream o;
    writeStructureNodes(o, s, names);
    std::istringstream in(o.str());
    std::string line;
    while (std::getline(in, line)) d.w.add(line);
  }
  d.w.end();
}

void writeStateDump(std::ostream &o, Funcdata *fd, IfaceStatus *status)
{
  StateDump d(fd, status, o);
  d.w.line(record({"BKSTATE", "2", BK_GHIDRA_COMMIT, escape(d.glb->archid)}));
  writeFunction(d);
  writeActions(d);
  writeSpaces(d);
  writeVarnodes(d);
  writeOps(d);
  writeBlocks(d);
  writeProtoSection(d);
  writeCallSpecSection(d);
  writeJumpTableSection(d);
  preRegisterHighSymbols(d);
  writeScopeSection(d);
  writeHeritageSection(d);
  writeHighSection(d);
  writeTypeSection(d);
  writeCSection(d);
  d.w.finish();
}

/// `bk dump state <file>`
class BkDumpState : public BkCommand {
public:
  virtual void execute(istream &s) {
    Funcdata *fd = requireFunction();
    std::string file = nextWord(s);
    if (file.empty()) throw IfaceParseError("Missing output file");
    AtomicFile out(file);
    writeStateDump(out.stream(), fd, status);
    out.commit();
  }
};

void registerStateCommands(IfaceStatus *status)
{
  status->registerCom(new BkDumpState(), "bk", "dump", "state");
}

} // namespace bk
