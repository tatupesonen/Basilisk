/* Basilisk console extension: naming a structured hierarchy and writing its
 * `S` and `P` records (format bkstruct 1, docs/features/decomp-oracle.md 4.7). */
#include "bk_cfg.hh"

namespace bk {

static const BlockGraph *asGraph(const FlowBlock *bl)
{
  if (bl->getType() == FlowBlock::t_copy || bl->getType() == FlowBlock::t_plain ||
      bl->getType() == FlowBlock::t_basic)
    return (const BlockGraph *)0;
  return dynamic_cast<const BlockGraph *>(bl);
}

static void nameNode(const FlowBlock *bl, int4 (*leafId)(const FlowBlock *, const void *), const void *arg,
                     int4 &counter, std::map<const FlowBlock *, std::string> &names)
{
  const BlockGraph *g = asGraph(bl);
  if (g == (const BlockGraph *)0) {
    names[bl] = "L" + num(leafId(bl, arg));
    return;
  }
  names[bl] = "S" + num(counter++);
  for (int4 i = 0; i < g->getSize(); ++i)
    nameNode(g->getBlock(i), leafId, arg, counter, names);
}

void NodeNames::build(const BlockGraph &top, int4 (*leafId)(const FlowBlock *, const void *), const void *arg)
{
  names.clear();
  int4 counter = 0;
  for (int4 i = 0; i < top.getSize(); ++i)
    nameNode(top.getBlock(i), leafId, arg, counter, names);
}

std::string NodeNames::of(const FlowBlock *bl) const
{
  if (bl == (const FlowBlock *)0) return "-";
  std::map<const FlowBlock *, std::string>::const_iterator it = names.find(bl);
  return (it == names.end()) ? std::string("?") : it->second;
}

/// Kind names: Ghidra's, but `ifnoexit` and `if` as their own (typeToName
/// writes `ifelse` and `properif`).
static std::string kindName(FlowBlock::block_type t)
{
  switch (t) {
  case FlowBlock::t_copy: return "copy";
  case FlowBlock::t_goto: return "goto";
  case FlowBlock::t_multigoto: return "multigoto";
  case FlowBlock::t_ls: return "list";
  case FlowBlock::t_condition: return "condition";
  case FlowBlock::t_if: return "if";
  case FlowBlock::t_ifelse: return "ifelse";
  case FlowBlock::t_ifnoexit: return "ifnoexit";
  case FlowBlock::t_ifgoto: return "ifgoto";
  case FlowBlock::t_whiledo: return "whiledo";
  case FlowBlock::t_dowhile: return "dowhile";
  case FlowBlock::t_infloop: return "infloop";
  case FlowBlock::t_switch: return "switch";
  default: return FlowBlock::typeToName(t);
  }
}

static std::string kindData(const FlowBlock *bl, const NodeNames &names)
{
  std::ostringstream s;
  switch (bl->getType()) {
  case FlowBlock::t_goto: {
    const BlockGoto *g = (const BlockGoto *)bl;
    s << names.of(g->getGotoTarget()) << ',' << hx(g->getGotoType());
    break;
  }
  case FlowBlock::t_ifgoto: {
    const BlockIfGoto *g = (const BlockIfGoto *)bl;
    s << names.of(g->getGotoTarget()) << ',' << hx(g->getGotoType());
    break;
  }
  case FlowBlock::t_multigoto: {
    const BlockMultiGoto *g = (const BlockMultiGoto *)bl;
    for (int4 i = 0; i < g->numGotos(); ++i) s << names.of(g->getGoto(i)) << ',';
    s << (g->hasDefaultGoto() ? "default" : "-");
    break;
  }
  case FlowBlock::t_condition:
    s << get_opname(((const BlockCondition *)bl)->getOpcode());
    break;
  case FlowBlock::t_whiledo:
    s << (((const BlockWhileDo *)bl)->hasOverflowSyntax() ? "overflow" : "-");
    break;
  case FlowBlock::t_switch: {
    const BlockSwitch *sw = (const BlockSwitch *)bl;
    if (sw->caseblocks.empty()) s << '-';
    for (size_t i = 0; i < sw->caseblocks.size(); ++i) {
      const BlockSwitch::CaseOrder &c(sw->caseblocks[i]);
      if (i != 0) s << ',';
      s << names.of(c.block) << ':' << c.outindex << ':' << c.chain << ':' << hx(c.gototype) << ':'
        << (c.isexit ? 1 : 0) << ':' << (c.isdefault ? 1 : 0);
    }
    break;
  }
  default:
    s << '-';
  }
  return s.str();
}

static std::string edgeList(const std::vector<BlockEdge> &edges, const NodeNames &names)
{
  if (edges.empty()) return "-";
  std::ostringstream s;
  for (size_t i = 0; i < edges.size(); ++i) {
    if (i != 0) s << ',';
    s << names.of(edges[i].point) << ':' << edges[i].reverse_index << ':' << hx(edges[i].label);
  }
  return s.str();
}

static void writeNode(std::ostream &o, const FlowBlock *bl, const BlockGraph &top, const NodeNames &names)
{
  const BlockGraph *g = asGraph(bl);
  o << "S\t" << names.of(bl) << '\t' << kindName(bl->getType()) << '\t' << bl->getIndex() << '\t'
    << hx(bl->getFlags()) << '\t' << bl->getStructureDepth() << '\t' << bl->getBasicCount() << '\t';
  const FlowBlock *parent = bl->getParent();
  o << ((parent == (const FlowBlock *)0 || parent == &top) ? std::string("-") : names.of(parent)) << '\t';
  if (g == (const BlockGraph *)0 || g->getSize() == 0) o << '-';
  else
    for (int4 i = 0; i < g->getSize(); ++i) o << (i ? "," : "") << names.of(g->getBlock(i));
  o << '\t' << kindData(bl, names) << '\t' << edgeList(bl->intothis, names) << '\t'
    << edgeList(bl->outofthis, names) << '\n';
  if (g != (const BlockGraph *)0)
    for (int4 i = 0; i < g->getSize(); ++i) writeNode(o, g->getBlock(i), top, names);
}

void writeStructureNodes(std::ostream &o, const BlockGraph &top, const NodeNames &names)
{
  for (int4 i = 0; i < top.getSize(); ++i) writeNode(o, top.getBlock(i), top, names);
  o << "P\t";
  if (top.getSize() == 0) o << '-';
  for (int4 i = 0; i < top.getSize(); ++i) o << (i ? "," : "") << names.of(top.getBlock(i));
  o << '\n';
}

} // namespace bk
