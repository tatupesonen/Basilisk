/* Basilisk console extension: object names and canonical keys (bk_ids.hh). */
#include "bk_ids.hh"

#include <algorithm>

namespace bk {

DumpIds::DumpIds(Funcdata *f) : fd(f)
{
  Architecture *glb = fd->getArch();
  for (int4 i = 0; i < glb->numSpaces(); ++i) {
    AddrSpace *spc = glb->getSpace(i);
    if (spc != (AddrSpace *)0) spaceByPointer[(uintb)(uintp)spc] = spc->getIndex();
  }
  for (size_t i = 0; i < fd->qlst.size(); ++i) callIndex[fd->qlst[i]] = (int4)i;
  // Highs, numbered by their smallest member's create index.
  std::map<uint4, const HighVariable *> byFirst;
  for (VarnodeLocSet::const_iterator it = fd->vbank.loc_tree.begin(); it != fd->vbank.loc_tree.end(); ++it) {
    const HighVariable *h = (*it)->high;
    if (h == (const HighVariable *)0) continue;
    uint4 first = ~(uint4)0;
    for (size_t k = 0; k < h->inst.size(); ++k) first = std::min(first, h->inst[k]->getCreateIndex());
    byFirst[first] = h;
  }
  int4 n = 0;
  for (std::map<uint4, const HighVariable *>::const_iterator it = byFirst.begin(); it != byFirst.end(); ++it)
    highIndex[it->second] = n++;
}

std::string DumpIds::seq(const SeqNum &sq)
{
  return addrText(sq.getAddr()) + ":" + hx(sq.getTime());
}

std::string DumpIds::op(const PcodeOp *op) const
{
  return (op == (const PcodeOp *)0) ? std::string("-") : seq(op->getSeqNum());
}

std::string DumpIds::vn(const Varnode *v)
{
  if (v == (const Varnode *)0) return "-";
  std::ostringstream s;
  s << 'v' << std::hex << v->getCreateIndex();
  return s.str();
}

std::string DumpIds::block(const FlowBlock *bl)
{
  return (bl == (const FlowBlock *)0) ? std::string("-") : "b" + num(bl->getIndex());
}

bool DumpIds::isPointerValued(const Varnode *v) const
{
  AddrSpace *spc = v->getSpace();
  if (spc->getType() == IPTR_IOP || spc->getType() == IPTR_FSPEC) return true;
  if (spc->getType() == IPTR_CONSTANT && v->getSize() == (int4)sizeof(void *))
    return spaceByPointer.find(v->getOffset()) != spaceByPointer.end();
  return false;
}

uintb DumpIds::canonicalOffset(const Varnode *v) const
{
  AddrSpace *spc = v->getSpace();
  if (spc->getType() == IPTR_IOP)
    return ((const PcodeOp *)(uintp)v->getOffset())->getSeqNum().getTime();
  if (spc->getType() == IPTR_FSPEC) {
    std::map<const FuncCallSpecs *, int4>::const_iterator it =
        callIndex.find((const FuncCallSpecs *)(uintp)v->getOffset());
    return (it == callIndex.end()) ? ~(uintb)0 : (uintb)it->second;
  }
  if (spc->getType() == IPTR_CONSTANT && v->getSize() == (int4)sizeof(void *)) {
    std::map<uintb, int4>::const_iterator it = spaceByPointer.find(v->getOffset());
    if (it != spaceByPointer.end()) return (uintb)it->second;
  }
  return v->getOffset();
}

std::string DumpIds::offsetText(const Varnode *v) const
{
  AddrSpace *spc = v->getSpace();
  if (spc->getType() == IPTR_IOP)
    return "op:" + seq(((const PcodeOp *)(uintp)v->getOffset())->getSeqNum());
  if (spc->getType() == IPTR_FSPEC)
    return "call:" + call((const FuncCallSpecs *)(uintp)v->getOffset());
  if (isPointerValued(v))
    return "space:" + fd->getArch()->getSpace((int4)canonicalOffset(v))->getName();
  return hx(v->getOffset());
}

std::string DumpIds::call(const FuncCallSpecs *fc) const
{
  std::map<const FuncCallSpecs *, int4>::const_iterator it = callIndex.find(fc);
  return (it == callIndex.end()) ? std::string("-") : "c" + num(it->second);
}

std::string DumpIds::high(const HighVariable *h) const
{
  std::map<const HighVariable *, int4>::const_iterator it = highIndex.find(h);
  return (it == highIndex.end()) ? std::string("-") : "h" + num(it->second);
}

std::vector<const HighVariable *> DumpIds::highs(void) const
{
  std::vector<const HighVariable *> res(highIndex.size());
  for (std::map<const HighVariable *, int4>::const_iterator it = highIndex.begin(); it != highIndex.end(); ++it)
    res[it->second] = it->first;
  return res;
}

std::string DumpIds::type(const Datatype *dt)
{
  if (dt == (const Datatype *)0) return "-";
  std::map<const Datatype *, int4>::const_iterator it = typeIndex.find(dt);
  if (it != typeIndex.end()) return "t" + num(it->second);
  int4 n = (int4)types.size();
  typeIndex[dt] = n;
  types.push_back(dt);
  return "t" + num(n);
}

std::string DumpIds::symbol(const Symbol *sym)
{
  if (sym == (const Symbol *)0) return "-";
  if (sym->getScope() != fd->getScopeLocal() && foreignIndex.find(sym) == foreignIndex.end()) {
    foreignIndex[sym] = (int4)foreign.size();
    foreign.push_back(sym);
  }
  std::ostringstream s;
  s << 's' << std::hex << sym->getId();
  return s.str();
}

/// The comparison of an Address with a canonical offset (Address::operator<).
static int4 compareAddr(const AddrSpace *s1, uintb o1, const AddrSpace *s2, uintb o2)
{
  if (s1 != s2) return (s1->getIndex() < s2->getIndex()) ? -1 : 1;
  if (o1 != o2) return (o1 < o2) ? -1 : 1;
  return 0;
}

struct CanonLocDef {
  const DumpIds *ids;
  bool operator()(const Varnode *a, const Varnode *b) const {   // VarnodeCompareLocDef, varnode.cc:34
    int4 c = compareAddr(a->getSpace(), ids->canonicalOffset(a), b->getSpace(), ids->canonicalOffset(b));
    if (c != 0) return c < 0;
    if (a->getSize() != b->getSize()) return a->getSize() < b->getSize();
    uint4 f1 = a->getFlags() & (Varnode::input | Varnode::written);
    uint4 f2 = b->getFlags() & (Varnode::input | Varnode::written);
    if (f1 != f2) return (f1 - 1) < (f2 - 1);
    if (f1 == Varnode::written) {
      if (a->getDef()->getSeqNum() != b->getDef()->getSeqNum())
        return a->getDef()->getSeqNum() < b->getDef()->getSeqNum();
    }
    else if (f1 == 0)
      return a->getCreateIndex() < b->getCreateIndex();
    return false;
  }
};

struct CanonDefLoc {
  const DumpIds *ids;
  bool operator()(const Varnode *a, const Varnode *b) const {   // VarnodeCompareDefLoc, varnode.cc:63
    uint4 f1 = a->getFlags() & (Varnode::input | Varnode::written);
    uint4 f2 = b->getFlags() & (Varnode::input | Varnode::written);
    if (f1 != f2) return (f1 - 1) < (f2 - 1);
    if (f1 == Varnode::written) {
      if (a->getDef()->getSeqNum() != b->getDef()->getSeqNum())
        return a->getDef()->getSeqNum() < b->getDef()->getSeqNum();
    }
    int4 c = compareAddr(a->getSpace(), ids->canonicalOffset(a), b->getSpace(), ids->canonicalOffset(b));
    if (c != 0) return c < 0;
    if (a->getSize() != b->getSize()) return a->getSize() < b->getSize();
    if (f1 == 0) return a->getCreateIndex() < b->getCreateIndex();
    return false;
  }
};

void DumpIds::locOrder(std::vector<Varnode *> &out) const
{
  out.assign(fd->vbank.loc_tree.begin(), fd->vbank.loc_tree.end());
  CanonLocDef cmp = {this};
  std::stable_sort(out.begin(), out.end(), cmp);
}

void DumpIds::defOrder(std::vector<Varnode *> &out) const
{
  out.assign(fd->vbank.def_tree.begin(), fd->vbank.def_tree.end());
  CanonDefLoc cmp = {this};
  std::stable_sort(out.begin(), out.end(), cmp);
}

void SectionWriter::end(void)
{
  line("@" + name + "\t" + num((intb)records.size()));
  for (size_t i = 0; i < records.size(); ++i) line(records[i]);
  records.clear();
}

std::string joinList(const std::vector<std::string> &items)
{
  if (items.empty()) return "-";
  std::string s;
  for (size_t i = 0; i < items.size(); ++i) {
    if (i != 0) s += ',';
    s += items[i];
  }
  return s;
}

} // namespace bk
