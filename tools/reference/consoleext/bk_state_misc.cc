/* Basilisk console extension: the @scope, @heritage, @highs, @types and @c
 * sections of the state dump (bk_state.hh). */
#include "bk_state.hh"

#include <algorithm>

namespace bk {

static std::string symbolKind(const Symbol *sym)
{
  if (dynamic_cast<const FunctionSymbol *>(sym) != 0) return "function";
  if (dynamic_cast<const EquateSymbol *>(sym) != 0) return "equate";
  if (dynamic_cast<const UnionFacetSymbol *>(sym) != 0) return "unionfacet";
  if (dynamic_cast<const LabSymbol *>(sym) != 0) return "label";
  if (dynamic_cast<const ExternRefSymbol *>(sym) != 0) return "externref";
  return "symbol";
}

/// Where an entry is stored: an address, `hash:0x…` for a dynamic entry, `-` otherwise.
static std::string entryStorage(const SymbolEntry *e)
{
  const MapEntry *m = dynamic_cast<const MapEntry *>(e);
  if (m != (const MapEntry *)0) return addrText(m->getAddr());
  const DynamicEntry *dyn = dynamic_cast<const DynamicEntry *>(e);
  if (dyn != (const DynamicEntry *)0) return "hash:" + hx(dyn->getHash());
  return "-";
}

static std::string symbolId(const Symbol *sym)
{
  std::ostringstream s;
  s << 's' << std::hex << sym->getId();
  return s.str();
}

static bool byId(const Symbol *a, const Symbol *b) { return a->getId() < b->getId(); }

void preRegisterHighSymbols(StateDump &d)
{
  std::vector<const HighVariable *> highs = d.ids.highs();
  for (size_t i = 0; i < highs.size(); ++i) d.ids.symbol(highs[i]->symbol);
}

void writeScopeSection(StateDump &d)
{
  d.w.begin("scope");
  ScopeLocal *scope = d.fd->getScopeLocal();
  if (scope != (ScopeLocal *)0) {
    d.w.add(record({"Z", escape(scope->getName()), scope->space == (AddrSpace *)0 ? std::string("-")
                                                                                   : escape(scope->space->getName()),
                    flag(scope->stackGrowsNegative), flag(scope->rangeLocked), flag(scope->overlapProblems),
                    flag(scope->openParamRefs), hx(scope->minParamOffset), hx(scope->maxParamOffset),
                    rangeListText(scope->rangetree)}));
    for (list<NameRecommend>::const_iterator it = scope->nameRecommend.begin(); it != scope->nameRecommend.end(); ++it)
      d.w.add(record({"N", addrText((*it).addr), addrText((*it).useaddr), num((*it).size), escape((*it).name),
                      hx((*it).symbolId)}));
    for (list<DynamicRecommend>::const_iterator it = scope->dynRecommend.begin(); it != scope->dynRecommend.end(); ++it)
      d.w.add(record({"D", addrText((*it).usePoint), hx((*it).hash), escape((*it).name), hx((*it).symbolId)}));
    for (list<TypeRecommend>::const_iterator it = scope->typeRecommend.begin(); it != scope->typeRecommend.end(); ++it)
      d.w.add(record({"Y", addrText((*it).getAddress()), d.ids.type((*it).getType())}));
    std::vector<Symbol *> syms(scope->nametree.begin(), scope->nametree.end());
    std::stable_sort(syms.begin(), syms.end(), byId);
    for (size_t i = 0; i < syms.size(); ++i) {
      Symbol *sym = syms[i];
      d.w.add(record({"S", symbolId(sym), escape(sym->name), escape(sym->displayName), d.ids.type(sym->type),
                      hx(sym->flags), hx(sym->dispflags), num(sym->category), num(sym->catindex), num(sym->nameDedup),
                      symbolKind(sym), num(sym->wholeCount)}));
      for (size_t k = 0; k < sym->mapentry.size(); ++k) {
        const SymbolEntry *e = sym->mapentry[k];
        d.w.add(record({"M", entryStorage(e), num(e->getSize()), num(e->getOffset()), rangeListText(e->getUseLimit()),
                        hx(e->extraflags), hx(e->properties)}));
      }
    }
  }
  const std::vector<const Symbol *> &foreign(d.ids.foreignSymbols());
  for (size_t i = 0; i < foreign.size(); ++i) {
    const Symbol *sym = foreign[i];
    std::string where = "-";
    if (!sym->mapentry.empty()) where = entryStorage(sym->mapentry[0]);
    d.w.add(record({"G", symbolId(sym), escape(sym->getName()), escape(sym->getScope()->getName()), where}));
  }
  d.w.end();
}

static std::string guardRecord(StateDump &d, const char *kind, const LoadGuard &g)
{
  return record({"L", kind, d.ids.op(g.op), g.spc == (AddrSpace *)0 ? std::string("-") : escape(g.spc->getName()),
                 hx(g.pointerBase), hx(g.minimumOffset), hx(g.maximumOffset), num(g.step), num(g.analysisState)});
}

void writeHeritageSection(StateDump &d)
{
  const Heritage &h(d.fd->heritage);
  d.w.begin("heritage");
  d.w.add(record({"Z", num(h.pass), num(h.maxdepth)}));
  for (size_t i = 0; i < h.infolist.size(); ++i) {
    const HeritageInfo &info(h.infolist[i]);
    if (info.space == (AddrSpace *)0) continue;
    d.w.add(record({"I", escape(info.space->getName()), num(info.delay), num(info.deadcodedelay),
                    num(info.deadremoved), flag(info.loadGuardSearch), flag(info.warningissued),
                    flag(info.hasCallPlaceholders)}));
  }
  for (map<Address, LocationMap::SizePass>::const_iterator it = h.globaldisjoint.themap.begin();
       it != h.globaldisjoint.themap.end(); ++it)
    d.w.add(record({"M", addrText((*it).first), num((*it).second.size), num((*it).second.pass)}));
  for (list<LoadGuard>::const_iterator it = h.loadGuard.begin(); it != h.loadGuard.end(); ++it)
    d.w.add(guardRecord(d, "load", *it));
  for (list<LoadGuard>::const_iterator it = h.storeGuard.begin(); it != h.storeGuard.end(); ++it)
    d.w.add(guardRecord(d, "store", *it));
  std::vector<std::string> copies;
  for (size_t i = 0; i < h.loadCopyOps.size(); ++i) copies.push_back(d.ids.op(h.loadCopyOps[i]));
  d.w.add(record({"C", joinList(copies)}));
  d.w.end();
}

void writeHighSection(StateDump &d)
{
  std::vector<const HighVariable *> highs = d.ids.highs();
  d.w.begin("highs");
  for (size_t i = 0; i < highs.size(); ++i) {
    const HighVariable *h = highs[i];
    std::vector<std::string> members;
    for (size_t k = 0; k < h->inst.size(); ++k) members.push_back(DumpIds::vn(h->inst[k]));
    std::string piece = "-";
    if (h->piece != (VariablePiece *)0) {
      const VariableGroup *g = h->piece->getGroup();
      std::string first = "-";
      if (g != (const VariableGroup *)0 && !g->pieceSet.empty()) first = d.ids.high((*g->pieceSet.begin())->getHigh());
      piece = first + ":" + num(h->piece->getOffset()) + ":" + num(h->piece->getSize()) + ":" +
              num(g == (const VariableGroup *)0 ? 0 : g->getSize()) + ":" +
              num(g == (const VariableGroup *)0 ? 0 : g->getSymbolOffset());
    }
    d.w.add(record({"H", d.ids.high(h), joinList(members), num(h->numMergeClasses), hx(h->highflags), hx(h->flags),
                    d.ids.type(h->type), DumpIds::vn(h->nameRepresentative), d.ids.symbol(h->symbol),
                    num(h->symboloffset), piece}));
  }
  d.w.end();
}

void writeTypeSection(StateDump &d)
{
  d.w.begin("types");
  const std::vector<const Datatype *> &types(d.ids.typeList());
  for (size_t i = 0; i < types.size(); ++i) {
    const Datatype *dt = types[i];
    std::string meta;
    metatype2string(dt->getMetatype(), meta);
    std::ostringstream xml;
    XmlEncode enc(xml, false);
    dt->encode(enc);
    d.w.add(record({"T", "t" + num((intb)i), hx(dt->getId()), meta, num(dt->getSize()), escape(dt->getName()),
                    escape(xml.str())}));
  }
  d.w.end();
}

void writeCSection(StateDump &d)
{
  d.w.begin("c");
  // processing_complete survives Funcdata::clear (funcdata.cc), so it is
  // stale while a function is decompiled a second time; the root action
  // standing mid-way tells such a stop apart from a finished function.
  if (d.fd->isProcComplete() && d.glb->allacts.getCurrent()->getStatus() != Action::status_mid) {
    std::ostringstream c;
    d.glb->print->setOutputStream(&c);
    d.glb->print->docFunction(d.fd);
    d.glb->print->setOutputStream(d.status->fileoptr);
    std::istringstream in(c.str());
    std::string line;
    while (std::getline(in, line)) d.w.add(record({"C", escape(line)}));
  }
  d.w.end();
}

} // namespace bk
