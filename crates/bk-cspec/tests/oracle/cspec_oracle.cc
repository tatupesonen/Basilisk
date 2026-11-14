// Oracle for bk-cspec: evaluates Ghidra's own compiler-specification reader
// and prototype models (architecture.cc, fspec.cc, modelrules.cc, linked from
// the reference build's objects) and prints one record per line. Built and
// run by regen.sh; the output is tests/data/cspec_oracle.txt.gz, replayed by
// tests/oracle_replay.rs. Not part of the Rust build. Compiled with
// -fno-access-control to read private members, -std=c++11.
//
// Usage: cspec_oracle <sleighhome> <signatures.txt> <processors-dir>
//
// Nothing here depends on iteration over pointer-keyed or hash containers:
// pairs come in .ldefs order, models in name order (std::map<string>),
// entries, rules and effects in list order. Every value printed is computed
// in its own statement, so no output depends on the order C++ evaluates
// function arguments.
//
// Records (tab separated; addresses are space-index:hex-offset:size):
//   PAIR   pair cspec-path heavy(0|1)                 | PAIRERR pair message
//   SPACE  pair index name type addrsize wordsize bigendian delay deadcodedelay truncated reversejust
//   DEFSPACE pair code-index data-index
//   REG    pair name addr
//   ORG    pair pointer-size alignmap(csv)
//   SPEC   pair default eval-current eval-called funcptr-align aggressive-trim retaddr
//   SPLIT  pair addr splitoffset
//   GLOBAL pair space-index first last
//   INJ    pair id type name ninputs noutputs paramshift
//   MODEL  pair name extrapop merged alias hasthis construct printed stackneg injentry injreturn
//   LIST   pair model in|out kind numgroup maxdelay thisbefore autokilled resstart fallback
//   ENTRY  pair model in|out idx addr minsize align numslots class groups flags join
//   RULE   pair model in|out idx description
//   SHARED pair model idx description
//   EFFECT pair model kind addr          TRASH/INTERNAL pair model addr
//   LRANGE/PRANGE pair model space first last
//   ASSIGN pair model sig result         (pieces addr/flags/type, or ERR message)
//   TSET   pair model in|out set trials  TRES pair model in|out set result
//   Q      pair model in|out addr size possible slot characterize biggest unjust ext
//   EFF    pair model addr size effect
//   JOIN   pair model in|out hi lo result   SPLITQ pair model in|out entry result

#include "architecture.hh"
#include "grammar.hh"
#include "libdecomp.hh"
#include "sleigh_arch.hh"

#include <fstream>
#include <iostream>
#include <set>
#include <sstream>

using namespace std;
using namespace ghidra;

namespace {

string mname(type_metatype m) {
  string res;
  metatype2string(m, res);
  return res;
}

string esc(const string &s) {
  string out;
  for (char c : s) {
    if (c == '\t') out += "\\t";
    else if (c == '\n') out += "\\n";
    else if (c == '\\') out += "\\\\";
    else out += c;
  }
  return out;
}

string hexs(uintb v) {
  ostringstream s;
  s << hex << v;
  return s.str();
}

string addr(AddrSpace *spc, uintb off, int4 size) {
  if (spc == (AddrSpace *)0) return "-";
  string res = to_string(spc->getIndex());
  res += ':';
  res += hexs(off);
  res += ':';
  res += to_string(size);
  return res;
}

string vn(const VarnodeData &v) { return addr(v.space, v.offset, v.size); }

Architecture *build(const string &id) {
  ArchitectureCapability *cap = ArchitectureCapability::getCapability("xml");
  istringstream s("<binaryimage arch=\"" + id + "\"></binaryimage>");
  DocumentStorage store;
  Document *doc = store.parseDocument(s);
  store.registerTag(doc->getRoot());
  ostringstream err;
  Architecture *g = cap->buildArchitecture("", "", &err);
  g->init(store);
  return g;
}

string desc(Datatype *dt) {
  type_metatype m = dt->getMetatype();
  string sz = to_string(dt->getSize());
  if (m == TYPE_PTR) {
    string inner = desc(((TypePointer *)dt)->getPtrTo());
    return "ptr" + sz + "(" + inner + ")";
  }
  if (m == TYPE_ARRAY) {
    TypeArray *a = (TypeArray *)dt;
    string inner = desc(a->getBase());
    string n = to_string(a->numElements());
    return "array" + sz + "(" + inner + "x" + n + ")";
  }
  if (m == TYPE_STRUCT || m == TYPE_UNION) {
    string nm = mname(m);
    return nm + sz + ":" + dt->getName();
  }
  if (m == TYPE_VOID) return "void";
  string nm = mname(m);
  return nm + sz;
}

// ---- rule descriptions (mirrored by the Rust replay) ----

string sizeDesc(const SizeRestrictedFilter *f) {
  string res = "[" + to_string(f->minSize) + "," + to_string(f->maxSize) + ",{";
  bool first = true;
  for (int4 s : f->sizes) {
    if (!first) res += ' ';
    res += to_string(s);
    first = false;
  }
  return res + "}]";
}

string filterDesc(const DatatypeFilter *f) {
  if (const HomogeneousAggregate *h = dynamic_cast<const HomogeneousAggregate *>(f)) {
    string m = mname(h->metaType);
    return "homog:" + m + ":" + to_string(h->maxPrimitives) + sizeDesc(h);
  }
  if (const ArrayFilter *a = dynamic_cast<const ArrayFilter *>(f)) {
    string el = "el[" + to_string(a->minElements) + "," + to_string(a->maxElements) + "]";
    return "array" + sizeDesc(a) + el;
  }
  if (const MetaTypeFilter *m = dynamic_cast<const MetaTypeFilter *>(f)) {
    string nm = mname(m->metaType);
    return "meta:" + nm + sizeDesc(m);
  }
  const SizeRestrictedFilter *s = dynamic_cast<const SizeRestrictedFilter *>(f);
  return "any" + sizeDesc(s);
}

string qualDesc(const QualifierFilter *q) {
  if (const AndFilter *a = dynamic_cast<const AndFilter *>(q)) {
    string res = "and(";
    for (size_t i = 0; i < a->subQualifiers.size(); ++i) {
      if (i) res += ',';
      res += qualDesc(a->subQualifiers[i]);
    }
    return res + ")";
  }
  if (const VarargsFilter *v = dynamic_cast<const VarargsFilter *>(q))
    return "varargs(" + to_string(v->firstPos) + "," + to_string(v->lastPos) + ")";
  if (const PositionMatchFilter *p = dynamic_cast<const PositionMatchFilter *>(q))
    return "pos(" + to_string(p->position) + ")";
  const DatatypeMatchFilter *d = dynamic_cast<const DatatypeMatchFilter *>(q);
  string inner = filterDesc(d->typeFilter);
  return "at(" + to_string(d->position) + "," + inner + ")";
}

int4 entryIndex(const ParamListStandard *list, const ParamEntry *e) {
  if (e == (const ParamEntry *)0) return -1;
  int4 i = 0;
  for (std::list<ParamEntry>::const_iterator it = list->entry.begin(); it != list->entry.end(); ++it, ++i)
    if (&(*it) == e) return i;
  return -2;
}

string tilesDesc(const ParamListStandard *list, const vector<const ParamEntry *> &tiles) {
  string res = "{";
  for (size_t i = 0; i < tiles.size(); ++i) {
    if (i) res += ' ';
    res += to_string(entryIndex(list, tiles[i]));
  }
  return res + "}";
}

string b(bool v) { return v ? "1" : "0"; }

string actionDesc(const ParamListStandard *list, const AssignAction *a) {
  if (const GotoStack *g = dynamic_cast<const GotoStack *>(a))
    return "goto_stack(" + to_string(entryIndex(list, g->stackEntry)) + ")";
  if (const ConvertToPointer *c = dynamic_cast<const ConvertToPointer *>(a))
    return "convert_to_ptr(" + (c->space == (AddrSpace *)0 ? string("-1") : to_string(c->space->getIndex())) + ")";
  if (const MultiSlotAssign *m = dynamic_cast<const MultiSlotAssign *>(a)) {
    string res = "join(" + to_string((int)m->resourceType) + "," + b(m->isBigEndian) + b(m->consumeFromStack) +
      b(m->consumeMostSig) + b(m->enforceAlignment) + b(m->justifyRight) + b(m->allowBackfill) + ",";
    string tiles = tilesDesc(list, m->tiles);
    string st = to_string(entryIndex(list, m->stackEntry));
    return res + tiles + "," + st + ")";
  }
  if (const MultiMemberAssign *m = dynamic_cast<const MultiMemberAssign *>(a)) {
    string st = to_string(entryIndex(list, m->stackEntry));
    return "join_per_primitive(" + to_string((int)m->resourceType) + "," + b(m->isRecursive) +
      b(m->consumeFromStack) + b(m->consumeMostSig) + "," + st + ")";
  }
  if (const MultiSlotDualAssign *m = dynamic_cast<const MultiSlotDualAssign *>(a)) {
    string res = "join_dual_class(" + to_string((int)m->baseType) + "," + to_string((int)m->altType) + "," +
      b(m->isBigEndian) + b(m->consumeFromStack) + b(m->consumeMostSig) + b(m->justifyRight) + b(m->fillAlternate) +
      "," + to_string(m->tileSize) + ",";
    string bt = tilesDesc(list, m->baseTiles);
    string at = tilesDesc(list, m->altTiles);
    string st = to_string(entryIndex(list, m->stackEntry));
    return res + bt + "," + at + "," + st + ")";
  }
  if (const ConsumeAs *c = dynamic_cast<const ConsumeAs *>(a))
    return "consume(" + to_string((int)c->resourceType) + ")";
  if (const HiddenReturnAssign *h = dynamic_cast<const HiddenReturnAssign *>(a))
    return "hidden_return(" + to_string(h->retCode) + ")";
  if (const ConsumeExtra *c = dynamic_cast<const ConsumeExtra *>(a)) {
    string tiles = tilesDesc(list, c->tiles);
    return "consume_extra(" + to_string((int)c->resourceType) + "," + b(c->matchSize) + "," + tiles + ")";
  }
  if (const ExtraStack *e = dynamic_cast<const ExtraStack *>(a)) {
    string st = to_string(entryIndex(list, e->stackEntry));
    return "extra_stack(" + to_string(e->afterBytes) + "," + to_string((int)e->afterStorage) + "," + st + ")";
  }
  const ConsumeRemaining *c = dynamic_cast<const ConsumeRemaining *>(a);
  string tiles = tilesDesc(list, c->tiles);
  return "consume_remaining(" + to_string((int)c->resourceType) + "," + tiles + ")";
}

string ruleDesc(const ParamListStandard *list, const ModelRule &r) {
  string res = filterDesc(r.filter);
  res += " | ";
  res += (r.qualifier == (QualifierFilter *)0) ? string("-") : qualDesc(r.qualifier);
  res += " | ";
  for (size_t i = 0; i < r.preconditions.size(); ++i) {
    if (i) res += ';';
    res += actionDesc(list, r.preconditions[i]);
  }
  res += " | ";
  res += actionDesc(list, r.assign);
  res += " | ";
  for (size_t i = 0; i < r.sideeffects.size(); ++i) {
    if (i) res += ';';
    res += actionDesc(list, r.sideeffects[i]);
  }
  return res;
}

const char *kindName(uint4 t) {
  switch (t) {
    case ParamList::p_standard: return "standard";
    case ParamList::p_standard_out: return "standard_out";
    case ParamList::p_register: return "register";
    case ParamList::p_register_out: return "register_out";
    default: return "merged";
  }
}

// ---- decode dump ----

void dumpList(const string &pair, const string &model, const char *io, const ParamListStandard *list) {
  uint4 kind = list->getType();
  bool merged = (kind == ParamList::p_merged);
  string rs;
  for (size_t i = 0; i < list->resourceStart.size(); ++i) {
    if (i) rs += ',';
    rs += to_string(list->resourceStart[i]);
  }
  string fallback = "-";
  if (kind == ParamList::p_standard_out || kind == ParamList::p_register_out)
    fallback = b(((const ParamListStandardOut *)list)->useFillinFallback);
  // A merged list leaves numgroup, maxdelay and the flags uninitialised.
  string ng = merged ? string("-") : to_string(list->numgroup);
  string md = merged ? string("-") : to_string(list->maxdelay);
  string tb = merged ? string("-") : b(list->thisbeforeret);
  string ak = merged ? string("-") : b(list->autoKilledByCall);
  cout << "LIST\t" << pair << '\t' << model << '\t' << io << '\t' << kindName(kind) << '\t' << ng << '\t' << md
       << '\t' << tb << '\t' << ak << '\t' << (merged ? string("-") : rs) << '\t' << fallback << '\n';
  int4 idx = 0;
  for (std::list<ParamEntry>::const_iterator it = list->entry.begin(); it != list->entry.end(); ++it, ++idx) {
    const ParamEntry &e(*it);
    string groups;
    for (size_t i = 0; i < e.groupSet.size(); ++i) {
      if (i) groups += ',';
      groups += to_string(e.groupSet[i]);
    }
    string join = "-";
    if (e.joinrec != (JoinRecord *)0) {
      join = "";
      for (int4 i = 0; i < e.joinrec->numPieces(); ++i) {
        if (i) join += ',';
        join += vn(e.joinrec->getPiece(i));
      }
    }
    string a = addr(e.spaceid, e.addressbase, e.size);
    cout << "ENTRY\t" << pair << '\t' << model << '\t' << io << '\t' << idx << '\t' << a << '\t' << e.minsize
         << '\t' << e.alignment << '\t' << e.numslots << '\t' << (int)e.type << '\t' << groups << '\t' << e.flags
         << '\t' << join << '\n';
  }
  idx = 0;
  for (std::list<ModelRule>::const_iterator it = list->modelRules.begin(); it != list->modelRules.end(); ++it, ++idx) {
    string d = ruleDesc(list, *it);
    cout << "RULE\t" << pair << '\t' << model << '\t' << io << '\t' << idx << '\t' << esc(d) << '\n';
  }
}

void dumpModel(const string &pair, ProtoModel *m) {
  string name = m->getName();
  string alias = (m->compatModel == (const ProtoModel *)0) ? string("-") : m->compatModel->getName();
  string ie = to_string(m->injectUponEntry);
  string ir = to_string(m->injectUponReturn);
  cout << "MODEL\t" << pair << '\t' << name << '\t' << m->extrapop << '\t' << b(m->isMerged()) << '\t' << alias
       << '\t' << b(m->hasThis) << '\t' << b(m->isConstruct) << '\t' << b(m->isPrinted) << '\t'
       << b(m->stackgrowsnegative) << '\t' << ie << '\t' << ir << '\n';
  dumpList(pair, name, "in", (const ParamListStandard *)m->input);
  dumpList(pair, name, "out", (const ParamListStandard *)m->output);
  for (size_t i = 0; i < m->sharedActions.size(); ++i) {
    const SharedAction *a = m->sharedActions[i];
    string d;
    if (const ShareStackAction *s = dynamic_cast<const ShareStackAction *>(a)) {
      string ins = to_string(entryIndex((const ParamListStandard *)m->input, s->inputStackEntry));
      string outs = to_string(entryIndex((const ParamListStandard *)m->output, s->outputStackEntry));
      d = "sharestack(" + b(s->inputFirst) + "," + to_string(s->extraAlign) + "," + ins + "," + outs + ")";
    }
    else
      d = "hidden_return";
    cout << "SHARED\t" << pair << '\t' << name << '\t' << i << '\t' << d << '\n';
  }
  for (size_t i = 0; i < m->effectlist.size(); ++i) {
    const EffectRecord &e(m->effectlist[i]);
    string a = vn(e.range);
    cout << "EFFECT\t" << pair << '\t' << name << '\t' << e.type << '\t' << a << '\n';
  }
  for (size_t i = 0; i < m->likelytrash.size(); ++i) {
    string a = vn(m->likelytrash[i]);
    cout << "TRASH\t" << pair << '\t' << name << '\t' << a << '\n';
  }
  for (size_t i = 0; i < m->internalstorage.size(); ++i) {
    string a = vn(m->internalstorage[i]);
    cout << "INTERNAL\t" << pair << '\t' << name << '\t' << a << '\n';
  }
  for (set<Range>::const_iterator it = m->localrange.begin(); it != m->localrange.end(); ++it) {
    string s = to_string((*it).getSpace()->getIndex());
    cout << "LRANGE\t" << pair << '\t' << name << '\t' << s << '\t' << hexs((*it).getFirst()) << '\t'
         << hexs((*it).getLast()) << '\n';
  }
  for (set<Range>::const_iterator it = m->paramrange.begin(); it != m->paramrange.end(); ++it) {
    string s = to_string((*it).getSpace()->getIndex());
    cout << "PRANGE\t" << pair << '\t' << name << '\t' << s << '\t' << hexs((*it).getFirst()) << '\t'
         << hexs((*it).getLast()) << '\n';
  }
}

void dumpArch(const string &pair, Architecture *g, const string &cspecText) {
  for (int4 i = 0; i < g->numSpaces(); ++i) {
    AddrSpace *s = g->getSpace(i);
    if (s == (AddrSpace *)0) continue;
    cout << "SPACE\t" << pair << '\t' << i << '\t' << s->getName() << '\t' << (int)s->getType() << '\t'
         << s->getAddrSize() << '\t' << s->getWordSize() << '\t' << b(s->isBigEndian()) << '\t' << s->getDelay()
         << '\t' << s->getDeadcodeDelay() << '\t' << b(s->isTruncated()) << '\t' << b(s->isReverseJustified()) << '\n';
  }
  cout << "DEFSPACE\t" << pair << '\t' << g->getDefaultCodeSpace()->getIndex() << '\t'
       << g->getDefaultDataSpace()->getIndex() << '\n';
  map<VarnodeData, string> regs;
  g->translate->getAllRegisters(regs);
  set<string> named;
  for (map<VarnodeData, string>::const_iterator it = regs.begin(); it != regs.end(); ++it) {
    const string &nm((*it).second);
    if (cspecText.find("\"" + nm + "\"") != string::npos || cspecText.find("=\"" + nm + "\"") != string::npos)
      named.insert(nm);
  }
  const char *extra[] = {"EDI","ESI","DX","DI","RDI","RSI","RDX","RAX","XMM0","XMM1","XMM2","AX","RBX","CL","AL",
    "EBX","DIL","w0","x0","x1","x8","s0","d0","q0","q1","a0","a1","a2","a3","v0","f0","f0_1","f12","f14","f12_13",
    "f14_15","r3","r4","r5","r8","r9","f1","f2","f3","f4","f5","o0","o1","o2","o3","o4","o5","o4_5","o2_3","o0_1",
    "fs0","fs1","fs3","fs5","fs7","fs9","fs11","fd0","fd2","fd4","fd6","fq0","R12","R13","R14","R25R24","R23R22",
    "R21R20","ESI",0};
  for (int4 i = 0; extra[i] != 0; ++i) named.insert(extra[i]);
  for (set<string>::const_iterator it = named.begin(); it != named.end(); ++it) {
    VarnodeData v;
    try { v = g->translate->getRegister(*it); }
    catch (LowlevelError &) { continue; }
    string a = vn(v);
    cout << "REG\t" << pair << '\t' << *it << '\t' << a << '\n';
  }
  string am;
  for (size_t i = 0; i < g->types->alignMap.size(); ++i) {
    if (i) am += ',';
    am += to_string(g->types->alignMap[i]);
  }
  cout << "ORG\t" << pair << '\t' << g->types->getSizeOfPointer() << '\t' << am << '\n';
  string ec = (g->evalfp_current == (ProtoModel *)0) ? string("-") : g->evalfp_current->getName();
  string el = (g->evalfp_called == (ProtoModel *)0) ? string("-") : g->evalfp_called->getName();
  string ra = vn(g->defaultReturnAddr);
  cout << "SPEC\t" << pair << '\t' << g->defaultfp->getName() << '\t' << ec << '\t' << el << '\t' << g->funcptr_align
       << '\t' << b(g->aggressive_ext_trim) << '\t' << ra << '\n';
  for (size_t i = 0; i < g->splitrecords.size(); ++i) {
    string a = vn(g->splitrecords[i].storage);
    cout << "SPLIT\t" << pair << '\t' << a << '\t' << g->splitrecords[i].splitoffset << '\n';
  }
  const RangeList &gr(g->symboltab->getGlobalScope()->getRangeTree());
  for (set<Range>::const_iterator it = gr.begin(); it != gr.end(); ++it) {
    string s = to_string((*it).getSpace()->getIndex());
    cout << "GLOBAL\t" << pair << '\t' << s << '\t' << hexs((*it).getFirst()) << '\t' << hexs((*it).getLast()) << '\n';
  }
  for (size_t i = 0; i < g->pcodeinjectlib->injection.size(); ++i) {
    InjectPayload *p = g->pcodeinjectlib->injection[i];
    cout << "INJ\t" << pair << '\t' << i << '\t' << p->getType() << '\t' << esc(p->getName()) << '\t' << p->sizeInput()
         << '\t' << p->sizeOutput() << '\t' << p->getParamShift() << '\n';
  }
  for (map<string, ProtoModel *>::const_iterator it = g->protoModels.begin(); it != g->protoModels.end(); ++it)
    dumpModel(pair, (*it).second);
}

// ---- heavy tables ----

struct Sig {
  char kind;
  int4 vararg;
  string text;
};

string piecesDesc(const vector<ParameterPieces> &res) {
  string out;
  for (size_t i = 0; i < res.size(); ++i) {
    if (i) out += ' ';
    const ParameterPieces &p(res[i]);
    string a = p.addr.isInvalid() ? string("-") : addr(p.addr.getSpace(), p.addr.getOffset(), p.type->getSize());
    string d = desc(p.type);
    out += a + "/" + to_string(p.flags) + "/" + d;
  }
  return out;
}

void assignTable(const string &pair, Architecture *g, ProtoModel *m, const vector<Sig> &sigs) {
  for (size_t i = 0; i < sigs.size(); ++i) {
    if (sigs[i].kind == 'S') continue;
    string out;
    try {
      PrototypePieces pieces;
      istringstream s(sigs[i].text);
      parse_protopieces(pieces, s, g);
      if (sigs[i].kind == 'V') pieces.firstVarArgSlot = sigs[i].vararg;
      vector<ParameterPieces> res;
      m->assignParameterStorage(pieces, res, false);
      out = piecesDesc(res);
    }
    catch (ParseError &err) { out = "ERR " + err.explain; }
    catch (LowlevelError &err) { out = "ERR " + err.explain; }
    cout << "ASSIGN\t" << pair << '\t' << m->getName() << '\t' << i << '\t' << esc(out) << '\n';
  }
}

struct TrialIn {
  AddrSpace *spc;
  uintb off;
  int4 size;
};

vector<TrialIn> candidates(const ParamListStandard *list, bool output) {
  vector<TrialIn> res;
  for (std::list<ParamEntry>::const_iterator it = list->entry.begin(); it != list->entry.end(); ++it) {
    const ParamEntry &e(*it);
    if (e.joinrec != (JoinRecord *)0) continue;
    if (e.alignment == 0) {
      TrialIn t = {e.spaceid, e.addressbase, e.size};
      res.push_back(t);
      if (output && e.size > 4) {
        uintb off = e.spaceid->isBigEndian() ? e.addressbase + (e.size - 4) : e.addressbase;
        TrialIn h = {e.spaceid, off, 4};
        res.push_back(h);
      }
    }
    else {
      int4 n = e.numslots < 6 ? e.numslots : 6;
      for (int4 k = 0; k < n; ++k) {
        uintb off = e.addressbase + (uintb)(k * e.alignment);
        if ((e.flags & ParamEntry::reverse_stack) != 0)
          off = e.addressbase + (uintb)((e.numslots - 1 - k) * e.alignment);
        TrialIn t = {e.spaceid, off, e.alignment};
        res.push_back(t);
      }
    }
  }
  return res;
}

void runSet(const string &pair, ProtoModel *m, const char *io, int4 setIdx, const vector<TrialIn> &set, bool output) {
  string in;
  for (size_t i = 0; i < set.size(); ++i) {
    if (i) in += ' ';
    in += addr(set[i].spc, set[i].off, set[i].size);
  }
  cout << "TSET\t" << pair << '\t' << m->getName() << '\t' << io << '\t' << setIdx << '\t' << in << '\n';
  string out;
  try {
    ParamActive active(false);
    for (size_t i = 0; i < set.size(); ++i) {
      ParamTrial &t(active.registerTrial(Address(set[i].spc, set[i].off), set[i].size));
      t.markActive();
    }
    if (output) m->deriveOutputMap(&active);
    else m->deriveInputMap(&active);
    const ParamListStandard *list = (const ParamListStandard *)(output ? m->output : m->input);
    for (int4 i = 0; i < active.getNumTrials(); ++i) {
      ParamTrial &t(active.getTrial(i));
      if (i) out += ' ';
      string a = addr(t.getAddress().getSpace(), t.getAddress().getOffset(), t.getSize());
      string e = to_string(entryIndex(list, t.getEntry()));
      out += a + "/" + to_string(t.flags & 0x7ff) + "/" + to_string(t.getSlot()) + "/" + e + "/" + to_string(t.getOffset());
    }
  }
  catch (LowlevelError &err) { out = "ERR " + err.explain; }
  cout << "TRES\t" << pair << '\t' << m->getName() << '\t' << io << '\t' << setIdx << '\t' << esc(out) << '\n';
}

void trialTable(const string &pair, ProtoModel *m, bool output) {
  const char *io = output ? "out" : "in";
  const ParamListStandard *list = (const ParamListStandard *)(output ? m->output : m->input);
  vector<TrialIn> c = candidates(list, output);
  int4 n = c.size();
  int4 idx = 0;
  if (output) {
    for (int4 i = 0; i < n; ++i) {
      vector<TrialIn> s(1, c[i]);
      runSet(pair, m, io, idx++, s, true);
      if (i + 1 < n) {
        s.push_back(c[i + 1]);
        runSet(pair, m, io, idx++, s, true);
      }
    }
    runSet(pair, m, io, idx++, c, true);
    return;
  }
  for (int4 k = 1; k <= n; ++k) {
    vector<TrialIn> s(c.begin(), c.begin() + k);
    runSet(pair, m, io, idx++, s, false);
  }
  for (int4 g = 0; g < n; ++g) {
    vector<TrialIn> s;
    for (int4 i = 0; i < n; ++i) if (i != g) s.push_back(c[i]);
    runSet(pair, m, io, idx++, s, false);
  }
  for (int4 d = 1; d <= 2; ++d) {
    for (int4 g = 0; g + d < n; ++g) {
      vector<TrialIn> s;
      for (int4 i = 0; i < n; ++i) if (i != g && i != g + d) s.push_back(c[i]);
      runSet(pair, m, io, idx++, s, false);
    }
  }
  vector<TrialIn> r(c.rbegin(), c.rend());
  runSet(pair, m, io, idx++, r, false);
}

string extName(OpCode op) {
  switch (op) {
    case CPUI_INT_ZEXT: return "INT_ZEXT";
    case CPUI_INT_SEXT: return "INT_SEXT";
    case CPUI_PIECE: return "PIECE";
    default: return "COPY";
  }
}

void queryTable(const string &pair, ProtoModel *m, bool output) {
  const char *io = output ? "out" : "in";
  const ParamListStandard *list = (const ParamListStandard *)(output ? m->output : m->input);
  set<std::pair<std::pair<int4, uintb>, int4> > seen;
  vector<TrialIn> probes;
  for (std::list<ParamEntry>::const_iterator it = list->entry.begin(); it != list->entry.end(); ++it) {
    const ParamEntry &e(*it);
    vector<VarnodeData> ranges;
    if (e.joinrec != (JoinRecord *)0) {
      for (int4 i = 0; i < e.joinrec->numPieces(); ++i) ranges.push_back(e.joinrec->getPiece(i));
    }
    else {
      VarnodeData v;
      v.space = e.spaceid;
      v.offset = e.addressbase;
      v.size = e.size;
      ranges.push_back(v);
    }
    for (size_t r = 0; r < ranges.size(); ++r) {
      const VarnodeData &v(ranges[r]);
      if (v.space->getType() == IPTR_CONSTANT) continue;
      uintb offs[5] = {v.offset - 1, v.offset, v.offset + 1, v.offset + v.size / 2, v.offset + v.size - 1};
      int4 sizes[5] = {1, 2, 4, 8, (int4)v.size};
      for (int4 i = 0; i < 5; ++i) {
        for (int4 j = 0; j < 5; ++j) {
          uintb off = offs[i] & calc_mask(v.space->getAddrSize());
          std::pair<std::pair<int4, uintb>, int4> key(make_pair(v.space->getIndex(), off), sizes[j]);
          if (!seen.insert(key).second) continue;
          TrialIn t = {v.space, off, sizes[j]};
          probes.push_back(t);
        }
      }
    }
  }
  for (size_t i = 0; i < probes.size(); ++i) {
    Address a(probes[i].spc, probes[i].off);
    int4 sz = probes[i].size;
    string poss = b(list->possibleParam(a, sz));
    int4 slot, slotsize;
    string ws = list->possibleParamWithSlot(a, sz, slot, slotsize) ? to_string(slot) + "," + to_string(slotsize) : string("-");
    string ch = to_string(list->characterizeAsParam(a, sz));
    VarnodeData res;
    string big = list->getBiggestContainedParam(a, sz, res) ? vn(res) : string("-");
    VarnodeData res2;
    string unj = list->unjustifiedContainer(a, sz, res2) ? vn(res2) : string("-");
    VarnodeData res3;
    OpCode op = list->assumedExtension(a, sz, res3);
    string ext = extName(op);
    if (op != CPUI_COPY) ext += " " + vn(res3);
    string pa = addr(probes[i].spc, probes[i].off, sz);
    cout << "Q\t" << pair << '\t' << m->getName() << '\t' << io << '\t' << pa << '\t' << poss << '\t' << ws << '\t'
         << ch << '\t' << big << '\t' << unj << '\t' << ext << '\n';
  }
  // checkJoin over neighbouring entries, checkSplit at half of each entry.
  vector<const ParamEntry *> es;
  for (std::list<ParamEntry>::const_iterator it = list->entry.begin(); it != list->entry.end(); ++it) es.push_back(&(*it));
  for (size_t i = 0; i + 1 < es.size(); ++i) {
    for (int4 dir = 0; dir < 2; ++dir) {
      const ParamEntry *hi = dir ? es[i + 1] : es[i];
      const ParamEntry *lo = dir ? es[i] : es[i + 1];
      if (hi->joinrec != (JoinRecord *)0 || lo->joinrec != (JoinRecord *)0) continue;
      int4 hs = hi->alignment ? hi->alignment : hi->size;
      int4 ls = lo->alignment ? lo->alignment : lo->size;
      string r = b(list->checkJoin(Address(hi->spaceid, hi->addressbase), hs, Address(lo->spaceid, lo->addressbase), ls));
      cout << "JOIN\t" << pair << '\t' << m->getName() << '\t' << io << '\t' << entryIndex(list, hi) << '\t'
           << entryIndex(list, lo) << '\t' << r << '\n';
    }
  }
  for (size_t i = 0; i < es.size(); ++i) {
    const ParamEntry *e = es[i];
    if (e->joinrec != (JoinRecord *)0 || e->size < 2) continue;
    string r = b(list->checkSplit(Address(e->spaceid, e->addressbase), e->size, e->size / 2));
    cout << "SPLITQ\t" << pair << '\t' << m->getName() << '\t' << io << '\t' << i << '\t' << r << '\n';
  }
}

void effectTable(const string &pair, ProtoModel *m) {
  set<std::pair<std::pair<int4, uintb>, int4> > seen;
  vector<TrialIn> probes;
  for (size_t i = 0; i < m->effectlist.size(); ++i) {
    const VarnodeData &v(m->effectlist[i].range);
    int4 sizes[4] = {1, 4, 8, (int4)v.size};
    uintb offs[3] = {v.offset, v.offset + 1, v.offset - 1};
    for (int4 a = 0; a < 3; ++a) {
      for (int4 s = 0; s < 4; ++s) {
        if (sizes[s] == 0) continue;
        uintb off = offs[a] & calc_mask(v.space->getAddrSize());
        std::pair<std::pair<int4, uintb>, int4> key(make_pair(v.space->getIndex(), off), sizes[s]);
        if (!seen.insert(key).second) continue;
        TrialIn t = {v.space, off, sizes[s]};
        probes.push_back(t);
      }
    }
  }
  for (size_t i = 0; i < probes.size(); ++i) {
    uint4 e = m->hasEffect(Address(probes[i].spc, probes[i].off), probes[i].size);
    string pa = addr(probes[i].spc, probes[i].off, probes[i].size);
    cout << "EFF\t" << pair << '\t' << m->getName() << '\t' << pa << '\t' << e << '\n';
  }
}

int run(const string &sigfile, const string &procdir) {
  vector<Sig> sigs;
  {
    ifstream in(sigfile.c_str());
    string line;
    while (getline(in, line)) {
      if (line.empty() || line[0] == '#') continue;
      Sig s;
      s.kind = line[0];
      s.vararg = -1;
      if (s.kind == 'V') {
        size_t sp = line.find(' ', 2);
        s.vararg = atoi(line.substr(2, sp - 2).c_str());
        s.text = line.substr(sp + 1);
      }
      else
        s.text = line.substr(2);
      sigs.push_back(s);
    }
  }
  set<string> heavyDone;
  const vector<LanguageDescription> &descs = SleighArchitecture::getDescriptions();
  for (size_t di = 0; di < descs.size(); ++di) {
    const LanguageDescription &d(descs[di]);
    for (int4 c = 0; c < d.numCompilers(); ++c) {
      const CompilerTag &tag(d.getCompiler(c));
      string pair = d.getId() + ":" + tag.getId();
      string spec = tag.getSpec();
      Architecture *g = (Architecture *)0;
      try {
        g = build(pair);
      }
      catch (LowlevelError &err) { cout << "PAIRERR\t" << pair << '\t' << esc(err.explain) << '\n'; continue; }
      catch (DecoderError &err) { cout << "PAIRERR\t" << pair << '\t' << esc(err.explain) << '\n'; continue; }
      bool heavy = heavyDone.insert(spec).second;
      cout << "PAIR\t" << pair << '\t' << esc(spec) << '\t' << b(heavy) << '\n';
      string text;
      {
        ifstream in((procdir + "/" + spec).c_str());
        ostringstream s;
        s << in.rdbuf();
        text = s.str();
      }
      dumpArch(pair, g, text);
      if (heavy) {
        for (size_t i = 0; i < sigs.size(); ++i) {
          if (sigs[i].kind != 'S') continue;
          try {
            istringstream s(sigs[i].text);
            parse_C(g, s);
          }
          catch (ParseError &err) { cout << "SERR\t" << pair << '\t' << i << '\t' << esc(err.explain) << '\n'; }
          catch (LowlevelError &err) { cout << "SERR\t" << pair << '\t' << i << '\t' << esc(err.explain) << '\n'; }
        }
        for (map<string, ProtoModel *>::const_iterator it = g->protoModels.begin(); it != g->protoModels.end(); ++it) {
          ProtoModel *m = (*it).second;
          if (m->getAliasParent() != (const ProtoModel *)0) continue;
          assignTable(pair, g, m, sigs);
          trialTable(pair, m, false);
          trialTable(pair, m, true);
          queryTable(pair, m, false);
          queryTable(pair, m, true);
          effectTable(pair, m);
        }
      }
      delete g;
    }
  }
  return 0;
}

}  // namespace

int main(int argc, char **argv) {
  if (argc < 4) {
    cerr << "usage: cspec_oracle <sleighhome> <signatures.txt> <processors-dir>\n";
    return 2;
  }
  startDecompilerLibrary(argv[1]);
  return run(argv[2], argv[3]);
}
