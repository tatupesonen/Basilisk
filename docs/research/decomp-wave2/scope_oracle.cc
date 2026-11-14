// Prototype oracle for D06 (decomp-symbols): Ghidra's ScopeInternal and
// Database over generated symbol sets.  Each case builds a fresh Database
// (global scope plus up to three namespaces) on the x86-64 architecture of a
// data test, fills it with generated symbols through the public methods and
// through <mapsym> decoding, applies mutations, and records every query's
// answer.  Usage: scope_oracle SLEIGHHOME datatest.xml SEED CASES
//
// The random generator is xorshift64* written out here (no std::
// distributions), so the same seed gives the same cases with every C++
// library.  Rows are tab-separated; the first field is the case number.
#include "libdecomp.hh"
#include "xml_arch.hh"
#include "database.hh"
#include "funcdata.hh"

#include <sstream>
#include <iostream>
using std::cout; using std::cerr; using std::endl;

using namespace ghidra;

static uint8 rs;
static uint8 rnd(void) { rs ^= rs >> 12; rs ^= rs << 25; rs ^= rs >> 27; return rs * 0x2545F4914F6CDD1DULL; }
static uint4 r(uint4 n) { return (uint4)(rnd() % n); }

static Architecture *conf;
static ostringstream warn;
static int4 kase;
static AddrSpace *ram, *stk;
static vector<Scope *> scopes;		// 0 = global
static vector<Symbol *> syms;		// every live symbol we made (may contain removed: null)

static string esc(const string &s)
{
  string res;
  for(int4 i=0;i<s.size();++i) {
    char c = s[i];
    if (c == '\n') res += "\\n";
    else if (c == '\t') res += "\\t";
    else res += c;
  }
  return res;
}

static void row(const string &kind,const string &text)
{
  cout << kase << '\t' << kind << '\t' << esc(text) << '\n';
  string w = warn.str();
  if (!w.empty()) { cout << kase << "\tW\t" << esc(w) << '\n'; warn.str(""); }
}

static string addrStr(const Address &a)
{
  if (a.isInvalid()) return "-";
  ostringstream s;
  s << a.getSpace()->getName() << ":0x" << hex << a.getOffset();
  return s.str();
}

static string symStr(const Symbol *sym)
{
  if (sym == (const Symbol *)0) return "-";
  ostringstream s;
  s << "s" << hex << sym->getId() << dec << ':' << sym->getName() << ':' << sym->getScope()->getName()
    << ":f" << hex << sym->getFlags() << ":d" << sym->getDisplayFormat() << dec << ":c" << sym->getCategory()
    << ':' << sym->getCategoryIndex() << ":t" << sym->getType()->getSize();
  return s.str();
}

static string entryStr(const MapEntry *e)
{
  if (e == (const MapEntry *)0) return "-";
  ostringstream s;
  s << symStr(e->getSymbol()) << '@' << addrStr(e->getAddr()) << ':' << e->getSize() << ":o" << e->getOffset()
    << ":x" << hex << e->getAllFlags() << dec << ":u";
  e->getUseLimit().printBounds(s);
  return s.str();
}

static Datatype *randType(void)
{
  static const int4 sizes[] = { 1, 2, 4, 8, 16, 3 };
  int4 sz = sizes[r(6)];
  if (sz <= 8 && sz != 3) return conf->types->getBase(sz,TYPE_UNKNOWN);
  return conf->types->getTypeArray(sz,conf->types->getBase(1,TYPE_UNKNOWN));
}

static Address randData(void)
{
  if (r(4) == 0) return Address(stk,0xffffffffffffffc0ULL + r(0x20));
  return Address(ram,0x1000 + r(0x80));
}

static Address randUse(void)
{
  if (r(3) == 0) return Address();
  return Address(ram,0x400000 + r(0x40));
}

static const char *names[] = { "a", "b", "sym", "sym_00", "sym_01", "Var1", "x", "lab", "f" };

static string randName(void) { return names[r(9)]; }

static Scope *randScope(void) { return scopes[r(scopes.size())]; }

static void addDecoded(Scope *sc)
{
  // A <mapsym> with a <symbol> and one map entry whose use limit has 1-3 ranges
  ostringstream xml;
  XmlEncode enc(xml);
  Datatype *ct = randType();
  Address a = randData();
  enc.openElement(ELEM_MAPSYM);
  enc.openElement(ELEM_SYMBOL);
  enc.writeString(ATTRIB_NAME,randName());
  if (r(2)) enc.writeBool(ATTRIB_TYPELOCK,true);
  if (r(3)==0) enc.writeBool(ATTRIB_NAMELOCK,true);
  if (r(4)==0) enc.writeBool(ATTRIB_READONLY,true);
  enc.writeSignedInteger(ATTRIB_CAT,-1);
  ct->encodeRef(enc);
  enc.closeElement(ELEM_SYMBOL);
  a.encode(enc);
  enc.openElement(ELEM_RANGELIST);
  int4 n = r(4);
  for(int4 i=0;i<n;++i) {
    uintb f = 0x400000 + r(0x40);
    enc.openElement(ELEM_RANGE);
    enc.writeSpace(ATTRIB_SPACE,ram);
    enc.writeUnsignedInteger(ATTRIB_FIRST,f);
    enc.writeUnsignedInteger(ATTRIB_LAST,f + r(8));
    enc.closeElement(ELEM_RANGE);
  }
  enc.closeElement(ELEM_RANGELIST);
  enc.closeElement(ELEM_MAPSYM);
  istringstream is(xml.str());
  Document *doc = xml_tree(is);
  XmlDecode dec(conf,doc->getRoot());
  Symbol *sym = sc->addMapSym(dec);
  delete doc;
  if (sym != (Symbol *)0) syms.push_back(sym);
  row("+mapsym",symStr(sym) + " " + xml.str());
}

static void build(void)
{
  Database *db = new Database(conf,true);
  ScopeInternal *glob = new ScopeInternal(0,"",conf);
  db->attachScope(glob,(Scope *)0);
  delete conf->symboltab;
  conf->symboltab = db;
  scopes.clear(); syms.clear();
  scopes.push_back(glob);
  if (r(2)) db->addRange(glob,ram,0,ram->getHighest());
  else db->addRange(glob,ram,0x1000,0x103f);
  row("global",r(2) ? "" : "");
  int4 nns = r(4);
  static const char *paths[] = { "ns1::x", "ns2::x", "ns1::ns3::x" };
  for(int4 i=0;i<nns;++i) {
    string base;
    Scope *ns = db->findCreateScopeFromSymbolName(paths[i],base,(Scope *)0);
    bool seen = false;
    for(int4 j=0;j<scopes.size();++j) if (scopes[j]==ns) seen = true;
    if (!seen) scopes.push_back(ns);
    // ancestors created on the way
    Scope *p = ns->getParent();
    while(p != (Scope *)0) { bool s2=false; for(int4 j=0;j<scopes.size();++j) if (scopes[j]==p) s2=true; if (!s2) scopes.push_back(p); p = p->getParent(); }
    int4 nr = r(3);
    for(int4 k=0;k<nr;++k) {
      uintb f = 0x1000 + r(0x80);
      if (r(3)==0) { uintb s1 = 0xffffffffffffffc0ULL + r(0x10); uintb s2 = 0xffffffffffffffcfULL + r(0x10); db->addRange(ns,stk,s1,s2); }
      else db->addRange(ns,ram,f,f + r(0x30));
    }
    ostringstream s; s << ns->getFullName() << " id=0x" << hex << ns->getId() << ' ';
    ns->printBounds(s);
    row("scope",s.str());
  }
  int4 nprop = r(3);
  for(int4 i=0;i<nprop;++i) {
    uintb f = 0x1000 + r(0x80);
    uint4 fl = r(2) ? Varnode::readonly : Varnode::volatil;
    Range rng(ram,f,f + r(0x20));
    if (r(4)==0) db->clearPropertyRange(fl,rng); else db->setPropertyRange(fl,rng);
    ostringstream s; s << hex << fl << ' ' << f; row("prop",s.str());
  }
}

static void populate(void)
{
  int4 n = 1 + r(40);
  for(int4 i=0;i<n;++i) {
    Scope *sc = randScope();
    try {
      switch(r(9)) {
      case 0: case 1: case 2: {
	Address a = randData(); Address u = randUse();
	string nm = randName(); Datatype *ct = randType();
	MapEntry *e = sc->addSymbol(nm,ct,a,u);
	syms.push_back(e->getSymbol());
	row("+sym",entryStr(e) + " use=" + addrStr(u));
	break;
      }
      case 3: {
	Address a(ram,0x1000 + r(0x80));
	FunctionSymbol *f = sc->addFunction(a,randName());
	syms.push_back(f);
	f->getFunction();		// instantiate now: creates the local scope (child, id = symbol id)
	row("+func",symStr(f) + " " + addrStr(a));
	break;
      }
      case 4: {
	Address a(ram,0x1000 + r(0x80));
	LabSymbol *l = sc->addCodeLabel(a,randName());
	syms.push_back(l);
	row("+label",symStr(l));
	break;
      }
      case 5: {
	Address a(ram,0x1000 + r(0x80)); Address ref(ram,0x1000 + r(0x80));
	ExternRefSymbol *x = sc->addExternalRef(a,ref,r(2) ? randName() : string());
	syms.push_back(x);
	row("+extref",symStr(x) + " ref=" + addrStr(ref));
	break;
      }
      case 6: {
	string nm = randName(); uint4 fmt = r(6); uintb val = rnd() & 0xff; Address u = randUse(); uint8 h = rnd();
	Symbol *q = sc->addEquateSymbol(nm,fmt,val,u,h);
	syms.push_back(q);
	row("+equate",symStr(q));
	break;
      }
      case 7: addDecoded(sc); break;
      case 8: {
	if (syms.empty()) break;
	Symbol *s = syms[r(syms.size())];
	if (s == (Symbol *)0) break;
	if (dynamic_cast<FunctionSymbol *>(s) != 0) break;
	Address a = randData(); Address u = randUse();
	MapEntry *e = s->getScope()->addMapPoint(s,a,u);
	row("+map",entryStr(e) + (s->isMultiEntry() ? " multi" : ""));
	break;
      }
      }
    }
    catch(LowlevelError &err) { row("!add",err.explain); }
  }
}

static void mutate(void)
{
  int4 n = r(8);
  for(int4 i=0;i<n;++i) {
    if (syms.empty()) return;
    int4 k = r(syms.size());
    Symbol *s = syms[k];
    if (s == (Symbol *)0) continue;
    Scope *sc = s->getScope();
    try {
      switch(r(6)) {
      case 0: { string nm = randName(); sc->renameSymbol(s,nm); row("rename",symStr(s)); break; }
      case 1: { if (dynamic_cast<FunctionSymbol *>(s)!=0 || s->getCategory()==Symbol::equate) break; sc->retypeSymbol(s,randType()); row("retype",symStr(s)); break; }
      case 2: { if (dynamic_cast<FunctionSymbol *>(s)!=0) break; row("remove",symStr(s)); sc->removeSymbol(s); syms[k] = (Symbol *)0; break; }
      case 3: { sc->setAttribute(s,Varnode::typelock); row("lock",symStr(s)); break; }
      case 4: { sc->clearAttribute(s,Varnode::namelock|Varnode::typelock); row("unlock",symStr(s)); break; }
      case 5: { if (s->getCategory()==Symbol::equate) break; sc->setCategory(s,0,r(3)); row("cat",symStr(s)); break; }
      }
    }
    catch(LowlevelError &err) { row("!mut",err.explain); }
    catch(RecovError &err) { row("!mut",err.explain); }
  }
}

static void query(void)
{
  int4 n = 40;
  for(int4 i=0;i<n;++i) {
    Scope *sc = randScope();
    Address a = randData(); int4 sz = 1 + r(8); Address u = randUse();
    ostringstream q; q << sc->getName() << ' ' << addrStr(a) << ' ' << sz << ' ' << addrStr(u) << " -> ";
    try {
      switch(r(13)) {
      case 0: row("queryByAddr",q.str() + entryStr(sc->queryByAddr(a,u))); break;
      case 1: row("queryContainer",q.str() + entryStr(sc->queryContainer(a,sz,u))); break;
      case 2: { uint4 fl = 0; MapEntry *e = sc->queryProperties(a,sz,u,fl); ostringstream s; s << hex << fl; row("queryProperties",q.str() + entryStr(e) + " flags=" + s.str()); break; }
      case 3: row("findAddr",q.str() + entryStr(sc->findAddr(a,u))); break;
      case 4: row("findContainer",q.str() + entryStr(sc->findContainer(a,sz,u))); break;
      case 5: row("findClosestFit",q.str() + entryStr(sc->findClosestFit(a,sz,u))); break;
      case 6: row("findOverlap",q.str() + entryStr(sc->findOverlap(a,sz))); break;
      case 7: row("findSymbolBefore",q.str() + entryStr(sc->findSymbolBefore(a,u))); break;
      case 8: row("findSymbolAfter",q.str() + entryStr(sc->findSymbolAfter(a,u))); break;
      case 9: { Funcdata *fd = sc->queryFunction(a); row("queryFunction",q.str() + (fd ? fd->getName() + "@" + addrStr(fd->getAddress()) : string("-"))); break; }
      case 10: { LabSymbol *l = sc->queryCodeLabel(a); row("queryCodeLabel",q.str() + symStr(l)); break; }
      case 11: { Funcdata *fd = sc->queryExternalRefFunction(a); row("queryExternalRefFunction",q.str() + (fd ? fd->getName() : string("-"))); break; }
      case 12: { Scope *d = sc->discoverScope(a,sz,u); const Scope *m = conf->symboltab->mapScope(sc,a,u);
	  row("discoverScope",q.str() + (d ? d->getFullName() + "|" + d->getName() : string("-")) + " map=" + (m ? m->getName() : string("-"))); break; }
      }
    }
    catch(LowlevelError &err) { row("!query",err.explain); }
  }
  for(int4 i=0;i<12;++i) {
    Scope *sc = randScope();
    string nm = randName();
    try {
      switch(r(5)) {
      case 0: { vector<Symbol *> res; sc->queryByName(nm,res); ostringstream s; s << sc->getName() << ' ' << nm << " ->"; for(int4 j=0;j<res.size();++j) s << ' ' << symStr(res[j]); row("queryByName",s.str()); break; }
      case 1: row("isNameUsed",sc->getName() + " " + nm + " -> " + (sc->isNameUsed(nm,(const Scope *)0) ? "1" : "0")); break;
      case 2: row("makeNameUnique",sc->getName() + " " + nm + " -> " + sc->makeNameUnique(nm)); break;
      case 3: row("buildUndefinedName",sc->getName() + " -> " + sc->buildUndefinedName()); break;
      case 4: { string base; static const char *full[] = { "ns1::a", "ns1::ns3::b", "::x", "ns9::y", "ns2::f", "a" };
	  string fn = full[r(6)]; Scope *rs2 = conf->symboltab->resolveScopeFromSymbolName(fn,base,sc);
	  row("resolveScopeFromSymbolName",sc->getName() + " " + fn + " -> " + (rs2 ? rs2->getFullName() + "|" + base : string("-"))); break; }
      }
    }
    catch(LowlevelError &err) { row("!name",err.explain); }
  }
  for(int4 i=0;i<6;++i) {
    if (syms.empty()) break;
    Symbol *s = syms[r(syms.size())];
    if (s == (Symbol *)0) continue;
    Scope *use = randScope();
    ostringstream d; d << symStr(s) << " in " << use->getName() << " -> " << s->getResolutionDepth(use);
    row("depth",d.str());
  }
  for(int4 i=0;i<6;++i) {
    Scope *sc = scopes[0];
    Address a = randData(); Address u = randUse();
    static const uint4 fls[] = { 0, Varnode::addrtied, Varnode::persist, Varnode::input, Varnode::addrtied|Varnode::persist, Varnode::indirect_creation };
    uint4 fl = fls[r(6)];
    int4 index = r(3);
    Datatype *ct = r(4) ? randType() : (Datatype *)0;
    string nm = sc->buildVariableName(a,u,ct,index,fl);
    ostringstream s; s << addrStr(a) << ' ' << hex << fl << dec << " -> " << nm << " index=" << index;
    row("buildVariableName",s.str());
  }
}

static void dump(void)
{
  for(int4 i=0;i<scopes.size();++i) {
    ostringstream s;
    scopes[i]->printEntries(s);
    row("print",s.str());
    // An instantiated FunctionSymbol encodes its Funcdata (<function>, D07's),
    // which crashes without a prototype model (FuncProto::encode reads a null
    // model).  Hide the Funcdata so the symbol encodes as <functionshell>.
    vector<pair<FunctionSymbol *,Funcdata *> > hidden;
    for(int4 j=0;j<syms.size();++j) {
      FunctionSymbol *f = dynamic_cast<FunctionSymbol *>(syms[j]);
      if (f != (FunctionSymbol *)0 && f->fd != (Funcdata *)0) { hidden.push_back(make_pair(f,f->fd)); f->fd = (Funcdata *)0; }
    }
    ostringstream x;
    XmlEncode enc(x);
    scopes[i]->encode(enc);
    for(int4 j=0;j<hidden.size();++j) hidden[j].first->fd = hidden[j].second;
    row("xml",x.str());
    ScopeInternal *si = (ScopeInternal *)scopes[i];
    ostringstream m;
    for(set<Symbol *>::const_iterator it=si->beginMultiEntry();it!=si->endMultiEntry();++it) m << symStr(*it) << ' ';
    row("multi",m.str());
    ostringstream c;
    for(int4 j=0;j<si->category.size();++j) {
      c << '[' << j << ':';
      for(int4 k=0;k<si->category[j].size();++k) c << ' ' << symStr(si->category[j][k]);
      c << ']';
    }
    row("cats",c.str());
  }
  ostringstream p;
  const partmap<Address,uint4> &props(conf->symboltab->getProperties());
  for(partmap<Address,uint4>::const_iterator it=props.begin();it!=props.end();++it) p << addrStr((*it).first) << '=' << hex << (*it).second << dec << ' ';
  row("props",p.str());
}

int main(int argc,char **argv)
{
  if (argc != 5) { cerr << "usage: scope_oracle SLEIGHHOME datatest.xml SEED CASES" << endl; return 2; }
  startDecompilerLibrary(argv[1]);
  DocumentStorage store;
  Document *doc = store.openDocument(argv[2]);
  const List &list(doc->getRoot()->getChildren());
  for(List::const_iterator it=list.begin();it!=list.end();++it)
    if ((*it)->getName() == "binaryimage") store.registerTag(*it);
  conf = ArchitectureCapability::getCapability("xml")->buildArchitecture("test","",&warn);
  conf->init(store);
  warn.str("");
  ram = conf->getSpaceByName("ram");
  stk = conf->getStackSpace();
  rs = strtoull(argv[3],0,0) | 1;
  int4 cases = atoi(argv[4]);
  for(kase=0;kase<cases;++kase) {
    try {
      build();
      populate();
      mutate();
      query();
      dump();
    }
    catch(LowlevelError &err) { row("!case",err.explain); }
    catch(RecovError &err) { row("!case",err.explain); }
  }
  return 0;
}
