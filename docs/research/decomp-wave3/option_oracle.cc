// Prototype oracle for D07 (decomp-core): every option of Ghidra's
// OptionDatabase (options.cc) applied to an architecture, with the
// configuration it leaves behind.
//
// usage: option_oracle SLEIGHHOME datatest.xml FUNCADDR SEED CASES
//   e.g. option_oracle REF DT/elseif.xml 0x1006ca 1 3000
//
// The architecture is a data test's; one function "f" exists at FUNCADDR so
// that the options naming a function have something to change.  A case is a
// short sequence of option commands from the default state.  The first
// cases are directed (every option with every value of a pool as its first
// parameter, then pairs); the rest are random sequences.
//
// Rows (tab separated; first field the case number, -1 for the header):
//   H  format
//   (directed cases: 42 names x pool, then 11 two-parameter options x 20 x pool)
//   I  one row per key of the initial state: key=value
//   O  option name, p1, p2, p3 ('-' for empty), outcome class
//      (ok | parse | recov | lowlevel | skip), the returned or thrown text,
//      then the keys whose value changed, as key=value separated by blanks
//   R  the keys Architecture::resetDefaults() changed back after the case
//   U  the keys that still differ from the initial state after
//      resetDefaults() (the oracle then restores them itself)
//
// "skip": the command would dereference a null root action in Ghidra (the
// current root is empty); it is not executed.
#include "libdecomp.hh"
#include "xml_arch.hh"
#include "printc.hh"
#include "sleigh.hh"

#include <sstream>
#include <iostream>
using std::cout; using std::cerr; using std::endl;

using namespace ghidra;

static uint8 rs;
static uint8 rnd(void) { rs ^= rs >> 12; rs ^= rs << 25; rs ^= rs >> 27; return rs * 0x2545F4914F6CDD1DULL; }
static uint4 r(uint4 n) { return (uint4)(rnd() % n); }

static Architecture *conf;
static Funcdata *fd;
static int4 kase;
typedef map<string,string> State;

static string num(intb v) { ostringstream s; s << v; return s.str(); }
static string hx(uintb v) { ostringstream s; s << "0x" << hex << v; return s.str(); }

static uint4 fnv(const string &t)
{
  uint4 h = 0x811c9dc5;
  for(uint4 i=0;i<t.size();++i) { h ^= (uint1)t[i]; h *= 0x01000193; }
  return h;
}

static void walkRules(Action *a,const string &path,string &disabled,string &warned)
{
  string p = path.empty() ? a->getName() : path + ":" + a->getName();
  if ((a->flags & Action::rule_warnings_on) != 0) { warned += (warned.empty() ? "" : ","); warned += p; }
  ActionGroup *g = dynamic_cast<ActionGroup *>(a);
  if (g != (ActionGroup *)0) {
    for(uint4 i=0;i<g->list.size();++i) walkRules(g->list[i],p,disabled,warned);
    return;
  }
  ActionPool *pool = dynamic_cast<ActionPool *>(a);
  if (pool != (ActionPool *)0) {
    for(uint4 i=0;i<pool->allrules.size();++i) {
      Rule *rl = pool->allrules[i];
      if (rl->isDisabled()) { disabled += (disabled.empty() ? "" : ","); disabled += p + ":" + rl->getName(); }
      if ((rl->flags & Rule::warnings_on) != 0) { warned += (warned.empty() ? "" : ","); warned += p + ":" + rl->getName(); }
    }
  }
}

static void capture(State &st)
{
  st.clear();
  st["trim"] = num(conf->trim_recurse_max);
  st["implied"] = num(conf->max_implied_ref);
  st["termdup"] = num(conf->max_term_duplication);
  st["basetype"] = num(conf->max_basetype_size);
  st["flow"] = hx(conf->flowoptions);
  st["maxinstr"] = num(conf->max_instructions);
  st["baddata"] = hx(conf->max_baddata);
  st["inferptr"] = num(conf->infer_pointers);
  st["forloops"] = num(conf->analyze_for_loops);
  st["readonly"] = num(conf->readonlypropagate);
  st["nanall"] = num(conf->nan_ignore_all);
  st["nancmp"] = num(conf->nan_ignore_compare);
  st["alias"] = num(conf->alias_block_level);
  st["split"] = num(conf->split_datatype_config);
  st["jumpmax"] = num(conf->max_jumptable_size);
  st["default"] = conf->defaultfp->getName();
  st["evalcur"] = (conf->evalfp_current == (ProtoModel *)0) ? "-" : conf->evalfp_current->getName();
  st["evalcalled"] = (conf->evalfp_called == (ProtoModel *)0) ? "-" : conf->evalfp_called->getName();
  for(map<string,ProtoModel *>::const_iterator it=conf->protoModels.begin();it!=conf->protoModels.end();++it) {
    st["m." + (*it).first + ".extrapop"] = num((*it).second->getExtraPop());
    st["m." + (*it).first + ".printed"] = num((*it).second->printInDecl());
  }
  st["f.flags"] = hx(fd->getFuncProto().flags);
  st["f.extrapop"] = num(fd->getFuncProto().getExtraPop());
  st["root"] = conf->allacts.getCurrentName();
  Action *cur = conf->allacts.getCurrent();
  if (cur == (Action *)0) {
    st["act"] = "null";
    st["disabled"] = "-";
    st["warned"] = "-";
  }
  else {
    ostringstream s;
    cur->print(s,0,0);
    string t = s.str();
    int4 lines = 0;
    for(uint4 i=0;i<t.size();++i) if (t[i] == '\n') lines += 1;
    st["act"] = num(lines) + ":" + hx(fnv(t));
    string disabled,warned;
    walkRules(cur,"",disabled,warned);
    st["disabled"] = disabled.empty() ? "-" : disabled;
    st["warned"] = warned.empty() ? "-" : warned;
  }
  for(map<string,ActionGroupList>::const_iterator it=conf->allacts.groupmap.begin();it!=conf->allacts.groupmap.end();++it) {
    string g;
    for(set<string>::const_iterator jt=(*it).second.list.begin();jt!=(*it).second.list.end();++jt) {
      g += (g.empty() ? "" : ","); g += *jt;
    }
    st["groups." + (*it).first] = g.empty() ? "-" : g;
  }
  string derived;
  for(map<string,Action *>::const_iterator it=conf->allacts.actionmap.begin();it!=conf->allacts.actionmap.end();++it) {
    derived += (derived.empty() ? "" : ","); derived += (*it).first;
    if ((*it).second == (Action *)0) derived += "(null)";
  }
  st["derived"] = derived;
  st["lang"] = conf->print->getName();
  string langs;
  for(uint4 i=0;i<conf->printlist.size();++i) { langs += (i ? "," : ""); langs += conf->printlist[i]->getName(); }
  st["langs"] = langs;
  PrintLanguage *pl = conf->print;
  st["p.mods"] = hx(pl->mods);
  st["p.head"] = hx(pl->head_comment_type);
  st["p.instr"] = hx(pl->instr_comment_type);
  st["p.cindent"] = num(pl->line_commentindent);
  st["p.ns"] = num((int4)pl->namespc_strategy);
  st["p.cstart"] = pl->commentstart.empty() ? "-" : pl->commentstart;
  st["p.cend"] = pl->commentend.empty() ? "-" : pl->commentend;
  st["p.indent"] = num(pl->emit->getIndentIncrement());
  EmitPrettyPrint *pp = dynamic_cast<EmitPrettyPrint *>(pl->emit);
  st["p.maxline"] = (pp == (EmitPrettyPrint *)0) ? "-" : num(pp->maxlinesize);
  PrintC *pc = dynamic_cast<PrintC *>(pl);
  if (pc != (PrintC *)0) {
    st["c.null"] = num(pc->option_NULL);
    st["c.inplace"] = num(pc->option_inplace_ops);
    st["c.conv"] = num(pc->option_convention);
    st["c.nocast"] = num(pc->option_nocasts);
    st["c.unplaced"] = num(pc->option_unplaced);
    st["c.hideexts"] = num(pc->option_hide_exts);
    st["c.bfunc"] = num((int4)pc->option_brace_func);
    st["c.bifelse"] = num((int4)pc->option_brace_ifelse);
    st["c.bloop"] = num((int4)pc->option_brace_loop);
    st["c.bswitch"] = num((int4)pc->option_brace_switch);
  }
  string tops;
  for(uint4 i=0;i<conf->inst.size();++i) {
    TypeOp *t = conf->inst[i];
    if (t == (TypeOp *)0) continue;
    tops += t->getName();
    tops += ',';
    TypeOpFunc *tf = dynamic_cast<TypeOpFunc *>(t);
    if (tf != (TypeOpFunc *)0) { tops += num((int4)tf->metaout); tops += ','; tops += num((int4)tf->metain); }
    tops += num(t->addlflags);
    tops += ';';
  }
  st["typeops"] = hx(fnv(tops));
  Sleigh *sl = dynamic_cast<Sleigh *>((Translate *)conf->translate);
  st["ctxset"] = (sl == (Sleigh *)0) ? "-" : num(sl->cache->allowset);
}

static string delta(const State &a,const State &b)
{
  string res;
  for(State::const_iterator it=b.begin();it!=b.end();++it) {
    State::const_iterator o = a.find((*it).first);
    if (o == a.end() || (*o).second != (*it).second) {
      res += (res.empty() ? "" : " ");
      string v = (*it).second;
      for(uint4 i=0;i<v.size();++i) if (v[i] == ' ') v[i] = '_';
      res += (*it).first + "=" + v;
    }
  }
  for(State::const_iterator it=a.begin();it!=a.end();++it)
    if (b.find((*it).first) == b.end()) { res += (res.empty() ? "" : " "); res += (*it).first + "=<gone>"; }
  return res.empty() ? "-" : res;
}

static const char *optnames[] = {
  "extrapop","readonly","defaultprototype","inferconstptr","analyzeforloops","inline","noreturn",
  "warning","nullprinting","inplaceops","conventionprinting","nocastprinting","maxlinewidth",
  "indentincrement","commentindent","commentstyle","commentheader","commentinstruction",
  "integerformat","braceformat","setaction","currentaction","allowcontextset","ignoreunimplemented",
  "errorunimplemented","errorreinterpreted","errortoomanyinstructions","baddatacount","protoeval",
  "setlanguage","jumptablemax","jumpload","togglerule","aliasblock","maxinstruction",
  "namespacestrategy","splitdatatype","nanignore",
  "hideextensions","structalign","nosuchoption","addr" };
static const int4 numopt = sizeof(optnames) / sizeof(optnames[0]);

static vector<string> pool;

static void buildPool(void)
{
  static const char *fixed[] = {
    "", "on", "off", "true", "false", "abc", "0", "1", "16", "0x20", "010", "-5", "12abc",
    "99999999999", "unknown", "default", "__thiscall", "nosuchmodel", "f", "nosuchfunc",
    "decompile", "jumptable", "normalize", "paramid", "register", "firstpass", "newroot",
    "base", "deadcode", "splitcopy", "splitpointer", "floatprecision", "nosuchgroup",
    "earlyremoval", "ignorenan", "oppool1:earlyremoval",
    "universal:fullloop:mainloop:stackstall:oppool1:earlyremoval", "mainloop", "blockstructure",
    "nosuchrule", "header", "warningheader", "warning", "user1", "user2", "user3",
    "hex", "dec", "best", "hexadecimal", "same", "next", "skip", "function", "ifelse", "loop",
    "switch", "c", "cplusplus", "/*x", "//y", "none", "struct", "array", "pointer", "all",
    "compare", "minimal", "c-language", "java-language", "nosuch-language" };
  for(uint4 i=0;i<sizeof(fixed)/sizeof(fixed[0]);++i) pool.push_back(fixed[i]);
  for(map<string,ProtoModel *>::const_iterator it=conf->protoModels.begin();it!=conf->protoModels.end();++it)
    pool.push_back((*it).first);
}

static State initial;
static map<string,int4> origExtrapop;
static ProtoModel *origDefault,*origCur,*origCalled;
static uint4 origFuncFlags;
static int4 origFuncExtrapop;

static void restore(void)
{
  conf->resetDefaults();
  State afterReset;
  capture(afterReset);
  string left = delta(initial,afterReset);
  if (left != "-") cout << kase << "\tU\t" << left << '\n';
  if (conf->defaultfp != origDefault) conf->setDefaultModel(origDefault);
  conf->evalfp_current = origCur;
  conf->evalfp_called = origCalled;
  for(map<string,ProtoModel *>::const_iterator it=conf->protoModels.begin();it!=conf->protoModels.end();++it) {
    (*it).second->setExtraPop(origExtrapop[(*it).first]);
    (*it).second->setPrintInDecl((*it).second != origDefault);
  }
  origDefault->setPrintInDecl(false);
  fd->getFuncProto().flags = origFuncFlags;
  fd->getFuncProto().setExtraPop(origFuncExtrapop);
  conf->setPrintLanguage("c-language");
  conf->translate->allowContextSet(true);
  // languages created by setlanguage stay in printlist; reset them all
  conf->resetDefaults();
}

static void apply(const string &nm,const string &p1,const string &p2,const string &p3)
{
  State before,after;
  capture(before);
  string cls = "ok";
  string text;
  bool nullroot = (conf->allacts.getCurrent() == (Action *)0);
  if (nullroot && (nm == "warning" || nm == "nanignore")) {
    cls = "skip";
  }
  else {
    try {
      text = conf->options->set(ElementId::find(nm,0),p1,p2,p3);
    }
    catch(ParseError &err) { cls = "parse"; text = err.explain; }
    catch(RecovError &err) { cls = "recov"; text = err.explain; }
    catch(LowlevelError &err) { cls = "lowlevel"; text = err.explain; }
  }
  capture(after);
  cout << kase << "\tO\t" << nm << '\t' << (p1.empty() ? "-" : p1) << '\t' << (p2.empty() ? "-" : p2) << '\t'
       << (p3.empty() ? "-" : p3) << '\t' << cls << '\t' << (text.empty() ? "-" : text) << '\t' << delta(before,after) << '\n';
}

static void endCase(void)
{
  State before,after;
  capture(before);
  conf->resetDefaults();
  capture(after);
  cout << kase << "\tR\t" << delta(before,after) << '\n';
  restore();
}

int main(int argc,char **argv)
{
  if (argc != 6) { cerr << "usage: option_oracle SLEIGHHOME datatest.xml FUNCADDR SEED CASES" << endl; return 2; }
  startDecompilerLibrary(argv[1]);
  DocumentStorage store;
  Document *doc = store.openDocument(argv[2]);
  const List &list(doc->getRoot()->getChildren());
  for(List::const_iterator it=list.begin();it!=list.end();++it)
    if ((*it)->getName() == "binaryimage") store.registerTag(*it);
  ostringstream warn;
  conf = ArchitectureCapability::getCapability("xml")->buildArchitecture("test","",&warn);
  conf->init(store);
  Address entry(conf->getDefaultCodeSpace(),strtoull(argv[3],0,0));
  fd = conf->symboltab->getGlobalScope()->addFunction(entry,"f")->getFunction();
  origDefault = conf->defaultfp;
  origCur = conf->evalfp_current;
  origCalled = conf->evalfp_called;
  for(map<string,ProtoModel *>::const_iterator it=conf->protoModels.begin();it!=conf->protoModels.end();++it)
    origExtrapop[(*it).first] = (*it).second->getExtraPop();
  origFuncFlags = fd->getFuncProto().flags;
  origFuncExtrapop = fd->getFuncProto().getExtraPop();
  buildPool();
  capture(initial);
  kase = -1;
  cout << kase << "\tH\tbk-option-oracle\t1\n";
  for(State::const_iterator it=initial.begin();it!=initial.end();++it)
    cout << kase << "\tI\t" << (*it).first << '=' << (*it).second << '\n';
  kase = 0;
  // directed: each option with each pool value as p1, alone
  for(int4 i=0;i<numopt;++i)
    for(uint4 j=0;j<pool.size();++j) {
      apply(optnames[i],pool[j],"","");
      endCase();
      kase += 1;
    }
  // directed: each option with each pair (p1 from a short list, p2 from the pool)
  static const char *first[] = { "f", "decompile", "firstpass", "newroot", "earlyremoval", "ignorenan",
				 "header", "warning", "function", "ifelse", "loop", "switch", "struct",
				 "array", "pointer", "base", "splitcopy", "0x10", "unknown", "mainloop" };
  // only the options that read a second parameter
  static const char *pairopt[] = { "extrapop", "inline", "noreturn", "warning", "commentheader",
				   "commentinstruction", "braceformat", "setaction", "currentaction",
				   "togglerule", "splitdatatype" };
  for(uint4 i=0;i<sizeof(pairopt)/sizeof(pairopt[0]);++i)
    for(uint4 a=0;a<sizeof(first)/sizeof(first[0]);++a)
      for(uint4 j=0;j<pool.size();++j) {
	apply(pairopt[i],first[a],pool[j],"");
	endCase();
	kase += 1;
      }
  // random sequences, three parameters
  rs = strtoull(argv[4],0,0) | 1;
  int4 cases = atoi(argv[5]);
  for(int4 c=0;c<cases;++c) {
    uint4 len = 2 + r(4);
    for(uint4 i=0;i<len;++i) {
      uint4 oi = r(numopt - 4);	// the last four names are not options
      uint4 a = r(pool.size());
      uint4 b = r(pool.size());
      uint4 cc = r(pool.size());
      uint4 n2 = r(3);
      uint4 n3 = r(4);
      apply(optnames[oi],pool[a],(n2 == 0) ? "" : pool[b],(n3 != 0) ? "" : pool[cc]);
    }
    endCase();
    kase += 1;
  }
  return 0;
}
