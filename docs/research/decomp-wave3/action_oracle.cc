// Prototype oracle for D07 (decomp-core): Ghidra's action framework
// (Action, ActionGroup, ActionRestartGroup, ActionPool, Rule; action.cc)
// driven by synthetic trees whose leaves follow a script.
//
// usage: action_oracle SLEIGHHOME datatest.xml FUNCADDR SEED CASES
//   e.g. action_oracle REF DT/elseif.xml 0x1006ca 1 2000
//
// Every case builds a random tree under an ActionRestartGroup, sets random
// breakpoints, and calls perform() until it stops returning -1.  The function
// the tree runs on is the raw p-code of one data-test function (flow followed,
// nothing else): the pools walk real ops, the scripted rules change an opcode,
// destroy an op or insert an op, which is all ActionPool reacts to.
//
// Rows (tab separated, first field the case number, -1 for the header):
//   H  format, commit note
//   F  the function's ops after flow: seqnum opcode-name evaltype
//   N  node: id parent kind flags(hex) name group [script]
//        kind = restart:<max> | group | pool | start | leaf | rule
//        leaf script: steps "d<delta>[!]" ('!' = requests a restart)
//        rule script: "<opcodes>" then steps n|a|c|k|i
//           n no change, a apply, c apply and flip INT_ADD/INT_SUB or
//           BOOL_AND/BOOL_OR, k apply and destroy the op, i apply and insert
//           a COPY after the op (c, k, i fall back to a when not possible)
//   L  the tree as Action::print renders it, one row per line
//   B  breakpoint: node-id bits(hex)   J  jumptable-recovery flag set
//   S  specifier: text, id of getSubAction's result, id of getSubRule's ('-')
//   K  clone by group list: groups, then the clone's print lines joined by '|'
//   C  one row per call made during a perform: "a<id>:<delta>[!]" or
//      "r<id>@<seqnum>:<step>" (calls joined by ' ')
//   P  perform result, root status, printState text
//   W  text sent to the architecture's message stream during the perform
//   E  at the end: id status count count_tests count_apply
//   Z  flags of the function at the end (hex); number of "Exceeded maximum
//      restarts" header warnings
//
// Random draws are xorshift64*, one per statement.
#include "libdecomp.hh"
#include "xml_arch.hh"

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
static ostringstream calls;
static ostringstream warn;
static int4 nextid;
static vector<OpCode> opcodes;		// opcodes present in the raw function
static const char *names[] = { "alpha", "beta", "gamma", "delta", "alpha", "beta" };
static const char *groups[] = { "g1", "g2", "g3" };

struct NodeInfo { int4 id; int4 parent; Action *act; Rule *rule; };
static vector<NodeInfo> nodes;

static string seqText(const PcodeOp *op)
{
  ostringstream s;
  s << op->getSeqNum();
  return s.str();
}

struct Step { int4 delta; bool restart; };

class ScriptAction : public Action {
public:
  int4 id;
  vector<Step> script;
  uint4 pos;
  ScriptAction(uint4 f,const string &nm,const string &g) : Action(f,nm,g) { pos = 0; }
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ScriptAction(flags,getName(),getGroup());
  }
  virtual int4 apply(Funcdata &data) {
    Step st; st.delta = 0; st.restart = false;
    if (pos < script.size()) st = script[pos];
    pos += 1;
    count += st.delta;
    if (st.restart) data.setRestartPending(true);
    calls << " a" << id << ':' << st.delta << (st.restart ? "!" : "");
    return 0;
  }
};

class StartAction : public Action {
public:
  int4 id;
  StartAction(const string &g) : Action(0,"start",g) {}
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new StartAction(getGroup());
  }
  virtual int4 apply(Funcdata &data) {
    data.startProcessing();
    calls << " a" << id << ":0";
    return 0;
  }
};

class ScriptRule : public Rule {
public:
  int4 id;
  vector<uint4> oplist;
  string script;
  uint4 pos;
  ScriptRule(const string &g,const string &nm) : Rule(g,0,nm) { pos = 0; }
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0;
    ScriptRule *res = new ScriptRule(getGroup(),getName());
    res->oplist = oplist;
    return res;
  }
  virtual void getOpList(vector<uint4> &ol) const { ol = oplist; }
  virtual int4 applyOp(PcodeOp *op,Funcdata &data) {
    char st = 'n';
    if (pos < script.size()) st = script[pos];
    pos += 1;
    string sq = seqText(op);
    if (st == 'c') {
      OpCode opc = op->code();
      OpCode other = CPUI_MAX;
      if (opc == CPUI_INT_ADD) other = CPUI_INT_SUB;
      else if (opc == CPUI_INT_SUB) other = CPUI_INT_ADD;
      else if (opc == CPUI_BOOL_AND) other = CPUI_BOOL_OR;
      else if (opc == CPUI_BOOL_OR) other = CPUI_BOOL_AND;
      if (other == CPUI_MAX) st = 'a';
      else data.opSetOpcode(op,other);
    }
    else if (st == 'k') {
      if (op->isCallOrBranch() || op->code() == CPUI_RETURN || op->code() == CPUI_STORE) st = 'a';
      else data.opDestroy(op);
    }
    else if (st == 'i') {
      if (op->isCallOrBranch() || op->code() == CPUI_RETURN) st = 'a';
      else {
	PcodeOp *newop = data.newOp(1,op->getAddr());
	data.opSetOpcode(newop,CPUI_COPY);
	data.newUniqueOut(1,newop);
	data.opSetInput(newop,data.newConstant(1,0),0);
	data.opInsertAfter(newop,op);
      }
    }
    calls << " r" << id << '@' << sq << ':' << st;
    return (st == 'n') ? 0 : 1;
  }
};

static void row(const string &kind,const string &text)
{
  cout << kase << '\t' << kind << '\t' << text << '\n';
}

static uint4 randFlags(void)
{
  uint4 f = 0;
  uint4 a = r(10);
  if (a < 3) f |= Action::rule_repeatapply;
  uint4 b = r(10);
  if (b == 0) f |= Action::rule_onceperfunc;
  uint4 c = r(10);
  if (c == 0) f |= Action::rule_oneactperfunc;
  return f;
}

static void describe(int4 id,int4 parent,const string &kind,uint4 flags,const string &nm,
		     const string &grp,const string &script)
{
  ostringstream s;
  s << id << '\t' << parent << '\t' << kind << '\t' << hex << "0x" << flags << '\t'
    << nm << '\t' << (grp.empty() ? "-" : grp) << '\t' << (script.empty() ? "-" : script);
  row("N",s.str());
}

static Action *buildLeaf(int4 parent)
{
  uint4 f = randFlags();
  uint4 ni = r(6);
  uint4 gi = r(3);
  ScriptAction *act = new ScriptAction(f,names[ni],groups[gi]);
  act->id = nextid++;
  uint4 len = r(6);
  ostringstream sc;
  for(uint4 i=0;i<len;++i) {
    Step st;
    uint4 d = r(10);
    st.delta = (d < 6) ? 0 : (d < 9 ? 1 : 2);
    uint4 rr = r(25);
    st.restart = (rr == 0);
    act->script.push_back(st);
    sc << (i ? "," : "") << 'd' << st.delta << (st.restart ? "!" : "");
  }
  describe(act->id,parent,"leaf",f,act->getName(),act->getGroup(),sc.str());
  NodeInfo ni2 = { act->id, parent, act, (Rule *)0 };
  nodes.push_back(ni2);
  return act;
}

static Action *buildPool(int4 parent)
{
  uint4 fr = r(4);
  uint4 f = (fr != 0) ? Action::rule_repeatapply : 0;
  uint4 ni = r(6);
  ActionPool *pool = new ActionPool(f,string("pool") + names[ni]);
  int4 pid = nextid++;
  describe(pid,parent,"pool",f,pool->getName(),"","");
  NodeInfo pn = { pid, parent, pool, (Rule *)0 };
  nodes.push_back(pn);
  uint4 nr = 1 + r(4);
  for(uint4 i=0;i<nr;++i) {
    uint4 rn = r(6);
    uint4 gi = r(3);
    ScriptRule *rl = new ScriptRule(groups[gi],string("r") + names[rn]);
    rl->id = nextid++;
    uint4 no = 1 + r(3);
    ostringstream sc;
    for(uint4 j=0;j<no;++j) {
      uint4 oi = r(opcodes.size());
      rl->oplist.push_back((uint4)opcodes[oi]);
      sc << (j ? "," : "") << get_opname(opcodes[oi]);
    }
    sc << ' ';
    uint4 len = r(12);
    for(uint4 j=0;j<len;++j) {
      uint4 k = r(12);
      char st = (k < 6) ? 'n' : (k < 9 ? 'a' : (k == 9 ? 'c' : (k == 10 ? 'k' : 'i')));
      rl->script += st;
    }
    sc << (rl->script.empty() ? "-" : rl->script);
    describe(rl->id,pid,"rule",0,rl->getName(),rl->getGroup(),sc.str());
    NodeInfo rnode = { rl->id, pid, (Action *)0, rl };
    nodes.push_back(rnode);
    pool->addRule(rl);
  }
  return pool;
}

static Action *buildGroup(int4 parent,int4 depth,bool isroot);

static Action *buildMember(int4 parent,int4 depth)
{
  uint4 k = r(10);
  if (depth < 3 && k < 3) return buildGroup(parent,depth,false);
  if (k < 5) return buildPool(parent);
  return buildLeaf(parent);
}

static Action *buildGroup(int4 parent,int4 depth,bool isroot)
{
  ActionGroup *grp;
  int4 gid = nextid++;
  uint4 f;
  if (isroot) {
    uint4 fo = r(4);
    f = (fo != 0) ? Action::rule_onceperfunc : 0;
    int4 maxr = (int4)r(3);
    grp = new ActionRestartGroup(f,"root",maxr);
    ostringstream k;
    k << "restart:" << maxr;
    describe(gid,parent,k.str(),f,"root","","");
  }
  else {
    f = randFlags();
    uint4 ni = r(6);
    grp = new ActionGroup(f,string("grp") + names[ni]);
    describe(gid,parent,"group",f,grp->getName(),"","");
  }
  NodeInfo gn = { gid, parent, grp, (Rule *)0 };
  nodes.push_back(gn);
  if (isroot) {
    StartAction *st = new StartAction("g1");
    st->id = nextid++;
    describe(st->id,gid,"start",0,"start","g1","");
    NodeInfo sn = { st->id, gid, st, (Rule *)0 };
    nodes.push_back(sn);
    grp->addAction(st);
  }
  uint4 n = 1 + r(4);
  for(uint4 i=0;i<n;++i)
    grp->addAction(buildMember(gid,depth+1));
  return grp;
}

static int4 idOf(const Action *a)
{
  for(uint4 i=0;i<nodes.size();++i) if (nodes[i].act == a) return nodes[i].id;
  return -2;
}

static int4 idOfRule(const Rule *rl)
{
  for(uint4 i=0;i<nodes.size();++i) if (nodes[i].rule == rl) return nodes[i].id;
  return -2;
}

static void printLines(const Action *a,const string &kind,const string &prefix)
{
  ostringstream s;
  a->print(s,0,0);
  string t = s.str();
  string line;
  string joined = prefix;
  bool first = true;
  for(uint4 i=0;i<=t.size();++i) {
    if (i == t.size() || t[i] == '\n') {
      if (i == t.size() && line.empty()) break;
      if (kind == "L") row("L",line);
      else { joined += (first ? "" : "|"); joined += line; first = false; }
      line.clear();
    }
    else line += t[i];
  }
  if (kind != "L") row(kind,joined);
}

// Action::printState / ActionGroup::printState / ActionPool::printState, with
// the two places where Ghidra dereferences an end iterator made visible.
static void safeState(const Action *a,ostream &s)
{
  s << a->name;
  switch(a->status) {
  case Action::status_repeat:
  case Action::status_breakstarthit:
  case Action::status_start:
    s << " start";
    break;
  case Action::status_mid:
    s << ':';
    break;
  case Action::status_end:
    s << " end";
  }
  if (a->status != Action::status_mid) return;
  const ActionGroup *g = dynamic_cast<const ActionGroup *>(a);
  if (g != (const ActionGroup *)0) {
    if (g->state == g->list.end()) { s << "<past-the-end>"; return; }
    safeState(*g->state,s);
    return;
  }
  const ActionPool *p = dynamic_cast<const ActionPool *>(a);
  if (p != (const ActionPool *)0) {
    if (p->op_state == fd->endOpMain()) { s << " <past-the-end>"; return; }
    s << ' ' << (*p->op_state).second->getSeqNum();
  }
}

static string pathOf(int4 id)
{
  // ':'-joined names from the root down to the node
  vector<string> parts;
  int4 cur = id;
  while(cur >= 0) {
    for(uint4 i=0;i<nodes.size();++i) if (nodes[i].id == cur) {
      parts.push_back(nodes[i].act != (Action *)0 ? nodes[i].act->getName() : nodes[i].rule->getName());
      cur = nodes[i].parent;
      break;
    }
  }
  string res;
  for(int4 i=(int4)parts.size()-1;i>=0;--i) { res += parts[i]; if (i) res += ':'; }
  return res;
}

static void one(void)
{
  nodes.clear();
  nextid = 0;
  conf->clearAnalysis(fd);
  fd->flags &= ~((uint4)Funcdata::jumptablerecovery_on);
  Action *root = buildGroup(-1,0,true);
  printLines(root,"L","");

  // specifier look-ups
  for(int4 i=0;i<4;++i) {
    uint4 pick = r(nodes.size());
    string spec;
    uint4 form = r(4);
    const NodeInfo &nd(nodes[pick]);
    string nm = (nd.act != (Action *)0) ? nd.act->getName() : nd.rule->getName();
    if (form == 0) spec = nm;
    else if (form == 1) spec = pathOf(nd.id);
    else if (form == 2) spec = string("root:") + nm;
    else {
      string p = pathOf(nd.id);
      string::size_type c = p.find(':');
      spec = (c == string::npos) ? p : p.substr(c+1);
    }
    Action *sa = root->getSubAction(spec);
    Rule *sr = root->getSubRule(spec);
    ostringstream s;
    s << spec << '\t';
    if (sa != (Action *)0) s << idOf(sa); else s << '-';
    s << '\t';
    if (sr != (Rule *)0) s << idOfRule(sr); else s << '-';
    row("S",s.str());
  }

  // clone by group list
  {
    ActionGroupList gl;
    string gs;
    for(int4 i=0;i<3;++i) {
      uint4 in = r(2);
      if (in) { gl.list.insert(groups[i]); gs += (gs.empty() ? "" : ","); gs += groups[i]; }
    }
    Action *cl = root->clone(gl);
    if (cl == (Action *)0) row("K",(gs.empty() ? string("-") : gs) + "\tnull");
    else { printLines(cl,"K",(gs.empty() ? string("-") : gs) + "\t"); delete cl; }
  }

  // breakpoints
  uint4 nb = r(3);
  for(uint4 i=0;i<nb;++i) {
    uint4 pick = r(nodes.size());
    uint4 tpi = r(4);
    uint4 tp = (tpi == 0) ? Action::break_start : (tpi == 1 ? Action::tmpbreak_start
		: (tpi == 2 ? Action::break_action : Action::tmpbreak_action));
    const NodeInfo &nd(nodes[pick]);
    if (nd.act != (Action *)0) nd.act->breakpoint |= tp; else nd.rule->setBreak(tp);
    ostringstream s;
    s << nd.id << '\t' << hex << "0x" << tp;
    row("B",s.str());
  }
  uint4 warnpick = r(nodes.size());
  uint4 dowarn = r(4);
  if (dowarn == 0) {
    const NodeInfo &nd(nodes[warnpick]);
    if (nd.act != (Action *)0) nd.act->turnOnWarnings(); else nd.rule->turnOnWarnings();
    ostringstream s;
    s << nd.id;
    row("B",s.str() + "\twarn");
  }

  for(int4 round=0;round<2;++round) {
    root->reset(*fd);
    uint4 jt = r(10);
    if (jt == 0) { fd->flags |= Funcdata::jumptablerecovery_on; row("J",""); }
    for(int4 guard=0;guard<400;++guard) {
      calls.str("");
      warn.str("");
      int4 res;
      try {
	res = root->perform(*fd);
      } catch(LowlevelError &err) {
	row("C",calls.str().empty() ? "-" : calls.str().substr(1));
	row("!",err.explain);
	break;
      }
      row("C",calls.str().empty() ? "-" : calls.str().substr(1));
      ostringstream ps;
      safeState(root,ps);
      ostringstream s;
      s << res << '\t' << root->getStatus() << '\t' << ps.str();
      row("P",s.str());
      if (!warn.str().empty()) {
	string w = warn.str();
	for(uint4 i=0;i<w.size();++i) if (w[i] == '\n') w[i] = '|';
	row("W",w);
      }
      if (res >= 0) {
	// one more perform without a reset shows the once-per-function rule
	calls.str("");
	int4 again = root->perform(*fd);
	ostringstream s2;
	s2 << again << '\t' << root->getStatus() << "\tagain " << (calls.str().empty() ? "-" : calls.str().substr(1));
	row("P",s2.str());
	break;
      }
    }
    for(uint4 i=0;i<nodes.size();++i) {
      ostringstream s;
      const NodeInfo &nd(nodes[i]);
      if (nd.act != (Action *)0)
	s << nd.id << '\t' << nd.act->status << '\t' << nd.act->count << '\t' << nd.act->count_tests << '\t' << nd.act->count_apply;
      else
	s << nd.id << "\t-\t-\t" << nd.rule->count_tests << '\t' << nd.rule->count_apply;
      row("E",s.str());
    }
    int4 exceeded = 0;
    CommentSet::const_iterator citer = conf->commentdb->beginComment(fd->getAddress());
    CommentSet::const_iterator cend = conf->commentdb->endComment(fd->getAddress());
    for(;citer!=cend;++citer)
      if ((*citer)->getText().find("Exceeded maximum restarts") != string::npos) exceeded += 1;
    ostringstream z;
    z << hex << "0x" << fd->flags << dec << '\t' << exceeded;
    row("Z",z.str());
    conf->clearAnalysis(fd);
    fd->flags &= ~((uint4)Funcdata::jumptablerecovery_on);
  }
  delete root;
}

int main(int argc,char **argv)
{
  if (argc != 6) { cerr << "usage: action_oracle SLEIGHHOME datatest.xml FUNCADDR SEED CASES" << endl; return 2; }
  startDecompilerLibrary(argv[1]);
  DocumentStorage store;
  Document *doc = store.openDocument(argv[2]);
  const List &list(doc->getRoot()->getChildren());
  for(List::const_iterator it=list.begin();it!=list.end();++it)
    if ((*it)->getName() == "binaryimage") store.registerTag(*it);
  conf = ArchitectureCapability::getCapability("xml")->buildArchitecture("test","",&warn);
  conf->init(store);
  AddrSpace *ram = conf->getDefaultCodeSpace();
  Address entry(ram,strtoull(argv[3],0,0));
  fd = conf->symboltab->getGlobalScope()->addFunction(entry,"f")->getFunction();
  kase = -1;
  row("H","bk-action-oracle\t1");
  fd->startProcessing();
  bool seen[CPUI_MAX];
  for(int4 i=0;i<CPUI_MAX;++i) seen[i] = false;
  for(PcodeOpTree::const_iterator it=fd->beginOpMain();it!=fd->endOpMain();++it) {
    PcodeOp *op = (*it).second;
    ostringstream s;
    s << seqText(op) << '\t' << get_opname(op->code()) << '\t' << (op->isDead() ? "dead" : "alive");
    row("F",s.str());
    if (!op->isDead() && !seen[op->code()]) { seen[op->code()] = true; opcodes.push_back(op->code()); }
  }
  opcodes.push_back(CPUI_INT_SUB);	// reachable through the 'c' step
  rs = strtoull(argv[4],0,0) | 1;
  int4 cases = atoi(argv[5]);
  for(kase=0;kase<cases;++kase) {
    try { one(); }
    catch(LowlevelError &err) { row("!case",err.explain); }
  }
  return 0;
}
