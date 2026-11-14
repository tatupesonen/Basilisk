// Prototype oracle for D06 (decomp-symbols): Ghidra's ContextInternal over
// generated operation sequences.  Spaces come from the x86-64 architecture
// of a data test; each case uses a fresh ContextInternal with generated
// variables.  Usage: context_oracle SLEIGHHOME datatest.xml SEED CASES
// Random draws are xorshift64*, one per statement (argument evaluation
// order is unspecified in C++).
#include "libdecomp.hh"
#include "xml_arch.hh"
#include "globalcontext.hh"

#include <sstream>
#include <iostream>
using std::cout; using std::cerr; using std::endl;

using namespace ghidra;

static uint8 rs;
static uint8 rnd(void) { rs ^= rs >> 12; rs ^= rs << 25; rs ^= rs >> 27; return rs * 0x2545F4914F6CDD1DULL; }
static uint4 r(uint4 n) { return (uint4)(rnd() % n); }

static Architecture *conf;
static AddrSpace *ram, *reg;
static int4 kase;

static void row(const string &kind,const string &text)
{
  cout << kase << '\t' << kind << '\t' << text << '\n';
}

static Address randAddr(void)
{
  uintb off = 0x1000 + r(0x40);
  if (r(8) == 0) return Address(reg,off);
  return Address(ram,off);
}

static string words(const ContextInternal &ctx,const uintm *v)
{
  ostringstream s;
  for(int4 i=0;i<ctx.getContextSize();++i) s << (i ? "," : "") << hex << v[i];
  return s.str();
}

static string encodeOf(const ContextInternal &ctx)
{
  ostringstream x;
  XmlEncode enc(x);
  ctx.encode(enc);
  string res;
  string t = x.str();
  for(int4 i=0;i<t.size();++i) if (t[i] != '\n') res += t[i];
  return res;
}

static void one(void)
{
  ContextInternal ctx;
  vector<string> vars;
  int4 nv = 1 + r(6);
  for(int4 i=0;i<nv;++i) {
    int4 word = r(2);
    int4 start = r(32);
    int4 len = 1 + r(32 - start);
    ostringstream nm; nm << "v" << i;
    ctx.registerVariable(nm.str(),word*32 + start,word*32 + start + len - 1);
    vars.push_back(nm.str());
    ostringstream s; s << nm.str() << ' ' << word*32 + start << ' ' << word*32 + start + len - 1;
    row("var",s.str());
  }
  int4 nops = r(12);
  for(int4 i=0;i<nops;++i) {
    string v = vars[r(vars.size())];
    uintm val = (uintm)rnd();
    ostringstream s;
    switch(r(5)) {
    case 0: ctx.setVariableDefault(v,val); s << "default " << v << ' ' << hex << val; break;
    case 1: { Address a = randAddr(); ctx.setVariable(v,a,val); s << "set " << v << ' ' << a.getSpace()->getName() << ' ' << hex << a.getOffset() << ' ' << val; break; }
    case 2: { Address a = randAddr(); Address b = r(4) ? a + (int8)(1 + r(0x20)) : Address();
	ctx.setVariableRegion(v,a,b,val);
	s << "region " << v << ' ' << a.getSpace()->getName() << ' ' << hex << a.getOffset() << ' ' << (b.isInvalid() ? string("- -") : b.getSpace()->getName() + " " + std::to_string((unsigned long long)b.getOffset())) << ' ' << val; break; }
    case 3: { Address a = randAddr(); Address b = a + (int8)(1 + r(0x20));
	TrackedSet &ts(ctx.createSet(a,b));
	int4 n = r(3);
	s << "track " << a.getSpace()->getName() << ' ' << hex << a.getOffset() << ' ' << b.getOffset();
	for(int4 k=0;k<n;++k) {
	  TrackedContext tc; tc.loc.space = reg; tc.loc.offset = 8*r(4); tc.loc.size = 1 << r(4); tc.val = rnd();
	  ts.push_back(tc);
	  s << " (" << tc.loc.offset << ',' << tc.loc.size << ',' << tc.val << ')';
	}
	break; }
    case 4: { Address a = randAddr(); int4 w = r(ctx.getContextSize()); uintm mask = (uintm)rnd(); uintm value = (uintm)rnd() & mask;
	ctx.setContextChangePoint(a,w,mask,value);
	s << "change " << a.getSpace()->getName() << ' ' << hex << a.getOffset() << ' ' << w << ' ' << mask << ' ' << value; break; }
    }
    row("op",s.str());
  }
  for(int4 i=0;i<16;++i) {
    Address a = randAddr();
    uintb first,last;
    const uintm *v = ctx.getContext(a,first,last);
    ostringstream s;
    s << a.getSpace()->getName() << ' ' << hex << a.getOffset() << " -> " << words(ctx,v) << ' ' << first << ' ' << last;
    for(int4 k=0;k<vars.size();++k) s << ' ' << ((const ContextDatabase &)ctx).getVariable(vars[k],a);
    row("get",s.str());
    VarnodeData vd; vd.space = reg; vd.offset = r(32); vd.size = 1 << r(4);
    ostringstream t;
    t << a.getSpace()->getName() << ' ' << hex << a.getOffset() << ' ' << vd.offset << ' ' << vd.size << " -> " << ctx.getTrackedValue(vd,a);
    row("tracked",t.str());
  }
  string e = encodeOf(ctx);
  row("encode",e);
  if (!e.empty()) {		// decode into a fresh database with the same variables, encode again
    ContextInternal ctx2;
    for(int4 k=0;k<vars.size();++k) {
      const ContextBitRange &b(ctx.variables[vars[k]]);
      ctx2.registerVariable(vars[k],b.word*32 + b.startbit,b.word*32 + b.endbit);
    }
    istringstream is(e);
    Document *doc = xml_tree(is);
    XmlDecode dec(conf,doc->getRoot());
    ctx2.decode(dec);
    delete doc;
    row("redecode",encodeOf(ctx2));
  }
}

int main(int argc,char **argv)
{
  if (argc != 5) { cerr << "usage: context_oracle SLEIGHHOME datatest.xml SEED CASES" << endl; return 2; }
  startDecompilerLibrary(argv[1]);
  DocumentStorage store;
  Document *doc = store.openDocument(argv[2]);
  const List &list(doc->getRoot()->getChildren());
  for(List::const_iterator it=list.begin();it!=list.end();++it)
    if ((*it)->getName() == "binaryimage") store.registerTag(*it);
  ostringstream warn;
  conf = ArchitectureCapability::getCapability("xml")->buildArchitecture("test","",&warn);
  conf->init(store);
  ram = conf->getSpaceByName("ram");
  reg = conf->getSpaceByName("register");
  rs = strtoull(argv[3],0,0) | 1;
  int4 cases = atoi(argv[4]);
  for(kase=0;kase<cases;++kase) {
    try { one(); }
    catch(LowlevelError &err) { row("!case",err.explain); }
  }
  return 0;
}
