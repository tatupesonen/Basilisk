// Prototype oracle for D06 (decomp-symbols): what Ghidra's XmlArchitecture
// makes of each data test's <binaryimage> — the load image after pad(), the
// read-only ranges, the loader symbols, the property map, the global scope
// and the context database (from the .pspec/.cspec).  One table per run.
//
// Built against the reference build's optimised objects (see build.sh) with
// -fno-access-control, so private members can be read without patching
// Ghidra.  Usage: image_oracle SLEIGHHOME file.xml...
//
// Records (tab-separated):
//   F name                                   one data test
//   E message                                architecture failed to build
//   K space offset size ro fnv64             one chunk of the image, after pad()
//   Y space offset name                      one loader symbol (map order)
//   R space first last                       one read-only range (getReadonly)
//   P space offset flags                     one property change point
//   D flags                                  property default value
//   B line                                   global scope printBounds line
//   M line                                   global scope printEntries line
//   V name word startbit endbit shift mask   one context variable
//   C space offset words...                  one context split point (values)
//   c words...                               context default value
//   T space offset n (space,off,size,val)... one tracked-set split point
//   t n (space,off,size,val)...              tracked default
//   L space offset size ok fnv64|message     one loadFill probe
#include "libdecomp.hh"
#include "loadimage_xml.hh"
#include "xml_arch.hh"
#include "database.hh"
#include "globalcontext.hh"

#include <sstream>
#include <iostream>
using std::cout; using std::cerr; using std::endl;

using namespace ghidra;

static uint8 fnv(const uint1 *p,int4 n)
{
  uint8 h = 0xcbf29ce484222325ULL;
  for(int4 i=0;i<n;++i) { h ^= p[i]; h *= 0x100000001b3ULL; }
  return h;
}

static void lines(const char *tag,const string &text)
{
  istringstream s(text);
  string line;
  while(getline(s,line))
    cout << tag << '\t' << line << '\n';
}

static void probe(Architecture *conf,const Address &addr,int4 size)
{
  vector<uint1> buf(size > 0 ? size : 1);
  cout << "L\t" << addr.getSpace()->getName() << "\t0x" << hex << addr.getOffset() << dec << '\t' << size << '\t';
  try {
    conf->loader->loadFill(buf.data(),size,addr);
    cout << "ok\t" << hex << fnv(buf.data(),size) << dec << '\n';
  }
  catch(DataUnavailError &err) {
    cout << "err\t" << err.explain << '\n';
  }
}

static void tracked(const TrackedSet &ts)
{
  cout << ts.size();
  for(int4 i=0;i<ts.size();++i)
    cout << "\t(" << ts[i].loc.space->getName() << ",0x" << hex << ts[i].loc.offset << dec << ',' << ts[i].loc.size << ",0x" << hex << ts[i].val << dec << ')';
  cout << '\n';
}

static void one(const string &path)
{
  string base = path.substr(path.find_last_of('/')+1);
  cout << "F\t" << base << '\n';
  DocumentStorage store;
  Architecture *conf = (Architecture *)0;
  try {
    Document *doc = store.openDocument(path);
    const List &list(doc->getRoot()->getChildren());
    for(List::const_iterator it=list.begin();it!=list.end();++it)
      if ((*it)->getName() == "binaryimage") store.registerTag(*it);
    ArchitectureCapability *capa = ArchitectureCapability::getCapability("xml");
    ostringstream err;
    conf = capa->buildArchitecture("test","",&err);
    conf->init(store);
    conf->readLoaderSymbols();
  }
  catch(LowlevelError &e) { cout << "E\t" << e.explain << '\n'; return; }
  catch(DecoderError &e) { cout << "E\t" << e.explain << '\n'; return; }

  LoadImageXml *li = (LoadImageXml *)conf->loader;
  map<Address,vector<uint1> >::const_iterator ci;
  for(ci=li->chunk.begin();ci!=li->chunk.end();++ci) {
    const Address &a((*ci).first);
    const vector<uint1> &v((*ci).second);
    bool ro = li->readonlyset.find(a) != li->readonlyset.end();
    cout << "K\t" << a.getSpace()->getName() << "\t0x" << hex << a.getOffset() << dec << '\t' << v.size() << '\t'
	 << (ro ? 1 : 0) << '\t' << hex << fnv(v.empty() ? (const uint1 *)0 : &v[0],v.size()) << dec << '\n';
  }
  map<Address,string>::const_iterator si;
  for(si=li->addrtosymbol.begin();si!=li->addrtosymbol.end();++si)
    cout << "Y\t" << (*si).first.getSpace()->getName() << "\t0x" << hex << (*si).first.getOffset() << dec << '\t' << (*si).second << '\n';
  RangeList ro;
  li->getReadonly(ro);
  for(set<Range>::const_iterator ri=ro.begin();ri!=ro.end();++ri)
    cout << "R\t" << (*ri).getSpace()->getName() << "\t0x" << hex << (*ri).getFirst() << "\t0x" << (*ri).getLast() << dec << '\n';

  const partmap<Address,uint4> &props(conf->symboltab->getProperties());
  cout << "D\t0x" << hex << props.defaultValue() << dec << '\n';
  for(partmap<Address,uint4>::const_iterator pi=props.begin();pi!=props.end();++pi)
    cout << "P\t" << (*pi).first.getSpace()->getName() << "\t0x" << hex << (*pi).first.getOffset() << "\t0x" << (*pi).second << dec << '\n';

  Scope *glob = conf->symboltab->getGlobalScope();
  ostringstream b, m;
  glob->printBounds(b);
  glob->printEntries(m);
  lines("B",b.str());
  lines("M",m.str());

  ContextInternal *ctx = dynamic_cast<ContextInternal *>(conf->context);
  if (ctx != (ContextInternal *)0) {
    map<string,ContextBitRange>::const_iterator vi;
    for(vi=ctx->variables.begin();vi!=ctx->variables.end();++vi) {
      const ContextBitRange &r((*vi).second);
      cout << "V\t" << (*vi).first << '\t' << r.word << '\t' << r.startbit << '\t' << r.endbit << '\t' << r.shift << "\t0x" << hex << r.mask << dec << '\n';
    }
    cout << "c";
    for(int4 i=0;i<ctx->size;++i) cout << "\t0x" << hex << ctx->database.defaultValue().array[i] << dec;
    cout << '\n';
    partmap<Address,ContextInternal::FreeArray>::const_iterator di;
    for(di=ctx->database.begin();di!=ctx->database.end();++di) {
      cout << "C\t" << (*di).first.getSpace()->getName() << "\t0x" << hex << (*di).first.getOffset() << dec;
      for(int4 i=0;i<(*di).second.size;++i) cout << "\t0x" << hex << (*di).second.array[i] << dec;
      cout << '\n';
    }
    cout << "t\t";
    tracked(ctx->trackbase.defaultValue());
    partmap<Address,TrackedSet>::const_iterator ti;
    for(ti=ctx->trackbase.begin();ti!=ctx->trackbase.end();++ti) {
      cout << "T\t" << (*ti).first.getSpace()->getName() << "\t0x" << hex << (*ti).first.getOffset() << dec << '\t';
      tracked((*ti).second);
    }
  }

  // Probes around every chunk boundary (a copy of the keys: probing does not change the map).
  vector<pair<Address,int4> > keys;
  for(ci=li->chunk.begin();ci!=li->chunk.end();++ci) keys.push_back(make_pair((*ci).first,(int4)(*ci).second.size()));
  for(int4 i=0;i<keys.size();++i) {
    Address a = keys[i].first;
    int4 sz = keys[i].second;
    if (a.getOffset() != 0) probe(conf,a - 1,1);
    probe(conf,a,sz < 16 ? sz : 16);
    if (sz >= 2) probe(conf,a + (sz - 2),4);
    probe(conf,a + sz,1);
    probe(conf,a,sz + 1);
  }
  delete conf;
}

int main(int argc,char **argv)
{
  if (argc < 3) { cerr << "usage: image_oracle SLEIGHHOME file.xml..." << endl; return 2; }
  startDecompilerLibrary(argv[1]);
  for(int4 i=2;i<argc;++i) one(argv[i]);
  return 0;
}
