// The reference figures of the bk-sleigh benchmarks (features/sleigh-decode.md
// 6.6): Ghidra's C++ engine loading x86-64 (Sleigh::initialize plus the
// .pspec's <context_data>), then sweeping a code file with instructionLength
// (decode only) and with printAssembly (decode + text); best of N runs.
// Built by build.sh in this directory. Usage:
//   slabench <x86-64.sla> <x86-64.pspec> <code.bin> [runs]
#include "sleigh.hh"
#include "loadimage.hh"
#include <chrono>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <vector>

using namespace ghidra;

class BufferImage : public LoadImage {
  const std::vector<uint1> &data;
public:
  BufferImage(const std::vector<uint1> &d) : LoadImage("bench"), data(d) {}
  virtual void loadFill(uint1 *ptr,int4 size,const Address &addr) {
    uintb start = addr.getOffset();
    for(int4 i=0;i<size;++i) ptr[i] = (start + i < data.size()) ? data[start + i] : 0;
  }
  virtual string getArchType(void) const { return "bench"; }
  virtual void adjustVma(long adjust) {}
};

class NullAsm : public AssemblyEmit {
public:
  size_t chars = 0;
  virtual void dump(const Address &addr,const string &mnem,const string &body) { chars += mnem.size() + body.size(); }
};

static double now(void) {
  return std::chrono::duration<double>(std::chrono::steady_clock::now().time_since_epoch()).count();
}

int main(int argc,char **argv) {
  if (argc < 4) { fprintf(stderr,"usage: slabench sla pspec code [runs]\n"); return 2; }
  int runs = argc > 4 ? atoi(argv[4]) : 5;
  std::ifstream in(argv[3], std::ios::binary);
  std::vector<uint1> code((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  AttributeId::initialize();
  ElementId::initialize();
  double load = 1e9, decode = 1e9, text = 1e9;
  long instructions = 0, errors = 0;
  for(int run=0;run<runs;++run) {
    double t0 = now();
    DocumentStorage store;
    std::ostringstream tag;
    tag << "<sleigh>" << argv[1] << "</sleigh>";
    std::istringstream tagstream(tag.str());
    store.registerTag(store.parseDocument(tagstream)->getRoot());
    BufferImage image(code);
    ContextInternal context;
    Sleigh trans(&image,&context);
    trans.initialize(store);
    const Element *pspec = store.openDocument(argv[2])->getRoot();
    for(List::const_iterator it=pspec->getChildren().begin();it!=pspec->getChildren().end();++it) {
      if ((*it)->getName() != "context_data") continue;
      XmlDecode decoder(&trans,*it);
      context.decodeFromSpec(decoder);
    }
    double t1 = now();
    if (t1 - t0 < load) load = t1 - t0;
    for(int mode=0;mode<2;++mode) {
      NullAsm emit;
      long n = 0, e = 0;
      double s = now();
      size_t pos = 0;
      while(pos < code.size()) {
        Address addr(trans.getDefaultCodeSpace(),pos);
        int4 len;
        try {
          len = (mode == 0) ? trans.instructionLength(addr) : trans.printAssembly(emit,addr);
        } catch(LowlevelError &err) { e += 1; pos += 1; continue; }
        n += 1;
        pos += len;
      }
      double d = now() - s;
      if (mode == 0) { if (d < decode) decode = d; } else { if (d < text) text = d; }
      instructions = n; errors = e;
    }
  }
  printf("load_ms\t%.2f\ndecode_mips\t%.3f\ntext_mips\t%.3f\ninstructions\t%ld\nerrors\t%ld\n",
         load * 1000, instructions / decode / 1e6, instructions / text / 1e6, instructions, errors);
  return 0;
}
