// Times Ghidra's C++ loader on one .sla file: Sleigh::initialize (file read,
// inflate, decode, cross references), best of N runs. The baseline for the
// bk-sla benchmark (docs/features/sla.md, acceptance 3; docs/PERF.md).
//
// Build (reference build from scripts/build-reference.sh):
//   R=../reference
//   g++ -std=c++11 -O2 -w -DLOCAL_ZLIB -fsigned-char -I$R/src/cpp \
//       slaload.cc $R/src/cpp/libsla.a $R/src/zlib/libz.a -o slaload
// Run:
//   ./slaload $R/Ghidra/Processors/x86/data/languages/x86-64.sla 20
#include "sleigh.hh"
#include "loadimage.hh"
#include <chrono>
#include <cstdio>
#include <sstream>

using namespace ghidra;

class NoImage : public LoadImage {
public:
  NoImage(void) : LoadImage("none") {}
  virtual void loadFill(uint1 *ptr,int4 size,const Address &addr) {
    for(int4 i=0;i<size;++i) ptr[i] = 0;
  }
  virtual string getArchType(void) const { return "none"; }
  virtual void adjustVma(long adjust) {}
};

int main(int argc,char **argv) {
  if (argc < 2) { fprintf(stderr,"usage: slaload file.sla [runs]\n"); return 2; }
  int runs = argc > 2 ? atoi(argv[2]) : 10;
  AttributeId::initialize();
  ElementId::initialize();
  double best = 1e9;
  for(int i=0;i<runs;++i) {
    DocumentStorage store;
    std::ostringstream tag;
    tag << "<sleigh>" << argv[1] << "</sleigh>";
    std::istringstream tagstream(tag.str());
    store.registerTag(store.parseDocument(tagstream)->getRoot());
    NoImage image;
    ContextInternal context;
    Sleigh trans(&image,&context);
    auto start = std::chrono::steady_clock::now();
    trans.initialize(store);
    auto end = std::chrono::steady_clock::now();
    double ms = std::chrono::duration<double,std::milli>(end - start).count();
    if (ms < best) best = ms;
  }
  printf("Sleigh::initialize %s: best of %d: %.2f ms\n",argv[1],runs,best);
  return 0;
}
