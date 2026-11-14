// Oracle for bk-decomp-types: evaluates Ghidra's own TypeFactory, C parser
// and data organisation (type.cc, grammar.y, architecture.cc, linked from
// the reference build's objects) and prints one record per line. Built and
// run by regen.sh; the output is tests/data/types_oracle.txt.gz, replayed by
// tests/oracle_replay.rs and tests/oracle_dataorg.rs. Not part of the Rust
// build. Compiled with -fno-access-control to read the factory's private
// alignment map.
//
// Usage: types_oracle <sleighhome> <decls.txt> <lang>...   (main table)
//        types_oracle <sleighhome> --orgs                  (every pair)
//
// Record format: tab-separated fields, strings escaped (\t \n \\).
//   ENV  lang space addrsize wordsize bigendian codeaddrsize spsize farinner farbase model maxbase
//   ORG  lang int long char wchar ptr altptr enumsize enumsigned alignmap(comma)
//   CORE lang <encodeCoreTypes xml>
//   D    lang i OK desc... | ERR msg | DONE kind
//   F/B  lang i k ...            fields and bitfields of a composite result
//   CMP  lang i row              sign of compare(Ti,Tj,10) for all j ('.' no type)
//   DEP  lang i row              compareDependency(Ti,Tj)==0 ? '0' : '1'
//   M    lang i value complement shift names
//   E    lang i <encode xml>
//   Q    lang i op args result
//   G    lang <typegrp xml>
//   H    hexbytes hash
//   ORGP lang:compiler cspec sla ENV-fields ORG-fields | ORGP id ERR msg

#include "architecture.hh"
#include "grammar.hh"
#include "libdecomp.hh"
#include "sleigh_arch.hh"

#include <fstream>
#include <iostream>
#include <sstream>

using namespace std;
using namespace ghidra;

namespace {

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

string envFields(Architecture *g) {
  ostringstream s;
  AddrSpace *data = g->getDefaultDataSpace();
  AddrSpace *stack = g->getStackSpace();
  int4 sp = -1;
  if (stack != (AddrSpace *)0 && stack->numSpacebase() > 0) sp = stack->getSpacebase(0).size;
  int4 inner = -1, base = -1;
  SegmentOp *seg = g->getSegmentOp(data);
  if (seg != (SegmentOp *)0 && seg->hasFarPointerSupport()) { inner = seg->getInnerSize(); base = seg->getBaseSize(); }
  s << esc(data->getName()) << '\t' << data->getAddrSize() << '\t' << data->getWordSize() << '\t'
    << (data->isBigEndian() ? 1 : 0) << '\t' << g->getDefaultCodeSpace()->getAddrSize() << '\t' << sp << '\t'
    << inner << '\t' << base << '\t' << esc(g->defaultfp->getName()) << '\t' << g->max_basetype_size;
  return s.str();
}

string orgFields(Architecture *g) {
  TypeFactory *t = g->types;
  ostringstream s;
  s << t->sizeOfInt << '\t' << t->sizeOfLong << '\t' << t->sizeOfChar << '\t' << t->sizeOfWChar << '\t'
    << t->sizeOfPointer << '\t' << t->sizeOfAltPointer << '\t' << t->enumsize << '\t'
    << (t->enumtype == TYPE_ENUM_INT ? 1 : 0) << '\t';
  for (size_t i = 0; i < t->alignMap.size(); ++i) s << (i ? "," : "") << t->alignMap[i];
  return s.str();
}

string raw(Datatype *ct) {
  if (ct == (Datatype *)0) return "null";
  ostringstream s;
  ct->printRaw(s);
  return esc(s.str());
}

string desc(Datatype *ct) {
  ostringstream s;
  s << hex << ct->getId() << dec << '\t' << ct->getSize() << '\t' << ct->getAlignment() << '\t'
    << ct->getAlignSize() << '\t' << (int)ct->getMetatype() << '\t' << (int)ct->getSubMeta() << '\t'
    << hex << ct->flags << dec << '\t' << raw(ct) << '\t' << esc(ct->getName());
  return s.str();
}

string encodeText(Datatype *ct) {
  ostringstream s;
  XmlEncode enc(s, false);
  ct->encode(enc);
  return esc(s.str());
}

bool hasModel(Architecture *g, const string &nm) { return g->hasModel(nm); }

void composite(const string &lang, int i, Datatype *ct) {
  if (ct->getMetatype() == TYPE_STRUCT || ct->getMetatype() == TYPE_UNION) {
    const vector<TypeField> &fields = (ct->getMetatype() == TYPE_STRUCT) ? ((TypeStruct *)ct)->field : ((TypeUnion *)ct)->field;
    for (size_t k = 0; k < fields.size(); ++k)
      cout << "F\t" << lang << '\t' << i << '\t' << k << '\t' << fields[k].offset << '\t' << fields[k].ident << '\t'
           << esc(fields[k].name) << '\t' << raw(fields[k].type) << '\n';
  }
  if (ct->getMetatype() == TYPE_STRUCT) {
    TypeStruct *st = (TypeStruct *)ct;
    for (int4 k = 0; k < st->numBitFields(); ++k) {
      const TypeBitField &b(st->getBitField(k));
      cout << "B\t" << lang << '\t' << i << '\t' << k << '\t' << b.bits.byteOffset << '\t' << b.bits.byteSize << '\t'
           << b.bits.leastSigBit << '\t' << b.bits.numBits << '\t' << b.ident << '\t' << esc(b.name) << '\t'
           << raw(b.type) << '\n';
    }
  }
}

// Queries over a grid of offsets and sizes.
void queries(const string &lang, int i, Datatype *ct, TypeFactory *t) {
  type_metatype m = ct->getMetatype();
  bool comp = (m == TYPE_STRUCT || m == TYPE_UNION || m == TYPE_ARRAY);
  int4 top = ct->getSize() + 2;
  if (top > 40) top = 40;
  if (comp) {
    for (int4 off = 0; off < top; ++off) {
      int8 newoff;
      Datatype *sub = ct->getSubType(off, &newoff);
      cout << "Q\t" << lang << '\t' << i << "\tsub\t" << off << '\t' << raw(sub) << ',' << newoff << '\n';
      cout << "Q\t" << lang << '\t' << i << "\thole\t" << off << '\t' << ct->getHoleSize(off) << '\n';
      for (int4 hint = 1; hint <= 4; hint += 3) {
        int8 res = -12345;
        bool ok = ct->nearestArrayedComponent(off, hint, &res);
        cout << "Q\t" << lang << '\t' << i << "\tnearest\t" << off << ',' << hint << '\t' << (ok ? 1 : 0) << ',' << (ok ? res : 0) << '\n';
      }
      static const int4 sizes[] = {1, 2, 4, 8};
      for (int4 sz : sizes) {
        int8 noff;
        Datatype *small = ct->findSmallestContainer(off, sz, &noff);
        cout << "Q\t" << lang << '\t' << i << "\tsmallest\t" << off << ',' << sz << '\t' << raw(small) << ',' << noff << '\n';
        Datatype *piece = t->getExactPiece(ct, off, sz);
        cout << "Q\t" << lang << '\t' << i << "\tpiece\t" << off << ',' << sz << '\t' << raw(piece);
        if (piece != (Datatype *)0) cout << ',' << (int)piece->getMetatype() << ',' << (int)piece->getSubMeta() << ',' << hex << piece->flags << dec;
        cout << '\n';
      }
    }
  }
  if (m == TYPE_INT || m == TYPE_UINT || m == TYPE_UNKNOWN || m == TYPE_BOOL) {
    static const int4 sizes[] = {1, 2, 4, 8};
    for (int4 sz : sizes)
      cout << "Q\t" << lang << '\t' << i << "\tresize\t" << sz << '\t' << raw(t->resizeInteger(ct, sz)) << '\n';
  }
  cout << "Q\t" << lang << '\t' << i << "\tconcretize\t-\t" << raw(t->concretize(ct)) << '\n';
  TypePointer *ps = t->getTypePointerStripArray(t->getSizeOfPointer(), ct, 1);
  cout << "Q\t" << lang << '\t' << i << "\tstrip\t-\t" << raw(ps) << ',' << (int)ps->getSubMeta() << ',' << hex << ps->flags << dec << '\n';
  if (m == TYPE_STRUCT && ct->getSize() > 0) {
    TypePointer *p = t->getTypePointer(t->getSizeOfPointer(), ct, 1);
    for (int4 off = 1; off < top; ++off) {
      Datatype *to = TypePointerRel::getPtrToFromParent(ct, off, *t);
      TypePointerRel *rel = t->getTypePointerRel(p, to, off);
      cout << "Q\t" << lang << '\t' << i << "\trel\t" << off << '\t' << raw(rel) << ',' << (int)rel->getSubMeta() << ','
           << hex << rel->flags << dec << ',' << raw(rel->getStripped()) << '\n';
    }
  }
}

int mainTable(const string &declfile, const vector<string> &langs) {
  vector<string> decls;
  {
    ifstream in(declfile.c_str());
    string line;
    while (getline(in, line)) if (!line.empty()) decls.push_back(line);
  }
  for (const string &lang : langs) {
    Architecture *g = build(lang);
    TypeFactory *t = g->types;
    cout << "ENV\t" << lang << '\t' << envFields(g) << '\n';
    cout << "ORG\t" << lang << '\t' << orgFields(g) << '\n';
    {
      ostringstream s;
      XmlEncode enc(s, false);
      t->encodeCoreTypes(enc);
      cout << "CORE\t" << lang << '\t' << esc(s.str()) << '\n';
    }
    vector<Datatype *> res(decls.size(), (Datatype *)0);
    for (size_t i = 0; i < decls.size(); ++i) {
      char kind = decls[i][0];
      string text = decls[i].substr(2);
      try {
        istringstream s(text);
        if (kind == 'T') {
          string name;
          Datatype *ct = parse_type(s, name, g);
          res[i] = ct;
          cout << "D\t" << lang << '\t' << i << "\tOK\t" << desc(ct) << '\t' << esc(name) << '\n';
          composite(lang, i, ct);
        }
        else {
          parse_C(g, s);
          cout << "D\t" << lang << '\t' << i << "\tDONE\n";
        }
      }
      catch (ParseError &err) {
        cout << "D\t" << lang << '\t' << i << "\tERR\t" << esc(err.explain) << '\n';
      }
      catch (LowlevelError &err) {
        cout << "D\t" << lang << '\t' << i << "\tERR\t" << esc(err.explain) << '\n';
      }
    }
    for (size_t i = 0; i < decls.size(); ++i) {
      if (res[i] == (Datatype *)0) continue;
      string cmp, dep;
      for (size_t j = 0; j < decls.size(); ++j) {
        if (res[j] == (Datatype *)0) { cmp += '.'; dep += '.'; continue; }
        int4 c = res[i]->compare(*res[j], 10);
        cmp += (c < 0) ? '<' : (c > 0 ? '>' : '=');
        dep += (res[i]->compareDependency(*res[j]) == 0) ? '0' : '1';
      }
      cout << "CMP\t" << lang << '\t' << i << '\t' << cmp << '\n';
      cout << "DEP\t" << lang << '\t' << i << '\t' << dep << '\n';
    }
    for (size_t i = 0; i < decls.size(); ++i) {
      if (res[i] == (Datatype *)0) continue;
      cout << "E\t" << lang << '\t' << i << '\t' << encodeText(res[i]) << '\n';
      if (res[i]->isEnumType() && res[i]->getMetatype() != TYPE_PTR) {
        TypeEnum *te = (TypeEnum *)res[i];
        vector<uintb> vals;
        for (uintb v = 0; v < 1024; ++v) vals.push_back(v);
        uintb x = 0x9e3779b97f4a7c15ULL;
        for (int k = 0; k < 64; ++k) { x ^= x << 13; x ^= x >> 7; x ^= x << 17; vals.push_back(x); vals.push_back(~(uintb)k); }
        for (uintb v : vals) {
          TypeEnum::Representation rep;
          te->getMatches(v, rep);
          cout << "M\t" << lang << '\t' << i << '\t' << hex << v << dec << '\t' << (rep.complement ? 1 : 0) << '\t' << rep.shiftAmount << '\t';
          for (size_t k = 0; k < rep.matchname.size(); ++k) cout << (k ? "," : "") << esc(rep.matchname[k]);
          cout << '\n';
        }
      }
    }
    {
      ostringstream s;
      XmlEncode enc(s, false);
      t->encode(enc);
      cout << "G\t" << lang << '\t' << esc(s.str()) << '\n';
    }
    for (size_t i = 0; i < decls.size(); ++i) {
      if (res[i] == (Datatype *)0) continue;
      try {
        queries(lang, i, res[i], t);
      }
      catch (LowlevelError &err) {
        cout << "Q\t" << lang << '\t' << i << "\terror\t-\t" << esc(err.explain) << '\n';
      }
    }
    delete g;
  }
  // hashName over 1,000 names, some with bytes >= 0x80.
  uint8 x = 88172645463325252ULL;
  for (int k = 0; k < 1000; ++k) {
    string nm;
    int len = 1 + k % 13;
    for (int c = 0; c < len; ++c) {
      x ^= x << 13; x ^= x >> 7; x ^= x << 17;
      unsigned char b = (k % 4 == 3) ? (unsigned char)(0x20 + x % 0xdf) : (unsigned char)("abcdefghijklmnopqrstuvwxyz_0123456789"[x % 37]);
      nm += (char)b;
    }
    string hx;
    for (unsigned char b : nm) { char buf[3]; snprintf(buf, sizeof buf, "%02x", b); hx += buf; }
    cout << "H\t" << hx << '\t' << hex << Datatype::hashName(nm) << dec << '\n';
  }
  return 0;
}

int allOrgs(void) {
  const vector<LanguageDescription> &descs = SleighArchitecture::getDescriptions();
  for (const LanguageDescription &d : descs) {
    for (int4 c = 0; c < d.numCompilers(); ++c) {
      const CompilerTag &tag(d.getCompiler(c));
      string id = d.getId() + ":" + tag.getId();
      try {
        Architecture *g = build(id);
        cout << "ORGP\t" << id << '\t' << esc(tag.getSpec()) << '\t' << esc(d.getSlaFile()) << '\t' << envFields(g) << '\t' << orgFields(g) << '\n';
        delete g;
      }
      catch (LowlevelError &err) {
        cout << "ORGP\t" << id << "\tERR\t" << esc(err.explain) << '\n';
      }
      catch (DecoderError &err) {
        cout << "ORGP\t" << id << "\tERR\t" << esc(err.explain) << '\n';
      }
    }
  }
  return 0;
}

} // namespace

int main(int argc, char **argv) {
  if (argc < 3) {
    cerr << "usage: types_oracle <sleighhome> <decls.txt> <lang>... | <sleighhome> --orgs\n";
    return 2;
  }
  startDecompilerLibrary(argv[1]);
  if (string(argv[2]) == "--orgs") return allOrgs();
  vector<string> langs;
  for (int i = 3; i < argc; ++i) langs.push_back(argv[i]);
  return mainTable(argv[2], langs);
}
