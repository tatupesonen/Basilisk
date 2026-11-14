// pcodedump: Basilisk's disassembly and p-code oracle.
//
// Loads one SLEIGH language with Ghidra's own C++ engine (libsla), applies the
// context defaults of its processor specification, decodes a byte buffer as a
// linear sweep from a base address and prints every instruction and its p-code
// in the line format documented in tools/reference/README.md. The format is a
// contract for checked-in snapshots and for the parser in crates/bk-testkit;
// change the two together and bump FORMAT_VERSION.
//
// Modelled on Ghidra's sleighexample.cc. Built by scripts/build-reference.sh
// against the objects of the reference build; it is a development oracle and
// never part of the product (ADR-005).
//
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of Basilisk, under the project licence (LICENSE at the repository root).
// The patches under tools/reference/patches/ modify Ghidra's Apache-2.0 source
// and stay under that source's licence.

#include "loadimage.hh"
#include "sleigh.hh"
#include "filemanage.hh"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>

using namespace ghidra;

using std::cerr;
using std::string;
using std::vector;

namespace {

const int FORMAT_VERSION = 1;

// Exit codes: 0 success (decode errors are reported in the output, not here),
// 1 the language could not be found or loaded, 2 bad command line.
const int EXIT_LOAD = 1;
const int EXIT_USAGE = 2;

struct UsageError {
  string message;
  explicit UsageError(const string &m) : message(m) {}
};

struct LoadError {
  string message;
  explicit LoadError(const string &m) : message(m) {}
};

// ---------------------------------------------------------------- byte source

/// The input buffer presented to SLEIGH as a load image. Bytes outside the
/// buffer read as zero: the engine always fetches a fixed look-ahead window, so
/// the last instructions of a buffer must not fail merely because the window
/// runs past the end. An instruction that really needs bytes past the end is
/// reported as truncated by the sweep.
class BufferLoadImage : public LoadImage {
  uintb base;
  const vector<uint1> &data;
public:
  BufferLoadImage(uintb b,const vector<uint1> &d) : LoadImage("pcodedump"), base(b), data(d) {}
  virtual void loadFill(uint1 *ptr,int4 size,const Address &addr) {
    uintb start = addr.getOffset();
    for(int4 i=0;i<size;++i) {
      uintb off = start + (uintb)i - base;	// Wraps to a huge value below the base
      ptr[i] = (off < data.size()) ? data[(size_t)off] : 0;
    }
  }
  virtual string getArchType(void) const { return "pcodedump"; }
  virtual void adjustVma(long adjust) {}
};

// -------------------------------------------------------------------- output

/// Append \b text with tab, newline, carriage return and backslash escaped, so
/// a field can never break the line or field structure.
void appendEscaped(string &out,const string &text)

{
  for(size_t i=0;i<text.size();++i) {
    char c = text[i];
    switch(c) {
    case '\\': out += "\\\\"; break;
    case '\t': out += "\\t"; break;
    case '\n': out += "\\n"; break;
    case '\r': out += "\\r"; break;
    default: out += c; break;
    }
  }
}

void appendHex(string &out,uintb val)

{
  char buf[32];
  snprintf(buf,sizeof(buf),"0x%llx",(unsigned long long)val);
  out += buf;
}

void appendDec(string &out,uintb val)

{
  char buf[32];
  snprintf(buf,sizeof(buf),"%llu",(unsigned long long)val);
  out += buf;
}

void appendBytes(string &out,const vector<uint1> &data,size_t start,size_t len)

{
  static const char digits[] = "0123456789abcdef";
  for(size_t i=0;i<len && start+i<data.size();++i) {
    uint1 b = data[start+i];
    out += digits[b >> 4];
    out += digits[b & 0xf];
  }
}

/// Collects the assembly text of one instruction.
class AssemblyCapture : public AssemblyEmit {
public:
  string mnemonic;
  string body;
  virtual void dump(const Address &addr,const string &mnem,const string &bod) {
    mnemonic = mnem;
    body = bod;
  }
};

/// Formats the p-code ops of one instruction as `P` records.
class PcodeCapture : public PcodeEmit {
  const Translate &trans;
  void appendVarnode(const VarnodeData &vn,bool isSpaceRef);
public:
  string text;		///< The `P` lines accumulated for the current instruction
  uintb count;		///< Number of ops emitted over the whole run
  bool format;		///< False to only count ops (quiet mode)
  PcodeCapture(const Translate &t,bool f) : trans(t), count(0), format(f) {}
  virtual void dump(const Address &addr,OpCode opc,VarnodeData *outvar,VarnodeData *vars,int4 isize);
};

void PcodeCapture::appendVarnode(const VarnodeData &vn,bool isSpaceRef)

{
  text += '(';
  text += vn.space->getName();
  text += ',';
  if (isSpaceRef) {
    // The constant holds a host pointer to the address space; print the
    // space's index instead and name the space as the fourth element.
    AddrSpace *spc = vn.getSpaceFromConst();
    appendHex(text,(uintb)spc->getIndex());
    text += ',';
    appendDec(text,vn.size);
    text += ',';
    text += spc->getName();
  }
  else {
    appendHex(text,vn.offset);
    text += ',';
    appendDec(text,vn.size);
    if (vn.space->getType() != IPTR_CONSTANT) {
      string name = trans.getExactRegisterName(vn.space,vn.offset,(int4)vn.size);
      if (!name.empty()) {
	text += ',';
	text += name;
      }
    }
  }
  text += ')';
}

void PcodeCapture::dump(const Address &addr,OpCode opc,VarnodeData *outvar,VarnodeData *vars,int4 isize)

{
  count += 1;
  if (!format) return;
  text += "P\t";
  text += get_opname(opc);
  text += '\t';
  if (outvar != (VarnodeData *)0)
    appendVarnode(*outvar,false);
  else
    text += '-';
  bool hasSpaceRef = (opc == CPUI_LOAD || opc == CPUI_STORE);
  for(int4 i=0;i<isize;++i) {
    text += '\t';
    appendVarnode(vars[i],hasSpaceRef && i == 0);
  }
  text += '\n';
}

// ------------------------------------------------------- language resolution

struct LanguageFiles {
  string ldefs;			///< The .ldefs file that defines the language
  string slafile;		///< Path of the compiled .sla
  string pspec;			///< Path of the processor specification
  const Element *element;	///< The <language> element, owned by the DocumentStorage
};

/// Directory part of a path, including the trailing separator.
string directoryOf(const string &path)

{
  string::size_type pos = path.find_last_of('/');
  if (pos == string::npos) return "./";
  return path.substr(0,pos+1);
}

bool findAttribute(const Element *el,const string &name,string &res)

{
  for(int4 i=0;i<el->getNumAttributes();++i) {
    if (el->getAttributeName(i) == name) {
      res = el->getAttributeValue(i);
      return true;
    }
  }
  return false;
}

/// List the language directories under \b root exactly as
/// SleighArchitecture::scanForSleighDirectories does: a `Ghidra` directory at
/// most two levels down, its `Processors` and `contrib` children, each
/// module's `data/languages` and that directory's subdirectories. A root that
/// does not have this layout is itself taken as a language directory.
void collectLanguageDirectories(const string &root,vector<string> &res)

{
  vector<string> ghidradir;
  vector<string> procdir;
  vector<string> moduledir;

  FileManage::scanDirectoryRecursive(ghidradir,"Ghidra",root,2);
  for(size_t i=0;i<ghidradir.size();++i) {
    FileManage::scanDirectoryRecursive(procdir,"Processors",ghidradir[i],1);
    FileManage::scanDirectoryRecursive(procdir,"contrib",ghidradir[i],1);
  }
  for(size_t i=0;i<procdir.size();++i)
    FileManage::directoryList(moduledir,procdir[i]);
  vector<string> datadirs;
  for(size_t i=0;i<moduledir.size();++i)
    FileManage::scanDirectoryRecursive(datadirs,"data",moduledir[i],1);
  vector<string> languagedirs;
  for(size_t i=0;i<datadirs.size();++i)
    FileManage::scanDirectoryRecursive(languagedirs,"languages",datadirs[i],1);
  for(size_t i=0;i<languagedirs.size();++i)
    res.push_back(languagedirs[i]);
  for(size_t i=0;i<languagedirs.size();++i)
    FileManage::directoryList(res,languagedirs[i]);
  if (res.empty())
    res.push_back(root);
  std::sort(res.begin(),res.end());	// Directory order is otherwise arbitrary
}

/// Find the language with the given id. Unlike Ghidra, which searches every
/// language directory for the file names an .ldefs mentions, the .sla and
/// .pspec are resolved relative to the .ldefs that names them.
LanguageFiles findLanguage(const string &root,const string &langid,DocumentStorage &store)

{
  vector<string> dirs;
  collectLanguageDirectories(root,dirs);
  vector<string> ldefs;
  for(size_t i=0;i<dirs.size();++i)
    FileManage::matchListDir(ldefs,".ldefs",true,dirs[i],false);
  std::sort(ldefs.begin(),ldefs.end());
  if (ldefs.empty())
    throw LoadError("no .ldefs files found under " + root);

  for(size_t i=0;i<ldefs.size();++i) {
    const Element *rootel;
    try {
      rootel = store.openDocument(ldefs[i])->getRoot();
    } catch(DecoderError &err) {
      cerr << "pcodedump: warning: cannot parse " << ldefs[i] << ": " << err.explain << '\n';
      continue;
    }
    const List &children(rootel->getChildren());
    for(List::const_iterator iter=children.begin();iter!=children.end();++iter) {
      const Element *el = *iter;
      string id;
      if (el->getName() != "language" || !findAttribute(el,"id",id) || id != langid) continue;
      LanguageFiles res;
      string slafile,pspec;
      if (!findAttribute(el,"slafile",slafile))
	throw LoadError("language " + langid + " in " + ldefs[i] + " has no slafile attribute");
      if (!findAttribute(el,"processorspec",pspec))
	throw LoadError("language " + langid + " in " + ldefs[i] + " has no processorspec attribute");
      string dir = directoryOf(ldefs[i]);
      res.ldefs = ldefs[i];
      res.slafile = dir + slafile;
      res.pspec = dir + pspec;
      res.element = el;
      return res;
    }
  }
  throw LoadError("language " + langid + " is not defined by any .ldefs under " + root);
}

/// Apply what SleighArchitecture applies to the translator and context before
/// any instruction is decoded: the <truncate_space> children of the language
/// definition and the <context_data> of the processor specification.
void applyLanguageSetup(const LanguageFiles &files,Sleigh &trans,ContextInternal &context,
			DocumentStorage &store)
{
  const List &children(files.element->getChildren());
  for(List::const_iterator iter=children.begin();iter!=children.end();++iter) {
    if ((*iter)->getName() != "truncate_space") continue;
    XmlDecode decoder(&trans,*iter);
    TruncationTag tag;
    tag.decode(decoder);
    trans.truncateSpace(tag);
  }

  const Element *pspec = store.openDocument(files.pspec)->getRoot();
  const List &specs(pspec->getChildren());
  for(List::const_iterator iter=specs.begin();iter!=specs.end();++iter) {
    if ((*iter)->getName() != "context_data") continue;
    XmlDecode decoder(&trans,*iter);
    context.decodeFromSpec(decoder);
  }
}

// --------------------------------------------------------------- command line

struct Options {
  string root;
  string langid;
  uintb base;
  vector<std::pair<string,uintm> > context;
  bool haveHex;
  string hex;
  bool quiet;		///< Decode and lift without printing instruction records
  bool timing;		///< Report load and decode times on standard error
  Options(void) : base(0), haveHex(false), quiet(false), timing(false) {}
};

void usage(void)

{
  cerr << "USAGE: pcodedump <root> <language-id> <base-address> [options] < bytes\n"
       << "  <root>            directory scanned for .ldefs files (the reference directory)\n"
       << "  <language-id>     for example x86:LE:64:default\n"
       << "  <base-address>    byte offset of the first input byte in the default code space\n"
       << "  --context N=V     set context variable N over the whole code space (repeatable)\n"
       << "  --hex HEXBYTES    decode these bytes instead of standard input\n"
       << "  --quiet           decode and lift everything but print only the H and T records\n"
       << "  --timing          print language load and decode times on standard error\n";
}

uintb parseNumber(const string &text,const string &what)

{
  if (text.empty())
    throw UsageError("missing " + what);
  char *end;
  unsigned long long val = strtoull(text.c_str(),&end,0);
  if (*end != '\0')
    throw UsageError("bad " + what + ": " + text);
  return (uintb)val;
}

int hexDigit(char c)

{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

void parseHexBytes(const string &text,vector<uint1> &data)

{
  int high = -1;
  for(size_t i=0;i<text.size();++i) {
    char c = text[i];
    if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '_') continue;
    int digit = hexDigit(c);
    if (digit < 0)
      throw UsageError("bad hex digit in --hex argument");
    if (high < 0)
      high = digit;
    else {
      data.push_back((uint1)((high << 4) | digit));
      high = -1;
    }
  }
  if (high >= 0)
    throw UsageError("odd number of hex digits in --hex argument");
}

Options parseOptions(int argc,char **argv)

{
  Options opt;
  vector<string> positional;
  for(int i=1;i<argc;++i) {
    string arg(argv[i]);
    if (arg == "--context") {
      if (++i >= argc) throw UsageError("--context needs NAME=VALUE");
      string pair(argv[i]);
      string::size_type pos = pair.find('=');
      if (pos == string::npos || pos == 0) throw UsageError("--context needs NAME=VALUE");
      opt.context.push_back(std::make_pair(pair.substr(0,pos),
					   (uintm)parseNumber(pair.substr(pos+1),"context value")));
    }
    else if (arg == "--hex") {
      if (++i >= argc) throw UsageError("--hex needs a hex string");
      opt.haveHex = true;
      opt.hex = argv[i];
    }
    else if (arg == "--quiet")
      opt.quiet = true;
    else if (arg == "--timing")
      opt.timing = true;
    else if (arg.size() > 1 && arg[0] == '-' && arg[1] == '-')
      throw UsageError("unknown option " + arg);
    else
      positional.push_back(arg);
  }
  if (positional.size() != 3)
    throw UsageError("expected <root> <language-id> <base-address>");
  opt.root = positional[0];
  opt.langid = positional[1];
  opt.base = parseNumber(positional[2],"base address");
  return opt;
}

void readStandardInput(vector<uint1> &data)

{
  uint1 buf[65536];
  size_t n;
  while((n = fread(buf,1,sizeof(buf),stdin)) > 0)
    data.insert(data.end(),buf,buf+n);
}

double secondsSince(const std::chrono::steady_clock::time_point &start)

{
  return std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
}

void flush(string &out)

{
  fwrite(out.data(),1,out.size(),stdout);
  out.clear();
}

// ---------------------------------------------------------------- the sweep

struct SweepCounts {
  uintb instructions;
  uintb errors;
  SweepCounts(void) : instructions(0), errors(0) {}
};

void appendErrorRecord(string &out,uintb offset,const vector<uint1> &data,size_t pos,size_t len,
		       const char *kind,const string &message)
{
  out += "E\t";
  appendHex(out,offset);
  out += '\t';
  appendDec(out,len);
  out += '\t';
  appendBytes(out,data,pos,len);
  out += '\t';
  out += kind;
  out += '\t';
  appendEscaped(out,message);
  out += '\n';
}

/// Decode the buffer front to back. Each position yields either an `I` record
/// followed by its `P` records (or by one `U` record when the instruction
/// could not be lifted), or an `E` record after which decoding resumes at the
/// next byte.
SweepCounts sweep(Sleigh &trans,const Options &opt,const vector<uint1> &data,PcodeCapture &pcode,string &out)

{
  SweepCounts counts;
  AssemblyCapture assembly;
  AddrSpace *codespace = trans.getDefaultCodeSpace();
  size_t pos = 0;

  while(pos < data.size()) {
    uintb offset = opt.base + pos;
    Address addr(codespace,offset);
    size_t remaining = data.size() - pos;
    int4 length = 0;

    // Disassemble. A failure here means the bytes are not an instruction.
    try {
      if (opt.quiet)
	length = trans.instructionLength(addr);
      else
	length = trans.printAssembly(assembly,addr);
    } catch(BadDataError &err) {
      if (!opt.quiet) appendErrorRecord(out,offset,data,pos,1,"bad-data",err.explain);
      counts.errors += 1;
      pos += 1;
      continue;
    } catch(LowlevelError &err) {
      if (!opt.quiet) appendErrorRecord(out,offset,data,pos,1,"error",err.explain);
      counts.errors += 1;
      pos += 1;
      continue;
    }
    if (length <= 0) {
      if (!opt.quiet) appendErrorRecord(out,offset,data,pos,1,"error","instruction has no length");
      counts.errors += 1;
      pos += 1;
      continue;
    }
    if ((size_t)length > remaining) {
      if (!opt.quiet)
	appendErrorRecord(out,offset,data,pos,remaining,"truncated","instruction extends past the end of the input");
      counts.errors += 1;
      break;
    }

    // Lift. The flow length differs from the instruction's own length when
    // delay-slot instructions are folded into its p-code.
    pcode.text.clear();
    int4 flowLength = length;
    string liftError;
    string liftErrorKind;	// Empty when the instruction lifted
    try {
      flowLength = trans.oneInstruction(pcode,addr);
    } catch(UnimplError &err) {
      liftErrorKind = "unimplemented";
      liftError = err.explain;
      if (err.instruction_length > 0)
	flowLength = err.instruction_length;
    } catch(BadDataError &err) {
      liftErrorKind = "bad-data";	// For example an undecodable delay slot
      liftError = err.explain;
    } catch(LowlevelError &err) {
      liftErrorKind = "error";
      liftError = err.explain;
    }

    counts.instructions += 1;
    if (!opt.quiet) {
      out += "I\t";
      appendHex(out,offset);
      out += '\t';
      appendDec(out,(uintb)length);
      out += '\t';
      appendDec(out,(uintb)flowLength);
      out += '\t';
      appendBytes(out,data,pos,(size_t)length);
      out += '\t';
      appendEscaped(out,assembly.mnemonic);
      out += '\t';
      appendEscaped(out,assembly.body);
      out += '\n';
      if (!liftErrorKind.empty()) {
	out += "U\t";
	out += liftErrorKind;
	out += '\t';
	appendEscaped(out,liftError);
	out += '\n';
      }
      else
	out += pcode.text;
      if (out.size() > (1 << 16))
	flush(out);
    }
    if (!liftErrorKind.empty())
      counts.errors += 1;
    pos += (size_t)length;
  }
  return counts;
}

int run(int argc,char **argv)

{
  Options opt = parseOptions(argc,argv);

  vector<uint1> data;
  if (opt.haveHex)
    parseHexBytes(opt.hex,data);
  else
    readStandardInput(data);

  AttributeId::initialize();
  ElementId::initialize();

  std::chrono::steady_clock::time_point loadStart = std::chrono::steady_clock::now();
  DocumentStorage store;
  LanguageFiles files = findLanguage(opt.root,opt.langid,store);
  BufferLoadImage loader(opt.base,data);
  ContextInternal context;
  Sleigh trans(&loader,&context);
  try {
    std::ostringstream tag;
    tag << "<sleigh>";
    xml_escape(tag,files.slafile.c_str());
    tag << "</sleigh>";
    std::istringstream tagstream(tag.str());
    store.registerTag(store.parseDocument(tagstream)->getRoot());
    trans.initialize(store);
    applyLanguageSetup(files,trans,context,store);
    // Command-line values win over the processor specification, which sets
    // its values on address ranges rather than as defaults, so set a range too.
    Address first(trans.getDefaultCodeSpace(),0);
    for(size_t i=0;i<opt.context.size();++i)
      context.setVariableRegion(opt.context[i].first,first,Address(),opt.context[i].second);
  } catch(DecoderError &err) {
    throw LoadError("cannot load " + opt.langid + " (" + files.slafile + "): " + err.explain);
  } catch(LowlevelError &err) {
    throw LoadError("cannot load " + opt.langid + " (" + files.slafile + "): " + err.explain);
  }
  double loadSeconds = secondsSince(loadStart);

  string out;
  out += "H\t";
  appendDec(out,(uintb)FORMAT_VERSION);
  out += '\t';
  appendEscaped(out,opt.langid);
  out += '\t';
  out += trans.getDefaultCodeSpace()->getName();
  out += '\t';
  appendHex(out,opt.base);
  out += '\t';
  appendDec(out,data.size());
  out += '\n';

  PcodeCapture pcode(trans,!opt.quiet);
  std::chrono::steady_clock::time_point decodeStart = std::chrono::steady_clock::now();
  SweepCounts counts = sweep(trans,opt,data,pcode,out);
  double decodeSeconds = secondsSince(decodeStart);

  out += "T\t";
  appendDec(out,counts.instructions);
  out += '\t';
  appendDec(out,counts.errors);
  out += '\n';
  flush(out);
  fflush(stdout);

  if (opt.timing) {
    char buf[256];
    snprintf(buf,sizeof(buf),
	     "timing\tload_seconds=%.6f\tdecode_seconds=%.6f\tinstructions=%llu\tops=%llu\terrors=%llu\tbytes=%llu\n",
	     loadSeconds,decodeSeconds,(unsigned long long)counts.instructions,
	     (unsigned long long)pcode.count,(unsigned long long)counts.errors,
	     (unsigned long long)data.size());
    cerr << buf;
  }
  return 0;
}

} // End anonymous namespace

int main(int argc,char **argv)

{
  try {
    return run(argc,argv);
  } catch(UsageError &err) {
    cerr << "pcodedump: " << err.message << '\n';
    usage();
    return EXIT_USAGE;
  } catch(LoadError &err) {
    cerr << "pcodedump: " << err.message << '\n';
    return EXIT_LOAD;
  } catch(DecoderError &err) {
    cerr << "pcodedump: " << err.explain << '\n';
    return EXIT_LOAD;
  } catch(LowlevelError &err) {
    cerr << "pcodedump: " << err.explain << '\n';
    return EXIT_LOAD;
  }
}
