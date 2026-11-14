// snippetdump: Basilisk's oracle for p-code snippets.
//
// Loads one SLEIGH language with Ghidra's own C++ engine (libsla), reads
// snippet records from standard input, compiles each body with Ghidra's
// snippet compiler (PcodeSnippet, pcodeparse.y) exactly as the decompiler's
// injection library does (PcodeInjectLibrarySleigh::parseInject), and prints
// the compiled template as XML (ConstructTpl::encode through XmlEncode) or
// the failure. The record formats are documented in tools/reference/README.md;
// they are a contract with crates/bk-sleigh-snippet's differential test, so
// change the two together and bump FORMAT_VERSION.
//
// Built by scripts/build-reference.sh against the objects of the reference
// build; a development oracle, never part of the product (ADR-005).
//
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of Basilisk, under the project licence (LICENSE at the repository root).

#include "loadimage.hh"
#include "sleigh.hh"
#include "pcodeparse.hh"
#include "filemanage.hh"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <sstream>

using namespace ghidra;

using std::cerr;
using std::string;
using std::vector;

namespace {

const int FORMAT_VERSION = 1;

const int EXIT_LOAD = 1;
const int EXIT_USAGE = 2;
const int EXIT_INPUT = 3;

struct UsageError {
  string message;
  explicit UsageError(const string &m) : message(m) {}
};

struct LoadError {
  string message;
  explicit LoadError(const string &m) : message(m) {}
};

struct InputError {
  string message;
  explicit InputError(const string &m) : message(m) {}
};

/// No instruction bytes are ever read: snippets are compiled, not decoded.
class EmptyLoadImage : public LoadImage {
public:
  EmptyLoadImage(void) : LoadImage("snippetdump") {}
  virtual void loadFill(uint1 *ptr,int4 size,const Address &addr) {
    for(int4 i=0;i<size;++i) ptr[i] = 0;
  }
  virtual string getArchType(void) const { return "snippetdump"; }
  virtual void adjustVma(long adjust) {}
};

// ------------------------------------------------------------------ escaping

/// Append \b text with backslash, tab, line feed, carriage return and NUL
/// escaped, so a field never breaks the line or field structure.
void appendEscaped(string &out,const string &text)

{
  for(size_t i=0;i<text.size();++i) {
    char c = text[i];
    switch(c) {
    case '\\': out += "\\\\"; break;
    case '\t': out += "\\t"; break;
    case '\n': out += "\\n"; break;
    case '\r': out += "\\r"; break;
    case '\0': out += "\\0"; break;
    default: out += c; break;
    }
  }
}

/// The inverse of appendEscaped.
string unescape(const string &field)

{
  string res;
  for(size_t i=0;i<field.size();++i) {
    char c = field[i];
    if (c != '\\') {
      res += c;
      continue;
    }
    if (++i >= field.size())
      throw InputError("dangling backslash");
    switch(field[i]) {
    case '\\': res += '\\'; break;
    case 't': res += '\t'; break;
    case 'n': res += '\n'; break;
    case 'r': res += '\r'; break;
    case '0': res += '\0'; break;
    default: throw InputError(string("bad escape \\") + field[i]);
    }
  }
  return res;
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

uintb parseNumber(const string &text,const string &what)

{
  if (text.empty())
    throw InputError("missing " + what);
  char *end;
  unsigned long long val = strtoull(text.c_str(),&end,0);
  if (*end != '\0')
    throw InputError("bad " + what + ": " + text);
  return (uintb)val;
}

vector<string> splitTabs(const string &line)

{
  vector<string> res;
  string::size_type start = 0;
  for(;;) {
    string::size_type pos = line.find('\t',start);
    if (pos == string::npos) {
      res.push_back(line.substr(start));
      return res;
    }
    res.push_back(line.substr(start,pos-start));
    start = pos + 1;
  }
}

// ------------------------------------------------------- language resolution
// As in pcodedump.cc: the .sla and .pspec are resolved beside the .ldefs that
// defines the language.

struct LanguageFiles {
  string slafile;
  const Element *element;
};

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
  std::sort(res.begin(),res.end());
}

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
      cerr << "snippetdump: warning: cannot parse " << ldefs[i] << ": " << err.explain << '\n';
      continue;
    }
    const List &children(rootel->getChildren());
    for(List::const_iterator iter=children.begin();iter!=children.end();++iter) {
      const Element *el = *iter;
      string id;
      if (el->getName() != "language" || !findAttribute(el,"id",id) || id != langid) continue;
      string slafile;
      if (!findAttribute(el,"slafile",slafile))
	throw LoadError("language " + langid + " in " + ldefs[i] + " has no slafile attribute");
      LanguageFiles res;
      res.slafile = directoryOf(ldefs[i]) + slafile;
      res.element = el;
      return res;
    }
  }
  throw LoadError("language " + langid + " is not defined by any .ldefs under " + root);
}

/// Apply the <truncate_space> children of the language definition, as
/// SleighArchitecture does before the injection library is built.
void applyTruncations(const LanguageFiles &files,Sleigh &trans)

{
  const List &children(files.element->getChildren());
  for(List::const_iterator iter=children.begin();iter!=children.end();++iter) {
    if ((*iter)->getName() != "truncate_space") continue;
    XmlDecode decoder(&trans,*iter);
    TruncationTag tag;
    tag.decode(decoder);
    trans.truncateSpace(tag);
  }
}

// ------------------------------------------------------------------- records

/// One input record: `S`, source, base, body, then `index:name` parameters.
struct Record {
  string source;
  enum { carried, start, fixed } basekind;
  uintb base;
  string body;
  vector<std::pair<string,int4> > params;
};

Record parseRecord(const string &line)

{
  vector<string> fields = splitTabs(line);
  if (fields.size() < 4 || fields[0] != "S")
    throw InputError("expected S<TAB>source<TAB>base<TAB>body[<TAB>index:name]...");
  Record rec;
  rec.source = unescape(fields[1]);
  const string &base(fields[2]);
  if (base == "continue") {
    rec.basekind = Record::carried;
    rec.base = 0;
  }
  else if (base.compare(0,6,"fixed:") == 0) {
    rec.basekind = Record::fixed;
    rec.base = parseNumber(base.substr(6),"base");
  }
  else {
    rec.basekind = Record::start;
    rec.base = parseNumber(base,"base");
  }
  rec.body = unescape(fields[3]);
  for(size_t i=4;i<fields.size();++i) {
    string param = unescape(fields[i]);
    string::size_type colon = param.find(':');
    if (colon == string::npos)
      throw InputError("parameter without index: " + param);
    int4 index = (int4)parseNumber(param.substr(0,colon),"parameter index");
    rec.params.push_back(std::make_pair(param.substr(colon+1),index));
  }
  return rec;
}

struct Counts {
  uintb ok;
  uintb failed;
  Counts(void) : ok(0), failed(0) {}
};

/// Compile one record as parseInject does and append its result line.
void compileRecord(const Sleigh &trans,const Record &rec,uint4 &carried,string &out,Counts &counts)

{
  uint4 base = carried;
  if (rec.basekind != Record::carried)
    base = (uint4)rec.base;
  if (rec.basekind == Record::start)
    carried = base;

  PcodeSnippet compiler(&trans);
  for(size_t i=0;i<rec.params.size();++i)
    compiler.addOperand(rec.params[i].first,rec.params[i].second);
  compiler.setUniqueBase(base);
  std::istringstream s(rec.body);
  try {
    if (!compiler.parseStream(s)) {
      out += "F\t";
      appendEscaped(out,rec.source);
      out += '\t';
      appendHex(out,base);
      out += "\trejected\t";
      appendEscaped(out,compiler.getErrorMessage());
      out += '\n';
      counts.failed += 1;
      return;
    }
  } catch(LowlevelError &err) {
    out += "F\t";
    appendEscaped(out,rec.source);
    out += '\t';
    appendHex(out,base);
    out += "\texception\t";
    appendEscaped(out,err.explain);
    out += '\n';
    counts.failed += 1;
    return;
  }
  uint4 next = compiler.getUniqueBase();
  if (rec.basekind != Record::fixed)
    carried = next;
  ConstructTpl *tpl = compiler.releaseResult();
  std::ostringstream xml;
  {
    XmlEncode encoder(xml);
    tpl->encode(encoder,-1);
  }
  delete tpl;
  out += "O\t";
  appendEscaped(out,rec.source);
  out += '\t';
  appendHex(out,base);
  out += '\t';
  appendHex(out,next);
  out += '\t';
  appendDec(out,compiler.hasErrors() ? 1 : 0);
  out += '\t';
  appendEscaped(out,compiler.getErrorMessage());
  out += '\t';
  appendEscaped(out,xml.str());
  out += '\n';
  counts.ok += 1;
}

void usage(void)

{
  cerr << "USAGE: snippetdump <root> <language-id> < records\n"
       << "  <root>            directory scanned for .ldefs files (the reference directory)\n"
       << "  <language-id>     for example x86:LE:64:default\n"
       << "  records           one per line, see tools/reference/README.md\n";
}

int run(int argc,char **argv)

{
  if (argc != 3)
    throw UsageError("expected <root> <language-id>");
  string root(argv[1]);
  string langid(argv[2]);

  AttributeId::initialize();
  ElementId::initialize();

  DocumentStorage store;
  LanguageFiles files = findLanguage(root,langid,store);
  EmptyLoadImage loader;
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
    applyTruncations(files,trans);
  } catch(DecoderError &err) {
    throw LoadError("cannot load " + langid + " (" + files.slafile + "): " + err.explain);
  } catch(LowlevelError &err) {
    throw LoadError("cannot load " + langid + " (" + files.slafile + "): " + err.explain);
  }

  uint4 carried = trans.getUniqueStart(Translate::INJECT);
  string out;
  out += "H\t";
  appendDec(out,(uintb)FORMAT_VERSION);
  out += '\t';
  appendEscaped(out,langid);
  out += '\t';
  appendHex(out,trans.getUniqueBase());
  out += '\t';
  appendHex(out,carried);
  out += '\n';

  Counts counts;
  string line;
  uintb lineno = 0;
  while(std::getline(std::cin,line)) {
    lineno += 1;
    if (line.empty()) continue;
    Record rec;
    try {
      rec = parseRecord(line);
    } catch(InputError &err) {
      std::ostringstream msg;
      msg << "line " << lineno << ": " << err.message;
      throw InputError(msg.str());
    }
    compileRecord(trans,rec,carried,out,counts);
    fwrite(out.data(),1,out.size(),stdout);
    out.clear();
  }
  out += "T\t";
  appendDec(out,counts.ok);
  out += '\t';
  appendDec(out,counts.failed);
  out += '\n';
  fwrite(out.data(),1,out.size(),stdout);
  fflush(stdout);
  return 0;
}

} // End anonymous namespace

int main(int argc,char **argv)

{
  try {
    return run(argc,argv);
  } catch(UsageError &err) {
    cerr << "snippetdump: " << err.message << '\n';
    usage();
    return EXIT_USAGE;
  } catch(LoadError &err) {
    cerr << "snippetdump: " << err.message << '\n';
    return EXIT_LOAD;
  } catch(InputError &err) {
    cerr << "snippetdump: " << err.message << '\n';
    return EXIT_INPUT;
  } catch(DecoderError &err) {
    cerr << "snippetdump: " << err.explain << '\n';
    return EXIT_LOAD;
  } catch(LowlevelError &err) {
    cerr << "snippetdump: " << err.explain << '\n';
    return EXIT_LOAD;
  }
}
