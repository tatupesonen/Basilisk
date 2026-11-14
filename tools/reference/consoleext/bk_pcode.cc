/* Basilisk console extension: `bk pcode record|replay|stop` (format
 * pcoderec 1, docs/features/decomp-oracle.md 4.8) and `bk trace stream`
 * (4.9).
 *
 * The engine reaches the lifter only through Architecture::translate. A
 * proxy Translate takes its place: it shares the original's spaces, copies
 * its endianness, alignment, unique base and float formats, and forwards
 * every virtual method; for oneInstruction and instructionLength it either
 * records what the original answers (record) or answers from a recording,
 * by address (replay). The session lives for the console process. */
#include "bk_commands.hh"

#include <set>

namespace bk {

class PcodeSession;

/// The proxy translator.
class ProxyTranslate : public Translate {
public:
  const Translate *orig;
  PcodeSession *session;
  ProxyTranslate(const Translate *o, PcodeSession *s) : orig(o), session(s) {
    copySpaces(o);
    setBigEndian(o->isBigEndian());
    setUniqueBase(o->getUniqueBase());
    alignment = o->getAlignment();
    floatformats = o->floatformats;
  }
  virtual void initialize(DocumentStorage &store) { throw LowlevelError("bk pcode: the proxy is never initialised"); }
  virtual void registerContext(const string &name, int4 sbit, int4 ebit) {
    const_cast<Translate *>(orig)->registerContext(name, sbit, ebit);
  }
  virtual void setContextDefault(const string &name, uintm val) {
    const_cast<Translate *>(orig)->setContextDefault(name, val);
  }
  virtual void allowContextSet(bool val) const { orig->allowContextSet(val); }
  virtual const VarnodeData &getRegister(const string &nm) const { return orig->getRegister(nm); }
  virtual string getRegisterName(AddrSpace *base, uintb off, int4 size) const {
    return orig->getRegisterName(base, off, size);
  }
  virtual string getExactRegisterName(AddrSpace *base, uintb off, int4 size) const {
    return orig->getExactRegisterName(base, off, size);
  }
  virtual void getAllRegisters(map<VarnodeData, string> &reglist) const { orig->getAllRegisters(reglist); }
  virtual void getUserOpNames(vector<string> &res) const { orig->getUserOpNames(res); }
  virtual int4 instructionLength(const Address &baseaddr) const;
  virtual int4 oneInstruction(PcodeEmit &emit, const Address &baseaddr) const;
  virtual int4 printAssembly(AssemblyEmit &emit, const Address &baseaddr) const {
    return orig->printAssembly(emit, baseaddr);
  }
};

/// One recorded oneInstruction call.
struct InsnRecord {
  bool error;
  std::string kind;       ///< unimplemented | baddata | error
  int4 length;            ///< -1 for no length
  std::string message;
  std::vector<std::string> ops;   ///< the P records' text after the tag
};

/// One p-code op read back from a recording.
struct ReplayOp {
  Address addr;
  OpCode opc;
  bool hasOut;
  VarnodeData out;
  std::vector<VarnodeData> in;
};

class PcodeSession {
public:
  enum Mode { off, record, replay };
  Mode mode;
  Architecture *glb;
  const Translate *orig;
  std::vector<ProxyTranslate *> proxies;   ///< never freed: engine objects may still point at one
  std::string file;
  // recording
  std::vector<std::string> lines;          ///< I/U/L records with their P records, in call order
  std::map<Address, std::string> firstText;
  std::set<Address> contextDependent;
  int4 icount, ucount, lcount;
  // replay
  std::map<Address, InsnRecord> insns;
  std::map<Address, std::vector<ReplayOp> > ops;
  std::map<Address, int4> lengths;

  PcodeSession(void) : mode(off), glb((Architecture *)0), orig((const Translate *)0), icount(0), ucount(0), lcount(0) {}

  std::string varnodeText(const VarnodeData &v, bool spaceConst) const;
  void noteText(const Address &addr, const std::string &text);
  void loadRecording(const std::string &path);
  VarnodeData parseVarnode(const std::string &text, int4 line) const;
  void writeRecording(void);
};

static PcodeSession session;

/// `(space,0xOFFSET,SIZE[,NAME])` as pcodedump writes it; a LOAD/STORE
/// space constant as `(const,0x<space index>,SIZE,<space name>)`.
std::string PcodeSession::varnodeText(const VarnodeData &v, bool spaceConst) const
{
  std::ostringstream s;
  if (spaceConst && v.space->getType() == IPTR_CONSTANT) {
    for (int4 i = 0; i < orig->numSpaces(); ++i) {
      AddrSpace *spc = orig->getSpace(i);
      if (spc != (AddrSpace *)0 && (uintb)(uintp)spc == v.offset) {
        s << "(const," << hx(spc->getIndex()) << ',' << v.size << ',' << spc->getName() << ')';
        return s.str();
      }
    }
  }
  s << '(' << v.space->getName() << ',' << hx(v.offset) << ',' << v.size;
  std::string name = orig->getExactRegisterName(v.space, v.offset, v.size);
  if (!name.empty()) s << ',' << name;
  s << ')';
  return s.str();
}

void PcodeSession::noteText(const Address &addr, const std::string &text)
{
  std::map<Address, std::string>::iterator it = firstText.find(addr);
  if (it == firstText.end()) firstText[addr] = text;
  else if (it->second != text) contextDependent.insert(addr);
}

/// The emitter that logs each op and passes it on.
class RecordingEmit : public PcodeEmit {
  PcodeEmit &inner;
  const PcodeSession &s;
public:
  std::vector<std::string> ops;
  RecordingEmit(PcodeEmit &i, const PcodeSession &ss) : inner(i), s(ss) {}
  virtual void dump(const Address &addr, OpCode opc, VarnodeData *outvar, VarnodeData *vars, int4 isize) {
    std::string t = addrText(addr) + "\t" + get_opname(opc) + "\t" + (outvar == (VarnodeData *)0 ? std::string("-")
                                                                                              : s.varnodeText(*outvar, false));
    bool spaceArg = (opc == CPUI_LOAD || opc == CPUI_STORE);
    for (int4 i = 0; i < isize; ++i) t += "\t" + s.varnodeText(vars[i], spaceArg && i == 0);
    ops.push_back(t);
    inner.dump(addr, opc, outvar, vars, isize);
  }
};

int4 ProxyTranslate::instructionLength(const Address &baseaddr) const
{
  PcodeSession &s(*session);
  if (s.mode == PcodeSession::replay) {
    std::map<Address, int4>::const_iterator it = s.lengths.find(baseaddr);
    if (it == s.lengths.end()) throw LowlevelError("pcode replay: no length record for " + addrText(baseaddr));
    return it->second;
  }
  int4 len = orig->instructionLength(baseaddr);
  if (s.mode == PcodeSession::record) {
    std::string t = "L\t" + addrText(baseaddr) + "\t" + num(len);
    s.noteText(baseaddr, "L" + t);
    s.lines.push_back(t);
    s.lcount += 1;
  }
  return len;
}

int4 ProxyTranslate::oneInstruction(PcodeEmit &emit, const Address &baseaddr) const
{
  PcodeSession &s(*session);
  if (s.mode == PcodeSession::replay) {
    std::map<Address, InsnRecord>::const_iterator it = s.insns.find(baseaddr);
    if (it == s.insns.end()) throw LowlevelError("pcode replay: no record for " + addrText(baseaddr));
    const InsnRecord &r(it->second);
    if (r.error) {
      if (r.kind == "unimplemented") throw UnimplError(r.message, r.length);
      if (r.kind == "baddata") throw BadDataError(r.message);
      throw LowlevelError(r.message);
    }
    const std::vector<ReplayOp> &list(s.ops[baseaddr]);
    for (size_t i = 0; i < list.size(); ++i) {
      ReplayOp op = list[i];   // the emitter may keep pointers only for the call
      emit.dump(op.addr, op.opc, op.hasOut ? &op.out : (VarnodeData *)0, op.in.empty() ? (VarnodeData *)0 : &op.in[0],
                (int4)op.in.size());
    }
    return r.length;
  }
  if (s.mode != PcodeSession::record) return orig->oneInstruction(emit, baseaddr);
  RecordingEmit rec(emit, s);
  std::string head;
  int4 len = 0;
  try {
    len = orig->oneInstruction(rec, baseaddr);
    head = "I\t" + addrText(baseaddr) + "\t" + num(len) + "\t" + num((intb)rec.ops.size());
  }
  catch (UnimplError &err) {
    head = "U\t" + addrText(baseaddr) + "\tunimplemented\t" + num(err.instruction_length) + "\t" + escape(err.explain);
    s.noteText(baseaddr, head);
    s.lines.push_back(head);
    s.ucount += 1;
    throw;
  }
  catch (BadDataError &err) {
    head = "U\t" + addrText(baseaddr) + "\tbaddata\t-\t" + escape(err.explain);
    s.noteText(baseaddr, head);
    s.lines.push_back(head);
    s.ucount += 1;
    throw;
  }
  catch (LowlevelError &err) {
    head = "U\t" + addrText(baseaddr) + "\terror\t-\t" + escape(err.explain);
    s.noteText(baseaddr, head);
    s.lines.push_back(head);
    s.ucount += 1;
    throw;
  }
  std::string all = head;
  for (size_t i = 0; i < rec.ops.size(); ++i) all += "\nP\t" + rec.ops[i];
  s.noteText(baseaddr, all);
  s.lines.push_back(all);
  s.icount += 1;
  return len;
}

/// The language id and compiler spec id of an architecture id `lang:cspec`.
static void splitArchId(const std::string &archid, std::string &lang, std::string &cspec)
{
  size_t pos = archid.rfind(':');
  lang = (pos == std::string::npos) ? archid : archid.substr(0, pos);
  cspec = (pos == std::string::npos) ? std::string("-") : archid.substr(pos + 1);
}

void PcodeSession::writeRecording(void)
{
  AtomicFile out(file);
  std::ostream &o(out.stream());
  std::string lang, cspec;
  splitArchId(glb->archid, lang, cspec);
  o << "H\tpcoderec\t1\t" << escape(lang) << '\t' << escape(cspec) << '\n';
  for (std::set<Address>::const_iterator it = contextDependent.begin(); it != contextDependent.end(); ++it)
    o << "X\t" << addrText(*it) << '\n';
  for (size_t i = 0; i < lines.size(); ++i) o << lines[i] << '\n';
  o << "T\t" << icount << '\t' << ucount << '\t' << lcount << '\n';
  out.commit();
}

static void replayFail(int4 line, const std::string &msg)
{
  throw IfaceExecutionError("pcode replay: line " + num(line) + ": " + msg);
}

static Address parseAddr(const Translate *t, const std::string &text, int4 line)
{
  size_t pos = text.rfind(':');
  if (pos == std::string::npos) replayFail(line, "bad address " + text);
  AddrSpace *spc = t->getSpaceByName(text.substr(0, pos));
  if (spc == (AddrSpace *)0) replayFail(line, "unknown space in " + text);
  std::string off = text.substr(pos + 1);
  if (off.size() < 3 || off[0] != '0' || off[1] != 'x') replayFail(line, "bad offset in " + text);
  uintb v = 0;
  for (size_t i = 2; i < off.size(); ++i) {
    char c = off[i];
    int d = (c >= '0' && c <= '9') ? c - '0' : (c >= 'a' && c <= 'f') ? c - 'a' + 10 : -1;
    if (d < 0) replayFail(line, "bad offset in " + text);
    v = (v << 4) | (uintb)d;
  }
  return Address(spc, v);
}

VarnodeData PcodeSession::parseVarnode(const std::string &text, int4 line) const
{
  if (text.size() < 2 || text[0] != '(' || text[text.size() - 1] != ')') replayFail(line, "bad varnode " + text);
  std::vector<std::string> p = splitChar(text.substr(1, text.size() - 2), ',');
  if (p.size() < 3 || p.size() > 4) replayFail(line, "bad varnode " + text);
  Address a = parseAddr(orig, p[0] + ":" + p[1], line);
  int4 size;
  if (!parseIndex(p[2], size)) replayFail(line, "bad varnode size " + text);
  VarnodeData v;
  v.space = a.getSpace();
  v.offset = a.getOffset();
  v.size = size;
  if (p.size() == 4 && v.space->getType() == IPTR_CONSTANT) {   // a LOAD/STORE space constant
    AddrSpace *spc = orig->getSpaceByName(p[3]);
    if (spc == (AddrSpace *)0 || (uintb)spc->getIndex() != v.offset) replayFail(line, "bad space constant " + text);
    v.offset = (uintb)(uintp)spc;
  }
  return v;
}

void PcodeSession::loadRecording(const std::string &path)
{
  std::vector<std::string> in = readLines(path, 1024u * 1024u * 1024u);
  insns.clear();
  ops.clear();
  lengths.clear();
  if (in.empty()) replayFail(1, "empty file");
  std::vector<std::string> h = splitTabs(in[0]);
  if (h.size() != 5 || h[0] != "H" || h[1] != "pcoderec" || h[2] != "1") replayFail(1, "not a pcoderec 1 recording");
  std::map<Address, std::string> seen;
  size_t i = 1;
  for (; i < in.size(); ++i) {
    std::vector<std::string> f = splitTabs(in[i]);
    int4 ln = (int4)i + 1;
    if (f[0] == "X") throw IfaceExecutionError("pcode replay: context-dependent records at " + (f.size() > 1 ? f[1] : ""));
    if (f[0] == "T") break;
    if (f[0] == "L") {
      if (f.size() != 3) replayFail(ln, "bad L record");
      Address a = parseAddr(orig, f[1], ln);
      int4 len;
      if (!parseIndex(f[2], len)) replayFail(ln, "bad length");
      lengths[a] = len;
      continue;
    }
    if (f[0] == "U") {
      if (f.size() != 5) replayFail(ln, "bad U record");
      InsnRecord r;
      r.error = true;
      r.kind = f[2];
      r.length = -1;
      if (f[3] != "-" && !parseIndex(f[3], r.length)) replayFail(ln, "bad length");
      r.message = unescape(f[4]);
      insns[parseAddr(orig, f[1], ln)] = r;
      continue;
    }
    if (f[0] != "I" || f.size() != 4) replayFail(ln, "expected an I, U, L or T record");
    Address a = parseAddr(orig, f[1], ln);
    InsnRecord r;
    r.error = false;
    int4 count;
    if (!parseIndex(f[2], r.length) || !parseIndex(f[3], count)) replayFail(ln, "bad I record");
    std::vector<ReplayOp> list;
    for (int4 k = 0; k < count; ++k) {
      ++i;
      if (i >= in.size()) replayFail((int4)i + 1, "file ends inside an instruction");
      std::vector<std::string> p = splitTabs(in[i]);
      ln = (int4)i + 1;
      if (p.size() < 4 || p[0] != "P") replayFail(ln, "expected a P record");
      ReplayOp op;
      op.addr = parseAddr(orig, p[1], ln);
      op.opc = get_opcode(p[2]);
      if (op.opc == (OpCode)0) replayFail(ln, "unknown opcode " + p[2]);
      op.hasOut = (p[3] != "-");
      if (op.hasOut) op.out = parseVarnode(p[3], ln);
      for (size_t j = 4; j < p.size(); ++j) op.in.push_back(parseVarnode(p[j], ln));
      list.push_back(op);
    }
    insns[a] = r;
    ops[a] = list;
  }
  if (i >= in.size()) replayFail((int4)i + 1, "no T record");
}

/// `bk pcode record <file>` / `bk pcode replay <file>` / `bk pcode stop`
class BkPcode : public BkCommand {
  PcodeSession::Mode mode;
public:
  explicit BkPcode(PcodeSession::Mode m) : mode(m) {}
  virtual void execute(istream &s) {
    Architecture *glb = requireArch();
    if (mode == PcodeSession::off) {
      if (session.mode == PcodeSession::off) throw IfaceExecutionError("bk pcode: no recording or replay to stop");
      glb->translate = session.orig;
      if (session.mode == PcodeSession::record) session.writeRecording();
      session.mode = PcodeSession::off;
      return;
    }
    if (session.mode != PcodeSession::off) throw IfaceExecutionError("bk pcode: a recording or replay is active");
    if (dcp->fd != (Funcdata *)0)
      throw IfaceExecutionError("bk pcode: give it before the first load function (which lifts at once)");
    std::string file = nextWord(s);
    if (file.empty()) throw IfaceParseError("Missing file");
    session.glb = glb;
    session.orig = glb->translate;
    session.file = file;
    session.lines.clear();
    session.firstText.clear();
    session.contextDependent.clear();
    session.icount = session.ucount = session.lcount = 0;
    if (mode == PcodeSession::replay) session.loadRecording(file);
    ProxyTranslate *proxy = new ProxyTranslate(session.orig, &session);
    session.proxies.push_back(proxy);
    glb->translate = proxy;
    session.mode = mode;
  }
};

/// `bk trace stream`: the architecture's debug stream (where the
/// OPACTION_DEBUG trace goes) becomes the bulk output.
class BkTraceStream : public BkCommand {
public:
  virtual void execute(istream &s) {
    Architecture *glb = requireArch();
#ifdef OPACTION_DEBUG
    glb->setDebugStream(status->fileoptr);
#else
    (void)glb;
    throw IfaceExecutionError("bk trace stream needs decomp_bk_dbg (a CPUI_DEBUG build)");
#endif
  }
};

void registerPcodeCommands(IfaceStatus *status)
{
  status->registerCom(new BkPcode(PcodeSession::record), "bk", "pcode", "record");
  status->registerCom(new BkPcode(PcodeSession::replay), "bk", "pcode", "replay");
  status->registerCom(new BkPcode(PcodeSession::off), "bk", "pcode", "stop");
  status->registerCom(new BkTraceStream(), "bk", "trace", "stream");
}

} // namespace bk
