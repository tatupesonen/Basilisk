/* ###
 * Basilisk printer log (track decomp-out-spike, docs/research/decomp-out-spike).
 *
 * Linked only into the instrumented console built by build-instr.sh from a
 * copy of Ghidra's source patched with 0001-printer-hooks.patch. When the
 * environment variable BK_PRINTLOG is set to a path prefix, every
 * PrintLanguage::docFunction is logged into three files:
 *
 *   <prefix>.tree   what the printer decided: structural events (entry to and
 *                   exit from PrintC's emit methods, with the facts they read),
 *                   every push on the RPN stack, modifier and scope changes
 *   <prefix>.emit   every call the printer made on its Emit object
 *   <prefix>.diag   places where emission and tree building interleave
 *
 * Formats: tools/reference/README.md, "The printer log". Compiled with
 * -fno-access-control (as the console extension is) to read the printer's
 * private state. Without BK_PRINTLOG nothing is installed and the console
 * is Ghidra's.
 */
#include "printc.hh"
#include "printjava.hh"
#include "funcdata.hh"
#include "block.hh"
#include "comment.hh"
#include "bkinstr.hh"

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <map>
#include <sstream>

namespace ghidra {

namespace {

const char *const EVENT_NAMES[] = {
  "", "docFunction", "commentFuncHeader", "lineComment", "functionDeclaration", "symbolScope",
  "prototypeOutput", "prototypeInputs", "localVarDecls", "scopeVarDecls", "varDeclStatement",
  "varDecl", "blockBasic", "blockGraph", "blockCopy", "blockGoto", "blockLs", "blockCondition",
  "blockIf", "forLoop", "blockWhileDo", "blockDoWhile", "blockInfLoop", "blockSwitch",
  "switchCase", "label", "labelStatement", "anyLabelStatement", "gotoStatement", "commentGroup",
  "commentBlockTree", "statement", "expression", "inplaceOp", "constructor", "bitFieldStore",
  "bitFieldExpression", "opBranch", "opCbranch", "opBranchind", "opReturn", "docAllGlobals",
  "docSingleGlobal", "docTypeDefinitions", "typeDefinition", "structDefinition",
  "enumDefinition", "globalVarDeclsRecursive", "recurse"
};

const char *const EMIT_NAMES[] = {
  "", "beginDocument", "endDocument", "beginFunction", "endFunction", "beginBlock", "endBlock",
  "tagLine", "tagLineIndent", "beginReturnType", "endReturnType", "beginVarDecl", "endVarDecl",
  "beginStatement", "endStatement", "beginFuncProto", "endFuncProto", "tagVariable", "tagOp",
  "tagFuncName", "tagType", "tagField", "tagBitField", "tagComment", "tagLabel", "tagCaseLabel",
  "print", "openParen", "closeParen", "openGroup", "closeGroup", "clear", "spaces",
  "startIndent", "stopIndent", "startComment", "stopComment", "flush", "setPendingPrint",
  "cancelPendingPrint", "hasPendingPrint", "openBraceIndent", "openBrace", "closeBraceIndent",
  "setIndentIncrement"
};

const char *const STATE_NAMES[] = { "", "pushMod", "popMod", "setMod", "unsetMod", "pushScope", "popScope" };

const char *const TAG_NAMES[] = { "syntax", "vartoken", "functoken", "optoken", "typetoken",
  "fieldtoken", "bitfieldtoken", "casetoken", "blanktoken" };

/// Text field escaping of the Basilisk formats
string esc(const string &s)
{
  string r;
  for(size_t i=0;i<s.size();++i) {
    char c = s[i];
    switch(c) {
    case '\\': r += "\\\\"; break;
    case '\t': r += "\\t"; break;
    case '\n': r += "\\n"; break;
    case '\r': r += "\\r"; break;
    case '\0': r += "\\0"; break;
    default: r += c; break;
    }
  }
  return r;
}

string hexs(uintb v)
{
  ostringstream s;
  s << "0x" << hex << v;
  return s.str();
}

string decs(intb v)
{
  ostringstream s;
  s << dec << v;
  return s.str();
}

string addrKey(const Address &a)
{
  if (a.isInvalid() || a.getSpace() == (AddrSpace *)0) return "-";
  return a.getSpace()->getName() + ":" + hexs(a.getOffset());
}

string opKey(const PcodeOp *op)
{
  if (op == (const PcodeOp *)0) return "-";
  const SeqNum &sq(op->getSeqNum());
  return addrKey(sq.getAddr()) + ":" + hexs(sq.getTime());
}

string opDesc(const PcodeOp *op)
{
  if (op == (const PcodeOp *)0) return "-";
  return opKey(op) + "/" + get_opname(op->code());
}

string vnKey(const Varnode *vn)
{
  if (vn == (const Varnode *)0) return "-";
  ostringstream s;
  s << 'v' << hex << vn->getCreateIndex();
  return s.str();
}

string blKey(const FlowBlock *bl)
{
  if (bl == (const FlowBlock *)0) return "-";
  return FlowBlock::typeToName(bl->getType()) + ":" + decs(bl->getIndex());
}

string symKey(const Symbol *sym)
{
  if (sym == (const Symbol *)0) return "-";
  return "s" + hexs(sym->getId()).substr(2) + ":" + esc(sym->getName());
}

string typeKey(const Datatype *ct)
{
  if (ct == (const Datatype *)0) return "-";
  return "t" + hexs(ct->getId()).substr(2) + ":" + esc(ct->getDisplayName());
}

string fdKey(const Funcdata *fd)
{
  if (fd == (const Funcdata *)0) return "-";
  return "f:" + esc(fd->getName());
}

class PrintLog : public BkPrintHook {
  ofstream tree, emit, diag;
  int4 fnum;			///< Number of the current function (0 outside docFunction)
  int4 count;			///< Functions logged so far
  int4 docDepth;		///< Nesting of docFunction
  const PrintLanguage *cur;	///< The printer of the current function
  map<const OpToken *,string> tokenNames;
  map<const void *,int4> pendIds;	///< PendPrint objects, numbered in order of first use
  int4 pendEmit;		///< A logged Emit call waiting for its result (0 if none)
  string pendLine;
  long directEmits, interleaved, outside;

  void nameTokens(void);
  string tokName(const OpToken *tok);
  string pendKey(const void *p);
  string facts(const PrintLanguage *lng,int4 ev,const void *a,const void *b,intb c);
  string labelText(const FlowBlock *bl);
  void diagLine(const string &msg) { diag << "D\t" << fnum << '\t' << msg << '\n'; }
public:
  PrintLog(const string &prefix);
  virtual ~PrintLog(void);
  virtual void enter(const PrintLanguage *lng,int4 ev,const void *a,const void *b,intb c);
  virtual void leave(const PrintLanguage *lng,int4 ev,bool unwinding);
  virtual void pushOp(const PrintLanguage *lng,const OpToken *tok,const PcodeOp *op);
  virtual void pushAtom(const PrintLanguage *lng,const void *atom);
  virtual void pushVn(const PrintLanguage *lng,const Varnode *vn,const PcodeOp *op,uint4 m);
  virtual void state(const PrintLanguage *lng,int4 kind,uint4 val);
  virtual void emitCall(const Emit *e,int4 call,const string *s,intb i1,intb i2,const void *p1,const void *p2);
  virtual void emitResult(const Emit *e,int4 call,intb val);
};

PrintLog::PrintLog(const string &prefix)
  : tree((prefix + ".tree").c_str()), emit((prefix + ".emit").c_str()), diag((prefix + ".diag").c_str())
{
  fnum = 0; count = 0; docDepth = 0; cur = (const PrintLanguage *)0;
  pendEmit = 0; directEmits = 0; interleaved = 0; outside = 0;
  tree << "H\tbkprinttree\t1\n";
  emit << "H\tbkprintemit\t1\n";
  diag << "H\tbkprintdiag\t1\n";
  nameTokens();
}

PrintLog::~PrintLog(void)
{
  tree << "T\t" << count << '\n';
  emit << "T\t" << count << '\n';
  diag << "S\tdirect\t" << directEmits << "\tinterleaved\t" << interleaved << "\toutside\t" << outside << '\n';
  diag << "T\t" << count << '\n';
}

void PrintLog::nameTokens(void)
{
  tokenNames[&PrintC::hidden] = "hidden";
  tokenNames[&PrintC::scope] = "scope";
  tokenNames[&PrintC::object_member] = "object_member";
  tokenNames[&PrintC::pointer_member] = "pointer_member";
  tokenNames[&PrintC::subscript] = "subscript";
  tokenNames[&PrintC::function_call] = "function_call";
  tokenNames[&PrintC::bitwise_not] = "bitwise_not";
  tokenNames[&PrintC::boolean_not] = "boolean_not";
  tokenNames[&PrintC::unary_minus] = "unary_minus";
  tokenNames[&PrintC::unary_plus] = "unary_plus";
  tokenNames[&PrintC::addressof] = "addressof";
  tokenNames[&PrintC::dereference] = "dereference";
  tokenNames[&PrintC::typecast] = "typecast";
  tokenNames[&PrintC::multiply] = "multiply";
  tokenNames[&PrintC::divide] = "divide";
  tokenNames[&PrintC::modulo] = "modulo";
  tokenNames[&PrintC::binary_plus] = "binary_plus";
  tokenNames[&PrintC::binary_minus] = "binary_minus";
  tokenNames[&PrintC::shift_left] = "shift_left";
  tokenNames[&PrintC::shift_right] = "shift_right";
  tokenNames[&PrintC::shift_sright] = "shift_sright";
  tokenNames[&PrintC::less_than] = "less_than";
  tokenNames[&PrintC::less_equal] = "less_equal";
  tokenNames[&PrintC::greater_than] = "greater_than";
  tokenNames[&PrintC::greater_equal] = "greater_equal";
  tokenNames[&PrintC::equal] = "equal";
  tokenNames[&PrintC::not_equal] = "not_equal";
  tokenNames[&PrintC::bitwise_and] = "bitwise_and";
  tokenNames[&PrintC::bitwise_xor] = "bitwise_xor";
  tokenNames[&PrintC::bitwise_or] = "bitwise_or";
  tokenNames[&PrintC::boolean_and] = "boolean_and";
  tokenNames[&PrintC::boolean_or] = "boolean_or";
  tokenNames[&PrintC::boolean_xor] = "boolean_xor";
  tokenNames[&PrintC::assignment] = "assignment";
  tokenNames[&PrintC::comma] = "comma";
  tokenNames[&PrintC::new_op] = "new_op";
  tokenNames[&PrintC::multequal] = "multequal";
  tokenNames[&PrintC::divequal] = "divequal";
  tokenNames[&PrintC::remequal] = "remequal";
  tokenNames[&PrintC::plusequal] = "plusequal";
  tokenNames[&PrintC::minusequal] = "minusequal";
  tokenNames[&PrintC::leftequal] = "leftequal";
  tokenNames[&PrintC::rightequal] = "rightequal";
  tokenNames[&PrintC::andequal] = "andequal";
  tokenNames[&PrintC::orequal] = "orequal";
  tokenNames[&PrintC::xorequal] = "xorequal";
  tokenNames[&PrintC::type_expr_space] = "type_expr_space";
  tokenNames[&PrintC::type_expr_nospace] = "type_expr_nospace";
  tokenNames[&PrintC::ptr_expr] = "ptr_expr";
  tokenNames[&PrintC::array_expr] = "array_expr";
  tokenNames[&PrintC::enum_cat] = "enum_cat";
  tokenNames[&PrintJava::instanceof] = "instanceof";
}

/// The token's name and its printed characters (which adjustTypeOperators can change)
string PrintLog::tokName(const OpToken *tok)
{
  map<const OpToken *,string>::const_iterator it = tokenNames.find(tok);
  string nm = (it == tokenNames.end()) ? string("?") : (*it).second;
  return nm + "\t" + esc(tok->print1) + "\t" + esc(tok->print2);
}

string PrintLog::pendKey(const void *p)
{
  if (p == (const void *)0) return "-";
  map<const void *,int4>::const_iterator it = pendIds.find(p);
  if (it != pendIds.end()) return "p" + decs((*it).second);
  int4 id = pendIds.size();
  pendIds[p] = id;
  return "p" + decs(id);
}

/// The label PrintC::emitLabel prints for a block (printc.cc:3319)
string PrintLog::labelText(const FlowBlock *bl)
{
  bl = bl->getFrontLeaf();
  if (bl == (const FlowBlock *)0) return "-";
  const BlockBasic *bb = (const BlockBasic *)bl->subBlock(0);
  Address addr = bb->getEntryAddr();
  if (!bb->hasSpecialLabel() && bb->getType() == FlowBlock::t_basic) {
    const Scope *symScope = bb->getFuncdata()->getScopeLocal();
    Symbol *sym = symScope->queryCodeLabel(addr);
    if (sym != (Symbol *)0)
      return esc(sym->getDisplayName()) + "\t" + addrKey(addr);
  }
  ostringstream lb;
  if (bb->isJoined()) lb << "joined_";
  else if (bb->isDuplicated()) lb << "dup_";
  else lb << "code_";
  lb << addr.getShortcut();
  addr.printRaw(lb);
  return esc(lb.str()) + "\t" + addrKey(addr);
}

/// The facts a structural method reads from the function, in the order the
/// README lists them
string PrintLog::facts(const PrintLanguage *lng,int4 ev,const void *a,const void *b,intb c)
{
  const PrintC *pc = (const PrintC *)lng;
  ostringstream s;
  switch(ev) {
  case bk_ev_docFunction: {
    const Funcdata *fd = (const Funcdata *)a;
    s << esc(fd->getName()) << '\t' << addrKey(fd->getAddress());
    break;
  }
  case bk_ev_lineComment: {
    const Comment *comm = (const Comment *)a;
    s << c << '\t' << hexs(comm->getType()) << '\t' << addrKey(comm->getAddr()) << '\t' << esc(comm->getText());
    break;
  }
  case bk_ev_functionDeclaration: {
    const Funcdata *fd = (const Funcdata *)a;
    const FuncProto &proto(fd->getFuncProto());
    bool model = pc->option_convention && proto.printModelInDecl();
    s << esc(fd->getDisplayName()) << '\t' << fdKey(fd) << '\t';
    if (model) s << esc(proto.getModelName()) << '\t' << (proto.isModelUnknown() ? 1 : 0);
    else s << "-\t-";
    break;
  }
  case bk_ev_symbolScope: {
    const Symbol *sym = (const Symbol *)a;
    s << symKey(sym);
    break;
  }
  case bk_ev_prototypeOutput: {
    const Funcdata *fd = (const Funcdata *)b;
    const FuncProto *proto = (const FuncProto *)a;
    const PcodeOp *op = (const PcodeOp *)0;
    if (fd != (const Funcdata *)0) {
      op = fd->getFirstReturnOp();
      if (op != (const PcodeOp *)0 && op->numInput() < 2) op = (const PcodeOp *)0;
    }
    const Varnode *vn = (const Varnode *)0;
    if (proto->getOutputType()->getMetatype() != TYPE_VOID && op != (const PcodeOp *)0)
      vn = op->getIn(1);
    s << vnKey(vn);
    break;
  }
  case bk_ev_prototypeInputs: {
    const FuncProto *proto = (const FuncProto *)a;
    int4 sz = proto->numParams();
    s << sz << '\t' << (proto->isDotdotdot() ? 1 : 0) << '\t';
    if (sz == 0) s << '-';
    for(int4 i=0;i<sz;++i) {
      ProtoParameter *param = proto->getParam(i);
      if (i != 0) s << ',';
      if (pc->isSet(PrintLanguage::hide_thisparam) && param->isThisPointer()) s << "hidden";
      else if (param->getSymbol() != (Symbol *)0) s << "symbol";
      else s << "type";
    }
    break;
  }
  case bk_ev_scopeVarDecls:
    s << esc(((const Scope *)a)->getName()) << '\t' << c;
    break;
  case bk_ev_varDeclStatement:
  case bk_ev_varDecl:
    s << symKey((const Symbol *)a);
    break;
  case bk_ev_blockBasic: {
    const BlockBasic *bb = (const BlockBasic *)a;
    const PcodeOp *last = bb->lastOp();
    s << blKey(bb) << '\t' << opDesc(last) << '\t' << bb->sizeOut() << '\t';
    s << ((last != (const PcodeOp *)0 && last->isFallthruTrue()) ? 1 : 0) << '\t';
    for(int4 i=0;i<bb->sizeOut();++i) s << (i ? "," : "") << blKey(bb->getOut(i));
    if (bb->sizeOut() == 0) s << '-';
    break;
  }
  case bk_ev_blockGraph:
  case bk_ev_blockCopy:
  case bk_ev_blockGoto:
  case bk_ev_blockLs:
  case bk_ev_blockCondition:
  case bk_ev_blockIf:
  case bk_ev_forLoop:
  case bk_ev_blockWhileDo:
  case bk_ev_blockDoWhile:
  case bk_ev_blockInfLoop:
  case bk_ev_blockSwitch: {
    const FlowBlock *fb = (const FlowBlock *)a;
    // The op PrintC tags its keyword with: component 0's last op (printc.cc:3050, 3121, 3168, 3240, 3265)
    const PcodeOp *keyOp = (const PcodeOp *)0;
    if (ev == bk_ev_blockIf || ev == bk_ev_forLoop || ev == bk_ev_blockWhileDo || ev == bk_ev_blockDoWhile
	|| ev == bk_ev_blockInfLoop)
      keyOp = ((const BlockGraph *)fb)->getBlock(0)->lastOp();
    s << blKey(fb) << '\t' << opDesc(keyOp) << '\t';
    if (ev == bk_ev_blockCopy) {
      s << blKey(fb->subBlock(0));
      break;
    }
    const BlockGraph *bg = (const BlockGraph *)fb;
    int4 n = bg->getSize();
    for(int4 i=0;i<n;++i) s << (i ? "," : "") << blKey(bg->getBlock(i));
    if (n == 0) s << '-';
    switch(ev) {
    case bk_ev_blockGoto: {
      const BlockGoto *g = (const BlockGoto *)fb;
      s << '\t' << (g->gotoPrints() ? 1 : 0) << '\t' << blKey(g->getGotoTarget()) << '\t' << hexs(g->getGotoType());
      break;
    }
    case bk_ev_blockLs: {
      s << '\t';
      for(int4 i=0;i+1<n;++i)
	s << (i ? "," : "") << ((bg->getBlock(i+1) == bg->getBlock(i)->nextInFlow()) ? 1 : 0);
      if (n < 2) s << '-';
      break;
    }
    case bk_ev_blockCondition:
      s << '\t' << get_opname(((const BlockCondition *)fb)->getOpcode());
      break;
    case bk_ev_blockIf: {
      FlowBlock::block_type t = fb->getType();
      s << '\t' << FlowBlock::typeToName(t);
      if (t == FlowBlock::t_ifgoto) {
	const BlockIfGoto *ig = (const BlockIfGoto *)fb;
	s << '\t' << blKey(ig->getGotoTarget()) << '\t' << hexs(ig->getGotoType());
      }
      else s << "\t-\t-";
      break;
    }
    case bk_ev_forLoop:
    case bk_ev_blockWhileDo: {
      const BlockWhileDo *w = (const BlockWhileDo *)fb;
      s << '\t' << opDesc(w->getInitializeOp()) << '\t' << opDesc(w->getIterateOp()) << '\t' << (w->hasOverflowSyntax() ? 1 : 0);
      break;
    }
    case bk_ev_blockSwitch: {
      const BlockSwitch *sw = (const BlockSwitch *)fb;
      s << '\t' << sw->getNumCaseBlocks() << '\t';
      for(int4 i=0;i<sw->getNumCaseBlocks();++i)
	s << (i ? "," : "") << blKey(sw->getCaseBlock(i)) << ':' << hexs(sw->getGotoType(i)) << ':'
	  << (sw->isExit(i) ? 1 : 0) << ':' << (sw->isDefaultCase(i) ? 1 : 0);
      if (sw->getNumCaseBlocks() == 0) s << '-';
      break;
    }
    default:
      break;
    }
    break;
  }
  case bk_ev_switchCase: {
    const BlockSwitch *sw = (const BlockSwitch *)a;
    int4 i = (int4)c;
    s << i << '\t' << opDesc(sw->getCaseBlock(i)->firstOp()) << '\t' << (sw->isDefaultCase(i) ? 1 : 0) << '\t';
    if (sw->isDefaultCase(i)) s << hexs(sw->getLabel(i,0));
    else s << sw->getNumLabels(i);
    break;
  }
  case bk_ev_label:
    s << blKey((const FlowBlock *)a) << '\t' << labelText((const FlowBlock *)a);
    break;
  case bk_ev_labelStatement:
  case bk_ev_anyLabelStatement: {
    const FlowBlock *fb = (const FlowBlock *)a;
    s << blKey(fb) << '\t' << (fb->isLabelBumpUp() ? 1 : 0) << '\t' << (fb->isJumpTarget() ? 1 : 0) << '\t'
      << (fb->isUnstructuredTarget() ? 1 : 0);
    break;
  }
  case bk_ev_gotoStatement: {
    const FlowBlock *fb = (const FlowBlock *)a;
    s << blKey(fb) << '\t' << opDesc(fb->lastOp()) << '\t' << blKey((const FlowBlock *)b) << '\t' << hexs((uintb)c);
    break;
  }
  case bk_ev_commentGroup:
  case bk_ev_statement:
  case bk_ev_expression:
  case bk_ev_inplaceOp:
  case bk_ev_constructor:
  case bk_ev_bitFieldStore:
  case bk_ev_bitFieldExpression:
  case bk_ev_opBranch:
  case bk_ev_opCbranch:
  case bk_ev_opBranchind: {
    const PcodeOp *op = (const PcodeOp *)a;
    s << opDesc(op);
    if (op != (const PcodeOp *)0)
      s << '\t' << op->numInput() << '\t' << vnKey(op->getOut());
    break;
  }
  case bk_ev_opReturn: {
    const PcodeOp *op = (const PcodeOp *)a;
    s << opDesc(op) << '\t' << op->numInput() << '\t' << hexs(op->getHaltType());
    break;
  }
  case bk_ev_commentBlockTree:
    s << blKey((const FlowBlock *)a);
    break;
  case bk_ev_commentFuncHeader:
  case bk_ev_localVarDecls:
    s << fdKey((const Funcdata *)a);
    break;
  default:
    break;
  }
  return s.str();
}

void PrintLog::enter(const PrintLanguage *lng,int4 ev,const void *a,const void *b,intb c)
{
  if (ev == bk_ev_docFunction) {
    docDepth += 1;
    if (docDepth == 1) {
      cur = lng;
      count += 1;
      fnum = count;
      pendIds.clear();
      const PrintC *pc = (const PrintC *)lng;
      const Funcdata *fd = (const Funcdata *)a;
      tree << "F\t" << fnum << '\t' << esc(fd->getName()) << '\n';
      emit << "F\t" << fnum << '\t' << esc(fd->getName()) << '\n';
      // The printer's options and the emitter's configuration
      tree << "O\t" << esc(lng->getName()) << '\t' << hexs(pc->mods) << '\t' << pc->option_brace_func << '\t'
	   << pc->option_brace_ifelse << '\t' << pc->option_brace_loop << '\t' << pc->option_brace_switch << '\t'
	   << esc(pc->commentstart) << '\t' << esc(pc->commentend) << '\t' << pc->line_commentindent << '\t'
	   << hexs(pc->instr_comment_type) << '\t' << hexs(pc->head_comment_type) << '\t'
	   << (pc->option_unplaced ? 1 : 0) << '\t' << (pc->option_nocasts ? 1 : 0) << '\t'
	   << (pc->emit->emitsMarkup() ? 1 : 0) << '\n';
    }
  }
  if (fnum == 0) return;
  if (!lng->revpol.empty() || lng->pending < (int4)lng->nodepend.size()) {
    interleaved += 1;
    diagLine(string("enter ") + EVENT_NAMES[ev] + " with RPN stack " + decs(lng->revpol.size()) + " pending "
	     + decs(lng->nodepend.size() - lng->pending));
  }
  tree << ">\t" << EVENT_NAMES[ev] << '\t' << hexs(lng->mods);
  string f = facts(lng,ev,a,b,c);
  if (!f.empty()) tree << '\t' << f;
  tree << '\n';
}

void PrintLog::leave(const PrintLanguage *lng,int4 ev,bool unwinding)
{
  if (fnum == 0) return;
  tree << "<\t" << EVENT_NAMES[ev] << (unwinding ? "\t!" : "") << '\n';
  if (ev == bk_ev_docFunction) {
    docDepth -= 1;
    if (docDepth == 0) {
      tree << "/F\t" << fnum << '\t' << (unwinding ? "error" : "ok") << '\n';
      emit << "/F\t" << fnum << '\t' << (unwinding ? "error" : "ok") << '\n';
      tree.flush(); emit.flush(); diag.flush();
      fnum = 0;
      cur = (const PrintLanguage *)0;
    }
  }
}

void PrintLog::pushOp(const PrintLanguage *lng,const OpToken *tok,const PcodeOp *op)
{
  if (fnum == 0) return;
  tree << "P\t" << tokName(tok) << '\t' << opDesc(op) << '\n';
}

void PrintLog::pushAtom(const PrintLanguage *lng,const void *atomp)
{
  if (fnum == 0) return;
  const PrintLanguage::Atom &atom(*(const PrintLanguage::Atom *)atomp);
  // Only the fields emitAtom reads for the tag type are initialised (printlanguage.cc:376)
  string op = "-", second = "-", off = "-";
  switch(atom.type) {
  case PrintLanguage::vartoken: op = opDesc(atom.op); second = vnKey(atom.ptr_second.vn); break;
  case PrintLanguage::functoken: op = opDesc(atom.op); second = fdKey(atom.ptr_second.fd); break;
  case PrintLanguage::optoken: op = opDesc(atom.op); break;
  case PrintLanguage::typetoken: second = typeKey(atom.ptr_second.ct); break;
  case PrintLanguage::fieldtoken:
  case PrintLanguage::bitfieldtoken:
    op = opDesc(atom.op); second = typeKey(atom.ptr_second.ct); off = decs(atom.offset); break;
  case PrintLanguage::casetoken: op = opDesc(atom.op); second = hexs(atom.ptr_second.intValue); break;
  default: break;
  }
  tree << "A\t" << TAG_NAMES[atom.type] << '\t' << atom.highlight << '\t' << esc(atom.name) << '\t' << op << '\t'
       << second << '\t' << off << '\n';
}

void PrintLog::pushVn(const PrintLanguage *lng,const Varnode *vn,const PcodeOp *op,uint4 m)
{
  if (fnum == 0) return;
  tree << "V\t" << vnKey(vn) << '\t' << opDesc(op) << '\t' << hexs(m) << '\n';
}

void PrintLog::state(const PrintLanguage *lng,int4 kind,uint4 val)
{
  if (fnum == 0) return;
  tree << "M\t" << STATE_NAMES[kind] << '\t';
  if (kind == bk_st_pushScope || kind == bk_st_popScope)
    tree << (lng->curscope == (const Scope *)0 ? string("-") : esc(lng->curscope->getName()));
  else
    tree << hexs(val);
  tree << '\n';
}

void PrintLog::emitCall(const Emit *e,int4 call,const string *s,intb i1,intb i2,const void *p1,const void *p2)
{
  if (fnum == 0) { outside += 1; return; }
  if (bk_rpn_depth == 0) {
    directEmits += 1;
    if (cur != (const PrintLanguage *)0 && (!cur->revpol.empty() || cur->pending < (int4)cur->nodepend.size())) {
      interleaved += 1;
      diagLine(string("direct ") + EMIT_NAMES[call] + " with RPN stack " + decs(cur->revpol.size()) + " pending "
	       + decs(cur->nodepend.size() - cur->pending));
    }
  }
  ostringstream l;
  l << EMIT_NAMES[call];
  switch(call) {
  case bk_em_beginFunction: l << '\t' << fdKey((const Funcdata *)p1); break;
  case bk_em_beginBlock: l << '\t' << blKey((const FlowBlock *)p1); break;
  case bk_em_beginReturnType: l << '\t' << vnKey((const Varnode *)p1); break;
  case bk_em_beginVarDecl: l << '\t' << symKey((const Symbol *)p1); break;
  case bk_em_beginStatement: l << '\t' << opDesc((const PcodeOp *)p1); break;
  case bk_em_tagVariable: l << '\t' << esc(*s) << '\t' << i1 << '\t' << vnKey((const Varnode *)p1) << '\t' << opDesc((const PcodeOp *)p2); break;
  case bk_em_tagOp: l << '\t' << esc(*s) << '\t' << i1 << '\t' << opDesc((const PcodeOp *)p1); break;
  case bk_em_tagFuncName: l << '\t' << esc(*s) << '\t' << i1 << '\t' << fdKey((const Funcdata *)p1) << '\t' << opDesc((const PcodeOp *)p2); break;
  case bk_em_tagType: l << '\t' << esc(*s) << '\t' << i1 << '\t' << typeKey((const Datatype *)p1); break;
  case bk_em_tagField:
  case bk_em_tagBitField:
    l << '\t' << esc(*s) << '\t' << i1 << '\t' << typeKey((const Datatype *)p1) << '\t' << i2 << '\t' << opDesc((const PcodeOp *)p2); break;
  case bk_em_tagComment:
  case bk_em_tagLabel:
    l << '\t' << esc(*s) << '\t' << i1 << '\t' << (p1 ? ((const AddrSpace *)p1)->getName() : string("-")) << '\t' << hexs((uintb)i2); break;
  case bk_em_tagCaseLabel: l << '\t' << esc(*s) << '\t' << i1 << '\t' << opDesc((const PcodeOp *)p1) << '\t' << hexs((uintb)i2); break;
  case bk_em_print: l << '\t' << esc(*s) << '\t' << i1; break;
  case bk_em_openParen: l << '\t' << esc(*s); break;
  case bk_em_closeParen: l << '\t' << esc(*s) << '\t' << i1; break;
  case bk_em_spaces: l << '\t' << i1 << '\t' << i2; break;
  case bk_em_openBraceIndent:
  case bk_em_openBrace: l << '\t' << esc(*s) << '\t' << i1; break;
  case bk_em_closeBraceIndent: l << '\t' << esc(*s) << '\t' << i1; break;
  case bk_em_setPendingPrint:
  case bk_em_hasPendingPrint: l << '\t' << pendKey(p1); break;
  case bk_em_endDocument: case bk_em_endFunction: case bk_em_endBlock: case bk_em_tagLineIndent:
  case bk_em_endReturnType: case bk_em_endVarDecl: case bk_em_endStatement: case bk_em_endFuncProto:
  case bk_em_closeGroup: case bk_em_stopIndent: case bk_em_stopComment: case bk_em_setIndentIncrement:
    l << '\t' << i1; break;
  default: break;
  }
  switch(call) {		// Calls with a result: wait for it
  case bk_em_beginDocument: case bk_em_beginFunction: case bk_em_beginBlock: case bk_em_beginReturnType:
  case bk_em_beginVarDecl: case bk_em_beginStatement: case bk_em_beginFuncProto: case bk_em_openParen:
  case bk_em_openGroup: case bk_em_startIndent: case bk_em_startComment: case bk_em_hasPendingPrint:
  case bk_em_openBraceIndent:
    pendEmit = call;
    pendLine = l.str();
    return;
  default:
    break;
  }
  emit << l.str() << '\n';
}

void PrintLog::emitResult(const Emit *e,int4 call,intb val)
{
  if (fnum == 0 || pendEmit != call) return;
  emit << pendLine << "\t=\t" << val << '\n';
  pendEmit = 0;
}

/// Installs the logger when BK_PRINTLOG is set
struct Installer {
  PrintLog *log;
  Installer(void) {
    log = (PrintLog *)0;
    const char *prefix = getenv("BK_PRINTLOG");
    if (prefix != (const char *)0 && prefix[0] != '\0') {
      log = new PrintLog(prefix);
      bk_print_hook = log;
    }
  }
  ~Installer(void) {
    bk_print_hook = (BkPrintHook *)0;
    delete log;
  }
};

Installer installer;

} // namespace

} // End namespace ghidra
