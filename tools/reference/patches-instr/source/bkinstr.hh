/* Basilisk printer instrumentation (tools/reference/patches-instr in the
 * Basilisk repository). Not part of Ghidra. Every hook is a no-op while
 * bk_print_hook is null, which is the default: the console then behaves
 * exactly as Ghidra's. */
#ifndef __BKINSTR_HH__
#define __BKINSTR_HH__

#include "types.h"
#include <string>

namespace ghidra {

class PrintLanguage;
class OpToken;
class PcodeOp;
class Varnode;
class Emit;

/// Structural events of the printer: entry to and exit from PrintC's methods
enum BkPrintEvent {
  bk_ev_docFunction = 1, bk_ev_commentFuncHeader, bk_ev_lineComment, bk_ev_functionDeclaration,
  bk_ev_symbolScope, bk_ev_prototypeOutput, bk_ev_prototypeInputs, bk_ev_localVarDecls,
  bk_ev_scopeVarDecls, bk_ev_varDeclStatement, bk_ev_varDecl, bk_ev_blockBasic, bk_ev_blockGraph,
  bk_ev_blockCopy, bk_ev_blockGoto, bk_ev_blockLs, bk_ev_blockCondition, bk_ev_blockIf,
  bk_ev_forLoop, bk_ev_blockWhileDo, bk_ev_blockDoWhile, bk_ev_blockInfLoop, bk_ev_blockSwitch,
  bk_ev_switchCase, bk_ev_label, bk_ev_labelStatement, bk_ev_anyLabelStatement,
  bk_ev_gotoStatement, bk_ev_commentGroup, bk_ev_commentBlockTree, bk_ev_statement,
  bk_ev_expression, bk_ev_inplaceOp, bk_ev_constructor, bk_ev_bitFieldStore,
  bk_ev_bitFieldExpression, bk_ev_opBranch, bk_ev_opCbranch, bk_ev_opBranchind, bk_ev_opReturn,
  bk_ev_docAllGlobals, bk_ev_docSingleGlobal, bk_ev_docTypeDefinitions, bk_ev_typeDefinition,
  bk_ev_structDefinition, bk_ev_enumDefinition, bk_ev_globalVarDeclsRecursive, bk_ev_recurse,
  bk_ev_count
};

/// State changes of the printer (modifier and scope stacks)
enum BkPrintState { bk_st_pushMod = 1, bk_st_popMod, bk_st_setMod, bk_st_unsetMod, bk_st_pushScope, bk_st_popScope };

/// Calls on the Emit object, as PrintLanguage makes them
enum BkEmitCall {
  bk_em_beginDocument = 1, bk_em_endDocument, bk_em_beginFunction, bk_em_endFunction,
  bk_em_beginBlock, bk_em_endBlock, bk_em_tagLine, bk_em_tagLineIndent, bk_em_beginReturnType,
  bk_em_endReturnType, bk_em_beginVarDecl, bk_em_endVarDecl, bk_em_beginStatement,
  bk_em_endStatement, bk_em_beginFuncProto, bk_em_endFuncProto, bk_em_tagVariable, bk_em_tagOp,
  bk_em_tagFuncName, bk_em_tagType, bk_em_tagField, bk_em_tagBitField, bk_em_tagComment,
  bk_em_tagLabel, bk_em_tagCaseLabel, bk_em_print, bk_em_openParen, bk_em_closeParen,
  bk_em_openGroup, bk_em_closeGroup, bk_em_clear, bk_em_spaces, bk_em_startIndent,
  bk_em_stopIndent, bk_em_startComment, bk_em_stopComment, bk_em_flush, bk_em_setPendingPrint,
  bk_em_cancelPendingPrint, bk_em_hasPendingPrint, bk_em_openBraceIndent, bk_em_openBrace,
  bk_em_closeBraceIndent, bk_em_setIndentIncrement, bk_em_count
};

/// The logger interface; the implementation lives outside Ghidra's sources
class BkPrintHook {
public:
  virtual ~BkPrintHook(void) {}
  virtual void enter(const PrintLanguage *lng,int4 ev,const void *a,const void *b,intb c)=0;
  virtual void leave(const PrintLanguage *lng,int4 ev,bool unwinding)=0;
  virtual void pushOp(const PrintLanguage *lng,const OpToken *tok,const PcodeOp *op)=0;
  virtual void pushAtom(const PrintLanguage *lng,const void *atom)=0;
  virtual void pushVn(const PrintLanguage *lng,const Varnode *vn,const PcodeOp *op,uint4 m)=0;
  virtual void state(const PrintLanguage *lng,int4 kind,uint4 val)=0;
  virtual void emitCall(const Emit *e,int4 call,const std::string *s,intb i1,intb i2,const void *p1,const void *p2)=0;
  virtual void emitResult(const Emit *e,int4 call,intb val)=0;
};

extern BkPrintHook *bk_print_hook;	///< The active logger, or null (defined in prettyprint.cc)
extern int4 bk_emit_depth;		///< Nesting of hooked Emit calls (only the outermost is logged)
extern int4 bk_rpn_depth;		///< Nesting of the RPN machinery (pushOp, pushAtom, recurse)

/// Logs entry to and exit from a structural printer method
struct BkScope {
  const PrintLanguage *lng;
  int4 ev;
  bool on;
  BkScope(const PrintLanguage *l,int4 e,const void *a,const void *b,intb c) {
    lng = l; ev = e; on = (bk_print_hook != (BkPrintHook *)0);
    if (on) bk_print_hook->enter(l,e,a,b,c);
  }
  ~BkScope(void) { if (on && bk_print_hook != (BkPrintHook *)0) bk_print_hook->leave(lng,ev,std::uncaught_exception()); }
};

/// Marks a hooked Emit call; only the outermost one is logged
struct BkEmitGuard {
  bool top;
  BkEmitGuard(void) { top = (bk_print_hook != (BkPrintHook *)0) && (bk_emit_depth == 0); bk_emit_depth += 1; }
  ~BkEmitGuard(void) { bk_emit_depth -= 1; }
};

/// Marks the RPN machinery (emission from it is not \e direct)
struct BkRpnGuard {
  BkRpnGuard(void) { bk_rpn_depth += 1; }
  ~BkRpnGuard(void) { bk_rpn_depth -= 1; }
};

/// Logs the result of an outermost Emit call and passes it through
inline intb bk_emit_ret(const BkEmitGuard &g,const Emit *e,int4 call,intb val) {
  if (g.top) bk_print_hook->emitResult(e,call,val);
  return val;
}

} // End namespace ghidra

#define BK_SCOPE(ev,a,b,c) ghidra::BkScope bk_scope(this,ev,(const void *)(a),(const void *)(b),(intb)(c))
#define BK_EMIT(call,s,i1,i2,p1,p2) ghidra::BkEmitGuard bk_guard; \
  if (bk_guard.top) ghidra::bk_print_hook->emitCall(this,call,s,(intb)(i1),(intb)(i2),(const void *)(p1),(const void *)(p2))
#define BK_RET(call,v) (int4)ghidra::bk_emit_ret(bk_guard,this,call,(intb)(v))

#endif
