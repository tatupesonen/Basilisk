import re, sys
B = sys.argv[1]

def sub(path, old, new, count=1):
    p = f"{B}/cpp/{path}"
    t = open(p).read()
    n = t.count(old)
    if n != count:
        sys.exit(f"{path}: anchor found {n} times, expected {count}:\n{old}")
    open(p, "w").write(t.replace(old, new))

def scope(path, sig, ev, a="0", b="0", c="0"):
    """Insert a BK_SCOPE line as the first statement of the method with signature sig."""
    p = f"{B}/cpp/{path}"
    t = open(p).read()
    m = [x.start() for x in re.finditer(re.escape(sig) + r"\s*\n(\s*\n)?\{\n", t)]
    if len(m) != 1:
        sys.exit(f"{path}: {sig} found {len(m)} times")
    i = t.index("{\n", m[0]) + 2
    t = t[:i] + f"  BK_SCOPE({ev},{a},{b},{c});\n" + t[i:]
    open(p, "w").write(t)

# ---------------- printlanguage.hh: modifier and scope stack
H = "printlanguage.hh"
sub(H, "void pushScope(const Scope *sc) { scopestack.push_back(sc); curscope = sc; }",
       "void pushScope(const Scope *sc) { scopestack.push_back(sc); curscope = sc; if (bk_print_hook) bk_print_hook->state(this,bk_st_pushScope,0); }")
sub(H, "void pushMod(void) { modstack.push_back(mods); }",
       "void pushMod(void) { modstack.push_back(mods); if (bk_print_hook) bk_print_hook->state(this,bk_st_pushMod,mods); }")
sub(H, "void popMod(void) { mods = modstack.back(); modstack.pop_back(); }",
       "void popMod(void) { mods = modstack.back(); modstack.pop_back(); if (bk_print_hook) bk_print_hook->state(this,bk_st_popMod,mods); }")
sub(H, "void setMod(uint4 m) { mods |= m; }",
       "void setMod(uint4 m) { mods |= m; if (bk_print_hook) bk_print_hook->state(this,bk_st_setMod,m); }")
sub(H, "void unsetMod(uint4 m) { mods &= ~m; }",
       "void unsetMod(uint4 m) { mods &= ~m; if (bk_print_hook) bk_print_hook->state(this,bk_st_unsetMod,m); }")

# ---------------- printlanguage.cc
C = "printlanguage.cc"
sub(C, "  scopestack.pop_back();\n  if (scopestack.empty())",
       "  scopestack.pop_back();\n  if (bk_print_hook) bk_print_hook->state(this,bk_st_popScope,0);\n  if (scopestack.empty())")
# The hooks go after the recurse() that expands pending varnodes first, so the log is in RPN order
sub(C, "void PrintLanguage::pushOp(const OpToken *tok,const PcodeOp *op)\n\n{\n  if (pending < nodepend.size()) // Pending varnode pushes before op\n    recurse();\t\t\t// So we must recurse\n",
       "void PrintLanguage::pushOp(const OpToken *tok,const PcodeOp *op)\n\n{\n  BkRpnGuard bk_rpn;\n  if (pending < nodepend.size()) // Pending varnode pushes before op\n    recurse();\t\t\t// So we must recurse\n  if (bk_print_hook) bk_print_hook->pushOp(this,tok,op);\n")
sub(C, "void PrintLanguage::pushAtom(const Atom &atom)\n\n{\n  if (pending < nodepend.size()) // pending varnodes before atom\n    recurse();\t\t\t// So we must recurse\n",
       "void PrintLanguage::pushAtom(const Atom &atom)\n\n{\n  BkRpnGuard bk_rpn;\n  if (pending < nodepend.size()) // pending varnodes before atom\n    recurse();\t\t\t// So we must recurse\n  if (bk_print_hook) bk_print_hook->pushAtom(this,&atom);\n")
sub(C, "  // But it is more efficient to just call them in reverse order\n  nodepend.emplace_back(vn,op,m);\n",
       "  // But it is more efficient to just call them in reverse order\n  if (bk_print_hook) bk_print_hook->pushVn(this,vn,op,m);\n  nodepend.emplace_back(vn,op,m);\n")
sub(C, "void PrintLanguage::recurse(void)\n\n{\n",
       "void PrintLanguage::recurse(void)\n\n{\n  BkRpnGuard bk_rpn;\n")
scope(C, "void PrintLanguage::emitLineComment(int4 indent,const Comment *comm)", "bk_ev_lineComment", "comm", "0", "indent")

# ---------------- printc.cc
P = "printc.cc"
S = [
 ("void PrintC::emitSymbolScope(const Symbol *symbol)", "bk_ev_symbolScope", "symbol"),
 ("void PrintC::opBranch(const PcodeOp *op)", "bk_ev_opBranch", "op"),
 ("void PrintC::opCbranch(const PcodeOp *op)", "bk_ev_opCbranch", "op"),
 ("void PrintC::opBranchind(const PcodeOp *op)", "bk_ev_opBranchind", "op"),
 ("void PrintC::opReturn(const PcodeOp *op)", "bk_ev_opReturn", "op"),
 ("void PrintC::emitStructDefinition(const TypeStruct *ct)", "bk_ev_structDefinition", "ct"),
 ("void PrintC::emitEnumDefinition(const TypeEnum *ct)", "bk_ev_enumDefinition", "ct"),
 ("void PrintC::emitLocalVarDecls(const Funcdata *fd)", "bk_ev_localVarDecls", "fd"),
 ("void PrintC::emitStatement(const PcodeOp *inst)", "bk_ev_statement", "inst"),
 ("void PrintC::emitTypeDefinition(const Datatype *ct)", "bk_ev_typeDefinition", "ct"),
 ("void PrintC::docTypeDefinitions(const TypeFactory *typegrp)", "bk_ev_docTypeDefinitions", "typegrp"),
 ("bool PrintC::emitInplaceOp(const PcodeOp *op)", "bk_ev_inplaceOp", "op"),
 ("void PrintC::emitExpression(const PcodeOp *op)", "bk_ev_expression", "op"),
 ("void PrintC::emitConstructor(const PcodeOp *op)", "bk_ev_constructor", "op"),
 ("void PrintC::emitBitFieldStore(const PcodeOp *op)", "bk_ev_bitFieldStore", "op"),
 ("void PrintC::emitBitFieldExpression(const PcodeOp *op)", "bk_ev_bitFieldExpression", "op"),
 ("void PrintC::emitVarDecl(const Symbol *sym)", "bk_ev_varDecl", "sym"),
 ("void PrintC::emitVarDeclStatement(const Symbol *sym)", "bk_ev_varDeclStatement", "sym"),
 ("void PrintC::emitGlobalVarDeclsRecursive(Scope *symScope)", "bk_ev_globalVarDeclsRecursive", "symScope"),
 ("void PrintC::docAllGlobals(void)", "bk_ev_docAllGlobals", "0"),
 ("void PrintC::docSingleGlobal(const Symbol *sym)", "bk_ev_docSingleGlobal", "sym"),
 ("void PrintC::docFunction(const Funcdata *fd)", "bk_ev_docFunction", "fd"),
 ("void PrintC::emitBlockBasic(const BlockBasic *bb)", "bk_ev_blockBasic", "bb"),
 ("void PrintC::emitBlockGraph(const BlockGraph *bl)", "bk_ev_blockGraph", "bl"),
 ("void PrintC::emitBlockCopy(const BlockCopy *bl)", "bk_ev_blockCopy", "bl"),
 ("void PrintC::emitBlockGoto(const BlockGoto *bl)", "bk_ev_blockGoto", "bl"),
 ("void PrintC::emitBlockLs(const BlockList *bl)", "bk_ev_blockLs", "bl"),
 ("void PrintC::emitBlockCondition(const BlockCondition *bl)", "bk_ev_blockCondition", "bl"),
 ("void PrintC::emitBlockIf(const BlockIf *bl)", "bk_ev_blockIf", "bl"),
 ("void PrintC::emitForLoop(const BlockWhileDo *bl)", "bk_ev_forLoop", "bl"),
 ("void PrintC::emitBlockWhileDo(const BlockWhileDo *bl)", "bk_ev_blockWhileDo", "bl"),
 ("void PrintC::emitBlockDoWhile(const BlockDoWhile *bl)", "bk_ev_blockDoWhile", "bl"),
 ("void PrintC::emitBlockInfLoop(const BlockInfLoop *bl)", "bk_ev_blockInfLoop", "bl"),
 ("void PrintC::emitLabel(const FlowBlock *bl)", "bk_ev_label", "bl"),
 ("void PrintC::emitLabelStatement(const FlowBlock *bl)", "bk_ev_labelStatement", "bl"),
 ("void PrintC::emitAnyLabelStatement(const FlowBlock *bl)", "bk_ev_anyLabelStatement", "bl"),
 ("void PrintC::emitCommentGroup(const PcodeOp *inst)", "bk_ev_commentGroup", "inst"),
 ("void PrintC::emitCommentBlockTree(const FlowBlock *bl)", "bk_ev_commentBlockTree", "bl"),
 ("void PrintC::emitCommentFuncHeader(const Funcdata *fd)", "bk_ev_commentFuncHeader", "fd"),
 ("void PrintC::emitBlockSwitch(const BlockSwitch *bl)", "bk_ev_blockSwitch", "bl"),
]
for sig, ev, a in S:
    scope(P, sig, ev, a)
scope(P, "void PrintC::emitPrototypeOutput(const FuncProto *proto,\n\t\t\t\t const Funcdata *fd)", "bk_ev_prototypeOutput", "proto", "fd")
scope(P, "void PrintC::emitPrototypeInputs(const FuncProto *proto)", "bk_ev_prototypeInputs", "proto")
scope(P, "bool PrintC::emitScopeVarDecls(const Scope *symScope,int4 cat)", "bk_ev_scopeVarDecls", "symScope", "0", "cat")
scope(P, "void PrintC::emitGotoStatement(const FlowBlock *bl,const FlowBlock *exp_bl,\n\t\t\t       uint4 type)", "bk_ev_gotoStatement", "bl", "exp_bl", "type")
scope(P, "void PrintC::emitSwitchCase(int4 casenum,const BlockSwitch *switchbl)", "bk_ev_switchCase", "switchbl", "0", "casenum")
# emitFunctionDeclaration has no blank line before its brace
sub(P, "void PrintC::emitFunctionDeclaration(const Funcdata *fd)\n{\n",
       "void PrintC::emitFunctionDeclaration(const Funcdata *fd)\n{\n  BK_SCOPE(bk_ev_functionDeclaration,fd,0,0);\n")
print("print edits ok")
