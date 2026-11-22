import re, sys
B = sys.argv[1]

def sub(path, old, new, count=1):
    p = f"{B}/cpp/{path}"
    t = open(p).read()
    n = t.count(old)
    if n != count:
        sys.exit(f"{path}: anchor found {n} times, expected {count}:\n{old}")
    t = t.replace(old, new)
    open(p, "w").write(t)

# ---------------- prettyprint.hh
sub("prettyprint.hh", '#include "type.hh"\n', '#include "type.hh"\n#include "bkinstr.hh"\n')
sub("prettyprint.hh", "void setIndentIncrement(int4 val) { indentincrement = val; }",
    "void setIndentIncrement(int4 val) { BK_EMIT(bk_em_setIndentIncrement,0,val,0,0,0); indentincrement = val; }")
sub("prettyprint.hh", "void setPendingPrint(PendPrint *pend) { pendPrint = pend; }",
    "void setPendingPrint(PendPrint *pend) { BK_EMIT(bk_em_setPendingPrint,0,0,0,pend,0); pendPrint = pend; }")
sub("prettyprint.hh", "void cancelPendingPrint(void) { pendPrint = (PendPrint *)0; }",
    "void cancelPendingPrint(void) { BK_EMIT(bk_em_cancelPendingPrint,0,0,0,0,0); pendPrint = (PendPrint *)0; }")
sub("prettyprint.hh", "bool hasPendingPrint(PendPrint *pend) const { return (pendPrint == pend); }",
    "bool hasPendingPrint(PendPrint *pend) const { BK_EMIT(bk_em_hasPendingPrint,0,0,0,pend,0); return (BK_RET(bk_em_hasPendingPrint,(pendPrint == pend)) != 0); }")
sub("prettyprint.hh", "    stopIndent(id); tagLine(); print(brace);\n",
    "    BK_EMIT(bk_em_closeBraceIndent,&brace,id,0,0,0);\n    stopIndent(id); tagLine(); print(brace);\n")

# ---------------- prettyprint.cc
sub("prettyprint.cc", "const string Emit::EMPTY_STRING = \"\";\n",
    "const string Emit::EMPTY_STRING = \"\";\n\nBkPrintHook *bk_print_hook = (BkPrintHook *)0;\nint4 bk_emit_depth = 0;\nint4 bk_rpn_depth = 0;\n")
sub("prettyprint.cc", "int4 Emit::openBraceIndent(const string &brace,brace_style style)\n\n{\n",
    "int4 Emit::openBraceIndent(const string &brace,brace_style style)\n\n{\n  BK_EMIT(bk_em_openBraceIndent,&brace,style,0,0,0);\n")
sub("prettyprint.cc", "  int4 id = startIndent();\n  print(brace);\n  return id;\n",
    "  int4 id = startIndent();\n  print(brace);\n  return BK_RET(bk_em_openBraceIndent,id);\n")
sub("prettyprint.cc", "void Emit::openBrace(const string &brace,brace_style style)\n\n{\n",
    "void Emit::openBrace(const string &brace,brace_style style)\n\n{\n  BK_EMIT(bk_em_openBrace,&brace,style,0,0,0);\n")

# EmitPrettyPrint methods: (signature line, call id, args, result expression or None)
pp = [
 ("int4 EmitPrettyPrint::beginDocument(void)", "bk_em_beginDocument", "0,0,0,0,0"),
 ("void EmitPrettyPrint::endDocument(int4 id)", "bk_em_endDocument", "0,id,0,0,0"),
 ("int4 EmitPrettyPrint::beginFunction(const Funcdata *fd)", "bk_em_beginFunction", "0,0,0,fd,0"),
 ("void EmitPrettyPrint::endFunction(int4 id)", "bk_em_endFunction", "0,id,0,0,0"),
 ("int4 EmitPrettyPrint::beginBlock(const FlowBlock *bl)", "bk_em_beginBlock", "0,0,0,bl,0"),
 ("void EmitPrettyPrint::endBlock(int4 id)", "bk_em_endBlock", "0,id,0,0,0"),
 ("void EmitPrettyPrint::tagLine(void)", "bk_em_tagLine", "0,0,0,0,0"),
 ("void EmitPrettyPrint::tagLine(int4 indent)", "bk_em_tagLineIndent", "0,indent,0,0,0"),
 ("int4 EmitPrettyPrint::beginReturnType(const Varnode *vn)", "bk_em_beginReturnType", "0,0,0,vn,0"),
 ("void EmitPrettyPrint::endReturnType(int4 id)", "bk_em_endReturnType", "0,id,0,0,0"),
 ("int4 EmitPrettyPrint::beginVarDecl(const Symbol *sym)", "bk_em_beginVarDecl", "0,0,0,sym,0"),
 ("void EmitPrettyPrint::endVarDecl(int4 id)", "bk_em_endVarDecl", "0,id,0,0,0"),
 ("int4 EmitPrettyPrint::beginStatement(const PcodeOp *op)", "bk_em_beginStatement", "0,0,0,op,0"),
 ("void EmitPrettyPrint::endStatement(int4 id)", "bk_em_endStatement", "0,id,0,0,0"),
 ("int4 EmitPrettyPrint::beginFuncProto(void)", "bk_em_beginFuncProto", "0,0,0,0,0"),
 ("void EmitPrettyPrint::endFuncProto(int4 id)", "bk_em_endFuncProto", "0,id,0,0,0"),
 ("void EmitPrettyPrint::tagVariable(const string &name,syntax_highlight hl,const Varnode *vn,const PcodeOp *op)", "bk_em_tagVariable", "&name,hl,0,vn,op"),
 ("void EmitPrettyPrint::tagOp(const string &name,syntax_highlight hl,const PcodeOp *op)", "bk_em_tagOp", "&name,hl,0,op,0"),
 ("void EmitPrettyPrint::tagFuncName(const string &name,syntax_highlight hl,const Funcdata *fd,const PcodeOp *op)", "bk_em_tagFuncName", "&name,hl,0,fd,op"),
 ("void EmitPrettyPrint::tagType(const string &name,syntax_highlight hl,const Datatype *ct)", "bk_em_tagType", "&name,hl,0,ct,0"),
 ("void EmitPrettyPrint::tagField(const string &name,syntax_highlight hl,const Datatype *ct,int4 o,const PcodeOp *op)", "bk_em_tagField", "&name,hl,o,ct,op"),
 ("void EmitPrettyPrint::tagBitField(const string &name,syntax_highlight hl,const Datatype *ct,int4 id,const PcodeOp *op)", "bk_em_tagBitField", "&name,hl,id,ct,op"),
 ("void EmitPrettyPrint::tagComment(const string &name,syntax_highlight hl,const AddrSpace *spc,uintb off)", "bk_em_tagComment", "&name,hl,off,spc,0"),
 ("void EmitPrettyPrint::tagLabel(const string &name,syntax_highlight hl,const AddrSpace *spc,uintb off)", "bk_em_tagLabel", "&name,hl,off,spc,0"),
 ("void EmitPrettyPrint::tagCaseLabel(const string &name,syntax_highlight hl,const PcodeOp *op,uintb value)", "bk_em_tagCaseLabel", "&name,hl,value,op,0"),
 ("void EmitPrettyPrint::print(const string &data,syntax_highlight hl)", "bk_em_print", "&data,hl,0,0,0"),
 ("int4 EmitPrettyPrint::openParen(const string &paren,int4 id)", "bk_em_openParen", "&paren,id,0,0,0"),
 ("void EmitPrettyPrint::closeParen(const string &paren,int4 id)", "bk_em_closeParen", "&paren,id,0,0,0"),
 ("int4 EmitPrettyPrint::openGroup(void)", "bk_em_openGroup", "0,0,0,0,0"),
 ("void EmitPrettyPrint::closeGroup(int4 id)", "bk_em_closeGroup", "0,id,0,0,0"),
 ("int4 EmitPrettyPrint::startComment(void)", "bk_em_startComment", "0,0,0,0,0"),
 ("void EmitPrettyPrint::stopComment(int4 id)", "bk_em_stopComment", "0,id,0,0,0"),
 ("void EmitPrettyPrint::clear(void)", "bk_em_clear", "0,0,0,0,0"),
 ("void EmitPrettyPrint::spaces(int4 num,int4 bump)", "bk_em_spaces", "0,num,bump,0,0"),
 ("int4 EmitPrettyPrint::startIndent(void)", "bk_em_startIndent", "0,0,0,0,0"),
 ("void EmitPrettyPrint::stopIndent(int4 id)", "bk_em_stopIndent", "0,id,0,0,0"),
 ("void EmitPrettyPrint::flush(void)", "bk_em_flush", "0,0,0,0,0"),
]
p = f"{B}/cpp/prettyprint.cc"
t = open(p).read()
for sig, call, args in pp:
    head = sig + "\n\n{\n"
    if t.count(head) != 1:
        sys.exit(f"prettyprint.cc: {sig} found {t.count(head)} times")
    start = t.index(head)
    end = t.index("\n}\n", start)
    body = t[start + len(head):end + 1]
    body = f"  BK_EMIT({call},{args});\n" + body
    if sig.startswith("int4 "):
        rets = re.findall(r"  return ([a-z]+);\n", body)
        if len(rets) != 1:
            sys.exit(f"{sig}: returns {rets}")
        body = body.replace(f"  return {rets[0]};\n", f"  return BK_RET({call},{rets[0]});\n")
    t = t[:start + len(head)] + body + t[end + 1:]
open(p, "w").write(t)
print("emit edits ok")
