// Prototype oracle for D08 (decomp-typeop): what Ghidra's TypeOp classes,
// cast strategies and union scoring answer, over a grid of operand types.
// Throw-away (docs/agents/RULES.md): the D08 track replaces it with a
// generator under tools/reference/; removal point is the merge of D08.
//
// usage: typeop_oracle SLEIGHHOME ARCH [SECTIONS]
//   e.g. typeop_oracle REF x86:LE:64:default:gcc PSOXRU
//
// Rows are tab separated; the first field is the section letter.
//   H  format name, version, architecture, pointer size, int size, alt pointer size
//   T  grid type: index, description, size, metatype
//   P  opcode number, name (C), name (Java), flags, addlflags, boolean flip, behaviour kind
//   S  strategy, required type, current type, care_uint_int, care_ptr_uint -> castStandard
//   Z  strategy, out type, in type -> isSextCast isZextCast isSubpieceCast(0) isSubpieceCast(1)
//        isSubpieceCastEndian(0,little) isSubpieceCastEndian(0,big)
//   O  variant, opcode, shape, input types.., "->", output type | outLocal | inLocal per slot |
//        outToken | inCast per slot | operator name | propagateType per (inslot>outslot) |
//        markExplicitUnsigned per slot, markExplicitLongSize(0)
//   X  integer promotion: type, size, shape -> localExtensionType intPromotionType, then per
//        reading opcode: checkIntPromotionForCompare / ForExtension, getInputCast(0)
//   E  isExtensionCastImplied: extension opcode, out type, reading opcode, other operand shape
//   R  CALL / CALLIND / RETURN / CALLOTHER local types with and without a locked prototype
//   U  union scoring: parent type, opcode, slot, shape -> scores, field, resolved type
//
// "variant" and "strategy" are c or java: the type-operator table after
// selectJavaOperators(false|true) with CastStrategyC or CastStrategyJava,
// the two combinations Ghidra can be in (printc.cc:2424, printjava.cc:121).
// A type prints as its name, or structurally when it has none.
#include "libdecomp.hh"
#include "xml_arch.hh"
#include "printc.hh"
#include "grammar.hh"
#include "unionresolve.hh"

#include <sstream>
#include <iostream>
using std::cout; using std::cerr; using std::endl;

using namespace ghidra;

static Architecture *glb;
static TypeFactory *types;
static Funcdata *fd;
static BlockBasic *bb;
static CastStrategy *stratC, *stratJava;
static vector<Datatype *> grid;
static int4 ptrSize, intSize;

static string desc(const Datatype *t)
{
  if (t == (const Datatype *)0) return "-";
  ostringstream s;
  type_metatype m = t->getMetatype();
  if (t->isPointerRel()) {
    const TypePointerRel *r = (const TypePointerRel *)t;
    s << "rel{" << t->getSize() << ',' << r->getWordSize() << ',' << r->getByteOffset() << "}(" << desc(r->getPtrTo())
      << '|' << desc(r->getParent()) << ')';
  }
  else if (m == TYPE_PTR && t->getName().empty()) {
    const TypePointer *p = (const TypePointer *)t;
    s << "*{" << t->getSize() << ',' << p->getWordSize() << "}(" << desc(p->getPtrTo()) << ')';
  }
  else if (m == TYPE_ARRAY && t->getName().empty())
    s << '[' << ((const TypeArray *)t)->numElements() << "](" << desc(((const TypeArray *)t)->getBase()) << ')';
  else if (m == TYPE_PARTIALSTRUCT)
    s << "pstruct{" << ((const TypePartialStruct *)t)->getOffset() << ',' << t->getSize() << "}("
      << desc(((const TypePartialStruct *)t)->getParent()) << ')';
  else if (m == TYPE_PARTIALUNION)
    s << "punion{" << ((const TypePartialUnion *)t)->getOffset() << ',' << t->getSize() << "}("
      << desc(((TypePartialUnion *)t)->getParentUnion()) << ')';
  else if (m == TYPE_PARTIALENUM)
    s << "penum{" << ((const TypePartialEnum *)t)->getOffset() << ',' << t->getSize() << "}("
      << desc(((const TypePartialEnum *)t)->getParent()) << ')';
  else if (t->getName().empty())
    s << "anon{" << (int4)m << ',' << t->getSize() << '}';
  else
    s << t->getName();
  return s.str();
}

static Datatype *parse(const string &text)
{
  istringstream s(text);
  string unused;
  return parse_type(s,unused,glb);
}

static void buildGrid(void)
{
  static const char *decl[] = {
    "bool", "char", "int1", "uint1", "xunknown1", "int2", "uint2", "xunknown2", "wchar2",
    "int4", "uint4", "xunknown4", "float4", "int8", "uint8", "xunknown8", "float8",
    "void *", "int4 *", "uint4 *", "char *", "xunknown1 *", "float8 *", "int4 **", "code *",
    "int1 var[4]", "int4 var[2]", 0 };
  for(int4 i=0;decl[i]!=0;++i) grid.push_back(parse(decl[i]));
  parse("struct sone { int4 a; int4 b; }");
  parse("struct swrap { int8 w; }");
  parse("union uone { int8 l; float8 d; int4 *p; int1 a[8]; }");
  parse("union utwo { int4 i; float4 f; }");
  parse("enum eone { ONE=1, TWO=2 }");
  grid.push_back(types->findByName("sone"));
  grid.push_back(parse("sone *"));
  grid.push_back(types->findByName("swrap"));
  grid.push_back(types->findByName("uone"));
  grid.push_back(parse("uone *"));
  grid.push_back(types->findByName("utwo"));
  grid.push_back(types->findByName("eone"));
  grid.push_back(parse("eone *"));
  grid.push_back(types->getBase(4,TYPE_INT,"myint4"));
  TypePointer *sp = (TypePointer *)parse("sone *");
  grid.push_back(types->getTypePointerRel(sp,types->getBase(4,TYPE_INT),4));
  grid.push_back(types->getTypePartialUnion((TypeUnion *)types->findByName("uone"),0,4));
  grid.push_back(types->getTypePartialStruct(types->findByName("sone"),0,2));
}

// get_opname gives the SLEIGH names BUILD, DELAY_SLOT, LABEL, CROSSBUILD to four decompiler opcodes
static string opn(int4 opc)
{
  switch(opc) {
  case CPUI_MULTIEQUAL: return "MULTIEQUAL";
  case CPUI_INDIRECT: return "INDIRECT";
  case CPUI_PTRADD: return "PTRADD";
  case CPUI_PTRSUB: return "PTRSUB";
  default: break;
  }
  return get_opname((OpCode)opc);
}

static Address pc(void) { return Address(glb->getDefaultCodeSpace(),0x1000); }

// A variable with a type; flag 'e' explicit, 'i' implied, 's' spacebase
static Varnode *var(Datatype *t,char flag=' ')
{
  Varnode *vn = fd->newUnique(t->getSize(),t);
  if (flag == 'e') vn->setFlags(Varnode::explict);
  if (flag == 'i') vn->setFlags(Varnode::implied);
  if (flag == 's') vn->setFlags(Varnode::spacebase);
  return vn;
}

static Varnode *konst(Datatype *t,uintb val)
{
  Varnode *vn = fd->newConstant(t->getSize(),val & calc_mask(t->getSize()));
  vn->updateType(t,false,true);
  return vn;
}

static PcodeOp *mkop(OpCode opc,const vector<Varnode *> &in,Datatype *outType)
{
  PcodeOp *op = fd->newOp(in.size(),pc());
  fd->opSetOpcode(op,opc);
  for(uint4 i=0;i<in.size();++i) fd->opSetInput(op,in[i],i);
  if (outType != (Datatype *)0) {
    Varnode *out = fd->newUniqueOut(outType->getSize(),op);
    out->updateType(outType,false,true);
  }
  fd->opInsertEnd(op,bb);
  return op;
}

static void rmop(PcodeOp *op)
{
  vector<Varnode *> ins;
  for(int4 i=0;i<op->numInput();++i) if (op->getIn(i) != (Varnode *)0) ins.push_back(op->getIn(i));
  fd->opDestroy(op);
  for(uint4 i=0;i<ins.size();++i)
    if (ins[i]->hasNoDescend() && !ins[i]->isWritten() && !ins[i]->isAnnotation())
      fd->deleteVarnode(ins[i]);
}

static void setVariant(bool java)
{
  TypeOp::selectJavaOperators(glb->inst,java);
}

static void sectionP(void)
{
  for(int4 opc=1;opc<CPUI_MAX;++opc) {
    TypeOp *t = glb->inst[opc];
    if (t == (TypeOp *)0) continue;
    setVariant(false);
    string nc = t->getName();
    setVariant(true);
    string nj = t->getName();
    setVariant(false);
    OpBehavior *b = t->getBehavior();
    cout << "P\t" << opc << '\t' << opn(opc) << '\t' << nc << '\t' << nj << '\t' << hex << t->getFlags() << '\t'
	 << t->addlflags << dec << '\t' << (int4)t->getBooleanFlip() << '\t'
	 << (b->isSpecial() ? "special" : (b->isUnary() ? "unary" : "other")) << '\n';
  }
}

static void sectionS(void)
{
  for(int4 j=0;j<2;++j) {
    CastStrategy *st = (j==0) ? stratC : stratJava;
    const char *nm = (j==0) ? "c" : "java";
    for(uint4 a=0;a<grid.size();++a)
      for(uint4 b=0;b<grid.size();++b) {
	for(int4 f=0;f<4;++f)
	  cout << "S\t" << nm << '\t' << desc(grid[a]) << '\t' << desc(grid[b]) << '\t' << (f&1) << '\t' << (f>>1) << '\t'
	       << desc(st->castStandard(grid[a],grid[b],(f&1)!=0,(f&2)!=0)) << '\n';
	cout << "Z\t" << nm << '\t' << desc(grid[a]) << '\t' << desc(grid[b]) << '\t'
	     << st->isSextCast(grid[a],grid[b]) << st->isZextCast(grid[a],grid[b])
	     << st->isSubpieceCast(grid[a],grid[b],0) << st->isSubpieceCast(grid[a],grid[b],1)
	     << st->isSubpieceCastEndian(grid[a],grid[b],0,false) << st->isSubpieceCastEndian(grid[a],grid[b],0,true) << '\n';
      }
  }
}

// Everything the TypeOp of one op answers
static void answers(PcodeOp *op,CastStrategy *st)
{
  TypeOp *t = op->getOpcode();
  Varnode *out = op->getOut();
  cout << '|' << (out ? desc(op->outputTypeLocal()) : "-") << '|';
  for(int4 i=0;i<op->numInput();++i) cout << (i ? "," : "") << desc(op->inputTypeLocal(i));
  cout << '|' << (out ? desc(t->getOutputToken(op,st)) : "-") << '|';
  for(int4 i=0;i<op->numInput();++i) cout << (i ? "," : "") << desc(t->getInputCast(op,i,st));
  cout << '|' << t->getOperatorName(op) << '|';
  for(int4 a=-1;a<op->numInput();++a) {
    if (a < 0 && out == (Varnode *)0) continue;
    Varnode *invn = (a < 0) ? out : op->getIn(a);
    if (invn->isAnnotation()) continue;
    for(int4 b=-1;b<op->numInput();++b) {
      if (a == b) continue;
      if (b < 0 && out == (Varnode *)0) continue;
      Varnode *outvn = (b < 0) ? out : op->getIn(b);
      if (outvn->isAnnotation()) continue;
      Datatype *res = t->propagateType(invn->getType(),op,invn,outvn,a,b);
      if (res != (Datatype *)0)
	cout << a << '>' << b << '=' << desc(res) << ';';
    }
  }
  cout << '|';
  for(int4 i=0;i<op->numInput();++i) {
    Varnode *vn = op->getIn(i);
    if (!vn->isConstant()) { cout << '.'; continue; }
    uint4 before = vn->addlflags;
    bool u = st->markExplicitUnsigned(op,i);
    bool l = (i == 0) && st->markExplicitLongSize(op,i);
    vn->addlflags = before;
    cout << (u ? 'u' : '-') << (l ? 'l' : '-');
  }
  cout << '\n';
}

static Datatype *sized(int4 size,type_metatype m) { return types->getBase(size,m); }

static void emitO(const char *variant,CastStrategy *st,OpCode opc,const char *shape,vector<Varnode *> &in,
		  const vector<Datatype *> &shown,Datatype *outType)
{
  // INT_ADD reads the temporary type of the other operand (typeop.cc:1336)
  for(uint4 i=0;i<in.size();++i) in[i]->setTempType(in[i]->getType());
  PcodeOp *op = mkop(opc,in,outType);
  cout << "O\t" << variant << '\t' << opn(opc) << '\t' << shape;
  for(uint4 i=0;i<shown.size();++i) cout << '\t' << desc(shown[i]);
  cout << "\t->\t" << desc(outType) << '\t';
  answers(op,st);
  rmop(op);
}

static void sectionO(bool java)
{
  setVariant(java);
  const char *variant = java ? "java" : "c";
  CastStrategy *st = java ? stratJava : stratC;
  AddrSpace *dataSpc = glb->getDefaultDataSpace();
  static const uintb kval[] = { 0, 1, 4, 8, 0x7f, 0x80, 0xffffffffffffffffULL };
  for(int4 opc=1;opc<CPUI_MAX;++opc) {
    TypeOp *t = glb->inst[opc];
    if (t == (TypeOp *)0) continue;
    OpCode o = (OpCode)opc;
    uint4 fl = t->getFlags();
    bool boolOut = (fl & PcodeOp::booloutput) != 0;
    if (o == CPUI_CALL || o == CPUI_CALLIND || o == CPUI_CALLOTHER || o == CPUI_RETURN) continue;	// section R
    for(uint4 a=0;a<grid.size();++a) {
      Datatype *ta = grid[a];
      vector<Varnode *> in;
      vector<Datatype *> shown;
      if (o == CPUI_BRANCH || o == CPUI_BRANCHIND) {
	in.push_back(var(ta)); shown.push_back(ta);
	emitO(variant,st,o,"v",in,shown,(Datatype *)0);
	continue;
      }
      if (o == CPUI_CBRANCH) {
	if (ta->getSize() != 1) continue;
	in.push_back(var(sized(ptrSize,TYPE_UNKNOWN))); in.push_back(var(ta)); shown.push_back(ta);
	emitO(variant,st,o,"v",in,shown,(Datatype *)0);
	continue;
      }
      if (o == CPUI_LOAD || o == CPUI_STORE) {
	if (ta->getSize() != ptrSize) continue;
	for(uint4 b=0;b<grid.size();++b) {
	  for(int4 sh=0;sh<2;++sh) {		// the pointer plain, or the implied output of a CAST
	    in.clear(); shown.clear();
	    in.push_back(fd->newVarnodeSpace(dataSpc));
	    Varnode *ptr = var(ta);
	    PcodeOp *castOp = (PcodeOp *)0;
	    if (sh == 1) {
	      vector<Varnode *> cin; cin.push_back(ptr);
	      castOp = mkop(CPUI_CAST,cin,ta);
	      ptr = castOp->getOut();
	      ptr->setFlags(Varnode::implied);
	    }
	    in.push_back(ptr); shown.push_back(ta); shown.push_back(grid[b]);
	    if (o == CPUI_LOAD)
	      emitO(variant,st,o,sh ? "cast" : "v",in,shown,grid[b]);
	    else {
	      in.push_back(var(grid[b]));
	      emitO(variant,st,o,sh ? "cast" : "v",in,shown,(Datatype *)0);
	    }
	    if (castOp != (PcodeOp *)0) rmop(castOp);
	  }
	}
	continue;
      }
      if (o == CPUI_INDIRECT) {
	PcodeOp *other = mkop(CPUI_COPY,vector<Varnode *>(1,var(ta)),ta);
	in.push_back(var(ta)); in.push_back(fd->newVarnodeIop(other)); shown.push_back(ta);
	emitO(variant,st,o,"v",in,shown,ta);
	rmop(other);
	continue;
      }
      if (o == CPUI_SEGMENTOP) {
	if (ta->getSize() != ptrSize) continue;
	in.push_back(fd->newVarnodeSpace(dataSpc)); in.push_back(var(sized(2,TYPE_UNKNOWN))); in.push_back(var(ta));
	shown.push_back(ta);
	emitO(variant,st,o,"v",in,shown,sized(ptrSize,TYPE_UNKNOWN));
	in.clear();
	in.push_back(fd->newVarnodeSpace(dataSpc)); in.push_back(var(sized(2,TYPE_UNKNOWN))); in.push_back(var(ta));
	emitO(variant,st,o,"wide",in,shown,sized(ptrSize+2,TYPE_UNKNOWN));
	continue;
      }
      if (o == CPUI_CPOOLREF || o == CPUI_NEW) {
	in.push_back(var(ta)); in.push_back(konst(sized(4,TYPE_INT),1)); shown.push_back(ta);
	emitO(variant,st,o,"v",in,shown,sized(ptrSize,TYPE_UNKNOWN));
	continue;
      }
      if (o == CPUI_INSERT || o == CPUI_ZPULL || o == CPUI_SPULL) {
	in.push_back(var(ta));
	if (o == CPUI_INSERT) in.push_back(var(sized(4,TYPE_UNKNOWN)));
	in.push_back(konst(sized(4,TYPE_INT),3)); in.push_back(konst(sized(4,TYPE_INT),5));
	shown.push_back(ta);
	emitO(variant,st,o,"v",in,shown,(o == CPUI_INSERT) ? ta : sized(4,TYPE_UNKNOWN));
	continue;
      }
      if (o == CPUI_PTRSUB) {
	if (ta->getSize() != ptrSize) continue;
	for(int4 k=0;k<4;++k)
	  for(int4 sb=0;sb<2;++sb) {
	    in.clear(); shown.clear();
	    in.push_back(var(ta,sb ? 's' : ' ')); in.push_back(konst(sized(ptrSize,TYPE_INT),kval[k])); shown.push_back(ta);
	    ostringstream sh; sh << (sb ? "sb" : "") << 'k' << kval[k];
	    emitO(variant,st,o,sh.str().c_str(),in,shown,sized(ptrSize,TYPE_UNKNOWN));
	  }
	continue;
      }
      if (o == CPUI_PTRADD) {
	if (ta->getSize() != ptrSize) continue;
	for(int4 k=0;k<5;++k)			// constant index, or a variable index (k==4)
	  for(int4 m=0;m<3;++m) {
	    in.clear(); shown.clear();
	    in.push_back(var(ta));
	    if (k < 4) in.push_back(konst(sized(ptrSize,TYPE_INT),kval[k])); else in.push_back(var(sized(ptrSize,TYPE_INT)));
	    in.push_back(konst(sized(ptrSize,TYPE_INT),kval[m+1]));
	    shown.push_back(ta);
	    ostringstream sh; if (k < 4) sh << 'k' << kval[k]; else sh << 'v'; sh << 'm' << kval[m+1];
	    emitO(variant,st,o,sh.str().c_str(),in,shown,ta);
	  }
	continue;
      }
      if (o == CPUI_PIECE) {
	for(uint4 b=0;b<grid.size();++b) {
	  int4 sz = ta->getSize() + grid[b]->getSize();
	  for(uint4 c=0;c<grid.size();++c) {
	    if (grid[c]->getSize() != sz) continue;
	    in.clear(); shown.clear();
	    in.push_back(var(ta)); in.push_back(var(grid[b])); shown.push_back(ta); shown.push_back(grid[b]);
	    emitO(variant,st,o,"v",in,shown,grid[c]);
	  }
	}
	continue;
      }
      if (o == CPUI_SUBPIECE) {
	for(uint4 c=0;c<grid.size();++c) {
	  if (grid[c]->getSize() >= ta->getSize()) continue;
	  for(int4 off=0;off + grid[c]->getSize() <= ta->getSize();off += grid[c]->getSize()) {
	    in.clear(); shown.clear();
	    in.push_back(var(ta)); in.push_back(konst(sized(4,TYPE_INT),off)); shown.push_back(ta);
	    ostringstream sh; sh << 'k' << off;
	    emitO(variant,st,o,sh.str().c_str(),in,shown,grid[c]);
	  }
	}
	continue;
      }
      if ((fl & PcodeOp::unary) != 0 || o == CPUI_COPY || o == CPUI_CAST) {
	bool ext = (o == CPUI_INT_ZEXT || o == CPUI_INT_SEXT);
	for(uint4 c=0;c<grid.size();++c) {
	  Datatype *tc = grid[c];
	  if (boolOut) { if (c != 0) continue; }
	  else if (ext) { if (tc->getSize() <= ta->getSize()) continue; }
	  else if (o == CPUI_FLOAT_INT2FLOAT || o == CPUI_FLOAT_FLOAT2FLOAT || o == CPUI_FLOAT_TRUNC ||
		   o == CPUI_POPCOUNT || o == CPUI_LZCOUNT || o == CPUI_CAST) {
	    if (tc->getSize() > 8 || tc->getMetatype() == TYPE_STRUCT) continue;
	  }
	  else if (tc->getSize() != ta->getSize()) continue;
	  for(int4 sb=0;sb<((o == CPUI_COPY) ? 2 : 1);++sb) {
	    in.clear(); shown.clear();
	    in.push_back(var(ta,sb ? 's' : ' ')); shown.push_back(ta);
	    emitO(variant,st,o,sb ? "sb" : "v",in,shown,tc);
	  }
	}
	if (o == CPUI_INT_ZEXT && ta->getSize() < 8) {		// INT2FLOAT absorbing a ZEXT is in section X
	}
	continue;
      }
      // binary operators and MULTIEQUAL
      for(uint4 b=0;b<grid.size();++b) {
	Datatype *tb = grid[b];
	bool shift = t->isShiftOp();
	if (!shift && tb->getSize() != ta->getSize()) continue;
	if (shift && tb->getMetatype() != TYPE_INT && tb->getMetatype() != TYPE_UINT && tb->getMetatype() != TYPE_BOOL) continue;
	Datatype *outs[2];
	outs[0] = boolOut ? grid[0] : ta;
	outs[1] = boolOut ? (Datatype *)0 : sized(ta->getSize(),TYPE_UNKNOWN);
	for(int4 oi=0;oi<2;++oi) {
	  if (outs[oi] == (Datatype *)0 || (oi == 1 && outs[1] == outs[0])) continue;
	  in.clear(); shown.clear();
	  in.push_back(var(ta)); in.push_back(var(tb)); shown.push_back(ta); shown.push_back(tb);
	  emitO(variant,st,o,"v",in,shown,outs[oi]);
	}
	if (b != a && !shift) continue;
	// the second operand a constant (of the first operand's type unless a shift)
	for(int4 k=0;k<7;++k) {
	  in.clear(); shown.clear();
	  in.push_back(var(ta)); in.push_back(konst(shift ? tb : ta,kval[k])); shown.push_back(ta); shown.push_back(shift ? tb : ta);
	  ostringstream sh; sh << 'k' << hex << (kval[k] & calc_mask((shift ? tb : ta)->getSize()));
	  emitO(variant,st,o,sh.str().c_str(),in,shown,outs[0]);
	}
	// a pointer with an integer constant
	if (ta->getMetatype() == TYPE_PTR)
	  for(int4 k=0;k<7;++k) {
	    in.clear(); shown.clear();
	    Datatype *it = sized(ta->getSize(),TYPE_INT);
	    in.push_back(var(ta)); in.push_back(konst(it,kval[k])); shown.push_back(ta); shown.push_back(it);
	    ostringstream sh; sh << 'n' << hex << (kval[k] & calc_mask(it->getSize()));
	    emitO(variant,st,o,sh.str().c_str(),in,shown,outs[0]);
	  }
	// the first operand a constant
	in.clear(); shown.clear();
	in.push_back(konst(ta,0x90)); in.push_back(var(tb)); shown.push_back(ta); shown.push_back(tb);
	emitO(variant,st,o,"c90",in,shown,outs[0]);
	// the first operand flagged as a spacebase
	in.clear(); shown.clear();
	in.push_back(var(ta,'s')); in.push_back(var(tb)); shown.push_back(ta); shown.push_back(tb);
	emitO(variant,st,o,"sb",in,shown,outs[0]);
	// INT_ADD: the other operand a multiple
	if (o == CPUI_INT_ADD && ta->getSize() == ptrSize) {
	  for(int4 k=1;k<7;++k) {
	    vector<Varnode *> min; min.push_back(var(sized(ptrSize,TYPE_INT))); min.push_back(konst(sized(ptrSize,TYPE_INT),kval[k]));
	    PcodeOp *mult = mkop(CPUI_INT_MULT,min,sized(ptrSize,TYPE_INT));
	    in.clear(); shown.clear();
	    in.push_back(var(ta)); in.push_back(mult->getOut()); shown.push_back(ta); shown.push_back(sized(ptrSize,TYPE_INT));
	    ostringstream sh; sh << "mult" << hex << (kval[k] & calc_mask(ptrSize));
	    emitO(variant,st,o,sh.str().c_str(),in,shown,outs[0]);
	    rmop(mult);
	  }
	}
      }
    }
  }
  setVariant(false);
}

// A small value in one of the shapes localExtensionType distinguishes
static Varnode *shaped(Datatype *t,int4 shape,vector<PcodeOp *> &extra)
{
  switch(shape) {
  case 0: return var(t);			// free, neither explicit nor implied
  case 1: return var(t,'e');			// explicit
  case 2: return konst(t,0x7f);			// constant, high bit clear
  case 3: return konst(t,0x80ff);		// constant, high bit set (after masking, for sizes 1 and 2)
  default: break;
  }
  static const OpCode defs[] = { CPUI_CAST, CPUI_LOAD, CPUI_INT_AND, CPUI_INT_AND, CPUI_INT_EQUAL, CPUI_INT_ADD,
				 CPUI_INT_RIGHT, CPUI_INT_SRIGHT, CPUI_INT_OR, CPUI_INT_SDIV, CPUI_INT_2COMP, CPUI_COPY };
  OpCode d = defs[shape-4];
  vector<Varnode *> in;
  if (d == CPUI_LOAD) { in.push_back(fd->newVarnodeSpace(glb->getDefaultDataSpace())); in.push_back(var(sized(ptrSize,TYPE_UNKNOWN))); }
  else if (d == CPUI_CAST || d == CPUI_COPY || d == CPUI_INT_2COMP) in.push_back(var(t,'e'));
  else if (shape == 6) { in.push_back(var(t)); in.push_back(konst(t,0x7f)); }		// AND with a small mask
  else if (shape == 7) { in.push_back(var(t)); in.push_back(konst(t,0x80ff)); }	// AND with the high bit
  else { in.push_back(var(t,'e')); in.push_back(var(t,'e')); }
  PcodeOp *op = mkop(d,in,(d == CPUI_INT_EQUAL) ? grid[0] : t);
  extra.push_back(op);
  return op->getOut();
}

static const char *shapeName[] = { "free", "explicit", "k7f", "k80", "cast", "load", "andlo", "andhi", "equal", "add",
				   "right", "sright", "or", "sdiv", "neg", "copy" };

static void sectionX(bool java)
{
  setVariant(java);
  const char *variant = java ? "java" : "c";
  CastStrategy *st = java ? stratJava : stratC;
  static const char *small[] = { "bool", "char", "int1", "uint1", "xunknown1", "int2", "uint2", "xunknown2", "int4", "uint4", 0 };
  static const OpCode readers[] = { CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL, CPUI_INT_SLESS, CPUI_INT_SLESSEQUAL, CPUI_INT_LESS,
				    CPUI_INT_LESSEQUAL, CPUI_INT_RIGHT, CPUI_INT_SRIGHT, CPUI_INT_DIV, CPUI_INT_SDIV,
				    CPUI_INT_REM, CPUI_INT_SREM, CPUI_INT_ZEXT, CPUI_INT_SEXT, CPUI_FLOAT_INT2FLOAT };
  for(int4 i=0;small[i]!=0;++i) {
    Datatype *t = parse(small[i]);
    for(int4 sh=0;sh<16;++sh) {
      vector<PcodeOp *> extra;
      Varnode *vn = shaped(t,sh,extra);
      cout << "X\t" << variant << '\t' << desc(t) << '\t' << shapeName[sh] << '\t';
      // a constant needs its reader before it is asked (loneDescend, cast.cc:185)
      for(uint4 r=0;r<sizeof(readers)/sizeof(readers[0]);++r) {
	OpCode ro = readers[r];
	bool unary = (ro == CPUI_INT_ZEXT || ro == CPUI_INT_SEXT || ro == CPUI_FLOAT_INT2FLOAT);
	for(int4 osh=0;osh<(unary ? 1 : 4);++osh) {		// the other operand: free, explicit, small constant, big constant
	  vector<Varnode *> in;
	  in.push_back(vn);
	  if (!unary) in.push_back(shaped(t,osh,extra));
	  Datatype *ot = unary ? sized(8,(ro == CPUI_FLOAT_INT2FLOAT) ? TYPE_FLOAT : TYPE_INT) :
	    ((glb->inst[ro]->getFlags() & PcodeOp::booloutput) ? grid[0] : t);
	  PcodeOp *op = mkop(ro,in,ot);
	  cout << opn(ro) << ':' << shapeName[osh] << '=' << st->localExtensionType(vn,op) << ',' << st->intPromotionType(vn) << ',';
	  if (unary) cout << st->checkIntPromotionForExtension(op);
	  else cout << st->checkIntPromotionForCompare(op,0) << st->checkIntPromotionForCompare(op,1);
	  cout << ',' << desc(op->getOpcode()->getInputCast(op,0,st)) << ';';
	  fd->opUnsetInput(op,0);
	  Varnode *other = unary ? (Varnode *)0 : op->getIn(1);
	  fd->opDestroy(op);
	  if (other != (Varnode *)0 && !other->isWritten() && other->hasNoDescend()) fd->deleteVarnode(other);
	}
      }
      cout << '\n';
      for(int4 e=extra.size()-1;e>=0;--e) if (!extra[e]->isDead()) rmop(extra[e]);
    }
  }
  setVariant(false);
}

static void sectionE(bool java)
{
  setVariant(java);
  const char *variant = java ? "java" : "c";
  CastStrategy *st = java ? stratJava : stratC;
  static const OpCode readers[] = { CPUI_PTRADD, CPUI_INT_ADD, CPUI_INT_SUB, CPUI_INT_MULT, CPUI_INT_DIV, CPUI_INT_SDIV, CPUI_INT_AND,
				    CPUI_INT_OR, CPUI_INT_XOR, CPUI_INT_EQUAL, CPUI_INT_LESS, CPUI_INT_SLESS, CPUI_INT_LEFT, CPUI_COPY };
  static const char *outs[] = { "int4", "uint4", "int8", "uint8", 0 };
  for(int4 e=0;e<2;++e) {
    OpCode ext = e ? CPUI_INT_SEXT : CPUI_INT_ZEXT;
    for(int4 oi=0;outs[oi]!=0;++oi) {
      Datatype *ot = parse(outs[oi]);
      for(uint4 r=0;r<sizeof(readers)/sizeof(readers[0]);++r)
	for(int4 slot=0;slot<2;++slot)
	  for(int4 osh=0;osh<5;++osh) {		// other: free, explicit same type, explicit other sign, constant, explicit out
	    if (readers[r] == CPUI_COPY && (slot != 0 || osh != 0)) continue;
	    vector<Varnode *> ein; ein.push_back(var(parse("int2")));
	    PcodeOp *extOp = mkop(ext,ein,ot);
	    if (osh == 4) extOp->getOut()->setFlags(Varnode::explict);
	    Datatype *other = (osh == 2) ? sized(ot->getSize(),(ot->getMetatype() == TYPE_INT) ? TYPE_UINT : TYPE_INT) : ot;
	    Varnode *ov = (osh == 3) ? konst(ot,5) : var(other,(osh == 0) ? ' ' : 'e');
	    vector<Varnode *> in;
	    if (readers[r] == CPUI_COPY) in.push_back(extOp->getOut());
	    else if (readers[r] == CPUI_PTRADD) { in.push_back(slot ? ov : extOp->getOut()); in.push_back(slot ? extOp->getOut() : ov); in.push_back(konst(ot,4)); }
	    else { in.push_back(slot ? ov : extOp->getOut()); in.push_back(slot ? extOp->getOut() : ov); }
	    PcodeOp *rd = mkop(readers[r],in,(glb->inst[readers[r]]->getFlags() & PcodeOp::booloutput) ? grid[0] : ot);
	    cout << "E\t" << variant << '\t' << opn(ext) << '\t' << desc(ot) << '\t' << opn(readers[r]) << '\t' << slot << '\t' << osh << '\t'
		 << st->isExtensionCastImplied(extOp,rd) << st->isExtensionCastImplied(extOp,(PcodeOp *)0) << '\n';
	    rmop(rd);
	    rmop(extOp);
	  }
    }
  }
  setVariant(false);
}

static void rowR(const char *tag,PcodeOp *op)
{
  cout << "R\t" << tag << '\t' << opn(op->code()) << '\t';
  answers(op,stratC);
}

static void sectionR(void)
{
  Datatype *i4 = parse("int4"), *u8 = parse("uint8"), *pi4 = parse("int4 *"), *x8 = sized(8,TYPE_UNKNOWN), *x4 = sized(4,TYPE_UNKNOWN);
  for(int4 locked=0;locked<3;++locked) {		// no call spec; unlocked; locked int4 f(int4 *,uint8)
    for(int4 ind=0;ind<2;++ind) {
      vector<Varnode *> in;
      in.push_back(ind ? var(sized(ptrSize,TYPE_UNKNOWN)) : fd->newVarnode(1,Address(glb->getDefaultCodeSpace(),0x2000)));
      in.push_back(var(x8)); in.push_back(var(x8)); in.push_back(var(x4));
      PcodeOp *op = mkop(ind ? CPUI_CALLIND : CPUI_CALL,in,x4);
      FuncCallSpecs *fc = (FuncCallSpecs *)0;
      if (locked > 0) {
	fc = new FuncCallSpecs(op);
	fd->qlst.push_back(fc);
	fc->setInternal(glb->defaultfp,types->getTypeVoid());
	if (locked == 2) {
	  PrototypePieces pieces;
	  pieces.model = glb->defaultfp; pieces.name = "f"; pieces.outtype = i4; pieces.firstVarArgSlot = -1;
	  pieces.intypes.push_back(pi4); pieces.innames.push_back("a");
	  pieces.intypes.push_back(u8); pieces.innames.push_back("b");
	  fc->setPieces(pieces);
	}
	if (!ind) fd->opSetInput(op,fd->newVarnodeCallSpecs(fc),0);
      }
      rowR(locked == 0 ? "nospec" : (locked == 1 ? "unlocked" : "locked"),op);
      if (fc != (FuncCallSpecs *)0) { fd->qlst.pop_back(); }
      fd->opDestroy(op);
      if (fc != (FuncCallSpecs *)0) delete fc;
    }
  }
  for(int4 locked=0;locked<2;++locked) {
    if (locked) {
      PrototypePieces pieces;
      pieces.model = glb->defaultfp; pieces.name = "dummy"; pieces.outtype = i4; pieces.firstVarArgSlot = -1;
      fd->getFuncProto().setPieces(pieces);
    }
    for(int4 sz=4;sz<=8;sz+=4) {
      vector<Varnode *> in; in.push_back(var(sized(ptrSize,TYPE_UNKNOWN))); in.push_back(var(sized(sz,TYPE_UNKNOWN)));
      PcodeOp *op = mkop(CPUI_RETURN,in,(Datatype *)0);
      rowR(locked ? "retint4" : "retvoid",op);
      fd->opDestroy(op);
      // the same op outside any block (typeop.cc:911-913)
      vector<Varnode *> in2; in2.push_back(var(sized(ptrSize,TYPE_UNKNOWN))); in2.push_back(var(sized(sz,TYPE_UNKNOWN)));
      PcodeOp *dead = fd->newOp(2,pc());
      fd->opSetOpcode(dead,CPUI_RETURN);
      fd->opSetInput(dead,in2[0],0); fd->opSetInput(dead,in2[1],1);
      cout << "R\t" << (locked ? "retint4-noblock" : "retvoid-noblock") << "\tRETURN\t" << desc(dead->inputTypeLocal(0)) << ','
	   << desc(dead->inputTypeLocal(1)) << '\n';
    }
  }
  for(int4 index=0;index<(int4)glb->userops.useroplist.size() && index<4;++index) {
    vector<Varnode *> in; in.push_back(konst(sized(4,TYPE_INT),index)); in.push_back(var(x8));
    PcodeOp *op = mkop(CPUI_CALLOTHER,in,x8);
    rowR("userop",op);
    fd->opDestroy(op);
  }
}

static void rowU(const string &shape,Datatype *parent,PcodeOp *op,int4 slot)
{
  ScoreUnionFields sc(*fd,parent,op,slot);
  cout << "U\t" << desc(parent) << '\t' << opn(op->code()) << '\t' << slot << '\t' << shape << '\t';
  for(uint4 i=0;i<sc.scores.size();++i) cout << (i ? "," : "") << sc.scores[i];
  cout << '\t' << sc.result.fieldNum << '\t' << desc(sc.result.resolve) << '\t' << sc.trialCount << '\n';
}

static void sectionU(void)
{
  setVariant(false);
  vector<Datatype *> parents;
  parents.push_back(types->findByName("uone"));
  parents.push_back(parse("uone *"));
  parents.push_back(types->findByName("utwo"));
  parents.push_back(parse("utwo *"));
  static const OpCode second[] = { CPUI_MAX, CPUI_LOAD, CPUI_INT_ADD, CPUI_FLOAT_ADD, CPUI_CBRANCH, CPUI_INT_SLESS, CPUI_SUBPIECE, CPUI_STORE };
  AddrSpace *dataSpc = glb->getDefaultDataSpace();
  for(uint4 p=0;p<parents.size();++p) {
    Datatype *pt = parents[p];
    for(int4 opc=1;opc<CPUI_MAX;++opc) {
      TypeOp *t = glb->inst[opc];
      if (t == (TypeOp *)0) continue;
      OpCode o = (OpCode)opc;
      if (o == CPUI_INDIRECT || o == CPUI_CPOOLREF || o == CPUI_NEW || o == CPUI_INSERT || o == CPUI_ZPULL || o == CPUI_SPULL ||
	  o == CPUI_SEGMENTOP || o == CPUI_CALLOTHER) continue;
      uint4 fl = t->getFlags();
      int4 nin = ((fl & PcodeOp::unary) != 0 || o == CPUI_COPY || o == CPUI_BRANCH || o == CPUI_BRANCHIND) ? 1 : 2;
      if (o == CPUI_PTRADD || o == CPUI_STORE || o == CPUI_CALL || o == CPUI_CALLIND) nin = 3;
      bool hasOut = !(o == CPUI_STORE || o == CPUI_BRANCH || o == CPUI_CBRANCH || o == CPUI_BRANCHIND || o == CPUI_RETURN);
      for(int4 slot=-1;slot<nin;++slot) {
	if (slot < 0 && !hasOut) continue;
	if ((o == CPUI_LOAD || o == CPUI_STORE) && slot == 0) continue;
	for(int4 k=0;k<3;++k) {			// the other operand: a variable, the constant 4, the constant 16
	  for(uint4 s2=0;s2<sizeof(second)/sizeof(second[0]);++s2) {
	    if (k > 0 && nin < 2) continue;
	    if (s2 > 0 && !hasOut) continue;
	    if (s2 > 0 && k > 0) continue;
	    vector<Varnode *> in;
	    for(int4 i=0;i<nin;++i) {
	      if (i == slot) in.push_back(var(pt));
	      else if ((o == CPUI_LOAD || o == CPUI_STORE) && i == 0) in.push_back(fd->newVarnodeSpace(dataSpc));
	      else if (o == CPUI_PTRADD && i == 2) in.push_back(konst(sized(ptrSize,TYPE_INT),(k == 2) ? 16 : 8));
	      else if (k > 0 && i == 1) in.push_back(konst(sized(pt->getSize(),TYPE_INT),(k == 1) ? 4 : 16));
	      else if (o == CPUI_LOAD || o == CPUI_STORE || o == CPUI_CALLIND) in.push_back(var(sized(ptrSize,TYPE_UNKNOWN)));
	      else in.push_back(var(sized(pt->getSize(),TYPE_UNKNOWN)));
	    }
	    Datatype *ot = hasOut ? ((slot < 0) ? pt : (((fl & PcodeOp::booloutput) != 0) ? grid[0] : sized(pt->getSize(),TYPE_UNKNOWN))) : (Datatype *)0;
	    PcodeOp *op = mkop(o,in,ot);
	    PcodeOp *rd = (PcodeOp *)0;
	    if (s2 > 0) {
	      vector<Varnode *> rin;
	      OpCode ro = second[s2];
	      if (ro == CPUI_LOAD || ro == CPUI_STORE) rin.push_back(fd->newVarnodeSpace(dataSpc));
	      rin.push_back(op->getOut());
	      if (ro == CPUI_INT_ADD) rin.push_back(konst(sized(ot->getSize(),TYPE_INT),4));
	      else if (ro == CPUI_FLOAT_ADD || ro == CPUI_INT_SLESS) rin.push_back(var(sized(ot->getSize(),TYPE_UNKNOWN)));
	      else if (ro == CPUI_SUBPIECE) rin.push_back(konst(sized(4,TYPE_INT),0));
	      else if (ro == CPUI_STORE) rin.push_back(var(sized(4,TYPE_UNKNOWN)));
	      else if (ro == CPUI_CBRANCH) { rin.clear(); rin.push_back(var(sized(ptrSize,TYPE_UNKNOWN))); rin.push_back(op->getOut()); }
	      Datatype *rot = (ro == CPUI_STORE || ro == CPUI_CBRANCH) ? (Datatype *)0 :
		((ro == CPUI_INT_SLESS) ? grid[0] : sized((ro == CPUI_LOAD || ro == CPUI_SUBPIECE) ? 4 : ot->getSize(),TYPE_UNKNOWN));
	      rd = mkop(ro,rin,rot);
	    }
	    ostringstream sh;
	    sh << ((k == 0) ? "v" : ((k == 1) ? "k4" : "k16"));
	    if (s2 > 0) sh << '+' << opn(second[s2]);
	    rowU(sh.str(),pt,op,slot);
	    if (rd != (PcodeOp *)0) { fd->opUnsetInput(rd,rd->getSlot(op->getOut())); rmop(rd); }
	    rmop(op);
	  }
	}
      }
    }
  }
  // the truncation forms (unionresolve.cc:1164, 1200)
  TypeUnion *uone = (TypeUnion *)types->findByName("uone");
  static const OpCode trunc[] = { CPUI_COPY, CPUI_INT_ADD, CPUI_FLOAT_ADD, CPUI_LOAD, CPUI_INT_ZEXT, CPUI_SUBPIECE };
  for(int4 size=1;size<=8;size*=2)
    for(int4 off=0;off+size<=8;off+=size)
      for(uint4 r=0;r<sizeof(trunc)/sizeof(trunc[0]);++r) {
	OpCode ro = trunc[r];
	Datatype *vt = sized(size,TYPE_UNKNOWN);
	vector<Varnode *> in;
	if (ro == CPUI_LOAD) { if (size != ptrSize) continue; in.push_back(fd->newVarnodeSpace(dataSpc)); }
	in.push_back(var(vt));
	if (ro == CPUI_INT_ADD || ro == CPUI_FLOAT_ADD) in.push_back(var(vt));
	if (ro == CPUI_SUBPIECE) in.push_back(konst(sized(4,TYPE_INT),0));
	PcodeOp *op = mkop(ro,in,(ro == CPUI_INT_ZEXT) ? sized(16,TYPE_UNKNOWN) : ((ro == CPUI_SUBPIECE && size > 1) ? sized(size/2,TYPE_UNKNOWN) : vt));
	int4 slot = (ro == CPUI_LOAD) ? 1 : 0;
	{
	  ScoreUnionFields sc(*fd,uone,off,op,slot);
	  cout << "U\ttrunc-in{" << off << ',' << size << "}\t" << opn(ro) << '\t' << slot << "\t-\t";
	  for(uint4 i=0;i<sc.scores.size();++i) cout << (i ? "," : "") << sc.scores[i];
	  cout << '\t' << sc.result.fieldNum << '\t' << desc(sc.result.resolve) << '\t' << sc.trialCount << '\n';
	}
	{
	  ScoreUnionFields sc(*fd,uone,off,op,-1);
	  cout << "U\ttrunc-out{" << off << ',' << op->getOut()->getSize() << "}\t" << opn(ro) << "\t-1\t-\t";
	  for(uint4 i=0;i<sc.scores.size();++i) cout << (i ? "," : "") << sc.scores[i];
	  cout << '\t' << sc.result.fieldNum << '\t' << desc(sc.result.resolve) << '\t' << sc.trialCount << '\n';
	}
	{
	  ScoreUnionFields sc(*fd,uone,off,op);
	  cout << "U\ttrunc-sub{" << off << ',' << op->getOut()->getSize() << "}\t" << opn(ro) << "\t-\t-\t";
	  for(uint4 i=0;i<sc.scores.size();++i) cout << (i ? "," : "") << sc.scores[i];
	  cout << '\t' << sc.result.fieldNum << '\t' << desc(sc.result.resolve) << '\t' << sc.trialCount << '\n';
	}
	rmop(op);
      }
}

int main(int argc,char **argv)
{
  if (argc < 3) { cerr << "usage: typeop_oracle SLEIGHHOME ARCH [SECTIONS]" << endl; return 2; }
  string sections = (argc > 3) ? argv[3] : "PSOXERU";
  startDecompilerLibrary(argv[1]);
  istringstream s(string("<binaryimage arch=\"") + argv[2] + "\"></binaryimage>");
  DocumentStorage store;
  Document *doc = store.parseDocument(s);
  store.registerTag(doc->getRoot());
  ostringstream warn;
  glb = ArchitectureCapability::getCapability("xml")->buildArchitecture("","",&warn);
  glb->init(store);
  types = glb->types;
  fd = glb->symboltab->getGlobalScope()->addFunction(pc(),"dummy")->getFunction();
  fd->setHighLevel();
  bb = fd->bblocks.newBlockBasic(fd);
  stratC = new CastStrategyC(); stratC->setTypeFactory(types);
  stratJava = new CastStrategyJava(); stratJava->setTypeFactory(types);
  ptrSize = types->getSizeOfPointer();
  intSize = types->getSizeOfInt();
  buildGrid();
  cout << "H\tbk-typeop-oracle\t1\t" << argv[2] << '\t' << ptrSize << '\t' << intSize << '\t' << types->getSizeOfAltPointer() << '\n';
  for(uint4 i=0;i<grid.size();++i)
    cout << "T\t" << i << '\t' << desc(grid[i]) << '\t' << grid[i]->getSize() << '\t' << (int4)grid[i]->getMetatype() << '\n';
  for(uint4 i=0;i<sections.size();++i) {
    switch(sections[i]) {
    case 'P': sectionP(); break;
    case 'S': sectionS(); break;
    case 'O': sectionO(false); sectionO(true); break;
    case 'X': sectionX(false); sectionX(true); break;
    case 'E': sectionE(false); sectionE(true); break;
    case 'R': sectionR(); break;
    case 'U': sectionU(); break;
    default: break;
    }
    cout.flush();
  }
  return 0;
}
