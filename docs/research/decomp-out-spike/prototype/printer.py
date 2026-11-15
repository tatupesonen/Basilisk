"""Throw-away prototype, part 2: print a tree built by tree.py into Emit calls.

Each method mirrors the emission half of the PrintC method of the same name
(printc.cc), with every query of the function replaced by a fact of the node.
The modifier word is recomputed here from the tree, as PrintC's block methods
change it, and checked against the word logged at each node's entry.
Expressions are printed by replaying the tree in pre-order through a copy of
PrintLanguage's RPN emission (printlanguage.cc:129-407).

Output lines use the `.emit` format (tools/reference/README.md, "The printer
log"); ids are symbolic and compared after renumbering by first appearance.
"""
from tree import TOKENS, Struct, OpNode, Atom

FORCE_HEX, FORCE_DEC = 1, 2
NO_BRANCH, ONLY_BRANCH, COMMA_SEPARATE, FLAT = 0x80, 0x100, 0x200, 0x400
NOFALLTHRU, HIDE_THISPARAM, PENDING_BRACE = 0x1000, 0x4000, 0x8000
BRANCH_MODS = NO_BRANCH | ONLY_BRANCH
KEYWORD, COMMENT, TYPE, FUNCNAME, VAR, CONST, PARAM, GLOBAL, NOCOLOR, ERROR = range(10)
IF_KINDS = ("if", "ifelse", "ifgoto")
F_GOTO, F_BREAK, F_CONTINUE = 1, 2, 4


class Mismatch(Exception):
    pass


def unesc(s):
    out, i = [], 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            n = s[i + 1]
            out.append({"\\": "\\", "t": "\t", "n": "\n", "r": "\r", "0": "\0"}.get(n, n))
            i += 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def esc(s):
    return s.replace("\\", "\\\\").replace("\t", "\\t").replace("\n", "\\n").replace("\r", "\\r").replace("\0", "\\0")


class Pend:
    def __init__(self, style):
        self.style, self.indent_id = style, None


class Out:
    """Collects Emit calls; simulates the one piece of Emit state PrintC reads back."""

    def __init__(self):
        self.lines, self.nid, self.pend = [], 0, None

    def call(self, *a):
        self.lines.append("\t".join(str(x) for x in a))

    def open(self, *a):
        self.nid += 1
        self.lines.append("\t".join(str(x) for x in a) + f"\t=\tN{self.nid}")
        return f"N{self.nid}"

    def fire(self):
        # Emit::emitPending inside EmitPrettyPrint::tagLine (prettyprint.cc:945):
        # PendingBrace::callback opens the brace (printc.cc:3015), not logged
        if self.pend is not None:
            p, self.pend = self.pend, None
            self.nid += 1
            p.indent_id = f"N{self.nid}"

    def tagLine(self):
        self.fire()
        self.call("tagLine")

    def tagLineIndent(self, n):
        self.fire()
        self.call("tagLineIndent", n)

    def spaces(self, n, bump=0):
        self.call("spaces", n, bump)

    def print(self, s, hl=NOCOLOR):
        self.call("print", s, hl)

    def openBraceIndent(self, s, style):
        if style != 0:
            self.fire()
        return self.open("openBraceIndent", s, style)

    def openBrace(self, s, style):
        if style != 0:
            self.fire()
        self.call("openBrace", s, style)

    def closeBraceIndent(self, s, i):
        self.fire()
        self.call("closeBraceIndent", s, i)


class Kids:
    def __init__(self, node):
        self.node, self.items, self.i = node, node.kids, 0

    def peek(self):
        return self.items[self.i] if self.i < len(self.items) else None

    def take(self, kind=None):
        k = self.peek()
        if k is None:
            raise Mismatch(f"{self.node.kind}: expected {kind or 'a child'}, found the end")
        if kind is not None:
            if kind == "expr":
                if isinstance(k, Struct):
                    raise Mismatch(f"{self.node.kind}: expected an expression, found {k.kind}")
            elif not isinstance(k, Struct) or k.kind != kind:
                raise Mismatch(f"{self.node.kind}: expected {kind}, found {getattr(k, 'kind', 'an expression')}")
        self.i += 1
        return k

    def is_(self, kind):
        k = self.peek()
        if kind == "expr":
            return k is not None and not isinstance(k, Struct)
        return isinstance(k, Struct) and k.kind == kind

    def done(self):
        if self.i != len(self.items):
            k = self.items[self.i]
            raise Mismatch(f"{self.node.kind}: unexpected {getattr(k, 'kind', 'expression')}")


class Printer:
    def __init__(self, options):
        o = options
        self.lang = o[0]
        self.mods = int(o[1], 16)
        self.brace_func, self.brace_ifelse, self.brace_loop, self.brace_switch = (int(x) for x in o[2:6])
        self.commentstart, self.commentend = unesc(o[6]), unesc(o[7])
        self.line_commentindent = int(o[8])
        self.unplaced, self.nocasts = o[11] == "1", o[12] == "1"
        self.out = Out()
        self.modstack = []
        self.revpol = []
        self.mod_mismatches = []
        self.counts = {}

    # ---------------------------------------------------------- modifiers
    def pushMod(self):
        self.modstack.append(self.mods)

    def popMod(self):
        self.mods = self.modstack.pop()

    def setMod(self, m):
        self.mods |= m

    def unsetMod(self, m):
        self.mods &= ~m

    def isSet(self, m):
        return (self.mods & m) != 0

    # ---------------------------------------------------------- dispatch
    def node(self, n):
        if not isinstance(n, Struct):
            return self.expr(n)
        self.counts[n.kind] = self.counts.get(n.kind, 0) + 1
        if n.mods != self.mods:
            self.mod_mismatches.append((n.kind, n.mods, self.mods))
        m = getattr(self, "k_" + n.kind, None)
        if m is None:
            raise Mismatch(f"no printer for {n.kind}")
        k = Kids(n)
        m(n, n.facts, k)
        k.done()

    def rest(self, k):
        while k.peek() is not None:
            self.node(k.take())

    def child(self, k):
        """The single structural child a component's emit() produces."""
        self.node(k.take())

    # ---------------------------------------------------------- expressions
    def expr(self, e):
        """Replay the tree in pre-order through PrintLanguage's RPN emission."""
        self.counts["expression"] = self.counts.get("expression", 0) + 1
        self._walk(e)
        if self.revpol:
            raise Mismatch("expression left the RPN stack non-empty")

    def _walk(self, e):
        if isinstance(e, OpNode):
            self.pushOp(e)
            for c in e.kids:
                self._walk(c)
        else:
            self.pushAtom(e)

    def pushOp(self, e):
        tok = TOKENS[e.tok]
        if not self.revpol:
            paren = False
            i = self.out.open("openGroup")
        else:
            self.emitOp(self.revpol[-1])
            paren = self.parentheses(e.tok)
            i = self.out.open("openParen", "(") if paren else self.out.open("openGroup")
        self.revpol.append({"e": e, "tok": tok, "visited": 0, "paren": paren, "id": i, "id2": None})

    def pushAtom(self, a):
        if not self.revpol:
            self.emitAtom(a)
            return
        self.emitOp(self.revpol[-1])
        self.emitAtom(a)
        while self.revpol:
            top = self.revpol[-1]
            top["visited"] += 1
            if top["visited"] == top["tok"][0]:
                self.emitOp(top)
                if top["paren"]:
                    self.out.call("closeParen", ")", top["id"])
                else:
                    self.out.call("closeGroup", top["id"])
                self.revpol.pop()
            else:
                break

    def parentheses(self, name2):
        top = self.revpol[-1]
        t1, t2 = top["tok"], TOKENS[name2]
        prec1, typ1, stage = t1[1], t1[3], top["visited"]
        prec2, typ2 = t2[1], t2[3]
        if typ1 in ("space", "binary"):
            if prec1 > prec2:
                return True
            if prec1 < prec2:
                return False
            if t1[2] and top["e"].tok == name2:
                return False
            if typ2 == "postsurround" and stage == 0:
                return False
            return True
        if typ1 == "unary_prefix":
            if prec1 > prec2:
                return True
            if prec1 < prec2:
                return False
            return typ2 not in ("unary_prefix", "presurround")
        if typ1 == "postsurround":
            if stage == 1:
                return False
            if prec1 > prec2:
                return True
            if prec1 < prec2:
                return False
            return typ2 not in ("postsurround", "binary")
        if typ1 == "presurround":
            if stage == 0:
                return False
            if prec1 > prec2:
                return True
            if prec1 < prec2:
                return False
            return typ2 not in ("unary_prefix", "presurround")
        # hiddenfunction
        if stage == 0 and len(self.revpol) > 1:
            prev = self.revpol[-2]["tok"]
            if prev[3] not in ("binary", "unary_prefix"):
                return False
            if prev[1] < prec2:
                return False
        return True

    def emitOp(self, top):
        e, tok, v = top["e"], top["tok"], top["visited"]
        typ, spacing, bump = tok[3], tok[4], tok[5]
        o = self.out
        if typ == "binary":
            if v != 1:
                return
            o.spaces(spacing, bump)
            o.call("tagOp", e.print1, NOCOLOR, e.op)
            o.spaces(spacing, bump)
        elif typ == "unary_prefix":
            if v != 0:
                return
            o.call("tagOp", e.print1, NOCOLOR, e.op)
            o.spaces(spacing, bump)
        elif typ == "postsurround":
            if v == 0:
                return
            if v == 1:
                o.spaces(spacing, bump)
                top["id2"] = o.open("openParen", e.print1)
                o.spaces(0, bump)
            else:
                o.call("closeParen", e.print2, top["id2"])
        elif typ == "presurround":
            if v == 2:
                return
            if v == 0:
                top["id2"] = o.open("openParen", e.print1)
            else:
                o.call("closeParen", e.print2, top["id2"])
                o.spaces(spacing, bump)
        elif typ == "space":
            if v != 1:
                return
            o.spaces(spacing, bump)

    def emitAtom(self, a):
        o, t = self.out, a.tag
        if t == "syntax":
            o.call("print", a.text, a.hl)
        elif t == "vartoken":
            o.call("tagVariable", a.text, a.hl, a.second, a.op)
        elif t == "functoken":
            o.call("tagFuncName", a.text, a.hl, a.second, a.op)
        elif t == "optoken":
            o.call("tagOp", a.text, a.hl, a.op)
        elif t == "typetoken":
            o.call("tagType", a.text, a.hl, a.second)
        elif t == "fieldtoken":
            o.call("tagField", a.text, a.hl, a.second, a.offset, a.op)
        elif t == "bitfieldtoken":
            o.call("tagBitField", a.text, a.hl, a.second, a.offset, a.op)
        elif t == "casetoken":
            o.call("tagCaseLabel", a.text, a.hl, a.op, a.second)
        # blanktoken prints nothing

    # ---------------------------------------------------------- function level
    def k_docFunction(self, n, f, k):
        o = self.out
        modsave = self.mods
        i1 = o.open("beginFunction", "f:" + f[0])
        self.node(k.take("commentFuncHeader"))
        o.tagLine()
        self.node(k.take("functionDeclaration"))
        i = o.openBraceIndent("{", self.brace_func)
        self.node(k.take("localVarDecls"))
        self.node(k.take("blockGraph"))
        o.closeBraceIndent("}", i)
        o.tagLine()
        o.call("endFunction", i1)
        o.call("flush")
        self.mods = modsave

    def k_commentFuncHeader(self, n, f, k):
        o = self.out
        extra = False
        while k.is_("lineComment") and k.peek().facts[0] == "0" and not self.is_special_header(k.peek()):
            self.node(k.take())
            extra = True
        if self.unplaced:
            if extra:
                o.tagLine()
            extra = False
            while k.is_("lineComment") and not self.is_nocast_warning(k.peek()):
                self.node(k.take())
                extra = True
        if self.nocasts:
            if extra:
                o.tagLine()
            self.node(k.take("lineComment"))
            extra = True
        if extra:
            o.tagLine()

    @staticmethod
    def is_special_header(c):
        t = unesc(c.facts[3])
        return t.startswith("Comments that could not be placed") or t.startswith("DISPLAY WARNING: Type casts")

    @staticmethod
    def is_nocast_warning(c):
        return unesc(c.facts[3]).startswith("DISPLAY WARNING: Type casts")

    def k_lineComment(self, n, f, k):
        # PrintLanguage::emitLineComment (printlanguage.cc:593)
        o = self.out
        indent = int(f[0])
        if indent < 0:
            indent = self.line_commentindent
        spc, off = f[2].split(":", 1) if f[2] != "-" else ("-", "0x0")
        text = unesc(f[3])
        o.tagLineIndent(indent)
        i = o.open("startComment")
        o.call("tagComment", esc(self.commentstart), COMMENT, spc, off)
        pos = 0
        while pos < len(text):
            tok = text[pos]
            pos += 1
            if tok in " \t":
                count = 1
                while pos < len(text) and text[pos] in " \t":
                    count += 1
                    pos += 1
                o.spaces(count)
            elif tok == "\n":
                o.tagLine()
            elif tok == "\r":
                pass
            elif tok == "{" and pos < len(text) and text[pos] == "@":
                count = 1
                while pos < len(text):
                    t2 = text[pos]
                    count += 1
                    pos += 1
                    if t2 == "}":
                        break
                o.call("tagComment", esc(text[pos - count:pos]), COMMENT, spc, off)
            else:
                count = 1
                while pos < len(text) and text[pos] not in " \t\n\v\f\r":
                    count += 1
                    pos += 1
                o.call("tagComment", esc(text[pos - count:pos]), COMMENT, spc, off)
        if self.commentend:
            o.call("tagComment", esc(self.commentend), COMMENT, spc, off)
        o.call("stopComment", i)

    def k_functionDeclaration(self, n, f, k):
        o = self.out
        i = o.open("beginFuncProto")
        self.node(k.take("prototypeOutput"))
        o.spaces(1)
        if f[2] != "-":
            o.print(f[2], ERROR if f[3] == "1" else KEYWORD)
            o.spaces(1)
        i1 = o.open("openGroup")
        self.node(k.take("symbolScope"))
        o.call("tagFuncName", f[0], FUNCNAME, f[1], "-")
        o.spaces(0, 10)
        i2 = o.open("openParen", "(")
        o.spaces(0, 10)
        self.node(k.take("prototypeInputs"))
        o.call("closeParen", ")", i2)
        o.call("closeGroup", i1)
        o.call("endFuncProto", i)

    def k_symbolScope(self, n, f, k):
        if f[2] != "-":
            for name in f[2].split(","):
                self.out.print(name, GLOBAL)
                self.out.print(f[1], NOCOLOR)

    def k_prototypeOutput(self, n, f, k):
        i = self.out.open("beginReturnType", f[0])
        self.expr(k.take("expr"))
        self.out.call("endReturnType", i)

    def k_prototypeInputs(self, n, f, k):
        o = self.out
        sz, dots = int(f[0]), f[1] == "1"
        if sz == 0:
            o.print("void", KEYWORD)
        else:
            comma = False
            for kind in f[2].split(","):
                if comma:
                    o.print(",")
                if kind == "hidden":
                    continue
                comma = True
                if kind == "symbol":
                    self.node(k.take("varDecl"))
                else:
                    self.expr(k.take("expr"))
        if dots:
            if sz != 0:
                o.print(",")
            o.print("...")

    def k_localVarDecls(self, n, f, k):
        notempty = False
        while k.is_("scopeVarDecls"):
            c = k.take()
            notempty |= any(isinstance(x, Struct) and x.kind == "varDeclStatement" for x in c.kids)
            self.node(c)
        if notempty:
            self.out.tagLine()

    def k_scopeVarDecls(self, n, f, k):
        while k.is_("varDeclStatement"):
            self.node(k.take())

    def k_varDeclStatement(self, n, f, k):
        self.out.tagLine()
        self.node(k.take("varDecl"))
        self.out.print(";")

    def k_varDecl(self, n, f, k):
        i = self.out.open("beginVarDecl", f[0])
        self.expr(k.take("expr"))
        self.out.call("endVarDecl", i)

    # ---------------------------------------------------------- blocks
    @staticmethod
    def comps(f):
        return [] if f[2] == "-" else f[2].split(",")

    def k_blockGraph(self, n, f, k):
        for c in self.comps(f):
            i = self.out.open("beginBlock", c)
            self.child(k)
            self.out.call("endBlock", i)

    def k_blockBasic(self, n, f, k):
        o = self.out
        self.node(k.take("labelStatement"))
        if self.isSet(ONLY_BRANCH):
            if k.is_("expression"):     # the last op is a branch (a fact of the tree: the node exists)
                self.node(k.take())
            return
        separator = False
        while k.is_("statement") or (k.is_("commentGroup") and k.peek().facts[0] != "-"):
            if separator:
                if self.isSet(COMMA_SEPARATE):
                    o.print(",")
                    o.spaces(1)
                else:
                    self.node(k.take("commentGroup"))
                    o.tagLine()
            elif not self.isSet(COMMA_SEPARATE):
                self.node(k.take("commentGroup"))
                o.tagLine()
            self.node(k.take("statement"))
            separator = True
        if self.isSet(FLAT) and self.isSet(NOFALLTHRU):
            o.tagLine()
            i = o.open("beginStatement", f[1])
            o.print("goto", KEYWORD)
            o.spaces(1)
            self.node(k.take("label"))
            o.print(";")
            o.call("endStatement", i)
        self.node(k.take("commentGroup"))

    def k_labelStatement(self, n, f, k):
        if self.isSet(ONLY_BRANCH):
            return
        if self.isSet(FLAT):
            if f[2] != "1":
                return
        else:
            if f[3] != "1" or not f[0].startswith("copy:"):
                return
        self.out.tagLineIndent(0)
        self.node(k.take("label"))
        self.out.print(":")

    def k_anyLabelStatement(self, n, f, k):
        if f[1] == "1":
            return
        if k.is_("labelStatement"):      # absent when the block has no front leaf
            self.node(k.take())

    def k_label(self, n, f, k):
        if f[1] == "-":
            return
        spc, off = f[2].split(":", 1)
        self.out.call("tagLabel", f[1], NOCOLOR, spc, off)

    def k_blockCopy(self, n, f, k):
        self.node(k.take("anyLabelStatement"))
        self.child(k)

    def k_blockGoto(self, n, f, k):
        self.pushMod()
        self.setMod(NO_BRANCH)
        self.child(k)
        self.popMod()
        if f[3] == "1":
            self.out.tagLine()
            self.node(k.take("gotoStatement"))

    def k_gotoStatement(self, n, f, k):
        o = self.out
        i = o.open("beginStatement", f[1])
        t = int(f[3], 16)
        if t == F_BREAK:
            o.print("break", KEYWORD)
        elif t == F_CONTINUE:
            o.print("continue", KEYWORD)
        elif t == F_GOTO:
            o.print("goto", KEYWORD)
            o.spaces(1)
            self.node(k.take("label"))
        o.print(";")
        o.call("endStatement", i)

    def k_blockLs(self, n, f, k):
        o = self.out
        comps = self.comps(f)
        flow = [] if f[3] == "-" else [x == "1" for x in f[3].split(",")]
        if self.isSet(ONLY_BRANCH):
            self.child(k)
            return
        if not comps:
            return
        i1 = o.open("beginBlock", comps[0])
        if len(comps) == 1:
            self.child(k)
            o.call("endBlock", i1)
            return
        self.pushMod()
        if not self.isSet(FLAT):
            self.setMod(NO_BRANCH)
        for idx in range(len(comps) - 1):
            if idx > 0:
                i1 = o.open("beginBlock", comps[idx])
            if not flow[idx]:
                self.pushMod()
                self.setMod(NOFALLTHRU)
                self.child(k)
                self.popMod()
            else:
                self.child(k)
            o.call("endBlock", i1)
        self.popMod()
        i3 = o.open("beginBlock", comps[-1])
        self.child(k)
        o.call("endBlock", i3)

    def k_blockCondition(self, n, f, k):
        o = self.out
        comps = self.comps(f)
        if self.isSet(NO_BRANCH):
            i = o.open("beginBlock", comps[0])
            self.child(k)
            o.call("endBlock", i)
            return
        if self.isSet(ONLY_BRANCH) or self.isSet(COMMA_SEPARATE):
            i = o.open("openParen", "(")
            self.child(k)
            self.pushMod()
            self.unsetMod(ONLY_BRANCH)
            self.setMod(COMMA_SEPARATE)
            # emitOp on a fake RPN entry with visited 1 (printc.cc:2998)
            o.spaces(1, 0)
            o.call("tagOp", "&&" if f[3] == "BOOL_AND" else "||", NOCOLOR, "-")
            o.spaces(1, 0)
            i2 = o.open("openParen", "(")
            self.child(k)
            o.call("closeParen", ")", i2)
            self.popMod()
            o.call("closeParen", ")", i)

    def k_blockIf(self, n, f, k):
        o = self.out
        comps = self.comps(f)
        kind = f[3]
        pend = Pend(self.brace_ifelse)
        if self.isSet(PENDING_BRACE):
            o.call("setPendingPrint")
            o.pend = pend
        self.pushMod()
        self.unsetMod(NO_BRANCH | ONLY_BRANCH | PENDING_BRACE)
        self.pushMod()
        self.setMod(NO_BRANCH)
        self.child(k)
        self.popMod()
        self.node(k.take("commentBlockTree"))
        has = o.pend is pend
        o.call("hasPendingPrint", "=", 1 if has else 0)
        if has:
            o.call("cancelPendingPrint")
            o.pend = None
            o.spaces(1)
        else:
            o.tagLine()
        o.call("tagOp", "if", KEYWORD, f[1])
        o.spaces(1)
        self.pushMod()
        self.setMod(ONLY_BRANCH)
        self.child(k)
        self.popMod()
        if kind == "ifgoto":
            o.spaces(1)
            self.node(k.take("gotoStatement"))
        else:
            self.setMod(NO_BRANCH)
            i = o.openBraceIndent("{", self.brace_ifelse)
            i1 = o.open("beginBlock", comps[1])
            self.child(k)
            o.call("endBlock", i1)
            o.closeBraceIndent("}", i)
            if kind == "ifelse":
                o.tagLine()
                o.print("else", KEYWORD)
                if comps[2].split(":")[0] in IF_KINDS:
                    self.setMod(PENDING_BRACE)
                    i2 = o.open("beginBlock", comps[2])
                    self.child(k)
                    o.call("endBlock", i2)
                else:
                    i2 = o.openBraceIndent("{", self.brace_ifelse)
                    i3 = o.open("beginBlock", comps[2])
                    self.child(k)
                    o.call("endBlock", i3)
                    o.closeBraceIndent("}", i2)
            elif kind == "ifnoexit":
                i2 = o.open("beginBlock", comps[2])
                self.child(k)
                o.call("endBlock", i2)
        self.popMod()
        if pend.indent_id is not None:
            o.closeBraceIndent("}", pend.indent_id)

    def k_forLoop(self, n, f, k):
        o = self.out
        comps = self.comps(f)
        self.pushMod()
        self.unsetMod(BRANCH_MODS)
        self.node(k.take("anyLabelStatement"))
        self.node(k.take("commentBlockTree"))
        o.tagLine()
        o.call("tagOp", "for", KEYWORD, f[1])
        o.spaces(1)
        i1 = o.open("openParen", "(")
        self.pushMod()
        self.setMod(COMMA_SEPARATE)
        if f[3] != "-":
            i3 = o.open("beginStatement", f[3])
            self.node(k.take("expression"))
            o.call("endStatement", i3)
        o.print(";")
        o.spaces(1)
        self.child(k)
        o.print(";")
        o.spaces(1)
        i4 = o.open("beginStatement", f[4])
        self.node(k.take("expression"))
        o.call("endStatement", i4)
        self.popMod()
        o.call("closeParen", ")", i1)
        ind = o.openBraceIndent("{", self.brace_loop)
        self.setMod(NO_BRANCH)
        i2 = o.open("beginBlock", comps[1])
        self.child(k)
        o.call("endBlock", i2)
        o.closeBraceIndent("}", ind)
        self.popMod()

    def k_blockWhileDo(self, n, f, k):
        o = self.out
        comps = self.comps(f)
        if f[4] != "-":
            self.node(k.take("forLoop"))
            return
        self.pushMod()
        self.unsetMod(BRANCH_MODS)
        self.node(k.take("anyLabelStatement"))
        if f[5] == "1":
            o.tagLine()
            o.call("tagOp", "while", KEYWORD, f[1])
            i1 = o.open("openParen", "(")
            o.spaces(1)
            o.print("true", CONST)
            o.spaces(1)
            o.call("closeParen", ")", i1)
            ind = o.openBraceIndent("{", self.brace_loop)
            self.pushMod()
            self.setMod(NO_BRANCH)
            self.child(k)
            self.popMod()
            self.node(k.take("commentBlockTree"))
            o.tagLine()
            o.call("tagOp", "if", KEYWORD, f[1])
            o.spaces(1)
            self.pushMod()
            self.setMod(ONLY_BRANCH)
            self.child(k)
            self.popMod()
            o.spaces(1)
            self.node(k.take("gotoStatement"))
        else:
            self.node(k.take("commentBlockTree"))
            o.tagLine()
            o.call("tagOp", "while", KEYWORD, f[1])
            o.spaces(1)
            i1 = o.open("openParen", "(")
            self.pushMod()
            self.setMod(COMMA_SEPARATE)
            self.child(k)
            self.popMod()
            o.call("closeParen", ")", i1)
            ind = o.openBraceIndent("{", self.brace_loop)
        self.setMod(NO_BRANCH)
        i2 = o.open("beginBlock", comps[1])
        self.child(k)
        o.call("endBlock", i2)
        o.closeBraceIndent("}", ind)
        self.popMod()

    def k_blockDoWhile(self, n, f, k):
        o = self.out
        comps = self.comps(f)
        self.pushMod()
        self.unsetMod(BRANCH_MODS)
        self.node(k.take("anyLabelStatement"))
        o.tagLine()
        o.print("do", KEYWORD)
        i = o.openBraceIndent("{", self.brace_loop)
        self.pushMod()
        i2 = o.open("beginBlock", comps[0])
        self.setMod(NO_BRANCH)
        self.child(k)
        o.call("endBlock", i2)
        self.popMod()
        o.closeBraceIndent("}", i)
        o.spaces(1)
        o.call("tagOp", "while", KEYWORD, f[1])
        o.spaces(1)
        self.setMod(ONLY_BRANCH)
        self.child(k)
        o.print(";")
        self.popMod()

    def k_blockInfLoop(self, n, f, k):
        o = self.out
        comps = self.comps(f)
        self.pushMod()
        self.unsetMod(BRANCH_MODS)
        self.node(k.take("anyLabelStatement"))
        o.tagLine()
        o.print("do", KEYWORD)
        i = o.openBraceIndent("{", self.brace_loop)
        i1 = o.open("beginBlock", comps[0])
        self.child(k)
        o.call("endBlock", i1)
        o.closeBraceIndent("}", i)
        o.spaces(1)
        o.call("tagOp", "while", KEYWORD, f[1])
        i2 = o.open("openParen", "(")
        o.spaces(1)
        o.print("true", CONST)
        o.spaces(1)
        o.call("closeParen", ")", i2)
        o.print(";")
        self.popMod()

    def k_blockSwitch(self, n, f, k):
        o = self.out
        cases = [] if f[4] == "-" else [c.rsplit(":", 3) for c in f[4].split(",")]
        self.pushMod()
        self.unsetMod(BRANCH_MODS)
        self.pushMod()
        self.setMod(NO_BRANCH)
        self.child(k)
        self.popMod()
        o.tagLine()
        self.pushMod()
        self.setMod(ONLY_BRANCH | COMMA_SEPARATE)
        self.child(k)
        self.popMod()
        o.openBrace("{", self.brace_switch)
        for idx, (cblock, gtype, isexit, _isdef) in enumerate(cases):
            self.node(k.take("switchCase"))
            i = o.open("startIndent")
            if int(gtype, 16) != 0:
                o.tagLine()
                self.node(k.take("gotoStatement"))
            else:
                i2 = o.open("beginBlock", cblock)
                self.child(k)
                if isexit == "1" and idx != len(cases) - 1:
                    o.tagLine()
                    self.node(k.take("gotoStatement"))
                o.call("endBlock", i2)
            o.call("stopIndent", i)
        o.tagLine()
        o.print("}")
        self.popMod()

    def k_switchCase(self, n, f, k):
        o = self.out
        if f[2] == "1":
            o.tagLine()
            o.call("tagCaseLabel", "default", KEYWORD, f[1], f[3])
            o.print(":")
        else:
            for _ in range(int(f[3])):
                o.tagLine()
                o.print("case", KEYWORD)
                o.spaces(1)
                self.expr(k.take("expr"))
                o.print(":")

    # ---------------------------------------------------------- statements
    def k_statement(self, n, f, k):
        i = self.out.open("beginStatement", f[0])
        self.node(k.take("expression"))
        self.out.call("endStatement", i)
        if not self.isSet(COMMA_SEPARATE):
            self.out.print(";")

    def k_expression(self, n, f, k):
        self.rest(k)

    k_inplaceOp = k_constructor = k_bitFieldStore = k_bitFieldExpression = k_expression
    k_commentGroup = k_commentBlockTree = k_expression

    # opReturn's switch (printc.cc:777): these single halt kinds print as a function call
    HALTS = (0x200000, 0x400000, 0x800000, 0x1000000, 0x2000000)

    def k_opReturn(self, n, f, k):
        if int(f[2], 16) not in self.HALTS:
            self.out.call("tagOp", "return", KEYWORD, f[0])
            if int(f[1]) > 1:
                self.out.spaces(1)
        self.rest(k)

    def k_opBranch(self, n, f, k):
        if self.isSet(FLAT):
            self.out.call("tagOp", "goto", KEYWORD, f[0])
            self.out.spaces(1)
        self.rest(k)

    def k_opCbranch(self, n, f, k):
        o = self.out
        yesif = self.isSet(FLAT)
        yesparen = not self.isSet(COMMA_SEPARATE)
        if yesif:
            o.call("tagOp", "if", KEYWORD, f[0])
            o.spaces(1)
        i = o.open("openParen", "(") if yesparen else o.open("openGroup")
        self.expr(k.take("expr"))
        if yesparen:
            o.call("closeParen", ")", i)
        else:
            o.call("closeGroup", i)
        if yesif:
            o.spaces(1)
            o.print("goto", KEYWORD)
            o.spaces(1)

    def k_opBranchind(self, n, f, k):
        o = self.out
        o.call("tagOp", "switch", KEYWORD, f[0])
        i = o.open("openParen", "(")
        self.expr(k.take("expr"))
        o.call("closeParen", ")", i)
