"""Throw-away prototype, part 1: build a tree from the printer log's `.tree` file.

The `.emit` file is never read here. Format of the input:
tools/reference/README.md, "The printer log".

A function's tree is a `Struct` node per structural event (entry to a PrintC
emit method: kind, the modifier word logged at entry, and the facts it read)
whose children are, in order, the nested structural nodes and the complete
expressions pushed while it was open. An expression is an `OpNode` (an
OpToken with exactly `stage` children) or an `Atom`. The expressions are
rebuilt from the pushes alone, with the arity of each token.
"""

# OpToken table of printc.cc:23-77 and printjava.cc:21:
# name: (stage, precedence, associative, type, spacing, bump)
TOKENS = {
    "hidden": (1, 70, False, "hiddenfunction", 0, 0),
    "scope": (2, 70, True, "binary", 0, 0),
    "object_member": (2, 66, True, "binary", 0, 0),
    "pointer_member": (2, 66, True, "binary", 0, 0),
    "subscript": (2, 66, False, "postsurround", 0, 0),
    "function_call": (2, 66, False, "postsurround", 0, 10),
    "bitwise_not": (1, 62, False, "unary_prefix", 0, 0),
    "boolean_not": (1, 62, False, "unary_prefix", 0, 0),
    "unary_minus": (1, 62, False, "unary_prefix", 0, 0),
    "unary_plus": (1, 62, False, "unary_prefix", 0, 0),
    "addressof": (1, 62, False, "unary_prefix", 0, 0),
    "dereference": (1, 62, False, "unary_prefix", 0, 0),
    "typecast": (2, 62, False, "presurround", 0, 0),
    "multiply": (2, 54, True, "binary", 1, 0),
    "divide": (2, 54, False, "binary", 1, 0),
    "modulo": (2, 54, False, "binary", 1, 0),
    "binary_plus": (2, 50, True, "binary", 1, 0),
    "binary_minus": (2, 50, False, "binary", 1, 0),
    "shift_left": (2, 46, False, "binary", 1, 0),
    "shift_right": (2, 46, False, "binary", 1, 0),
    "shift_sright": (2, 46, False, "binary", 1, 0),
    "less_than": (2, 42, False, "binary", 1, 0),
    "less_equal": (2, 42, False, "binary", 1, 0),
    "greater_than": (2, 42, False, "binary", 1, 0),
    "greater_equal": (2, 42, False, "binary", 1, 0),
    "equal": (2, 38, False, "binary", 1, 0),
    "not_equal": (2, 38, False, "binary", 1, 0),
    "bitwise_and": (2, 34, True, "binary", 1, 0),
    "bitwise_xor": (2, 30, True, "binary", 1, 0),
    "bitwise_or": (2, 26, True, "binary", 1, 0),
    "boolean_and": (2, 22, False, "binary", 1, 0),
    "boolean_xor": (2, 20, False, "binary", 1, 0),
    "boolean_or": (2, 18, False, "binary", 1, 0),
    "assignment": (2, 14, False, "binary", 1, 5),
    "comma": (2, 2, True, "binary", 0, 0),
    "new_op": (2, 62, False, "space", 1, 0),
    "multequal": (2, 14, False, "binary", 1, 5),
    "divequal": (2, 14, False, "binary", 1, 5),
    "remequal": (2, 14, False, "binary", 1, 5),
    "plusequal": (2, 14, False, "binary", 1, 5),
    "minusequal": (2, 14, False, "binary", 1, 5),
    "leftequal": (2, 14, False, "binary", 1, 5),
    "rightequal": (2, 14, False, "binary", 1, 5),
    "andequal": (2, 14, False, "binary", 1, 5),
    "orequal": (2, 14, False, "binary", 1, 5),
    "xorequal": (2, 14, False, "binary", 1, 5),
    "type_expr_space": (2, 10, False, "space", 1, 0),
    "type_expr_nospace": (2, 10, False, "space", 0, 0),
    "ptr_expr": (1, 62, False, "unary_prefix", 0, 0),
    "array_expr": (2, 66, False, "postsurround", 1, 0),
    "enum_cat": (2, 26, True, "binary", 0, 0),
    "instanceof": (2, 60, True, "binary", 1, 0),
}


class Struct:
    __slots__ = ("kind", "mods", "facts", "kids", "unwound")

    def __init__(self, kind, mods, facts):
        self.kind, self.mods, self.facts, self.kids, self.unwound = kind, mods, facts, [], False


class OpNode:
    __slots__ = ("tok", "print1", "print2", "op", "kids")

    def __init__(self, tok, print1, print2, op):
        self.tok, self.print1, self.print2, self.op, self.kids = tok, print1, print2, op, []


class Atom:
    __slots__ = ("tag", "hl", "text", "op", "second", "offset")

    def __init__(self, f):
        self.tag, self.hl, self.text, self.op, self.second, self.offset = f


class Function:
    def __init__(self, num, name):
        self.num, self.name, self.options, self.root, self.status = num, name, None, None, None
        self.pushes = {"op": 0, "atom": 0, "vn": 0, "state": 0, "struct": 0}


class TreeError(Exception):
    pass


def read_functions(path):
    """Yield (Function) for every F ... /F block of a .tree file."""
    fn = None
    with open(path, encoding="utf-8", errors="surrogateescape") as f:
        for line in f:
            r = line.rstrip("\n").split("\t")
            tag = r[0]
            if tag == "F":
                fn = Function(int(r[1]), r[2])
                fn.records = []
            elif tag == "/F":
                fn.status = r[2]
                yield fn
                fn = None
            elif fn is not None:
                fn.records.append(r)


def build(fn):
    """Build fn.root from fn.records."""
    stack = []          # open Struct nodes
    expr = []           # open OpNodes with their missing child count: [node, remaining]
    root = None
    for r in fn.records:
        tag = r[0]
        if tag == "O":
            fn.options = r[1:]
        elif tag == ">":
            if expr:
                raise TreeError(f"structural event {r[1]} inside an unfinished expression")
            node = Struct(r[1], int(r[2], 16), r[3:])
            fn.pushes["struct"] += 1
            if stack:
                stack[-1].kids.append(node)
            else:
                root = node
            stack.append(node)
        elif tag == "<":
            if expr:
                raise TreeError(f"end of {r[1]} inside an unfinished expression")
            node = stack.pop()
            if node.kind != r[1]:
                raise TreeError(f"unbalanced {node.kind} / {r[1]}")
            node.unwound = len(r) > 2
        elif tag == "P":
            fn.pushes["op"] += 1
            node = OpNode(r[1], r[2], r[3], r[4])
            if r[1] not in TOKENS:
                raise TreeError(f"unknown token {r[1]}")
            attach(stack, expr, node)
            expr.append([node, TOKENS[r[1]][0]])
        elif tag == "A":
            fn.pushes["atom"] += 1
            attach(stack, expr, Atom(r[1:7]))
            while expr:
                expr[-1][1] -= 1
                if expr[-1][1] == 0:
                    expr.pop()
                else:
                    break
        elif tag == "V":
            fn.pushes["vn"] += 1
        elif tag == "M":
            fn.pushes["state"] += 1
    if stack or expr:
        raise TreeError("log ends inside an open node")
    fn.root = root
    return root


def attach(stack, expr, node):
    if expr:
        expr[-1][0].kids.append(node)
    elif stack:
        stack[-1].kids.append(node)
    else:
        raise TreeError("push outside any structural event")
