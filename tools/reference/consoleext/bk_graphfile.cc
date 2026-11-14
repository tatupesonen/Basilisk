/* Basilisk console extension: graph files (format bkgraph 1,
 * docs/features/decomp-oracle.md 4.6) — reading them into fact blocks and
 * writing a function's basic blocks as one. */
#include "bk_cfg.hh"

namespace bk {

static void fail(int4 line, const std::string &msg)
{
  std::ostringstream s;
  if (line > 0) s << "graph file line " << line << ": " << msg;
  else s << "graph file: " << msg;
  throw IfaceExecutionError(s.str());
}

static void parseFacts(const std::string &f, NodeSpec &n, int4 line)
{
  n.complex = n.switchOut = n.returns = n.negates = false;
  if (f == "-") return;
  if (f.empty()) fail(line, "empty facts field");
  for (size_t i = 0; i < f.size(); ++i) {
    bool *slot;
    switch (f[i]) {
    case 'c': slot = &n.complex; break;
    case 's': slot = &n.switchOut; break;
    case 'r': slot = &n.returns; break;
    case 'n': slot = &n.negates; break;
    default: fail(line, std::string("unknown fact '") + f[i] + "'"); return;
    }
    if (*slot) fail(line, std::string("fact '") + f[i] + "' given twice");
    *slot = true;
  }
}

static int4 parseNodeRef(const std::string &s, int4 count, int4 line, const char *what)
{
  int4 v;
  if (!parseIndex(s, v)) fail(line, std::string("bad ") + what + ": " + s);
  if (v >= count) fail(line, std::string(what) + " out of range: " + s);
  return v;
}

void parseGraphFile(const std::string &path, std::vector<NodeSpec> &nodes)
{
  std::vector<std::string> lines = readLines(path, MAX_GRAPH_BYTES);
  nodes.clear();
  size_t ln = 0;
  if (lines.empty()) fail(1, "empty file");
  std::vector<std::string> h = splitTabs(lines[0]);
  if (h.size() != 4 || h[0] != "H" || h[1] != "bkgraph")
    fail(1, "expected H\tbkgraph\t1\t<count>");
  if (h[2] != "1") fail(1, "unsupported graph file version " + h[2]);
  int4 count;
  if (!parseIndex(h[3], count) || count > MAX_GRAPH_NODES) fail(1, "bad node count " + h[3]);
  ln = 1;
  nodes.resize(count);
  for (int4 i = 0; i < count; ++i) {
    NodeSpec &n(nodes[i]);
    // N record
    if (ln >= lines.size()) fail((int4)ln + 1, "file ends before node " + num(i));
    std::vector<std::string> f = splitTabs(lines[ln]);
    int4 lno = (int4)ln + 1;
    if (f.size() != 7 || f[0] != "N") fail(lno, "expected an N record with 7 fields");
    int4 id;
    if (!parseIndex(f[1], id) || id != i) fail(lno, "node ids must be 0..n-1 in order, got " + f[1]);
    if (!parseIndex(f[2], n.index)) fail(lno, "bad index " + f[2]);
    if (!parseHex32(f[3], n.flags)) fail(lno, "bad flags " + f[3]);
    parseFacts(f[4], n, lno);
    if (n.returns && n.switchOut) fail(lno, "a node cannot both end in RETURN and switch");
    n.idom = (f[5] == "-") ? -1 : parseNodeRef(f[5], count, lno, "dominator");
    if (!parseIndex(f[6], n.numdesc)) fail(lno, "bad descendant count " + f[6]);
    ++ln;
    // I record
    if (ln >= lines.size()) fail((int4)ln + 1, "file ends before the in-edges of node " + num(i));
    f = splitTabs(lines[ln]);
    lno = (int4)ln + 1;
    if (f.size() != 3 || f[0] != "I" || f[1] != num(i)) fail(lno, "expected the I record of node " + num(i));
    if (f[2] != "-") {
      std::vector<std::string> edges = splitChar(f[2], ',');
      if (edges.empty()) fail(lno, "empty in-edge list");
      for (size_t k = 0; k < edges.size(); ++k) {
        std::vector<std::string> p = splitChar(edges[k], ':');
        if (p.size() != 3) fail(lno, "bad edge " + edges[k]);
        EdgeSpec e;
        e.src = parseNodeRef(p[0], count, lno, "edge source");
        if (!parseIndex(p[1], e.slot) || e.slot >= MAX_GRAPH_NODES) fail(lno, "bad out-slot " + p[1]);
        if (!parseHex32(p[2], e.label)) fail(lno, "bad edge label " + p[2]);
        n.in.push_back(e);
      }
    }
    ++ln;
    // optional A record
    if (ln < lines.size()) {
      f = splitTabs(lines[ln]);
      if (!f.empty() && f[0] == "A") {
        lno = (int4)ln + 1;
        if (f.size() != 4 || f[1] != num(i)) fail(lno, "expected the A record of node " + num(i));
        n.start = f[2];
        n.stop = f[3];
        ++ln;
      }
    }
  }
  if (ln >= lines.size() || lines[ln] != "T") fail((int4)ln + 1, "expected T");
  ++ln;
  if (ln != lines.size()) fail((int4)ln + 1, "text after T");
  // Every out-slot of every node must be named by exactly one in-edge.
  std::vector<std::vector<int4> > slots(count);
  for (int4 i = 0; i < count; ++i)
    for (size_t k = 0; k < nodes[i].in.size(); ++k)
      slots[nodes[i].in[k].src].push_back(0);   // one slot per edge out of src
  for (int4 i = 0; i < count; ++i)
    for (size_t k = 0; k < nodes[i].in.size(); ++k) {
      const EdgeSpec &e(nodes[i].in[k]);
      std::vector<int4> &s(slots[e.src]);
      if (e.slot >= (int4)s.size())
        fail(0, "out-slot " + num(e.slot) + " of node " + num(e.src) + " is beyond its " +
             num((intb)s.size()) + " out-edges");
      s[e.slot] += 1;
    }
  for (int4 i = 0; i < count; ++i)
    for (size_t k = 0; k < slots[i].size(); ++k)
      if (slots[i][k] != 1)
        fail(0, "out-slot " + num((intb)k) + " of node " + num(i) + " is named by " + num(slots[i][k]) +
             " in-edges (each must be named exactly once)");
}

FactBlock::FactBlock(int4 i, const NodeSpec &spec, FactContext *c)
  : id(i), complex(spec.complex), returns(spec.returns), negates(spec.negates), ctx(c)
{
}

bool FactBlock::negateCondition(bool toporbottom)
{
  if (ctx->flipLog != (std::vector<int4> *)0)
    ctx->flipLog->push_back(id);
  // As FlowBlock::negateCondition(true) on the block itself; the copies that
  // the structurer works on hold their own edges.
  if (outofthis.size() >= 2) swapEdges();
  return negates;
}

void buildFactGraph(const std::vector<NodeSpec> &nodes, BlockGraph &graph, FactContext &ctx)
{
  std::vector<FactBlock *> blocks;
  for (size_t i = 0; i < nodes.size(); ++i) {
    FactBlock *b = new FactBlock((int4)i, nodes[i], &ctx);
    graph.addBlock(b);
    b->index = nodes[i].index;
    b->numdesc = nodes[i].numdesc;
    b->flags = nodes[i].flags | (nodes[i].switchOut ? (uint4)FlowBlock::f_switch_out : 0);
    blocks.push_back(b);
  }
  std::vector<int4> outs(nodes.size(), 0);
  for (size_t i = 0; i < nodes.size(); ++i)
    for (size_t k = 0; k < nodes[i].in.size(); ++k)
      outs[nodes[i].in[k].src] += 1;
  for (size_t i = 0; i < nodes.size(); ++i)
    blocks[i]->outofthis.resize(outs[i]);
  for (size_t i = 0; i < nodes.size(); ++i) {
    FactBlock *t = blocks[i];
    for (size_t k = 0; k < nodes[i].in.size(); ++k) {
      const EdgeSpec &e(nodes[i].in[k]);
      FactBlock *src = blocks[e.src];
      t->intothis.push_back(BlockEdge(src, e.label, e.slot));
      src->outofthis[e.slot] = BlockEdge(t, e.label, (int4)t->intothis.size() - 1);
    }
    if (nodes[i].idom >= 0)
      t->immed_dom = blocks[nodes[i].idom];
  }
}

int4 factId(const FlowBlock *copy)
{
  const FactBlock *f = dynamic_cast<const FactBlock *>(copy->subBlock(0));
  return (f == (const FactBlock *)0) ? -1 : f->id;
}

int4 factLeafId(const FlowBlock *copy, const void *arg)
{
  return factId(copy);
}

void buildPositions(const BlockGraph &graph, PositionMap &out)
{
  out.clear();
  for (int4 i = 0; i < graph.getSize(); ++i)
    out[graph.getBlock(i)] = i;
}

int4 copiedPosition(const FlowBlock *copy, const void *arg)
{
  const PositionMap *m = (const PositionMap *)arg;
  PositionMap::const_iterator it = m->find(copy->subBlock(0));
  return (it == m->end()) ? -1 : it->second;
}

void writeBasicGraph(std::ostream &o, const BlockGraph &bblocks)
{
  PositionMap pos;
  buildPositions(bblocks, pos);
  int4 n = bblocks.getSize();
  o << "H\tbkgraph\t1\t" << n << '\n';
  for (int4 i = 0; i < n; ++i) {
    const FlowBlock *bl = bblocks.getBlock(i);
    std::string facts;
    if (bl->isComplex()) facts += 'c';
    if (bl->isSwitchOut()) facts += 's';
    PcodeOp *last = bl->lastOp();
    if (last != (PcodeOp *)0 && last->code() == CPUI_RETURN) facts += 'r';
    facts += 'n';   // BlockBasic::negateCondition always reports a data-flow change
    o << "N\t" << i << '\t' << bl->getIndex() << '\t' << hx(bl->getFlags()) << '\t' << facts << '\t';
    if (bl->getImmedDom() == (FlowBlock *)0) o << '-';
    else o << pos[bl->getImmedDom()];
    o << '\t' << bl->numdesc << '\n';
    o << "I\t" << i << '\t';
    if (bl->sizeIn() == 0) o << '-';
    for (int4 k = 0; k < bl->sizeIn(); ++k) {
      if (k != 0) o << ',';
      o << pos[bl->getIn(k)] << ':' << bl->getInRevIndex(k) << ':' << hx(bl->intothis[k].label);
    }
    o << '\n';
    if (!bl->getStart().isInvalid())
      o << "A\t" << i << '\t' << addrText(bl->getStart()) << '\t' << addrText(bl->getStop()) << '\n';
  }
  o << "T\n";
}

} // namespace bk
