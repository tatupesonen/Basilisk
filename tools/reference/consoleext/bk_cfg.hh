/* Basilisk console extension: graph files, fact blocks and structure dumps
 * (docs/features/decomp-oracle.md 4.6, 4.7). Shared by bk_cfg.cc (the
 * commands) and bk_state.cc (the @blocks and @structure sections). */
#ifndef BK_CFG_HH
#define BK_CFG_HH

#include "bk_io.hh"
#include "blockaction.hh"

#include <map>

namespace bk {

/// One in-edge of a graph-file node.
struct EdgeSpec {
  int4 src;     ///< Source node id
  int4 slot;    ///< Out-slot of the source
  uint4 label;  ///< Edge label (FlowBlock::edge_flags)
};

/// One node of a graph file (`N`, `I`, `A` records).
struct NodeSpec {
  int4 index;
  uint4 flags;
  bool complex, switchOut, returns, negates;
  int4 idom;                    ///< -1 when `-`
  int4 numdesc;
  std::vector<EdgeSpec> in;
  std::string start, stop;      ///< `A` record fields, empty when absent
};

/// Largest graph a graph file may describe.
const int4 MAX_GRAPH_NODES = 100000;
/// Largest graph file read, in bytes.
const size_t MAX_GRAPH_BYTES = 64u * 1024u * 1024u;

/// Parse a graph file (format bkgraph 1); throws IfaceExecutionError with the
/// line number on any malformed or inconsistent input.
void parseGraphFile(const std::string &path, std::vector<NodeSpec> &nodes);

/// Shared state of one bk cfg / bk structure command: the fake RETURN op and
/// the flip log of the fact blocks.
struct FactContext {
  PcodeOp *fakeReturn;              ///< Built once per command; read only by compareFinalOrder
  std::vector<int4> *flipLog;       ///< Where negateCondition logs, or null
  FactContext(void) : fakeReturn((PcodeOp *)0), flipLog((std::vector<int4> *)0) {}
};

/// A plain block carrying the four facts of decomp-cfg.md 4.1.
class FactBlock : public FlowBlock {
public:
  int4 id;
  bool complex, returns, negates;
  FactContext *ctx;
  FactBlock(int4 i, const NodeSpec &spec, FactContext *c);
  virtual bool isComplex(void) const { return complex; }
  virtual PcodeOp *lastOp(void) const { return returns ? ctx->fakeReturn : (PcodeOp *)0; }
  virtual bool negateCondition(bool toporbottom);
};

/// Build the fact blocks of `nodes` into `graph` (in list order, with edges,
/// labels, indices, dominators and descendant counts as given).
void buildFactGraph(const std::vector<NodeSpec> &nodes, BlockGraph &graph, FactContext &ctx);

/// The input id of a node of a copy graph (a BlockCopy of a FactBlock).
int4 factId(const FlowBlock *copy);

/// Names of the nodes of a structured hierarchy: leaves `L<id>`, structured
/// nodes `S<n>` numbered in pre-order (top-level list order, components in order).
class NodeNames {
  std::map<const FlowBlock *, std::string> names;
public:
  /// Leaves get `L<leafId(copy)>`.
  void build(const BlockGraph &top, int4 (*leafId)(const FlowBlock *, const void *), const void *arg);
  /// The name of a node, `?` when it is not in the hierarchy.
  std::string of(const FlowBlock *bl) const;
  bool has(const FlowBlock *bl) const { return names.find(bl) != names.end(); }
};

/// Write `S` records (pre-order) and the `P` record of a hierarchy.
void writeStructureNodes(std::ostream &o, const BlockGraph &top, const NodeNames &names);

/// Write a function's basic blocks as graph-file records (`H` … `T`), with
/// the real facts (decomp-oracle.md 4.7).
void writeBasicGraph(std::ostream &o, const BlockGraph &bblocks);

/// Positions of a graph's blocks in its list.
typedef std::map<const FlowBlock *, int4> PositionMap;
void buildPositions(const BlockGraph &graph, PositionMap &out);

/// Leaf id of a BlockCopy: the position of the block it copies, from a
/// PositionMap passed as `arg` (-1 when unknown).
int4 copiedPosition(const FlowBlock *copy, const void *arg);

/// Leaf id of a BlockCopy of a FactBlock (`arg` unused).
int4 factLeafId(const FlowBlock *copy, const void *arg);

} // namespace bk

#endif
