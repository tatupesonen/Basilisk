/* Basilisk console extension: `bk cfg analyze`, `bk structure`, `bk dump
 * blocks`, `bk dump structure` (docs/features/decomp-oracle.md 4.6, 4.7).
 * The structurer is run twice: by a replica of CollapseStructure::collapseAll
 * and collapseInternal (blockaction.cc) that calls Ghidra's own rule methods
 * in Ghidra's order and logs them, and by Ghidra's unmodified collapseAll on
 * a second copy; the command fails unless both give the same result. */
#include "bk_cfg.hh"
#include "bk_commands.hh"

#include <set>

namespace bk {

/// One goto mark found after a step of the collapse.
struct GotoEvent {
  const FlowBlock *source;
  int4 slot;
  const FlowBlock *target;
  std::string cause;
};

/// One rule application (the `R` records).
struct RuleEvent {
  std::string rule;
  const FlowBlock *node;
};

/// What the replica logs.
struct CollapseLog {
  std::vector<GotoEvent> gotos;
  std::vector<RuleEvent> rules;
};

typedef std::set<std::pair<const FlowBlock *, int4> > GotoSet;

static void snapshotGotos(const BlockGraph &g, GotoSet &out)
{
  out.clear();
  for (int4 i = 0; i < g.getSize(); ++i) {
    const FlowBlock *bl = g.getBlock(i);
    for (int4 k = 0; k < bl->sizeOut(); ++k)
      if ((bl->outofthis[k].label & FlowBlock::f_goto_edge) != 0)
        out.insert(std::make_pair(bl, k));
  }
}

/// Scan the level in list order and out-slot order for goto labels not in `before`.
static void newGotos(const BlockGraph &g, const GotoSet &before, const char *cause, CollapseLog &log)
{
  for (int4 i = 0; i < g.getSize(); ++i) {
    const FlowBlock *bl = g.getBlock(i);
    for (int4 k = 0; k < bl->sizeOut(); ++k)
      if ((bl->outofthis[k].label & FlowBlock::f_goto_edge) != 0 &&
          before.find(std::make_pair(bl, k)) == before.end()) {
        GotoEvent e;
        e.source = bl;
        e.slot = k;
        e.target = bl->getOut(k);
        e.cause = cause;
        log.gotos.push_back(e);
      }
  }
}

#define BK_RULE(method, label)                         \
  if (cs.method(bl)) {                                 \
    RuleEvent ev; ev.rule = label; ev.node = bl;       \
    log.rules.push_back(ev);                           \
    change = true;                                     \
    continue;                                          \
  }

/// CollapseStructure::collapseInternal (blockaction.cc:1776), logging.
static int4 replicaInternal(CollapseStructure &cs, FlowBlock *targetbl, CollapseLog &log)
{
  BlockGraph &graph(cs.graph);
  int4 index;
  bool change, fullchange;
  int4 isolated_count;
  FlowBlock *bl;
  do {
    do {
      change = false;
      index = 0;
      isolated_count = 0;
      while (index < graph.getSize()) {
        if (targetbl == (FlowBlock *)0) {
          bl = graph.getBlock(index);
          index += 1;
        }
        else {
          bl = targetbl;
          change = true;
          targetbl = (FlowBlock *)0;
          index = graph.getSize();
        }
        if ((bl->sizeIn() == 0) && (bl->sizeOut() == 0)) {
          isolated_count += 1;
          continue;
        }
        BK_RULE(ruleBlockGoto, "blockgoto")
        BK_RULE(ruleBlockCat, "blockcat")
        BK_RULE(ruleBlockProperIf, "blockproperif")
        BK_RULE(ruleBlockIfElse, "blockifelse")
        BK_RULE(ruleBlockWhileDo, "blockwhiledo")
        BK_RULE(ruleBlockDoWhile, "blockdowhile")
        BK_RULE(ruleBlockInfLoop, "blockinfloop")
        if (bl->isSwitchOut()) {   // ruleBlockSwitch looks at nothing else
          GotoSet before;
          snapshotGotos(graph, before);
          if (cs.ruleBlockSwitch(bl)) {
            RuleEvent ev; ev.rule = "blockswitch"; ev.node = bl;
            log.rules.push_back(ev);
            if (bl->getParent() == &graph)   // applied without building: checkSwitchSkips marked gotos
              newGotos(graph, before, "switchskip", log);
            change = true;
            continue;
          }
        }
      }
    } while (change);
    fullchange = false;
    for (index = 0; index < graph.getSize(); ++index) {
      bl = graph.getBlock(index);
      if (cs.ruleBlockIfNoExit(bl)) {
        RuleEvent ev; ev.rule = "blockifnoexit"; ev.node = bl;
        log.rules.push_back(ev);
        fullchange = true;
        break;
      }
      if (!bl->isSwitchOut()) continue;   // ruleCaseFallthru looks at nothing else
      GotoSet before;
      snapshotGotos(graph, before);
      if (cs.ruleCaseFallthru(bl)) {
        RuleEvent ev; ev.rule = "casefallthru"; ev.node = bl;
        log.rules.push_back(ev);
        newGotos(graph, before, "fallthru", log);
        fullchange = true;
        break;
      }
    }
  } while (fullchange);
  return isolated_count;
}

/// CollapseStructure::collapseConditions (blockaction.cc:1862), logging.
static void replicaConditions(CollapseStructure &cs, CollapseLog &log)
{
  bool change;
  do {
    change = false;
    for (int4 i = 0; i < cs.graph.getSize(); ++i) {
      FlowBlock *bl = cs.graph.getBlock(i);
      if (cs.ruleBlockOr(bl)) {
        RuleEvent ev; ev.rule = "blockor"; ev.node = bl;
        log.rules.push_back(ev);
        change = true;
      }
    }
  } while (change);
}

/// CollapseStructure::collapseAll (blockaction.cc:1885), logging.
static void replicaCollapseAll(CollapseStructure &cs, CollapseLog &log)
{
  cs.finaltrace = false;
  cs.graph.clearVisitCount();
  cs.orderLoopBodies();
  replicaConditions(cs, log);
  int4 isolated_count = replicaInternal(cs, (FlowBlock *)0, log);
  while (isolated_count < cs.graph.getSize()) {
    GotoSet before;
    snapshotGotos(cs.graph, before);
    FlowBlock *targetbl = cs.selectGoto();
    newGotos(cs.graph, before, targetbl != (FlowBlock *)0 ? "selected" : "clipped", log);
    isolated_count = replicaInternal(cs, targetbl, log);
  }
}

/// ActionFinalStructure::apply without finalizePrinting (which needs ops and jump tables).
static void finishStructure(BlockGraph &g)
{
  g.orderBlocks();
  g.scopeBreak(-1, -1);
  g.markUnstructured();
  g.markLabelBumpUp(false);
}

/// The fake RETURN op of the `r` fact: no parent, no inputs, never in a function.
class FakeReturn {
  PcodeOp *op;
public:
  explicit FakeReturn(Architecture *glb) {
    op = new PcodeOp(0, SeqNum(Address(), 0));
    op->setOpcode(glb->inst[CPUI_RETURN]);
  }
  ~FakeReturn(void) { delete op; }
  PcodeOp *get(void) const { return op; }
};

/// Options of `bk structure`.
struct StructureOptions {
  bool asgiven, finish, trace;
  std::string xmlFile;
  StructureOptions(void) : asgiven(false), finish(false), trace(false) {}
};

/// One run of the structurer on a fresh copy of the fact graph.
struct StructureRun {
  BlockGraph graph;
  std::vector<int4> flips;
  CollapseLog log;
  int4 changes;
  bool failed;
  std::string error;
  std::string body;   // C, S and P records (and F), for comparing the two runs
  StructureRun(void) : changes(0), failed(false) {}
};

static void runStructure(BlockGraph &in, FactContext &ctx, const StructureOptions &opt, bool replica,
                         StructureRun &run)
{
  ctx.flipLog = &run.flips;
  try {
    if (!opt.asgiven) {
      std::vector<FlowBlock *> rootlist;
      run.graph.structureLoops(rootlist);
      run.graph.calcForwardDominator(rootlist);
    }
    CollapseStructure cs(run.graph);
    if (replica) replicaCollapseAll(cs, run.log);
    else cs.collapseAll();
    run.changes = cs.getChangeCount();
    if (opt.finish) finishStructure(run.graph);
  }
  catch (LowlevelError &err) {
    run.failed = true;
    run.error = err.explain;
  }
  ctx.flipLog = (std::vector<int4> *)0;
  if (run.failed) return;
  NodeNames names;
  names.build(run.graph, factLeafId, (const void *)0);
  std::ostringstream s;
  for (size_t i = 0; i < run.flips.size(); ++i) s << "F\tL" << run.flips[i] << '\n';
  s << "C\t" << run.changes << '\n';
  writeStructureNodes(s, run.graph, names);
  run.body = s.str();
}

static void writeHeader(std::ostream &o, const char *format, const std::string &error)
{
  o << "H\t" << format << "\t1\t" << (error.empty() ? "ok" : "error") << '\t'
    << (error.empty() ? std::string("-") : escape(error)) << '\n';
}

/// `bk structure <graph> <out> [bare|asgiven] [finish] [trace] [xml <file>]`
class BkStructure : public BkCommand {
public:
  virtual void execute(istream &s) {
    Architecture *glb = requireArch();
    std::string infile = nextWord(s), outfile = nextWord(s);
    if (infile.empty()) throw IfaceParseError("Missing input file");
    if (outfile.empty()) throw IfaceParseError("Missing output file");
    StructureOptions opt;
    for (std::string w = nextWord(s); !w.empty(); w = nextWord(s)) {
      if (w == "bare") opt.asgiven = false;
      else if (w == "asgiven") opt.asgiven = true;
      else if (w == "finish") opt.finish = true;
      else if (w == "trace") opt.trace = true;
      else if (w == "xml") {
        opt.xmlFile = nextWord(s);
        if (opt.xmlFile.empty()) throw IfaceParseError("Missing xml output file");
      }
      else throw IfaceParseError("Unknown bk structure option: " + w);
    }
    std::vector<NodeSpec> nodes;
    parseGraphFile(infile, nodes);
    FakeReturn fake(glb);
    FactContext ctx;
    ctx.fakeReturn = fake.get();
    BlockGraph in;
    buildFactGraph(nodes, in, ctx);
    // Both copies are taken before either run: negateCondition swaps the
    // fact blocks' own edges, which buildCopy reads.
    StructureRun traced, plain;
    traced.graph.buildCopy(in);
    plain.graph.buildCopy(in);
    runStructure(in, ctx, opt, true, traced);
    runStructure(in, ctx, opt, false, plain);

    std::string error;
    if (traced.failed || plain.failed) {
      if (traced.failed && plain.failed && traced.error == plain.error) error = traced.error;
      else error = "trace replica differs";
    }
    else if (traced.body != plain.body) error = "trace replica differs";

    AtomicFile out(outfile);
    std::ostream &o(out.stream());
    writeHeader(o, "bkstruct", error);
    if (error.empty()) {
      NodeNames names;
      names.build(traced.graph, factLeafId, (const void *)0);
      for (size_t i = 0; i < traced.log.gotos.size(); ++i) {
        const GotoEvent &e(traced.log.gotos[i]);
        o << "G\t" << names.of(e.source) << '\t' << e.slot << '\t' << names.of(e.target) << '\t' << e.cause << '\n';
      }
      o << traced.body;
      if (opt.trace)
        for (size_t i = 0; i < traced.log.rules.size(); ++i)
          o << "R\t" << i << '\t' << traced.log.rules[i].rule << '\t' << names.of(traced.log.rules[i].node) << '\n';
    }
    o << "T\n";
    out.commit();
    if (!opt.xmlFile.empty() && error.empty()) {
      AtomicFile x(opt.xmlFile);
      XmlEncode encoder(x.stream());
      traced.graph.encode(encoder);
      x.commit();
    }
  }
};

/// `bk cfg analyze <graph> <out>`
class BkCfgAnalyze : public BkCommand {
public:
  virtual void execute(istream &s) {
    Architecture *glb = requireArch();
    std::string infile = nextWord(s), outfile = nextWord(s);
    if (infile.empty()) throw IfaceParseError("Missing input file");
    if (outfile.empty()) throw IfaceParseError("Missing output file");
    std::vector<NodeSpec> nodes;
    parseGraphFile(infile, nodes);
    FakeReturn fake(glb);
    FactContext ctx;
    ctx.fakeReturn = fake.get();
    BlockGraph in;
    buildFactGraph(nodes, in, ctx);
    BlockGraph g;
    g.buildCopy(in);
    std::vector<FlowBlock *> rootlist;
    std::string error;
    CollapseStructure cs(g);
    try {
      g.structureLoops(rootlist);
      g.calcForwardDominator(rootlist);
      g.clearVisitCount();
      cs.orderLoopBodies();
    }
    catch (LowlevelError &err) {
      error = err.explain;
    }
    AtomicFile out(outfile);
    std::ostream &o(out.stream());
    writeHeader(o, "bkcfg", error);
    if (error.empty()) writeAnalysis(o, g, rootlist, cs);
    o << "T\n";
    out.commit();
  }
private:
  static std::string idOf(const FlowBlock *bl) {
    return (bl == (const FlowBlock *)0) ? std::string("-") : num(factId(bl));
  }
  static void writeAnalysis(std::ostream &o, const BlockGraph &g, const std::vector<FlowBlock *> &rootlist,
                            const CollapseStructure &cs) {
    o << "O\t";
    if (g.getSize() == 0) o << '-';
    for (int4 i = 0; i < g.getSize(); ++i) o << (i ? "," : "") << idOf(g.getBlock(i));
    o << '\n';
    std::vector<int4> depth;
    g.buildDomDepth(depth);
    for (int4 i = 0; i < g.getSize(); ++i) {
      const FlowBlock *bl = g.getBlock(i);
      o << "N\t" << idOf(bl) << '\t' << bl->getIndex() << '\t' << idOf(bl->getImmedDom()) << '\t'
        << bl->numdesc << '\t' << depth[i] << '\n';
    }
    for (int4 i = 0; i < g.getSize(); ++i) {
      const FlowBlock *bl = g.getBlock(i);
      o << "I\t" << idOf(bl) << '\t';
      if (bl->sizeIn() == 0) o << '-';
      for (int4 k = 0; k < bl->sizeIn(); ++k)
        o << (k ? "," : "") << idOf(bl->getIn(k)) << ':' << bl->getInRevIndex(k) << ':' << hx(bl->intothis[k].label);
      o << '\n';
    }
    o << "R\t";
    if (rootlist.empty()) o << '-';
    for (size_t i = 0; i < rootlist.size(); ++i) o << (i ? "," : "") << idOf(rootlist[i]);
    o << '\n';
    for (std::list<LoopBody>::const_iterator it = cs.loopbody.begin(); it != cs.loopbody.end(); ++it) {
      const LoopBody &lb(*it);
      o << "L\t" << idOf(lb.head) << '\t' << lb.depth << '\t' << idOf(lb.exitblock) << '\t' << lb.uniquecount << '\t';
      if (lb.tails.empty()) o << '-';
      for (size_t k = 0; k < lb.tails.size(); ++k) o << (k ? "," : "") << idOf(lb.tails[k]);
      o << '\t';
      if (lb.exitedges.empty()) o << '-';
      bool first = true;
      for (std::list<FloatingEdge>::const_iterator e = lb.exitedges.begin(); e != lb.exitedges.end(); ++e) {
        o << (first ? "" : ",") << idOf((*e).getTop()) << '>' << idOf((*e).getBottom());
        first = false;
      }
      o << '\t' << ((lb.immed_container == (LoopBody *)0) ? std::string("-") : idOf(lb.immed_container->head)) << '\n';
    }
  }
};

/// `bk dump blocks <file>`
class BkDumpBlocks : public BkCommand {
public:
  virtual void execute(istream &s) {
    Funcdata *fd = requireFunction();
    std::string file = nextWord(s);
    if (file.empty()) throw IfaceParseError("Missing output file");
    AtomicFile out(file);
    writeBasicGraph(out.stream(), fd->getBasicBlocks());
    out.commit();
  }
};

void writeStructureDump(std::ostream &o, Funcdata *fd)
{
  PositionMap pos;
  buildPositions(fd->getBasicBlocks(), pos);
  NodeNames names;
  names.build(fd->getStructure(), copiedPosition, &pos);
  writeHeader(o, "bkstruct", "");
  writeStructureNodes(o, fd->getStructure(), names);
  o << "T\n";
}

/// `bk dump structure <file>`
class BkDumpStructure : public BkCommand {
public:
  virtual void execute(istream &s) {
    Funcdata *fd = requireFunction();
    std::string file = nextWord(s);
    if (file.empty()) throw IfaceParseError("Missing output file");
    AtomicFile out(file);
    writeStructureDump(out.stream(), fd);
    out.commit();
  }
};

void registerCfgCommands(IfaceStatus *status)
{
  status->registerCom(new BkStructure(), "bk", "structure");
  status->registerCom(new BkCfgAnalyze(), "bk", "cfg", "analyze");
  status->registerCom(new BkDumpBlocks(), "bk", "dump", "blocks");
  status->registerCom(new BkDumpStructure(), "bk", "dump", "structure");
}

} // namespace bk
