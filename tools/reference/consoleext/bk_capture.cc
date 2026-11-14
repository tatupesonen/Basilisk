/* Basilisk console extension: `bk capture structure <prefix>` — one
 * decompilation of the current function, stopping at every start of a
 * `blockstructure` action, of the action after each, and of the action after
 * `finalstructure`, writing the structurer's inputs and outputs there
 * (docs/features/decomp-cfg.md 6.3 item 2). A console script cannot do this
 * with `bk break` and `continue`: how often the `mainloop` instance of
 * `blockstructure` runs is not known in advance, and `continue` on a
 * finished decompilation is an error.
 *
 * Files, for structuring run k = 0, 1, …:
 *   <prefix>.<k>.blocks.bkg       bk dump blocks at a blockstructure start whose structure is empty
 *   <prefix>.<k>.structure.bks    bk dump structure at the next action's start
 *   <prefix>.final.structure.bks, <prefix>.final.state   at the start of the action after finalstructure
 *   <prefix>.end.structure.bks, <prefix>.end.state       when the decompilation is complete
 */
#include "bk_cfg.hh"
#include "bk_commands.hh"

namespace bk {

/// The entry after `pos` that is not inside it (the action that starts once
/// the one at `pos` has finished), or -1.
static int4 successor(const std::vector<ActionEntry> &entries, int4 pos)
{
  for (size_t j = pos + 1; j < entries.size(); ++j)
    if (entries[j].depth <= entries[pos].depth) return (int4)j;
  return -1;
}

class BkCaptureStructure : public BkCommand {
  void writeBlocks(Funcdata *fd, const std::string &path) {
    AtomicFile out(path);
    writeBasicGraph(out.stream(), fd->getBasicBlocks());
    out.commit();
  }
  void writeStructure(Funcdata *fd, const std::string &path) {
    AtomicFile out(path);
    writeStructureDump(out.stream(), fd);
    out.commit();
  }
  void writeState(Funcdata *fd, const std::string &path) {
    AtomicFile out(path);
    writeStateDump(out.stream(), fd, status);
    out.commit();
  }
public:
  virtual void execute(istream &s) {
    Architecture *glb = requireArch();
    Funcdata *fd = requireFunction();
    std::string prefix = nextWord(s);
    if (prefix.empty()) throw IfaceParseError("Missing file prefix");
    if (fd->hasNoCode()) throw IfaceExecutionError("No code for " + fd->getName());
    Action *root = glb->allacts.getCurrent();
    std::vector<ActionEntry> entries;
    collectActions(root, entries);
    std::vector<int4> structure, after, final;
    for (size_t i = 0; i < entries.size(); ++i) {
      if (entries[i].action == (Action *)0) continue;
      const std::string &name(entries[i].action->getName());
      if (name == "blockstructure") {
        structure.push_back((int4)i);
        int4 next = successor(entries, (int4)i);
        if (next >= 0) after.push_back(next);
      }
      else if (name == "finalstructure") {
        int4 next = successor(entries, (int4)i);
        if (next >= 0) final.push_back(next);
      }
    }
    root->clearBreakPoints();
    std::vector<int4> watched;
    watched.insert(watched.end(), structure.begin(), structure.end());
    watched.insert(watched.end(), after.begin(), after.end());
    watched.insert(watched.end(), final.begin(), final.end());
    for (size_t i = 0; i < watched.size(); ++i) {
      Action *a = entries[watched[i]].action;
      if (a != (Action *)0) a->breakpoint |= Action::break_start;
    }
    if (fd->isProcStarted()) glb->clearAnalysis(fd);
    root->reset(*fd);
    int4 runs = 0, pending = -1;
    try {
      int4 res = root->perform(*fd);
      while (res < 0) {
        for (size_t i = 0; i < structure.size(); ++i)
          if (entries[structure[i]].action->getStatus() == Action::status_breakstarthit &&
              fd->getStructure().getSize() == 0) {
            pending = runs++;
            writeBlocks(fd, prefix + "." + num(pending) + ".blocks.bkg");
          }
        for (size_t i = 0; i < after.size(); ++i)
          if (entries[after[i]].action->getStatus() == Action::status_breakstarthit && pending >= 0) {
            writeStructure(fd, prefix + "." + num(pending) + ".structure.bks");
            pending = -1;
          }
        for (size_t i = 0; i < final.size(); ++i)
          if (entries[final[i]].action->getStatus() == Action::status_breakstarthit) {
            writeStructure(fd, prefix + ".final.structure.bks");
            writeState(fd, prefix + ".final.state");
          }
        res = root->perform(*fd);
      }
    }
    catch (...) {
      root->clearBreakPoints();
      throw;
    }
    root->clearBreakPoints();
    writeStructure(fd, prefix + ".end.structure.bks");
    writeState(fd, prefix + ".end.state");
    *status->optr << "bk capture structure: " << std::dec << runs << " structuring runs" << endl;
  }
};

void registerCaptureCommands(IfaceStatus *status)
{
  status->registerCom(new BkCaptureStructure(), "bk", "capture", "structure");
}

} // namespace bk
