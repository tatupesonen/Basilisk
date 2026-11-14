/* Basilisk console extension (docs/features/decomp-oracle.md 4.10):
 * registration, `bk version`, `bk list actions`, positional breakpoints. */
#include "bk_commands.hh"

#include <iomanip>

namespace bk {

Architecture *BkCommand::requireArch(void) const
{
  if (dcp->conf == (Architecture *)0)
    throw IfaceExecutionError("Decompile action not loaded");
  return dcp->conf;
}

Funcdata *BkCommand::requireFunction(void) const
{
  if (dcp->fd == (Funcdata *)0)
    throw IfaceExecutionError("No function selected");
  return dcp->fd;
}

static void walkActions(Action *act, int4 depth, const std::string &parent, int4 &num,
                        std::vector<ActionEntry> &out)
{
  ActionEntry entry;
  entry.position = num;
  entry.depth = depth;
  entry.action = act;
  entry.rule = (Rule *)0;
  entry.pool = (ActionPool *)0;
  entry.path = parent.empty() ? act->getName() : parent + ":" + act->getName();
  std::ostringstream s;
  num = act->Action::print(s, num, depth);   // the header line only, as every print starts
  entry.line = s.str();
  out.push_back(entry);
  std::string path = entry.path;
  ActionGroup *group = dynamic_cast<ActionGroup *>(act);
  if (group != (ActionGroup *)0) {
    for (size_t i = 0; i < group->list.size(); ++i)
      walkActions(group->list[i], depth + 1, path, num, out);
    return;
  }
  ActionPool *pool = dynamic_cast<ActionPool *>(act);
  if (pool != (ActionPool *)0) {
    for (size_t i = 0; i < pool->allrules.size(); ++i) {
      Rule *rl = pool->allrules[i];
      ActionEntry r;
      r.position = num;
      r.depth = depth + 1;
      r.action = (Action *)0;
      r.rule = rl;
      r.pool = pool;
      r.path = path + ":" + rl->getName();
      std::ostringstream rs;   // ActionPool::print's rule line
      rs << std::setw(4) << std::dec << num;
      rs << (char)(rl->isDisabled() ? 'D' : ' ');
      rs << (char)(((rl->getBreakPoint() & (Action::break_action | Action::tmpbreak_action)) != 0) ? 'A' : ' ');
      for (int4 k = 0; k < (depth + 1) * 5 + 2; ++k) rs << ' ';
      rs << rl->getName();
      r.line = rs.str();
      out.push_back(r);
      num += 1;
    }
  }
}

void collectActions(Action *root, std::vector<ActionEntry> &out)
{
  int4 num = 0;
  walkActions(root, 0, "", num, out);
}

/// `bk version`
class BkVersion : public BkCommand {
public:
  virtual void execute(istream &s) {
    *status->optr << "bk console extension (" << FORMAT_VERSIONS << ")" << endl;
  }
};

/// `bk list actions`: `list action`'s lines for the current root (blank
/// separator lines and the `<--` state marker left out), each followed by a
/// tab and the full path.
class BkListActions : public BkCommand {
public:
  virtual void execute(istream &s) {
    Architecture *glb = requireArch();
    std::vector<ActionEntry> entries;
    collectActions(glb->allacts.getCurrent(), entries);
    // Built in a fresh stream: the console's streams keep whatever base and
    // fill earlier commands left (std::hex and setfill are sticky).
    std::ostringstream o;
    o << "H\tbkactions\t1\t" << glb->allacts.getCurrentName() << '\t' << entries.size() << '\n';
    for (size_t i = 0; i < entries.size(); ++i)
      o << entries[i].line << '\t' << entries[i].path << '\n';
    o << "T\n";
    *status->fileoptr << o.str() << std::flush;
  }
};

/// `bk break start <n>`, `bk break action <n>`, `bk break clear`
class BkBreak : public BkCommand {
  uint4 type;   // 0 = clear
public:
  explicit BkBreak(uint4 tp) : type(tp) {}
  virtual void execute(istream &s) {
    Architecture *glb = requireArch();
    Action *root = glb->allacts.getCurrent();
    if (type == 0) {
      root->clearBreakPoints();
      return;
    }
    std::string word = nextWord(s);
    int4 pos;
    if (!parseIndex(word, pos))
      throw IfaceParseError("Expected a position from list action, got: " + word);
    std::vector<ActionEntry> entries;
    collectActions(root, entries);
    if (pos >= (int4)entries.size())
      throw IfaceExecutionError("No action or rule at position " + word);
    const ActionEntry &e(entries[pos]);
    if (e.rule != (Rule *)0) {
      // ActionPool::processOp checks only a rule's action breakpoint
      // (Rule::checkActionBreak); a start breakpoint on a rule never stops.
      if (type == Action::break_start)
        throw IfaceExecutionError("Position " + word + " is rule " + e.path +
                                  ": rules have no start breakpoint");
      e.rule->setBreak(type);
      return;
    }
    e.action->breakpoint |= type;
  }
};

void registerCapabilityCommands(IfaceStatus *status)
{
  status->registerCom(new BkVersion(), "bk", "version");
  status->registerCom(new BkListActions(), "bk", "list", "actions");
  status->registerCom(new BkBreak(Action::break_start), "bk", "break", "start");
  status->registerCom(new BkBreak(Action::break_action), "bk", "break", "action");
  status->registerCom(new BkBreak(0), "bk", "break", "clear");
}

/// The extension's command group, discovered like IfaceDecompCapability.
class BkCapability : public IfaceCapability {
  static BkCapability instance;
  BkCapability(void) { name = "bk"; }
public:
  virtual void registerCommands(IfaceStatus *status) {
    registerCapabilityCommands(status);
    registerCfgCommands(status);
  }
};

BkCapability BkCapability::instance;

} // namespace bk
