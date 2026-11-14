/* Basilisk console extension: the command base class, the action-tree walk
 * shared by `bk list actions`, `bk break` and `bk dump state`, and the
 * registration functions of every source file. */
#ifndef BK_COMMANDS_HH
#define BK_COMMANDS_HH

#include "bk_io.hh"

namespace bk {

/// Every `bk` command shares the console's decompiler data (module "decompile").
class BkCommand : public IfaceDecompCommand {
protected:
  /// The architecture, or an IfaceExecutionError as Ghidra's commands give.
  Architecture *requireArch(void) const;
  /// The current function, or an IfaceExecutionError.
  Funcdata *requireFunction(void) const;
};

/// One line of `list action` for the current root: an action or a rule.
struct ActionEntry {
  int4 position;      ///< The number `list action` prints
  int4 depth;         ///< Nesting depth (0 for the root)
  Action *action;     ///< The action, or null for a rule
  Rule *rule;         ///< The rule, or null for an action
  ActionPool *pool;   ///< For a rule, the pool holding it
  std::string path;   ///< Full path, `universal:fullloop:…`
  std::string line;   ///< The line exactly as Action::print / ActionPool::print render it
};

/// Walk the current root in print order.
void collectActions(Action *root, std::vector<ActionEntry> &out);

void registerCapabilityCommands(IfaceStatus *status);
void registerCfgCommands(IfaceStatus *status);

} // namespace bk

#endif
