/* Basilisk console extension: names of the objects of one function, as every
 * dump writes them (docs/features/decomp-oracle.md 4.3) — never host
 * pointers — and the canonical keys that replace the three kinds of host
 * pointer Ghidra stores in varnode offsets. */
#ifndef BK_IDS_HH
#define BK_IDS_HH

#include "bk_io.hh"

#include <map>

namespace bk {

/// Naming context for one dump of one function.
class DumpIds {
  Funcdata *fd;
  std::map<uintb, int4> spaceByPointer;                    ///< (uintb)(AddrSpace *) -> space index
  std::map<const FuncCallSpecs *, int4> callIndex;         ///< position in Funcdata::qlst
  std::map<const HighVariable *, int4> highIndex;          ///< numbered by smallest member create index
  std::map<const Datatype *, int4> typeIndex;              ///< first-reference order
  std::vector<const Datatype *> types;
  std::map<const Symbol *, int4> foreignIndex;             ///< symbols of other scopes, first-reference order
  std::vector<const Symbol *> foreign;
public:
  explicit DumpIds(Funcdata *f);

  /// `<space>:0x<offset>:0x<time>` (the address may be `-`).
  static std::string seq(const SeqNum &sq);
  /// The op's sequence number, or `-`.
  std::string op(const PcodeOp *op) const;
  /// `v<create index hex>`, or `-`.
  static std::string vn(const Varnode *vn);
  /// `b<index>`, or `-`.
  static std::string block(const FlowBlock *bl);

  /// Whether a varnode's offset is a host pointer (iop, fspec, LOAD/STORE space constant).
  bool isPointerValued(const Varnode *vn) const;
  /// The varnode's offset with pointers replaced by their key: op time,
  /// call-spec position, space index.
  uintb canonicalOffset(const Varnode *vn) const;
  /// The offset field of a `V` record: `op:<seq>`, `call:c<k>`, `space:<name>` or `0x…`.
  std::string offsetText(const Varnode *vn) const;
  /// `c<k>` for a call spec of this function, `-` otherwise.
  std::string call(const FuncCallSpecs *fc) const;
  /// `h<n>` or `-`.
  std::string high(const HighVariable *h) const;
  /// All highs in number order.
  std::vector<const HighVariable *> highs(void) const;
  /// `t<n>` (registering the type on first reference) or `-`.
  std::string type(const Datatype *dt);
  /// Types referenced so far, in number order (grows while iterating is not allowed).
  const std::vector<const Datatype *> &typeList(void) const { return types; }
  /// `s<symbolId hex>`, or `-`; symbols outside the local scope are remembered for `G` records.
  std::string symbol(const Symbol *sym);
  /// Symbols of other scopes referenced so far.
  const std::vector<const Symbol *> &foreignSymbols(void) const { return foreign; }

  /// Ghidra's two bank orders with canonical keys substituted.
  void locOrder(std::vector<Varnode *> &out) const;
  void defOrder(std::vector<Varnode *> &out) const;
};

/// A dump being written: sections of records, with their counts and the
/// total line count of the `END` record.
class SectionWriter {
  std::ostream &out;
  long lines;
  std::string name;
  std::vector<std::string> records;
public:
  explicit SectionWriter(std::ostream &o) : out(o), lines(0) {}
  void line(const std::string &text) { out << text << '\n'; lines += 1; }
  void begin(const std::string &section) { name = section; records.clear(); }
  void add(const std::string &record) { records.push_back(record); }
  void end(void);
  void finish(void) { out << "END\t" << lines << '\n'; }
};

/// Join items with commas, `-` when empty.
std::string joinList(const std::vector<std::string> &items);

} // namespace bk

#endif
