/* Basilisk console extension (docs/features/decomp-oracle.md, ADR-042):
 * text helpers shared by every command — escaping, number and address
 * formatting, line splitting, and files written atomically.
 * Compiled outside Ghidra's Makefile with -fno-access-control; never part
 * of Ghidra's own consoles. */
#ifndef BK_IO_HH
#define BK_IO_HH

#include "ifacedecomp.hh"

#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace bk {

using namespace ghidra;

/// Format versions of every file the extension writes, printed by `bk version`.
extern const char *const FORMAT_VERSIONS;

/// Escape a text field: backslash, tab, LF, CR and NUL become \\ \t \n \r \0.
std::string escape(const std::string &s);

/// Lower-case hexadecimal with a 0x prefix (named so as not to hide std::hex).
std::string hx(uintb v);

/// Decimal (named so as not to hide std::dec).
std::string num(intb v);

/// `<space>:0x<offset>`, or `-` for an invalid address.
std::string addrText(const Address &addr);

/// Split a line at tabs.
std::vector<std::string> splitTabs(const std::string &line);

/// Split a field at a separator character; an empty field gives no items.
std::vector<std::string> splitChar(const std::string &field, char sep);

/// Parse a non-negative decimal integer that fits in int4; false when malformed.
bool parseIndex(const std::string &s, int4 &out);

/// Parse `0x…` lower- or upper-case hexadecimal into a uint4; false when malformed.
bool parseHex32(const std::string &s, uint4 &out);

/// Read the next whitespace-separated word of a command line; empty at the end.
std::string nextWord(std::istream &s);

/// A file written under `<path>.part` and renamed into place by commit(); an
/// uncommitted file is removed when the object goes away.
class AtomicFile {
  std::string path;
  std::string partPath;
  std::ofstream out;
  bool committed;
public:
  explicit AtomicFile(const std::string &p);
  ~AtomicFile(void);
  std::ostream &stream(void) { return out; }
  /// Flush, close and rename; throws IfaceExecutionError on failure.
  void commit(void);
};

/// Lines of a file, without their line breaks; throws IfaceExecutionError
/// when the file cannot be read or is larger than `maxBytes`.
std::vector<std::string> readLines(const std::string &path, size_t maxBytes);

} // namespace bk

#endif
