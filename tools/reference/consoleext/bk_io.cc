/* Basilisk console extension: text helpers (see bk_io.hh). */
#include "bk_io.hh"

#include <cstdio>
#include <iomanip>

namespace bk {

const char *const FORMAT_VERSIONS =
    "bkstate 1, bkgraph 1, bkcfg 1, bkstruct 1, pcoderec 1, bkactions 1";

std::string escape(const std::string &s)
{
  std::string res;
  res.reserve(s.size());
  for (size_t i = 0; i < s.size(); ++i) {
    char c = s[i];
    switch (c) {
    case '\\': res += "\\\\"; break;
    case '\t': res += "\\t"; break;
    case '\n': res += "\\n"; break;
    case '\r': res += "\\r"; break;
    case '\0': res += "\\0"; break;
    default: res += c; break;
    }
  }
  return res;
}

std::string unescape(const std::string &s)
{
  std::string res;
  res.reserve(s.size());
  for (size_t i = 0; i < s.size(); ++i) {
    if (s[i] != '\\' || i + 1 == s.size()) { res += s[i]; continue; }
    char c = s[++i];
    switch (c) {
    case '\\': res += '\\'; break;
    case 't': res += '\t'; break;
    case 'n': res += '\n'; break;
    case 'r': res += '\r'; break;
    case '0': res += '\0'; break;
    default: res += '\\'; res += c; break;
    }
  }
  return res;
}

std::string hx(uintb v)
{
  std::ostringstream s;
  s << "0x" << std::hex << std::nouppercase << v;
  return s.str();
}

std::string num(intb v)
{
  std::ostringstream s;
  s << std::dec << v;
  return s.str();
}

std::string addrText(const Address &addr)
{
  if (addr.isInvalid()) return "-";
  return addr.getSpace()->getName() + ":" + hx(addr.getOffset());
}

std::vector<std::string> splitTabs(const std::string &line)
{
  std::vector<std::string> res;
  size_t start = 0;
  for (;;) {
    size_t pos = line.find('\t', start);
    if (pos == std::string::npos) {
      res.push_back(line.substr(start));
      return res;
    }
    res.push_back(line.substr(start, pos - start));
    start = pos + 1;
  }
}

std::vector<std::string> splitChar(const std::string &field, char sep)
{
  std::vector<std::string> res;
  if (field.empty()) return res;
  size_t start = 0;
  for (;;) {
    size_t pos = field.find(sep, start);
    if (pos == std::string::npos) {
      res.push_back(field.substr(start));
      return res;
    }
    res.push_back(field.substr(start, pos - start));
    start = pos + 1;
  }
}

bool parseIndex(const std::string &s, int4 &out)
{
  if (s.empty() || s.size() > 9) return false;
  int4 v = 0;
  for (size_t i = 0; i < s.size(); ++i) {
    if (s[i] < '0' || s[i] > '9') return false;
    v = v * 10 + (s[i] - '0');
  }
  if (s.size() > 1 && s[0] == '0') return false;
  out = v;
  return true;
}

bool parseHex32(const std::string &s, uint4 &out)
{
  if (s.size() < 3 || s.size() > 10 || s[0] != '0' || s[1] != 'x') return false;
  uint4 v = 0;
  for (size_t i = 2; i < s.size(); ++i) {
    char c = s[i];
    uint4 d;
    if (c >= '0' && c <= '9') d = c - '0';
    else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
    else return false;
    v = (v << 4) | d;
  }
  out = v;
  return true;
}

std::string nextWord(std::istream &s)
{
  std::string w;
  s >> std::ws >> w;
  return w;
}

AtomicFile::AtomicFile(const std::string &p)
  : path(p), partPath(p + ".part"), committed(false)
{
  out.open(partPath.c_str(), std::ios::out | std::ios::trunc | std::ios::binary);
  if (!out)
    throw IfaceExecutionError("Unable to open output file: " + partPath);
}

AtomicFile::~AtomicFile(void)
{
  if (!committed) {
    if (out.is_open()) out.close();
    std::remove(partPath.c_str());
  }
}

void AtomicFile::commit(void)
{
  out.flush();
  bool ok = !out.fail();
  out.close();
  if (!ok || std::rename(partPath.c_str(), path.c_str()) != 0) {
    std::remove(partPath.c_str());
    committed = true;
    throw IfaceExecutionError("Unable to write output file: " + path);
  }
  committed = true;
}

std::vector<std::string> readLines(const std::string &path, size_t maxBytes)
{
  std::ifstream in(path.c_str(), std::ios::in | std::ios::binary);
  if (!in)
    throw IfaceExecutionError("Unable to open file: " + path);
  std::vector<std::string> lines;
  std::string line;
  size_t total = 0;
  while (std::getline(in, line)) {
    total += line.size() + 1;
    if (total > maxBytes)
      throw IfaceExecutionError("File too large: " + path);
    if (!line.empty() && line[line.size() - 1] == '\r')
      line.erase(line.size() - 1);
    lines.push_back(line);
  }
  return lines;
}

} // namespace bk
