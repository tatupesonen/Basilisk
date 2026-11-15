// Confirms three behaviours of Ghidra's rangemap (rangemap.hh), with its own
// header, under the host's C++ library. Records carry a name and a subsort.
#include <iostream>
#include <string>
#include "rangemap.hh"
using namespace std;
using namespace ghidra;
struct Sub {
  int v;
  Sub(void) { v = 0; }
  Sub(bool b) { v = b ? 1000 : 0; }
  Sub(int x) { v = x; }
  bool operator<(const Sub &o) const { return v < o.v; }
};
struct Rec {
  typedef unsigned long long linetype;
  typedef Sub subsorttype;
  typedef pair<int,int> inittype;	// name, subsort
  int name; int sub; linetype first, last;
  Rec(const inittype &d, linetype f, linetype l) { name = d.first; sub = d.second; first = f; last = l; }
  linetype getFirst(void) const { return first; }
  linetype getLast(void) const { return last; }
  Sub getSubsort(void) const { return Sub(sub); }
};
typedef rangemap<Rec> Map;
static void dump(const char *tag, Map &m) {
  cout << tag << ":";
  int n = 0;
  for (Map::const_iterator it = m.begin(); it != m.end(); ++it) n++;
  cout << " fragments=" << n << '\n';
}
int main() {
  {	// 1. duplicate last fragment
    Map m;
    m.insert(make_pair(0,0),0,9);
    m.insert(make_pair(1,0),5,9);
    dump("dup (Basilisk: 4 fragments)", m);
    pair<Map::const_iterator,Map::const_iterator> r = m.find(7);
    cout << "  find(7):";
    for (; r.first != r.second; ++r.first) cout << ' ' << (*r.first).name;
    cout << '\n';
  }
  {	// 2. stretch: S=[0,9] sub 1, T=[5,9] sub 2, R=[0,4] sub 3; erase R
    Map m;
    m.insert(make_pair(0,1),0,9);
    m.insert(make_pair(1,2),5,9);
    list<Rec>::iterator r = m.insert(make_pair(2,3),0,4);
    m.erase(r);
    pair<Map::const_iterator,Map::const_iterator> f = m.find(2);
    cout << "stretch: find(2) records:";
    for (; f.first != f.second; ++f.first) cout << ' ' << (*f.first).name << "[" << (*f.first).first << "," << (*f.first).last << "]";
    cout << "  (Basilisk: 0 1 1; T=[5,9] seen at 2)\n";
  }
  {	// 3. dangling: stretch T, split it, erase T: fragments left that name T
    Map m;
    m.insert(make_pair(0,1),0,9);
    list<Rec>::iterator t = m.insert(make_pair(1,2),5,9);
    list<Rec>::iterator r = m.insert(make_pair(2,3),0,4);
    m.erase(r);		// T stretched to [0,9]
    m.insert(make_pair(3,0),2,3);	// split pieces at 1|2 and 3|4
    int before = 0; for (Map::const_iterator it = m.begin(); it != m.end(); ++it) before++;
    m.erase(t);		// walk starts at lower_bound(5): misses T's [0,1],[2,3],[4,4]
    int after = 0; for (Map::const_iterator it = m.begin(); it != m.end(); ++it) after++;
    int live = 0; for (list<Rec>::const_iterator it = m.begin_list(); it != m.end_list(); ++it) live++;
    cout << "dangling: fragments before erase " << before << ", after " << after << ", records " << live << '\n';
  }
  return 0;
}
