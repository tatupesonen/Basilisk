/* Hashes log(k/n) for 1 <= k < n <= N, as DecisionNode::getScore computes
 * it (p = (double)count / total; log(p)), one line per n: "n hash".
 * With a second argument n, prints every k and the bits of log(k/n).
 * Compares the C libraries' log on exactly the inputs the SLEIGH
 * compiler's decision-tree scoring can give it.
 *   cc -O2 -ffp-contract=off logtable.c -lm -o logtable; ./logtable 16384 */
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint64_t bits(double d) { uint64_t u; memcpy(&u, &d, 8); return u; }

int main(int argc, char **argv) {
  int N = argc > 1 ? atoi(argv[1]) : 16384;
  if (argc > 2) {
    int n = atoi(argv[2]);
    for (int k = 1; k < n; ++k) {
      double p = ((double)k) / n;
      printf("%d %d %016llx\n", k, n, (unsigned long long)bits(log(p)));
    }
    return 0;
  }
  printf("log2 %016llx\n", (unsigned long long)bits(log(2.0)));
  for (int n = 2; n <= N; ++n) {
    uint64_t h = 1469598103934665603ULL;
    for (int k = 1; k < n; ++k) {
      double p = ((double)k) / n;
      h = (h ^ bits(log(p))) * 1099511628211ULL;
    }
    printf("%d %016llx\n", n, (unsigned long long)h);
  }
  return 0;
}
