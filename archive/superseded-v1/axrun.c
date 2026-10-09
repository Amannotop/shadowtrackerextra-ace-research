// axrun — CLI harness for shadowaxe (lab research ONLY)
#include "shadowaxe.h"
#include <stdio.h>
int main(int argc, char **argv) {
  if (argc < 3) { printf("usage: %s <binary> <out.json>\n", argv[0]); return 2; }
  int r = ax_analyze(argv[1], argv[2]);
  printf("ax_analyze -> %d (%s)\n", r, argv[2]);
  return r;
}
