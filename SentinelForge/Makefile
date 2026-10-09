# SentinelForge build
CC = clang
CFLAGS = -O2 -Wall -Wextra -Wno-unused-parameter -Iinclude -std=c11
SRC = src/ax_common.c src/ax_macho.c src/ax_symbols.c src/ax_strings.c \
      src/ax_xref.c src/ax_callgraph.c src/ax_imports.c src/ax_codesign.c \
      src/ax_receipt.c src/ax_environ.c src/ax_correlate.c src/ax_diff.c \
      src/ax_iterate.c src/ax_context.c src/ax_report.c src/main.c
OBJ = $(SRC:.c=.o)
BIN = sentinelforge

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) -lm

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

test: $(BIN)
	./tests/run_tests.sh

clean:
	rm -f $(OBJ) $(BIN)

.PHONY: all test clean
