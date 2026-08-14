# Makefile for RQ3 benchmark programs
# Compiles all C benchmarks into benchmarks/bin/

CC      ?= gcc
CFLAGS  := -O2 -Wall -Wextra -std=gnu11
LDFLAGS := -lrt
BINDIR  := $(CURDIR)/bin

SRCS := $(wildcard *.c)
BINS := $(patsubst %.c,$(BINDIR)/%,$(SRCS))

.PHONY: all clean

all: $(BINDIR) $(BINS)

$(BINDIR):
	mkdir -p $(BINDIR)

$(BINDIR)/%: %.c | $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -rf $(BINDIR)
