# ediagcbor — GNU make for Linux and macOS.
# FreeBSD: use Makefile with base make (native <sys/sbuf.h> + -lsbuf).
#
# Ubuntu:  apt install build-essential flex bison libcbor-dev pkg-config
# macOS:   brew install libcbor flex bison pkg-config
#          then: gmake   (or: make -f GNUmakefile)
#
# Always uses vendored portable sbuf (compat/) — no -static (not useful here).

PROG      := ediagcbor
YACC     ?= bison -y
LEX      ?= flex
PROVE    ?= prove
CC       ?= cc

UNAME_S  := $(shell uname -s 2>/dev/null)

SRCS := main.c ediagcbor.c diagnose.c parser.tab.c lex.yy.c compat/sbuf.c
OBJS := $(SRCS:.c=.o)

CBOR_CFLAGS := $(shell pkg-config --cflags libcbor 2>/dev/null)
CBOR_LIBS   := $(shell pkg-config --libs libcbor 2>/dev/null)

ifeq ($(CBOR_LIBS),)
  ifeq ($(UNAME_S),Darwin)
    $(error libcbor not found — brew install libcbor pkg-config)
  else
    $(error libcbor not found — apt install libcbor-dev pkg-config)
  endif
endif

CPPFLAGS += -DEDIAGCBOR_USE_COMPAT_SBUF -I. $(CBOR_CFLAGS)
CFLAGS   += -Wall -Wextra -Wpedantic
LDLIBS   += $(CBOR_LIBS) -lm
# Linux flex usually needs -lfl; macOS/Homebrew flex often does not.
FL_LIBS  := $(shell pkg-config --libs libfl 2>/dev/null)
ifeq ($(FL_LIBS),)
  ifneq ($(UNAME_S),Darwin)
    FL_LIBS := -lfl
  endif
endif
LDLIBS   += $(FL_LIBS)

.PHONY: all clean test test-chairs

all: $(PROG)

$(PROG): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

compat/sbuf.o: compat/sbuf.c compat/sys/sbuf.h
	@mkdir -p compat
	$(CC) $(CPPFLAGS) $(CFLAGS) -c compat/sbuf.c -o $@

parser.tab.c parser.tab.h: parser.y
	$(YACC) -b parser -d parser.y

lex.yy.c: lexer.l parser.tab.h
	$(LEX) -o lex.yy.c lexer.l

main.o ediagcbor.o diagnose.o lex.yy.o parser.tab.o: ediagcbor.h

EDN_LEGACY_FLAGS := --ellipsis --tag999 --c-comments --eol-slash-comments --legacy-numbers --indicator-suffix --raw-delim-max=16

test: $(PROG)
	EDN_TALLY=$(CURDIR)/.edn-tally BINARY=./$(PROG) \
	EDN_FLAGS='$(EDN_LEGACY_FLAGS)' $(PROVE) tests; \
	st=$$?; rm -f $(CURDIR)/.edn-tally; exit $$st

test-chairs: $(PROG)
	BINARY=./$(PROG) EDN_FLAGS= $(PROVE) tests/basic.t

clean:
	rm -f $(PROG) $(OBJS) parser.tab.c parser.tab.h lex.yy.c .edn-tally
