# ediagcbor — FreeBSD base make (native libsbuf + privatecbor).
# Ubuntu/Linux: use GNUmakefile (gmake).

PROG=		ediagcbor
YACC?=		yacc
LEX?=		lex
PROVE?=		prove
STATIC?=	1

SRCS=		main.c ediagcbor.c diagnose.c parser.tab.c lex.yy.c
OBJS=		${SRCS:.c=.o}

CPPFLAGS+=	-I/usr/src/contrib/libcbor/src \
		-I/usr/src/lib/libcbor
CFLAGS+=	-Wall -Wextra -Wpedantic
LDADD+=		-lprivatecbor -lsbuf -ll -lm

.if ${STATIC} == 1
LDFLAGS+=	-static
.endif

all: ${PROG}

${PROG}: ${OBJS}
	${CC} ${CPPFLAGS} ${CFLAGS} ${LDFLAGS} -o ${PROG} ${OBJS} ${LDADD}

.c.o:
	${CC} ${CPPFLAGS} ${CFLAGS} -c $< -o $@

parser.tab.c parser.tab.h: parser.y
	${YACC} -b parser -d parser.y

lex.yy.c: lexer.l parser.tab.h
	${LEX} -o lex.yy.c lexer.l

EDN_LEGACY_FLAGS=--ellipsis --tag999 --c-comments --eol-slash-comments --legacy-numbers --indicator-suffix --raw-delim-max=16

test: ${PROG}
	@rm -f ${.CURDIR}/.edn-tally; \
	EDN_TALLY=${.CURDIR}/.edn-tally BINARY=./${PROG} \
	EDN_FLAGS='${EDN_LEGACY_FLAGS}' \
	${PROVE} tests; \
	st=$$?; \
	if [ -s ${.CURDIR}/.edn-tally ]; then \
		awk -F'\t' '{a+=$$1; t+=$$2; s+=$$3} \
		    END {printf "Totals: %d assertions, %d TODO (divergences), %d skipped\n", a, t, s}' \
		    ${.CURDIR}/.edn-tally; \
	fi; \
	rm -f ${.CURDIR}/.edn-tally; \
	exit $$st

test-directives: ${PROG}
	BINARY=./${PROG} EDN_FLAGS='${EDN_LEGACY_FLAGS}' \
	${PROVE} -v --directives tests

test-chairs: ${PROG}
	BINARY=./${PROG} EDN_FLAGS= ${PROVE} tests/basic.t

PREFIX?=	/usr/local

clean:
	rm -f ${PROG} ${OBJS} parser.tab.c parser.tab.h lex.yy.c .edn-tally

install: ${PROG} ediagcbor.1
	install -d ${DESTDIR}${PREFIX}/bin ${DESTDIR}${PREFIX}/man/man1
	install -m 755 ${PROG} ${DESTDIR}${PREFIX}/bin/
	install -m 644 ediagcbor.1 ${DESTDIR}${PREFIX}/man/man1/

.PHONY: all clean test test-directives test-chairs install
