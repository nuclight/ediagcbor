%option noyywrap nodefault yylineno nounput noinput

%{
/*-
 * Lexer for CBOR EDN literals (draft-ietf-cbor-edn-literals, chairs post-27
 * defaults with opt-in legacy flags via edn_opts).
 *
 * Raw string literals use the start-condition technique from cbor-wg/edn
 * issue #99 / "Limiting backtick delimiters to maximum of 8": the opening
 * run of backquotes is counted (capped at edn_opts.raw_delim_max) and the
 * lexer switches to an exclusive RAW state that closes on an equal-width
 * run (alikerawdelim).
 */
#include <math.h>
#include <stdlib.h>
#include <string.h>

#include "ediagcbor.h"
#include "parser.tab.h"

enum prefix_mode {
	MODE_PLAIN,	/* unprefixed: '...' byte string or `...` text */
	MODE_APP	/* application-extension literal (h, b64, dt, ...) */
};

static struct edn_buf	g_raw;		/* accumulates literal content */
static enum prefix_mode	g_mode;		/* current string prefix mode */
static size_t		g_rdlen;	/* opening raw delimiter width */
static char		g_prefix[EDN_APP_PREFIX_MAX]; /* app-extension prefix */
static enum edn_ind	g_front_ind;	/* EI between prefix and body */

static void	raw_reset(enum prefix_mode);
static int	finish_quoted(enum edn_strtype, bool (*)(const char *,
		    size_t, struct edn_buf *, const char **));
static int	finish_raw(void);
static int	lex_error(const char *);
static int	lex_integer(const char *);
static int	lex_float(const char *);
static int	lex_simple(const char *);
static int	set_app_prefix(const char *, size_t);
%}

%x DQ SQ RAW BLOCKCOMMENT SLASHCOMMENT

WS		[ \t\r\n,]+
DIGIT		[0-9]
HEXFLOAT	[+-]?0[xX]([0-9a-fA-F]+(\.[0-9a-fA-F]*)?|\.[0-9a-fA-F]+)[pP][+-]?{DIGIT}+
HEXINT		[+-]?0[xX][0-9a-fA-F]+
OCTINT		[+-]?0[oO][0-7]+
BININT		[+-]?0[bB][01]+
DECINT		[+-]?{DIGIT}+
DECFLOAT	[+-]?({DIGIT}+\.{DIGIT}*|\.{DIGIT}+)([eE][+-]?{DIGIT}+)?
DECEXP		[+-]?{DIGIT}+[eE][+-]?{DIGIT}+
APREFIX		[A-Za-z][A-Za-z0-9_-]*

%%

{WS}			;	/* blank space and optional commas */
"#"[^\n]*		;	/* end-of-line comment (# always allowed) */
"//"[^\n]*		{
				if (!edn_opts_get()->allow_eol_slash)
					return (lex_error("// comments disabled"));
			}
"/*"			{
				if (!edn_opts_get()->allow_c_comments)
					return (lex_error("/* */ comments disabled"));
				BEGIN(BLOCKCOMMENT);
			}
"/"			{
				if (!edn_opts_get()->allow_c_comments)
					return (lex_error("/ / comments disabled"));
				BEGIN(SLASHCOMMENT);
			}

<BLOCKCOMMENT>"*/"	BEGIN(INITIAL);
<BLOCKCOMMENT>.|\n	;
<BLOCKCOMMENT><<EOF>>	return (lex_error("unterminated /* */ comment"));

<SLASHCOMMENT>"/"	BEGIN(INITIAL);
<SLASHCOMMENT>.|\n	;
<SLASHCOMMENT><<EOF>>	return (lex_error("unterminated / / comment"));

"\"\"_"			return (INDEF_TSTR_EMPTY);
"''_"			return (INDEF_BSTR_EMPTY);

"<<"			return (SEQOPEN);
">>"			return (SEQCLOSE);

"true"			return (KTRUE);
"false"			return (KFALSE);
"null"			return (KNULL);
"undefined"		return (KUNDEF);

"Infinity"		{ yylval.num = edn_num_double(INFINITY);  return (NUMBER); }
"-Infinity"		{ yylval.num = edn_num_double(-INFINITY); return (NUMBER); }
"NaN"			{ yylval.num = edn_num_double(NAN);	  return (NUMBER); }

"simple("[ \t\r\n]*{DIGIT}+[ \t\r\n]*")"	return (lex_simple(yytext));

{HEXFLOAT}		{
				if (!edn_opts_get()->allow_legacy_numbers)
					return (lex_error("non-JSON number form disabled"));
				return (lex_float(yytext));
			}
{HEXINT}		{
				if (!edn_opts_get()->allow_legacy_numbers)
					return (lex_error("non-JSON number form disabled"));
				return (lex_integer(yytext));
			}
{OCTINT}		{
				if (!edn_opts_get()->allow_legacy_numbers)
					return (lex_error("non-JSON number form disabled"));
				return (lex_integer(yytext));
			}
{BININT}		{
				if (!edn_opts_get()->allow_legacy_numbers)
					return (lex_error("non-JSON number form disabled"));
				return (lex_integer(yytext));
			}
{DECFLOAT}		{
				if (!edn_opts_get()->allow_legacy_numbers &&
				    yytext[0] == '+')
					return (lex_error("leading + in number disabled"));
				return (lex_float(yytext));
			}
{DECEXP}		{
				if (!edn_opts_get()->allow_legacy_numbers &&
				    yytext[0] == '+')
					return (lex_error("leading + in number disabled"));
				return (lex_float(yytext));
			}
{DECINT}		{
				if (!edn_opts_get()->allow_legacy_numbers &&
				    yytext[0] == '+')
					return (lex_error("leading + in number disabled"));
				return (lex_integer(yytext));
			}

"'"			{ g_front_ind = EDN_IND_NONE; raw_reset(MODE_PLAIN); BEGIN(SQ); }
"\""			{ g_front_ind = EDN_IND_NONE; raw_reset(MODE_PLAIN); BEGIN(DQ); }

	/*
	 * Application-extension string: app-prefix [_ei] '...'
	 * (h / b64 / dt / … — same path; decoding is in edn_make_app).
	 */
{APREFIX}"'"		{
				size_t plen;

				plen = (size_t)yyleng - 1;
				if (set_app_prefix(yytext, plen) != 0)
					return (LEXERR);
				raw_reset(MODE_APP);
				BEGIN(SQ);
			}

	/* Application-extension sequence: app-prefix [_ei] << ... >>. */
{APREFIX}"<<"		{
				size_t plen;

				plen = (size_t)yyleng - 2;
				if (set_app_prefix(yytext, plen) != 0)
					return (LEXERR);
				yylval.app.prefix = strdup(g_prefix);
				if (yylval.app.prefix == NULL)
					return (lex_error("out of memory"));
				yylval.app.front_ind = g_front_ind;
				edn_buf_init(&yylval.app.buf);
				return (APPSEQOPEN);
			}

	/* Raw text, or app-prefix [_ei] rawstring (h`…`, r_b`…`, …). */
{APREFIX}?`+		{
				size_t plen;

				plen = 0;
				while (plen < (size_t)yyleng &&
				    yytext[plen] != '`')
					plen++;
				g_front_ind = EDN_IND_NONE;
				if (plen == 0) {
					raw_reset(MODE_PLAIN);
				} else {
					if (set_app_prefix(yytext, plen) != 0)
						return (LEXERR);
					raw_reset(MODE_APP);
				}
				g_rdlen = yyleng - plen;
				if (g_rdlen > edn_opts_get()->raw_delim_max)
					return (lex_error("raw string "
					    "delimiter too long"));
				BEGIN(RAW);
			}

"..."			return (ELLIPSIS);

"["			return ('[');
"]"			return (']');
"{"			return ('{');
"}"			return ('}');
"("			return ('(');
")"			return (')');
":"			return (':');

_[A-Za-z0-9_]*		{ yylval.indef = (int)edn_spec_parse(yytext);
			  return (SPEC); }

.			return (lex_error("unexpected character"));

	/* Double-quoted text string. */
<DQ>\\(.|\n)		edn_buf_append(&g_raw, yytext, yyleng);
<DQ>[^"\\]+		edn_buf_append(&g_raw, yytext, yyleng);
<DQ>"\""		{ BEGIN(INITIAL); return (finish_quoted(EDN_TEXT, edn_decode_dq)); }
<DQ>.			edn_buf_append(&g_raw, yytext, yyleng);
<DQ><<EOF>>		return (lex_error("unterminated double-quoted string"));

	/* Single-quoted byte string or app-extension body. */
<SQ>\\(.|\n)		edn_buf_append(&g_raw, yytext, yyleng);
<SQ>[^'\\]+		edn_buf_append(&g_raw, yytext, yyleng);
<SQ>"'"			{ BEGIN(INITIAL); return (finish_quoted(EDN_BYTES, NULL)); }
<SQ>.			edn_buf_append(&g_raw, yytext, yyleng);
<SQ><<EOF>>		return (lex_error("unterminated single-quoted string"));

	/* Raw string; g_rdlen backquotes opened it (alikerawdelim: ==). */
<RAW>\r			;	/* carriage returns are ignored */
<RAW>\n			edn_buf_putc(&g_raw, '\n');
<RAW>`+			{
				if ((size_t)yyleng < g_rdlen) {
					edn_buf_append(&g_raw, yytext, yyleng);
				} else if ((size_t)yyleng == g_rdlen) {
					BEGIN(INITIAL);
					return (finish_raw());
				} else {
					edn_buf_append(&g_raw, yytext, yyleng);
				}
			}
<RAW>[^`\r\n]+		edn_buf_append(&g_raw, yytext, yyleng);
<RAW><<EOF>>		return (lex_error("unterminated raw string"));

%%

/*
 * App-string bodies that define their own inner grammar keep the quoted
 * text verbatim (h'' / b64'' comments & whitespace; r'' raw-CBOR tokens).
 * Other app prefixes get single-quote unescaping first.
 */
static bool
app_body_verbatim(const char *p)
{

	return (strcmp(p, "h") == 0 || strcmp(p, "b64") == 0 ||
	    strcmp(p, "r") == 0 || strcmp(p, "r_b") == 0);
}

/*
 * Record an app-extension prefix, splitting a trailing standard EI into
 * g_front_ind (h_2... → prefix "h", front _2).  r_b does not split (_b is
 * not a standard EI).  Returns 0 on success, -1 after lex_error().
 */
static int
set_app_prefix(const char *text, size_t plen)
{
	char tmp[EDN_APP_PREFIX_MAX];
	char base[EDN_APP_PREFIX_MAX];
	enum edn_ind ind;

	if (plen >= sizeof(tmp))
		return (lex_error("application-extension prefix too long"), -1);
	memcpy(tmp, text, plen);
	tmp[plen] = '\0';
	g_front_ind = EDN_IND_NONE;
	if (edn_split_prefix_indicator(tmp, base, sizeof(base), &ind)) {
		if (strlen(base) >= sizeof(g_prefix))
			return (lex_error("application-extension prefix too "
			    "long"), -1);
		memcpy(g_prefix, base, strlen(base) + 1);
		g_front_ind = ind;
	} else {
		memcpy(g_prefix, tmp, plen + 1);
	}
	return (0);
}

static void
raw_reset(enum prefix_mode mode)
{

	edn_buf_free(&g_raw);
	edn_buf_init(&g_raw);
	g_mode = mode;
	g_rdlen = 0;
}

static int
lex_error(const char *msg)
{

	parser_ctx_set_error(parser_get_ctx(), msg);
	return (LEXERR);
}

static int
finish_quoted(enum edn_strtype type,
    bool (*dq)(const char *, size_t, struct edn_buf *, const char **))
{
	bool (*dec)(const char *, size_t, struct edn_buf *, const char **);
	const char *err;

	if (g_mode == MODE_APP) {
		err = NULL;
		edn_buf_init(&yylval.app.buf);
		if (app_body_verbatim(g_prefix)) {
			if (!edn_buf_append(&yylval.app.buf,
			    edn_buf_data(&g_raw), edn_buf_len(&g_raw))) {
				edn_buf_free(&yylval.app.buf);
				return (lex_error("out of memory"));
			}
		} else if (!edn_decode_sq((const char *)edn_buf_data(&g_raw),
		    edn_buf_len(&g_raw), &yylval.app.buf, &err)) {
			edn_buf_free(&yylval.app.buf);
			return (lex_error(err));
		}
		yylval.app.prefix = strdup(g_prefix);
		if (yylval.app.prefix == NULL) {
			edn_buf_free(&yylval.app.buf);
			return (lex_error("out of memory"));
		}
		yylval.app.front_ind = g_front_ind;
		g_front_ind = EDN_IND_NONE;
		return (APPSTR);
	}
	/* Unprefixed "..." or '...'. */
	dec = (type == EDN_TEXT) ? dq : edn_decode_sq;
	err = NULL;
	edn_buf_init(&yylval.str.buf);
	yylval.str.type = type;
	yylval.str.front_ind = g_front_ind;
	g_front_ind = EDN_IND_NONE;
	if (!dec((const char *)edn_buf_data(&g_raw), edn_buf_len(&g_raw),
	    &yylval.str.buf, &err)) {
		edn_buf_free(&yylval.str.buf);
		return (lex_error(err));
	}
	return (type == EDN_TEXT ? TSTR : BSTR);
}

static int
finish_raw(void)
{

	if (g_mode == MODE_PLAIN) {
		yylval.str.buf = g_raw;
		yylval.str.type = EDN_TEXT;
		yylval.str.front_ind = g_front_ind;
		g_front_ind = EDN_IND_NONE;
		edn_buf_init(&g_raw);
		return (TSTR);
	}
	/* MODE_APP: h`…`, b64`…`, r`…`, dt`…`, … */
	yylval.app.buf = g_raw;
	edn_buf_init(&g_raw);
	yylval.app.prefix = strdup(g_prefix);
	if (yylval.app.prefix == NULL) {
		edn_buf_free(&yylval.app.buf);
		return (lex_error("out of memory"));
	}
	yylval.app.front_ind = g_front_ind;
	g_front_ind = EDN_IND_NONE;
	return (APPSTR);
}

static int
lex_integer(const char *text)
{
	const char *p;
	const char *err;
	bool neg;
	int base;

	p = text;
	neg = false;
	if (*p == '+' || *p == '-') {
		neg = (*p == '-');
		p++;
	}
	base = 10;
	if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
		base = 16;
		p += 2;
	} else if (p[0] == '0' && (p[1] == 'o' || p[1] == 'O')) {
		base = 8;
		p += 2;
	} else if (p[0] == '0' && (p[1] == 'b' || p[1] == 'B')) {
		base = 2;
		p += 2;
	}
	err = NULL;
	yylval.num = edn_num_int(p, base, neg, &err);
	if (yylval.num.item == NULL)
		return (lex_error(err));
	return (NUMBER);
}

static int
lex_float(const char *text)
{
	double d;

	d = strtod(text, NULL);
	yylval.num = edn_num_double(d);
	if (yylval.num.item == NULL)
		return (lex_error("out of memory"));
	return (NUMBER);
}

static int
lex_simple(const char *text)
{
	const char *p;
	unsigned long v;

	p = text;
	while (*p != '\0' && (*p < '0' || *p > '9'))
		p++;
	v = strtoul(p, NULL, 10);
	if (v > 255 || (v >= 24 && v <= 31))
		return (lex_error("simple value out of range"));
	yylval.simple = v;
	return (SIMPLEVAL);
}
