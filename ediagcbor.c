/*-
 * edn2cbor: helpers for converting CBOR EDN literals to binary CBOR.
 *
 * See ediagcbor.h for an overview.  This file holds the dynamic byte
 * buffer, the string-literal decoders (double-quoted, single-quoted, raw,
 * h, b64), numeric construction (including preferred/shortest CBOR
 * serialization choices), and the container constructors.
 */

#include "ediagcbor.h"

#include <sys/socket.h>

#include <netinet/in.h>

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

/* Feature flags (chairs post-27 defaults; see edn_opts in ediagcbor.h). ---- */

static struct edn_opts g_opts;

void
edn_opts_init(struct edn_opts *o)
{

	memset(o, 0, sizeof(*o));
	o->raw_delim_max = EDN_RAW_DEFAULT_DELIM;
}

void
edn_opts_set(const struct edn_opts *o)
{

	g_opts = *o;
	if (g_opts.raw_delim_max == 0)
		g_opts.raw_delim_max = EDN_RAW_DEFAULT_DELIM;
	if (g_opts.raw_delim_max > EDN_RAW_MAX_DELIM)
		g_opts.raw_delim_max = EDN_RAW_MAX_DELIM;
}

const struct edn_opts *
edn_opts_get(void)
{

	return (&g_opts);
}

bool
edn_split_prefix_indicator(const char *prefix, char *base, size_t baselen,
    enum edn_ind *ind)
{
	const char *us;
	enum edn_ind ei;
	size_t blen;

	*ind = EDN_IND_NONE;
	if (prefix == NULL || base == NULL || baselen == 0)
		return (false);
	us = strrchr(prefix, '_');
	if (us == NULL || us == prefix)
		return (false);
	ei = edn_spec_parse(us);
	if (ei == EDN_IND_NONE || ei == EDN_IND_INVALID)
		return (false);
	blen = (size_t)(us - prefix);
	if (blen == 0 || blen >= baselen)
		return (false);
	memcpy(base, prefix, blen);
	base[blen] = '\0';
	*ind = ei;
	return (true);
}

/* Buffer growth helpers (backed by sbuf(9)). ------------------------------ */

void
edn_buf_init(struct edn_buf *b)
{

	b->sb = NULL;
	b->finished = false;
}

static bool
edn_buf_ready(struct edn_buf *b)
{

	if (b->finished)
		return (false);
	if (b->sb == NULL) {
		b->sb = sbuf_new_auto();
		if (b->sb == NULL)
			return (false);
	}
	return (true);
}

bool
edn_buf_putc(struct edn_buf *b, unsigned char c)
{

	if (!edn_buf_ready(b))
		return (false);
	return (sbuf_putc(b->sb, c) == 0);
}

bool
edn_buf_append(struct edn_buf *b, const void *p, size_t n)
{

	if (n == 0)
		return (true);
	if (!edn_buf_ready(b))
		return (false);
	return (sbuf_bcat(b->sb, p, n) == 0);
}

const unsigned char *
edn_buf_data(struct edn_buf *b)
{

	if (b->sb == NULL)
		return ((const unsigned char *)"");
	if (!b->finished) {
		sbuf_finish(b->sb);
		b->finished = true;
	}
	return ((const unsigned char *)sbuf_data(b->sb));
}

size_t
edn_buf_len(struct edn_buf *b)
{

	if (b->sb == NULL)
		return (0);
	if (!b->finished) {
		sbuf_finish(b->sb);
		b->finished = true;
	}
	return ((size_t)sbuf_len(b->sb));
}

void
edn_buf_free(struct edn_buf *b)
{

	if (b->sb != NULL)
		sbuf_delete(b->sb);
	b->sb = NULL;
	b->finished = false;
}

/* UTF-8 encoding of a Unicode scalar value. ------------------------------- */

bool
edn_utf8_encode(struct edn_buf *b, uint32_t cp)
{

	if (cp < 0x80)
		return (edn_buf_putc(b, (unsigned char)cp));
	if (cp < 0x800)
		return (edn_buf_putc(b, (unsigned char)(0xc0 | (cp >> 6))) &&
		    edn_buf_putc(b, (unsigned char)(0x80 | (cp & 0x3f))));
	if (cp < 0x10000)
		return (edn_buf_putc(b, (unsigned char)(0xe0 | (cp >> 12))) &&
		    edn_buf_putc(b,
		    (unsigned char)(0x80 | ((cp >> 6) & 0x3f))) &&
		    edn_buf_putc(b, (unsigned char)(0x80 | (cp & 0x3f))));
	return (edn_buf_putc(b, (unsigned char)(0xf0 | (cp >> 18))) &&
	    edn_buf_putc(b, (unsigned char)(0x80 | ((cp >> 12) & 0x3f))) &&
	    edn_buf_putc(b, (unsigned char)(0x80 | ((cp >> 6) & 0x3f))) &&
	    edn_buf_putc(b, (unsigned char)(0x80 | (cp & 0x3f))));
}

/* Escape handling shared by double- and single-quoted literals. ----------- */

static int
hexval(int c)
{

	if (c >= '0' && c <= '9')
		return (c - '0');
	if (c >= 'a' && c <= 'f')
		return (c - 'a' + 10);
	if (c >= 'A' && c <= 'F')
		return (c - 'A' + 10);
	return (-1);
}

/*
 * Read exactly four hex digits starting at s[*i]; return the value or -1.
 */
static int
read_hex4(const char *s, size_t n, size_t *i)
{
	int v, d, k;

	v = 0;
	for (k = 0; k < 4; k++) {
		if (*i >= n)
			return (-1);
		d = hexval((unsigned char)s[*i]);
		if (d < 0)
			return (-1);
		v = (v << 4) | d;
		(*i)++;
	}
	return (v);
}

/*
 * Decode a "\u" escape (already past the 'u') into a Unicode scalar value,
 * honoring surrogate pairs and the "\u{...}" form.  For byte strings
 * (is_text == false) escapes in the printable-ASCII range are rejected.
 */
static bool
decode_u_escape(const char *s, size_t n, size_t *i, bool is_text,
    struct edn_buf *out, const char **err)
{
	uint32_t cp;
	int hi, lo, d;

	if (*i < n && s[*i] == '{') {
		(*i)++;
		cp = 0;
		if (*i >= n || s[*i] == '}') {
			*err = "empty \\u{} escape";
			return (false);
		}
		while (*i < n && s[*i] != '}') {
			d = hexval((unsigned char)s[*i]);
			if (d < 0) {
				*err = "invalid hex in \\u{} escape";
				return (false);
			}
			cp = (cp << 4) | (uint32_t)d;
			if (cp > 0x10ffff) {
				*err = "\\u{} scalar out of range";
				return (false);
			}
			(*i)++;
		}
		if (*i >= n) {
			*err = "unterminated \\u{} escape";
			return (false);
		}
		(*i)++;		/* consume '}' */
		if (cp >= 0xd800 && cp <= 0xdfff) {
			*err = "surrogate not allowed in \\u{}";
			return (false);
		}
	} else {
		hi = read_hex4(s, n, i);
		if (hi < 0) {
			*err = "invalid \\uXXXX escape";
			return (false);
		}
		if (hi >= 0xd800 && hi <= 0xdbff) {
			/* High surrogate: a low surrogate must follow. */
			if (*i + 1 >= n || s[*i] != '\\' || s[*i + 1] != 'u') {
				*err = "lone high surrogate";
				return (false);
			}
			*i += 2;
			lo = read_hex4(s, n, i);
			if (lo < 0xdc00 || lo > 0xdfff) {
				*err = "invalid low surrogate";
				return (false);
			}
			cp = 0x10000 + (((uint32_t)hi - 0xd800) << 10) +
			    ((uint32_t)lo - 0xdc00);
		} else if (hi >= 0xdc00 && hi <= 0xdfff) {
			*err = "lone low surrogate";
			return (false);
		} else {
			cp = (uint32_t)hi;
		}
	}
	if (!is_text && cp >= 0x20 && cp <= 0x7e) {
		*err = "\\u escape of printable ASCII not allowed in byte "
		    "string";
		return (false);
	}
	if (!edn_utf8_encode(out, cp)) {
		*err = "out of memory";
		return (false);
	}
	return (true);
}

static bool
decode_quoted(const char *s, size_t n, bool is_text, struct edn_buf *out,
    const char **err)
{
	size_t i;
	unsigned char c;

	for (i = 0; i < n; ) {
		c = (unsigned char)s[i];
		if (c == '\\') {
			i++;
			if (i >= n) {
				*err = "dangling backslash";
				return (false);
			}
			c = (unsigned char)s[i++];
			switch (c) {
			case 'b':
				if (!edn_buf_putc(out, 0x08))
					goto nomem;
				break;
			case 'f':
				if (!edn_buf_putc(out, 0x0c))
					goto nomem;
				break;
			case 'n':
				if (!edn_buf_putc(out, 0x0a))
					goto nomem;
				break;
			case 'r':
				if (!edn_buf_putc(out, 0x0d))
					goto nomem;
				break;
			case 't':
				if (!edn_buf_putc(out, 0x09))
					goto nomem;
				break;
			case '\\':
				if (!edn_buf_putc(out, '\\'))
					goto nomem;
				break;
			case '/':
				if (!is_text) {
					*err = "\\/ not allowed in "
					    "single-quoted string";
					return (false);
				}
				if (!edn_buf_putc(out, '/'))
					goto nomem;
				break;
			case '"':
				if (!is_text) {
					*err = "\\\" not allowed in "
					    "single-quoted string";
					return (false);
				}
				if (!edn_buf_putc(out, '"'))
					goto nomem;
				break;
			case '\'':
				if (is_text) {
					*err = "\\' not allowed in "
					    "double-quoted string";
					return (false);
				}
				if (!edn_buf_putc(out, '\''))
					goto nomem;
				break;
			case 'u':
				if (!decode_u_escape(s, n, &i, is_text, out,
				    err))
					return (false);
				break;
			default:
				*err = "invalid escape sequence";
				return (false);
			}
		} else if (c == '\r') {
			i++;		/* carriage returns are ignored */
		} else if (c == '\n') {
			if (!edn_buf_putc(out, 0x0a))
				goto nomem;
			i++;
		} else if (c < 0x20) {
			*err = "raw control character in string";
			return (false);
		} else {
			if (!edn_buf_putc(out, c))
				goto nomem;
			i++;
		}
	}
	return (true);
nomem:
	*err = "out of memory";
	return (false);
}

bool
edn_decode_dq(const char *s, size_t n, struct edn_buf *out, const char **err)
{

	return (decode_quoted(s, n, true, out, err));
}

bool
edn_decode_sq(const char *s, size_t n, struct edn_buf *out, const char **err)
{

	return (decode_quoted(s, n, false, out, err));
}

/*
 * Consume the body of an end-of-line comment starting at *i (just past the
 * "#" or "//"), stopping at LF or end of input.  Per the integrated-parser
 * ABNF (Figures 9, 11, 12) the comment body is *i-non-lf, where i-NONASCII
 * admits "\u" escapes that must be well-formed; so escape sequences are
 * validated here (and otherwise ignored).  *i is left at the LF or at n.
 */
static bool
skip_comment_body(const char *s, size_t n, size_t *i, const char **err)
{
	struct edn_buf scratch;
	bool ok;

	edn_buf_init(&scratch);
	ok = true;
	while (*i < n && s[*i] != '\n') {
		if (s[*i] != '\\') {
			(*i)++;
			continue;
		}
		(*i)++;			/* consume the backslash */
		if (*i >= n)
			break;
		if (s[*i] == 'u') {
			(*i)++;
			if (!decode_u_escape(s, n, i, true, &scratch, err)) {
				ok = false;
				break;
			}
		} else {
			(*i)++;		/* \' \\ etc.: ignored comment text */
		}
	}
	edn_buf_free(&scratch);
	return (ok);
}

/* h'': base16 with blank space and comments ignored. ---------------------- */

bool
edn_decode_hex(const char *s, size_t n, struct edn_buf *out, const char **err)
{
	size_t i;
	int hi, d;
	unsigned char c;

	hi = -1;
	for (i = 0; i < n; ) {
		c = (unsigned char)s[i];
		if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
			i++;
			continue;
		}
		if (c == '#') {
			i++;
			if (!skip_comment_body(s, n, &i, err))
				return (false);
			continue;
		}
		if (c == '/') {
			if (i + 1 < n && s[i + 1] == '/') {
				if (!edn_opts_get()->allow_eol_slash) {
					*err = "// comments in h'' disabled";
					return (false);
				}
				i += 2;
				if (!skip_comment_body(s, n, &i, err))
					return (false);
				continue;
			}
			if (!edn_opts_get()->allow_c_comments) {
				*err = "C-style comments in h'' disabled";
				return (false);
			}
			if (i + 1 < n && s[i + 1] == '*') {
				i += 2;
				while (i + 1 < n &&
				    !(s[i] == '*' && s[i + 1] == '/'))
					i++;
				if (i + 1 >= n) {
					*err = "unterminated comment in h''";
					return (false);
				}
				i += 2;
				continue;
			}
			/* Single-slash inline comment "/ ... /". */
			i++;
			while (i < n && s[i] != '/')
				i++;
			if (i >= n) {
				*err = "unterminated comment in h''";
				return (false);
			}
			i++;
			continue;
		}
		d = hexval(c);
		if (d < 0) {
			*err = "invalid character in h'' literal";
			return (false);
		}
		if (hi < 0) {
			hi = d;
		} else {
			if (!edn_buf_putc(out,
			    (unsigned char)((hi << 4) | d))) {
				*err = "out of memory";
				return (false);
			}
			hi = -1;
		}
		i++;
	}
	if (hi >= 0) {
		*err = "odd number of hex digits in h''";
		return (false);
	}
	return (true);
}

/*
 * r'' "raw CBOR" content (see ediagcbor.h).  Copy of edn_decode_hex extended
 * with three token kinds: '#' head tokens (#M.N[_x], CDDL-style), and inline
 * "..."/'...' string literals whose decoded content bytes are spliced in.
 * Unlike h'', here '#' is functional (a head token), so only slash comments
 * are supported.
 */

/* Defined later with the serializer; used by #M.N[_x] tokens. */
static void	emit_head(struct edn_buf *, unsigned, uint64_t, enum edn_ind);
static bool	arg_fits(uint64_t, enum edn_ind);

/*
 * Parse a CDDL-style head token:
 *   #M_      indefinite (ai=31); no argument
 *   #M.N     preferred head for major type M with numeric argument N
 *   #M.N_x   same, with forced width (_0.._3 only; _i rejected)
 */
static bool
rawcbor_head(const char *s, size_t n, size_t *ip, struct edn_buf *out,
    const char **err)
{
	char spec[8];
	size_t i, k;
	unsigned mt;
	uint64_t arg;
	enum edn_ind ind;

	i = *ip + 1;			/* just past '#' */
	if (i >= n || s[i] < '0' || s[i] > '7') {
		*err = "expected major type 0..7 after '#'";
		return (false);
	}
	mt = (unsigned)(s[i] - '0');
	i++;
	/* #M_ — indefinite length, no argument. */
	if (i < n && s[i] == '_' &&
	    (i + 1 >= n ||
	    !(isalnum((unsigned char)s[i + 1]) || s[i + 1] == '_'))) {
		emit_head(out, mt, 0, EDN_IND_INDEF);
		*ip = i + 1;
		return (true);
	}
	if (i >= n || s[i] != '.') {
		*err = "expected '.' or '_' after '#M'";
		return (false);
	}
	i++;
	if (i >= n || s[i] < '0' || s[i] > '9') {
		*err = "expected numeric argument after '#M.'";
		return (false);
	}
	arg = 0;
	while (i < n && s[i] >= '0' && s[i] <= '9') {
		if (arg > (UINT64_MAX - (uint64_t)(s[i] - '0')) / 10) {
			*err = "numeric argument overflow in '#'";
			return (false);
		}
		arg = arg * 10 + (uint64_t)(s[i] - '0');
		i++;
	}
	ind = EDN_IND_NONE;
	if (i < n && s[i] == '_') {
		k = i + 1;
		while (k < n && (isalnum((unsigned char)s[k]) || s[k] == '_'))
			k++;
		if (k - i >= sizeof(spec)) {
			*err = "encoding indicator too long in '#'";
			return (false);
		}
		memcpy(spec, s + i, k - i);
		spec[k - i] = '\0';
		ind = edn_spec_parse(spec);
		/*
		 * Preferred covers immediate; indefinite is written as #M_
		 * (no argument).  Reject _i, bare _, and unknown/reserved.
		 */
		if (ind != EDN_IND_AI24 && ind != EDN_IND_AI25 &&
		    ind != EDN_IND_AI26 && ind != EDN_IND_AI27) {
			*err = "unsupported encoding indicator in '#' "
			    "(use #M_ for indefinite)";
			return (false);
		}
		i = k;
	}
	if (ind != EDN_IND_NONE && !arg_fits(arg, ind)) {
		*err = "encoding indicator does not provide enough space "
		    "for the argument in '#'";
		return (false);
	}
	emit_head(out, mt, arg, ind);
	*ip = i;
	return (true);
}

static bool
rawcbor_string(const char *s, size_t n, size_t *ip, struct edn_buf *out,
    const char **err)
{
	size_t i, start;
	char q;

	q = s[*ip];
	i = *ip + 1;
	start = i;
	while (i < n) {
		if (s[i] == '\\') {
			i += 2;
			continue;
		}
		if (s[i] == q)
			break;
		i++;
	}
	if (i >= n) {
		*err = "unterminated string in r'' literal";
		return (false);
	}
	if (q == '"') {
		if (!edn_decode_dq(s + start, i - start, out, err))
			return (false);
	} else {
		if (!edn_decode_sq(s + start, i - start, out, err))
			return (false);
	}
	*ip = i + 1;			/* consume the closing quote */
	return (true);
}

bool
edn_decode_rawcbor(const char *s, size_t n, struct edn_buf *out,
    const char **err)
{
	size_t i;
	int hi, d;
	unsigned char c;

	hi = -1;
	for (i = 0; i < n; ) {
		c = (unsigned char)s[i];
		if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
			i++;
			continue;
		}
		if (c == '/') {
			if (i + 1 < n && s[i + 1] == '/') {
				i += 2;
				if (!skip_comment_body(s, n, &i, err))
					return (false);
				continue;
			}
			if (i + 1 < n && s[i + 1] == '*') {
				i += 2;
				while (i + 1 < n &&
				    !(s[i] == '*' && s[i + 1] == '/'))
					i++;
				if (i + 1 >= n) {
					*err = "unterminated comment in r''";
					return (false);
				}
				i += 2;
				continue;
			}
			i++;
			while (i < n && s[i] != '/')
				i++;
			if (i >= n) {
				*err = "unterminated comment in r''";
				return (false);
			}
			i++;
			continue;
		}
		if (c == '#' || c == '"' || c == '\'') {
			if (hi >= 0) {
				*err = "odd number of hex digits in r''";
				return (false);
			}
			if (c == '#') {
				if (!rawcbor_head(s, n, &i, out, err))
					return (false);
			} else if (!rawcbor_string(s, n, &i, out, err)) {
				return (false);
			}
			continue;
		}
		d = hexval(c);
		if (d < 0) {
			*err = "invalid character in r'' literal";
			return (false);
		}
		if (hi < 0) {
			hi = d;
		} else {
			if (!edn_buf_putc(out,
			    (unsigned char)((hi << 4) | d))) {
				*err = "out of memory";
				return (false);
			}
			hi = -1;
		}
		i++;
	}
	if (hi >= 0) {
		*err = "odd number of hex digits in r''";
		return (false);
	}
	return (true);
}

/* b64'': base64 / base64url with blank space and eol comments ignored. ---- */

static int
b64val(int c)
{

	if (c >= 'A' && c <= 'Z')
		return (c - 'A');
	if (c >= 'a' && c <= 'z')
		return (c - 'a' + 26);
	if (c >= '0' && c <= '9')
		return (c - '0' + 52);
	if (c == '+' || c == '-')
		return (62);
	if (c == '/' || c == '_')
		return (63);
	return (-1);
}

bool
edn_decode_b64(const char *s, size_t n, struct edn_buf *out, const char **err)
{
	size_t i;
	uint32_t acc;
	int bits, v, nsym, npad;
	unsigned char c;

	acc = 0;
	bits = 0;
	nsym = 0;
	npad = 0;
	for (i = 0; i < n; ) {
		c = (unsigned char)s[i];
		if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
			i++;
			continue;
		}
		/*
		 * Only '#' starts a comment in b64''; '/' is a base64
		 * alphabet character and "//" is data, not a comment.
		 */
		if (c == '#') {
			i++;
			if (!skip_comment_body(s, n, &i, err))
				return (false);
			continue;
		}
		if (c == '=') {
			npad++;
			i++;
			continue;
		}
		if (npad > 0) {
			*err = "base64 data after padding in b64'' literal";
			return (false);
		}
		v = b64val(c);
		if (v < 0) {
			*err = "invalid character in b64'' literal";
			return (false);
		}
		acc = (acc << 6) | (uint32_t)v;
		bits += 6;
		nsym++;
		if (bits >= 8) {
			bits -= 8;
			if (!edn_buf_putc(out,
			    (unsigned char)((acc >> bits) & 0xff))) {
				*err = "out of memory";
				return (false);
			}
		}
		i++;
	}
	if ((nsym & 3) == 1) {
		*err = "invalid base64 length in b64'' literal";
		return (false);
	}
	/*
	 * Padding is optional (the draft uses unpadded base64), but when
	 * present it must complete the final quantum exactly.
	 */
	if (npad > 0 && npad != ((4 - (nsym & 3)) & 3)) {
		*err = "incorrect base64 padding in b64'' literal";
		return (false);
	}
	/* Unused trailing bits must be zero. */
	if (bits > 0 && (acc & ((1U << bits) - 1)) != 0) {
		*err = "non-zero trailing bits in b64'' literal";
		return (false);
	}
	return (true);
}

/* Numeric construction. --------------------------------------------------- */

/*
 * Convert a string of base-2/8/10/16 digits to a minimal big-endian byte
 * array.  Returns a malloc'd buffer in *out with *outlen bytes (>= 1).
 */
static bool
digits_to_bytes(const char *digits, int base, unsigned char **out,
    size_t *outlen)
{
	unsigned char *le, *be, *p;
	size_t lelen, lecap, i, j, start;
	unsigned int carry, t;
	int d;

	lecap = 8;
	le = malloc(lecap);
	if (le == NULL)
		return (false);
	le[0] = 0;
	lelen = 1;
	for (i = 0; digits[i] != '\0'; i++) {
		d = hexval((unsigned char)digits[i]);
		if (d < 0 || d >= base) {
			free(le);
			return (false);
		}
		carry = (unsigned int)d;
		for (j = 0; j < lelen; j++) {
			t = (unsigned int)le[j] * (unsigned int)base + carry;
			le[j] = (unsigned char)(t & 0xff);
			carry = t >> 8;
		}
		while (carry != 0) {
			if (lelen == lecap) {
				p = realloc(le, lecap * 2);
				if (p == NULL) {
					free(le);
					return (false);
				}
				le = p;
				lecap *= 2;
			}
			le[lelen++] = (unsigned char)(carry & 0xff);
			carry >>= 8;
		}
	}
	/* Strip leading zero bytes (keep at least one). */
	start = lelen;
	while (start > 1 && le[start - 1] == 0)
		start--;
	be = malloc(start);
	if (be == NULL) {
		free(le);
		return (false);
	}
	for (i = 0; i < start; i++)
		be[i] = le[start - 1 - i];
	free(le);
	*out = be;
	*outlen = start;
	return (true);
}

static bool
bytes_fit_u64(const unsigned char *be, size_t len, uint64_t *val)
{
	uint64_t v;
	size_t i;

	if (len > 8)
		return (false);
	v = 0;
	for (i = 0; i < len; i++)
		v = (v << 8) | be[i];
	*val = v;
	return (true);
}

/* Subtract one from a minimal big-endian magnitude (which is nonzero). */
static void
bytes_dec(unsigned char *be, size_t *len)
{
	size_t i;

	i = *len;
	while (i > 0) {
		i--;
		if (be[i] != 0) {
			be[i]--;
			break;
		}
		be[i] = 0xff;
	}
	if (*len > 1 && be[0] == 0) {
		memmove(be, be + 1, *len - 1);
		(*len)--;
	}
}

static cbor_item_t *
build_uint_shortest(uint64_t v)
{

	if (v <= 0xff)
		return (cbor_build_uint8((uint8_t)v));
	if (v <= 0xffff)
		return (cbor_build_uint16((uint16_t)v));
	if (v <= 0xffffffff)
		return (cbor_build_uint32((uint32_t)v));
	return (cbor_build_uint64(v));
}

static cbor_item_t *
build_negint_shortest(uint64_t n)
{

	if (n <= 0xff)
		return (cbor_build_negint8((uint8_t)n));
	if (n <= 0xffff)
		return (cbor_build_negint16((uint16_t)n));
	if (n <= 0xffffffff)
		return (cbor_build_negint32((uint32_t)n));
	return (cbor_build_negint64(n));
}

static cbor_item_t *
build_bignum_tag(unsigned char *be, size_t len, bool negative)
{
	cbor_item_t *bs;

	bs = cbor_build_bytestring(be, len);
	if (bs == NULL)
		return (NULL);
	return (cbor_build_tag(negative ? 3 : 2, cbor_move(bs)));
}

cbor_item_t *
edn_int_from_str(const char *digits, int base, bool negative,
    const char **err)
{
	unsigned char *be;
	size_t len;
	uint64_t v;
	cbor_item_t *item;
	bool iszero;

	if (!digits_to_bytes(digits, base, &be, &len)) {
		*err = "invalid integer literal";
		return (NULL);
	}
	iszero = (len == 1 && be[0] == 0);
	if (iszero || !negative) {
		if (bytes_fit_u64(be, len, &v))
			item = build_uint_shortest(v);
		else
			item = build_bignum_tag(be, len, false);
		free(be);
		if (item == NULL)
			*err = "out of memory";
		return (item);
	}
	/* Negative, nonzero: encode -(n+1), so subtract one first. */
	bytes_dec(be, &len);
	if (bytes_fit_u64(be, len, &v))
		item = build_negint_shortest(v);
	else
		item = build_bignum_tag(be, len, true);
	free(be);
	if (item == NULL)
		*err = "out of memory";
	return (item);
}

/* IEEE 754 binary16 helpers, used to choose the shortest float head. ------ */

static uint16_t
f32_to_f16(uint32_t x)
{
	uint32_t sign, mant, halfm, rem, shift;
	int32_t e;

	sign = (x >> 16) & 0x8000U;
	e = (int32_t)((x >> 23) & 0xff) - 127 + 15;
	mant = x & 0x7fffffU;
	if (((x >> 23) & 0xff) == 0xff)
		return ((uint16_t)(sign | (mant != 0 ? 0x7e00U : 0x7c00U)));
	if (e >= 0x1f)
		return ((uint16_t)(sign | 0x7c00U));
	if (e <= 0) {
		if (e < -10)
			return ((uint16_t)sign);
		mant |= 0x800000U;
		shift = (uint32_t)(14 - e);
		halfm = mant >> shift;
		rem = mant & ((1U << shift) - 1);
		if (rem > (1U << (shift - 1)) ||
		    (rem == (1U << (shift - 1)) && (halfm & 1)))
			halfm++;
		return ((uint16_t)(sign | halfm));
	}
	halfm = mant >> 13;
	rem = mant & 0x1fffU;
	if (rem > 0x1000U || (rem == 0x1000U && (halfm & 1))) {
		halfm++;
		if (halfm == 0x400U) {
			halfm = 0;
			e++;
			if (e >= 0x1f)
				return ((uint16_t)(sign | 0x7c00U));
		}
	}
	return ((uint16_t)(sign | ((uint32_t)e << 10) | halfm));
}

static double
f16_to_double(uint16_t h)
{
	uint32_t sign, e, m;
	double val;

	sign = (h >> 15) & 1U;
	e = (h >> 10) & 0x1fU;
	m = h & 0x3ffU;
	if (e == 0)
		val = ldexp((double)m, -24);
	else if (e == 0x1f)
		val = (m != 0) ? NAN : INFINITY;
	else
		val = ldexp((double)(m | 0x400U), (int)e - 25);
	return (sign ? -val : val);
}

cbor_item_t *
edn_float_from_double(double d)
{
	float f;
	uint32_t bits;
	uint16_t h;

	if (isnan(d))
		return (cbor_build_float2((float)NAN));
	if ((double)(float)d != d)
		return (cbor_build_float8(d));
	f = (float)d;
	memcpy(&bits, &f, sizeof(bits));
	h = f32_to_f16(bits);
	if (f16_to_double(h) == d)
		return (cbor_build_float2(f));
	return (cbor_build_float4(f));
}

struct edn_num
edn_num_int(const char *digits, int base, bool negative, const char **err)
{
	struct edn_num num;
	unsigned char *be;
	size_t len;

	num.item = NULL;
	num.tagval = 0;
	num.taggable = false;
	num.item = edn_int_from_str(digits, base, negative, err);
	if (num.item == NULL)
		return (num);
	/* Determine whether the value is usable as a CBOR tag number. */
	if (!negative && digits_to_bytes(digits, base, &be, &len)) {
		if (bytes_fit_u64(be, len, &num.tagval))
			num.taggable = true;
		free(be);
	}
	return (num);
}

struct edn_num
edn_num_double(double d)
{
	struct edn_num num;

	num.item = edn_float_from_double(d);
	num.tagval = 0;
	num.taggable = false;
	return (num);
}

/* Container/value constructors. ------------------------------------------- */

void
edn_vec_init(struct edn_vec *v)
{

	v->items = NULL;
	v->len = 0;
	v->cap = 0;
}

bool
edn_vec_push(struct edn_vec *v, cbor_item_t *item)
{
	cbor_item_t **p;
	size_t ncap;

	if (v->len == v->cap) {
		ncap = (v->cap == 0) ? 8 : v->cap * 2;
		p = realloc(v->items, ncap * sizeof(*p));
		if (p == NULL)
			return (false);
		v->items = p;
		v->cap = ncap;
	}
	v->items[v->len++] = item;
	return (true);
}

void
edn_vec_free_items(struct edn_vec *v)
{
	size_t i;

	for (i = 0; i < v->len; i++)
		cbor_decref(&v->items[i]);
	free(v->items);
	v->items = NULL;
	v->len = 0;
	v->cap = 0;
}

void
edn_map_init(struct edn_map *m)
{

	m->pairs = NULL;
	m->len = 0;
	m->cap = 0;
}

bool
edn_map_push(struct edn_map *m, cbor_item_t *key, cbor_item_t *value)
{
	struct cbor_pair *p;
	size_t ncap;

	if (m->len == m->cap) {
		ncap = (m->cap == 0) ? 8 : m->cap * 2;
		p = realloc(m->pairs, ncap * sizeof(*p));
		if (p == NULL)
			return (false);
		m->pairs = p;
		m->cap = ncap;
	}
	m->pairs[m->len].key = key;
	m->pairs[m->len].value = value;
	m->len++;
	return (true);
}

void
edn_map_free_items(struct edn_map *m)
{
	size_t i;

	for (i = 0; i < m->len; i++) {
		cbor_decref(&m->pairs[i].key);
		cbor_decref(&m->pairs[i].value);
	}
	free(m->pairs);
	m->pairs = NULL;
	m->len = 0;
	m->cap = 0;
}

/*
 * The container builders below consume their argument completely: every
 * item reference is either handed to the resulting container (which holds
 * its own reference after cbor_array_push()/cbor_map_add() increment it,
 * so we release ours) or decref'd on error, and the backing storage is
 * freed.  The caller need only free the (now-empty) list struct itself.
 */
cbor_item_t *
edn_make_array(struct edn_vec *v, bool indefinite)
{
	cbor_item_t *arr;
	size_t i, j;

	arr = indefinite ? cbor_new_indefinite_array() :
	    cbor_new_definite_array(v->len);
	if (arr == NULL) {
		for (i = 0; i < v->len; i++)
			cbor_decref(&v->items[i]);
		goto done;
	}
	for (i = 0; i < v->len; i++) {
		if (!cbor_array_push(arr, v->items[i])) {
			cbor_decref(&arr);
			for (j = i; j < v->len; j++)
				cbor_decref(&v->items[j]);
			goto done;
		}
		cbor_decref(&v->items[i]);
	}
done:
	free(v->items);
	v->items = NULL;
	v->len = 0;
	v->cap = 0;
	return (arr);
}

cbor_item_t *
edn_make_map(struct edn_map *m, bool indefinite)
{
	cbor_item_t *map;
	size_t i, j;

	map = indefinite ? cbor_new_indefinite_map() :
	    cbor_new_definite_map(m->len);
	if (map == NULL) {
		for (i = 0; i < m->len; i++) {
			cbor_decref(&m->pairs[i].key);
			cbor_decref(&m->pairs[i].value);
		}
		goto done;
	}
	for (i = 0; i < m->len; i++) {
		if (!cbor_map_add(map, (struct cbor_pair){
		    .key = m->pairs[i].key,
		    .value = m->pairs[i].value})) {
			cbor_decref(&map);
			for (j = i; j < m->len; j++) {
				cbor_decref(&m->pairs[j].key);
				cbor_decref(&m->pairs[j].value);
			}
			goto done;
		}
		cbor_decref(&m->pairs[i].key);
		cbor_decref(&m->pairs[i].value);
	}
done:
	free(m->pairs);
	m->pairs = NULL;
	m->len = 0;
	m->cap = 0;
	return (map);
}

cbor_item_t *
edn_make_string(struct edn_str *s)
{
	cbor_item_t *item;

	if (s->type == EDN_TEXT)
		item = cbor_build_stringn((const char *)edn_buf_data(&s->buf),
		    edn_buf_len(&s->buf));
	else
		item = cbor_build_bytestring(edn_buf_data(&s->buf),
		    edn_buf_len(&s->buf));
	edn_buf_free(&s->buf);
	return (item);
}

cbor_item_t *
edn_make_indefinite_empty(enum edn_strtype type)
{

	if (type == EDN_TEXT)
		return (cbor_new_indefinite_string());
	return (cbor_new_indefinite_bytestring());
}

static void
vec_decref_all(struct edn_vec *v)
{
	size_t i;

	for (i = 0; i < v->len; i++)
		cbor_decref(&v->items[i]);
	free(v->items);
	v->items = NULL;
	v->len = 0;
	v->cap = 0;
}

cbor_item_t *
edn_make_streamstring(struct edn_vec *v, const char **err)
{
	cbor_item_t *str;
	size_t i;
	cbor_type t;
	bool ok;

	str = NULL;
	if (v->len == 0) {
		*err = "empty streamstring; use \"\"_ or ''_";
		goto done;
	}
	t = cbor_typeof(v->items[0]);
	if (t != CBOR_TYPE_STRING && t != CBOR_TYPE_BYTESTRING) {
		*err = "streamstring chunk is not a string";
		goto done;
	}
	str = (t == CBOR_TYPE_STRING) ? cbor_new_indefinite_string() :
	    cbor_new_indefinite_bytestring();
	if (str == NULL) {
		*err = "out of memory";
		goto done;
	}
	for (i = 0; i < v->len; i++) {
		if (cbor_typeof(v->items[i]) != t) {
			*err = "mixed string types in streamstring";
			cbor_decref(&str);
			str = NULL;
			goto done;
		}
		ok = (t == CBOR_TYPE_STRING) ?
		    cbor_string_add_chunk(str, v->items[i]) :
		    cbor_bytestring_add_chunk(str, v->items[i]);
		if (!ok) {
			*err = "streamstring chunk must be definite";
			cbor_decref(&str);
			str = NULL;
			goto done;
		}
	}
done:
	vec_decref_all(v);
	return (str);
}

cbor_item_t *
edn_make_embedded(struct edn_vec *v, const char **err)
{
	struct edn_buf seq;
	cbor_item_t *bs;
	size_t i;

	bs = NULL;
	edn_buf_init(&seq);
	for (i = 0; i < v->len; i++) {
		if (!edn_serialize(v->items[i], &seq, err))
			goto done;
	}
	bs = cbor_build_bytestring(edn_buf_data(&seq), edn_buf_len(&seq));
	if (bs == NULL)
		*err = "out of memory";
done:
	edn_buf_free(&seq);
	vec_decref_all(v);
	return (bs);
}

cbor_item_t *
edn_make_simple(unsigned long value)
{

	return (cbor_build_ctrl((uint8_t)value));
}

/* Application-extension literals (Section 3 / Section 4.1). ---------------- */

static cbor_item_t	*build_elision_null(const char **);

static cbor_item_t *
build_int64(long long v)
{

	if (v >= 0)
		return (build_uint_shortest((uint64_t)v));
	return (build_negint_shortest((uint64_t)(-(v + 1))));
}

/* "dt": RFC 3339 date/time decoded to an epoch-based number (Section 3.1). */

static bool
dt_is_leap(int y)
{

	return ((y % 4 == 0 && y % 100 != 0) || y % 400 == 0);
}

static int
dt_month_days(int y, int m)
{
	static const int days[] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31,
	    30, 31 };

	if (m == 2 && dt_is_leap(y))
		return (29);
	return (days[m - 1]);
}

/* Days from 1970-01-01 to y-m-d (proleptic Gregorian; Hinnant's algorithm). */
static long long
dt_days_from_civil(int y, int m, int d)
{
	long long era;
	unsigned yoe, doy, doe;

	y -= (m <= 2);
	era = (long long)((y >= 0 ? y : y - 399) / 400);
	yoe = (unsigned)(y - era * 400);
	doy = (unsigned)(153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + (unsigned)d - 1;
	doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
	return (era * 146097 + (long long)doe - 719468);
}

static bool
dt_read(const unsigned char *s, size_t n, size_t *i, int width, int *out)
{
	int v, k;

	v = 0;
	for (k = 0; k < width; k++) {
		if (*i >= n || s[*i] < '0' || s[*i] > '9')
			return (false);
		v = v * 10 + (s[*i] - '0');
		(*i)++;
	}
	*out = v;
	return (true);
}

static bool
dt_lit(const unsigned char *s, size_t n, size_t *i, char c)
{

	if (*i < n && s[*i] == (unsigned char)c) {
		(*i)++;
		return (true);
	}
	return (false);
}

static cbor_item_t *
edn_dt_value(const unsigned char *s, size_t n, bool tagged, const char **err)
{
	cbor_item_t *num, *res;
	double frac, scale;
	long long secs;
	size_t i, fstart;
	int year, mon, day, hh, mm, ss, offsign, offh, offm;
	bool hasfrac;

	i = 0;
	frac = 0.0;
	hasfrac = false;
	offsign = 0;
	offh = 0;
	offm = 0;
	if (!dt_read(s, n, &i, 4, &year) || !dt_lit(s, n, &i, '-') ||
	    !dt_read(s, n, &i, 2, &mon) || !dt_lit(s, n, &i, '-') ||
	    !dt_read(s, n, &i, 2, &day) || !dt_lit(s, n, &i, 'T') ||
	    !dt_read(s, n, &i, 2, &hh) || !dt_lit(s, n, &i, ':') ||
	    !dt_read(s, n, &i, 2, &mm) || !dt_lit(s, n, &i, ':') ||
	    !dt_read(s, n, &i, 2, &ss))
		goto bad;
	if (i < n && s[i] == '.') {
		i++;
		fstart = i;
		scale = 0.1;
		while (i < n && s[i] >= '0' && s[i] <= '9') {
			frac += (s[i] - '0') * scale;
			scale /= 10.0;
			i++;
		}
		if (i == fstart)
			goto bad;
		hasfrac = true;
	}
	if (i < n && s[i] == 'Z') {
		i++;
	} else if (i < n && (s[i] == '+' || s[i] == '-')) {
		offsign = (s[i] == '-') ? -1 : 1;
		i++;
		if (!dt_read(s, n, &i, 2, &offh) || !dt_lit(s, n, &i, ':') ||
		    !dt_read(s, n, &i, 2, &offm))
			goto bad;
	} else
		goto bad;
	if (i != n)
		goto bad;
	if (mon < 1 || mon > 12 || day < 1 || day > dt_month_days(year, mon) ||
	    hh > 23 || mm > 59 || ss > 60 || offh > 23 || offm > 59)
		goto bad;
	secs = dt_days_from_civil(year, mon, day) * 86400LL +
	    hh * 3600LL + mm * 60LL + ss;
	secs -= offsign * (offh * 3600LL + offm * 60LL);
	if (hasfrac && frac != 0.0)
		num = edn_float_from_double((double)secs + frac);
	else
		num = build_int64(secs);
	if (num == NULL) {
		*err = "out of memory";
		return (NULL);
	}
	if (!tagged)
		return (num);
	res = cbor_build_tag(1, cbor_move(num));
	if (res == NULL)
		*err = "out of memory";
	return (res);
bad:
	*err = "invalid dt date/time literal";
	return (NULL);
}

/* "ip": RFC 3986 IP address (optionally a prefix) decoded per RFC 9164. */

static bool
ip_parse_preflen(const char *s, long *out)
{
	char *end;
	long v;

	if (s[0] == '\0')
		return (false);
	if (s[0] == '0' && s[1] != '\0')	/* no leading zeros (uint ABNF) */
		return (false);
	errno = 0;
	v = strtol(s, &end, 10);
	if (*end != '\0' || v < 0 || errno != 0)
		return (false);
	*out = v;
	return (true);
}

static cbor_item_t *
ip_build(const unsigned char *addr, int nbytes, long preflen, int af,
    bool tagged, const char **err)
{
	cbor_item_t *bs, *plen, *arr, *res;

	res = NULL;
	if (preflen < 0) {
		res = cbor_build_bytestring(addr, (size_t)nbytes);
		if (res == NULL) {
			*err = "out of memory";
			return (NULL);
		}
	} else {
		/* Truncate trailing zero bytes within the prefix (RFC 9164). */
		while (nbytes > 0 && addr[nbytes - 1] == 0)
			nbytes--;
		bs = cbor_build_bytestring(addr, (size_t)nbytes);
		plen = build_uint_shortest((uint64_t)preflen);
		arr = cbor_new_definite_array(2);
		if (bs == NULL || plen == NULL || arr == NULL ||
		    !cbor_array_push(arr, plen) || !cbor_array_push(arr, bs)) {
			if (bs != NULL)
				cbor_decref(&bs);
			if (plen != NULL)
				cbor_decref(&plen);
			if (arr != NULL)
				cbor_decref(&arr);
			*err = "out of memory";
			return (NULL);
		}
		cbor_decref(&plen);
		cbor_decref(&bs);
		res = arr;
	}
	if (!tagged)
		return (res);
	res = cbor_build_tag(af == AF_INET ? 52 : 54, cbor_move(res));
	if (res == NULL)
		*err = "out of memory";
	return (res);
}

static cbor_item_t *
edn_ip_value(const unsigned char *s, size_t n, bool tagged, const char **err)
{
	char buf[64];
	unsigned char addr[16];
	char *slash;
	long preflen;
	int af, fulllen, nbytes;

	if (n == 0 || n >= sizeof(buf)) {
		*err = "invalid ip address literal";
		return (NULL);
	}
	memcpy(buf, s, n);
	buf[n] = '\0';
	if (strlen(buf) != n) {		/* embedded NUL */
		*err = "invalid ip address literal";
		return (NULL);
	}
	preflen = -1;
	slash = strchr(buf, '/');
	if (slash != NULL) {
		*slash = '\0';
		if (!ip_parse_preflen(slash + 1, &preflen)) {
			*err = "invalid ip address prefix length";
			return (NULL);
		}
	}
	if (inet_pton(AF_INET, buf, addr) == 1) {
		af = AF_INET;
		fulllen = 4;
	} else if (inet_pton(AF_INET6, buf, addr) == 1) {
		af = AF_INET6;
		fulllen = 16;
	} else {
		*err = "invalid ip address literal";
		return (NULL);
	}
	if (preflen > (long)fulllen * 8) {
		*err = "ip prefix length out of range";
		return (NULL);
	}
	nbytes = (preflen < 0) ? fulllen : (int)((preflen + 7) / 8);
	return (ip_build(addr, nbytes, preflen, af, tagged, err));
}

/*
 * Unresolved Application-Extension Tag (tag 999, Section 4.1): wrap the
 * prefix and the contained items as 999([prefix, [items...]]).  Consumes
 * the item vector.
 */
static cbor_item_t *
build_tag999(const char *prefix, struct edn_vec *items, const char **err)
{
	cbor_item_t *pfx, *inner, *outer, *tag;
	size_t i;

	pfx = cbor_build_string(prefix);
	inner = cbor_new_definite_array(items->len);
	outer = cbor_new_definite_array(2);
	tag = NULL;
	if (pfx == NULL || inner == NULL || outer == NULL) {
		*err = "out of memory";
		goto done;
	}
	for (i = 0; i < items->len; i++) {
		if (!cbor_array_push(inner, items->items[i])) {
			*err = "out of memory";
			goto done;
		}
	}
	if (!cbor_array_push(outer, pfx) || !cbor_array_push(outer, inner)) {
		*err = "out of memory";
		goto done;
	}
	cbor_decref(&pfx);
	cbor_decref(&inner);
	pfx = NULL;
	inner = NULL;
	if (!edn_opts_get()->allow_tag999) {
		*err = "unknown application-extension (CPA999 disabled)";
		goto done;
	}
	tag = cbor_build_tag(EDN_TAG_UNRESOLVED, cbor_move(outer));
	outer = NULL;
	if (tag == NULL)
		*err = "out of memory";
done:
	if (pfx != NULL)
		cbor_decref(&pfx);
	if (inner != NULL)
		cbor_decref(&inner);
	if (outer != NULL)
		cbor_decref(&outer);
	vec_decref_all(items);
	return (tag);
}

static cbor_item_t *
app_unknown_str(const char *prefix, const unsigned char *text, size_t len,
    const char **err)
{
	struct edn_vec v;
	cbor_item_t *str;

	str = cbor_build_stringn((const char *)text, len);
	if (str == NULL) {
		*err = "out of memory";
		return (NULL);
	}
	edn_vec_init(&v);
	if (!edn_vec_push(&v, str)) {
		cbor_decref(&str);
		*err = "out of memory";
		return (NULL);
	}
	return (build_tag999(prefix, &v, err));
}

/*
 * r'': decode raw-CBOR inner notation.  wrap=false → raw passthrough
 * (splice bytes verbatim); wrap=true (r_b'') → wrap in a byte string.
 */
static cbor_item_t *
edn_make_rawcbor(const char *text, size_t len, bool wrap, const char **err)
{
	struct edn_buf raw;
	cbor_item_t *item;

	edn_buf_init(&raw);
	if (!edn_decode_rawcbor(text, len, &raw, err)) {
		edn_buf_free(&raw);
		return (NULL);
	}
	item = cbor_build_bytestring(edn_buf_data(&raw), edn_buf_len(&raw));
	edn_buf_free(&raw);
	if (item == NULL) {
		*err = "out of memory";
		return (NULL);
	}
	if (!wrap && !edn_mark_raw(item, err)) {
		cbor_decref(&item);
		return (NULL);
	}
	return (item);
}

/*
 * float'': hex text OR already-decoded payload bytes of length 2/4/8 become
 * mt7 float16/32/64 with exact bit pattern (via raw passthrough).
 */
static cbor_item_t *
edn_make_float_ext(const unsigned char *text, size_t len, bool already_bytes,
    const char **err)
{
	struct edn_buf hex, out;
	cbor_item_t *item;
	unsigned char head;
	const unsigned char *payload;
	size_t n;

	edn_buf_init(&hex);
	if (already_bytes) {
		payload = text;
		n = len;
	} else {
		if (!edn_decode_hex((const char *)text, len, &hex, err)) {
			edn_buf_free(&hex);
			return (NULL);
		}
		payload = edn_buf_data(&hex);
		n = edn_buf_len(&hex);
	}
	if (n == 2)
		head = 0xf9;
	else if (n == 4)
		head = 0xfa;
	else if (n == 8)
		head = 0xfb;
	else {
		*err = "float'' requires 2, 4 or 8 payload bytes";
		edn_buf_free(&hex);
		return (NULL);
	}
	edn_buf_init(&out);
	if (!edn_buf_putc(&out, head) ||
	    !edn_buf_append(&out, payload, n)) {
		*err = "out of memory";
		edn_buf_free(&hex);
		edn_buf_free(&out);
		return (NULL);
	}
	edn_buf_free(&hex);
	item = cbor_build_bytestring(edn_buf_data(&out), edn_buf_len(&out));
	edn_buf_free(&out);
	if (item == NULL) {
		*err = "out of memory";
		return (NULL);
	}
	if (!edn_mark_raw(item, err)) {
		cbor_decref(&item);
		return (NULL);
	}
	return (item);
}

static bool
item_is_ellipsis(cbor_item_t *it)
{
	cbor_item_t *tagged;
	bool ok;

	if (cbor_typeof(it) != CBOR_TYPE_TAG ||
	    cbor_tag_value(it) != EDN_TAG_ELLIPSIS)
		return (false);
	tagged = cbor_tag_item(it);
	ok = cbor_is_null(tagged);
	cbor_decref(&tagged);
	return (ok);
}

static bool
get_str_bytes(cbor_item_t *it, const unsigned char **data, size_t *len,
    const char **err)
{

	if (cbor_typeof(it) == CBOR_TYPE_STRING &&
	    cbor_string_is_definite(it)) {
		*data = cbor_string_handle(it);
		*len = cbor_string_length(it);
		return (true);
	}
	if (cbor_typeof(it) == CBOR_TYPE_BYTESTRING &&
	    cbor_bytestring_is_definite(it)) {
		*data = cbor_bytestring_handle(it);
		*len = cbor_bytestring_length(it);
		return (true);
	}
	*err = "argument is not a definite string";
	return (false);
}

static cbor_item_t *
make_str_from_bytes(const unsigned char *data, size_t len, bool as_text,
    const char **err)
{
	cbor_item_t *item;

	if (as_text)
		item = cbor_build_stringn((const char *)data, len);
	else
		item = cbor_build_bytestring(data, len);
	if (item == NULL)
		*err = "out of memory";
	return (item);
}

/*
 * t1/b1: concatenate string arguments; any ellipsis yields CPA888([...]).
 * as_text selects text vs byte string for non-ellipsis results and fragments.
 */
static cbor_item_t *
edn_make_concat(struct edn_vec *items, bool as_text, const char **err)
{
	struct edn_buf joined, frag;
	cbor_item_t *item, *arr, *part, *ell;
	const unsigned char *data;
	size_t i, nparts, len;
	bool any_ell, in_frag;

	any_ell = false;
	for (i = 0; i < items->len; i++) {
		if (item_is_ellipsis(items->items[i])) {
			any_ell = true;
			break;
		}
	}
	if (!any_ell) {
		edn_buf_init(&joined);
		for (i = 0; i < items->len; i++) {
			if (!get_str_bytes(items->items[i], &data, &len, err) ||
			    !edn_buf_append(&joined, data, len)) {
				if (*err == NULL)
					*err = "out of memory";
				edn_buf_free(&joined);
				vec_decref_all(items);
				return (NULL);
			}
		}
		item = make_str_from_bytes(edn_buf_data(&joined),
		    edn_buf_len(&joined), as_text, err);
		edn_buf_free(&joined);
		vec_decref_all(items);
		return (item);
	}
	if (!edn_opts_get()->allow_ellipsis) {
		*err = "ellipsis not allowed when ingesting CDN";
		vec_decref_all(items);
		return (NULL);
	}

	/* Count array slots: merged string runs + each ellipsis. */
	nparts = 0;
	in_frag = false;
	for (i = 0; i < items->len; i++) {
		if (item_is_ellipsis(items->items[i])) {
			if (in_frag) {
				nparts++;
				in_frag = false;
			}
			nparts++;
		} else
			in_frag = true;
	}
	if (in_frag)
		nparts++;

	arr = cbor_new_definite_array(nparts);
	if (arr == NULL) {
		*err = "out of memory";
		vec_decref_all(items);
		return (NULL);
	}
	edn_buf_init(&frag);
	in_frag = false;
	for (i = 0; i < items->len; i++) {
		if (item_is_ellipsis(items->items[i])) {
			if (in_frag) {
				part = make_str_from_bytes(edn_buf_data(&frag),
				    edn_buf_len(&frag), as_text, err);
				edn_buf_free(&frag);
				edn_buf_init(&frag);
				in_frag = false;
				if (part == NULL ||
				    !cbor_array_push(arr, cbor_move(part))) {
					if (part != NULL)
						cbor_decref(&part);
					*err = "out of memory";
					cbor_decref(&arr);
					edn_buf_free(&frag);
					vec_decref_all(items);
					return (NULL);
				}
			}
			ell = build_elision_null(err);
			if (ell == NULL ||
			    !cbor_array_push(arr, cbor_move(ell))) {
				if (ell != NULL)
					cbor_decref(&ell);
				if (*err == NULL)
					*err = "out of memory";
				cbor_decref(&arr);
				edn_buf_free(&frag);
				vec_decref_all(items);
				return (NULL);
			}
			continue;
		}
		if (!get_str_bytes(items->items[i], &data, &len, err) ||
		    !edn_buf_append(&frag, data, len)) {
			if (*err == NULL)
				*err = "out of memory";
			cbor_decref(&arr);
			edn_buf_free(&frag);
			vec_decref_all(items);
			return (NULL);
		}
		in_frag = true;
	}
	if (in_frag) {
		part = make_str_from_bytes(edn_buf_data(&frag),
		    edn_buf_len(&frag), as_text, err);
		edn_buf_free(&frag);
		if (part == NULL || !cbor_array_push(arr, cbor_move(part))) {
			if (part != NULL)
				cbor_decref(&part);
			if (*err == NULL)
				*err = "out of memory";
			cbor_decref(&arr);
			vec_decref_all(items);
			return (NULL);
		}
	} else
		edn_buf_free(&frag);

	item = cbor_build_tag(EDN_TAG_ELLIPSIS, cbor_move(arr));
	if (item == NULL)
		*err = "out of memory";
	vec_decref_all(items);
	return (item);
}

/* ilbs/ilts: one indefinite-length string chunk per argument. */
static cbor_item_t *
edn_make_ilstring(struct edn_vec *items, bool as_text, const char **err)
{
	cbor_item_t *str, *chunk;
	const unsigned char *data;
	size_t i, len;

	str = as_text ? cbor_new_indefinite_string() :
	    cbor_new_indefinite_bytestring();
	if (str == NULL) {
		*err = "out of memory";
		vec_decref_all(items);
		return (NULL);
	}
	for (i = 0; i < items->len; i++) {
		if (item_is_ellipsis(items->items[i])) {
			*err = "ellipsis is not valid in ilbs/ilts";
			cbor_decref(&str);
			vec_decref_all(items);
			return (NULL);
		}
		if (!get_str_bytes(items->items[i], &data, &len, err)) {
			cbor_decref(&str);
			vec_decref_all(items);
			return (NULL);
		}
		chunk = make_str_from_bytes(data, len, as_text, err);
		if (chunk == NULL) {
			cbor_decref(&str);
			vec_decref_all(items);
			return (NULL);
		}
		if (as_text) {
			if (!cbor_string_add_chunk(str, cbor_move(chunk))) {
				cbor_decref(&chunk);
				*err = "out of memory";
				cbor_decref(&str);
				vec_decref_all(items);
				return (NULL);
			}
		} else if (!cbor_bytestring_add_chunk(str, cbor_move(chunk))) {
			cbor_decref(&chunk);
			*err = "out of memory";
			cbor_decref(&str);
			vec_decref_all(items);
			return (NULL);
		}
	}
	vec_decref_all(items);
	return (str);
}

cbor_item_t *
edn_make_app(const char *prefix, struct edn_buf *content, const char **err)
{
	const unsigned char *text;
	cbor_item_t *item;
	size_t len;

	text = edn_buf_data(content);
	len = edn_buf_len(content);
	if (strcmp(prefix, "h") == 0) {
		struct edn_buf decoded;

		edn_buf_init(&decoded);
		if (!edn_decode_hex((const char *)text, len, &decoded, err)) {
			edn_buf_free(&decoded);
			edn_buf_free(content);
			return (NULL);
		}
		item = cbor_build_bytestring(edn_buf_data(&decoded),
		    edn_buf_len(&decoded));
		edn_buf_free(&decoded);
		if (item == NULL)
			*err = "out of memory";
	} else if (strcmp(prefix, "b64") == 0) {
		struct edn_buf decoded;

		edn_buf_init(&decoded);
		if (!edn_decode_b64((const char *)text, len, &decoded, err)) {
			edn_buf_free(&decoded);
			edn_buf_free(content);
			return (NULL);
		}
		item = cbor_build_bytestring(edn_buf_data(&decoded),
		    edn_buf_len(&decoded));
		edn_buf_free(&decoded);
		if (item == NULL)
			*err = "out of memory";
	} else if (strcmp(prefix, "dt") == 0)
		item = edn_dt_value(text, len, false, err);
	else if (strcmp(prefix, "DT") == 0)
		item = edn_dt_value(text, len, true, err);
	else if (strcmp(prefix, "ip") == 0)
		item = edn_ip_value(text, len, false, err);
	else if (strcmp(prefix, "IP") == 0)
		item = edn_ip_value(text, len, true, err);
	else if (strcmp(prefix, "float") == 0)
		item = edn_make_float_ext(text, len, false, err);
	else if (strcmp(prefix, "r") == 0)
		item = edn_make_rawcbor((const char *)text, len, false, err);
	else if (strcmp(prefix, "r_b") == 0)
		item = edn_make_rawcbor((const char *)text, len, true, err);
	else
		item = app_unknown_str(prefix, text, len, err);
	edn_buf_free(content);
	return (item);
}

/*
 * Known extensions in app-sequence form, e.g. dt<<'...'>>, are equivalent
 * to the app-string form applied to the single contained string.
 */
static cbor_item_t *
app_seq_known(struct edn_vec *items, bool tagged, bool is_dt, const char **err)
{
	const unsigned char *data;
	cbor_item_t *res;
	size_t len;
	cbor_type t;

	res = NULL;
	if (items->len != 1) {
		*err = "app-sequence must contain a single string";
		goto done;
	}
	t = cbor_typeof(items->items[0]);
	if (t == CBOR_TYPE_STRING && cbor_string_is_definite(items->items[0])) {
		data = cbor_string_handle(items->items[0]);
		len = cbor_string_length(items->items[0]);
	} else if (t == CBOR_TYPE_BYTESTRING &&
	    cbor_bytestring_is_definite(items->items[0])) {
		data = cbor_bytestring_handle(items->items[0]);
		len = cbor_bytestring_length(items->items[0]);
	} else {
		*err = "app-sequence item is not a definite string";
		goto done;
	}
	res = is_dt ? edn_dt_value(data, len, tagged, err) :
	    edn_ip_value(data, len, tagged, err);
done:
	vec_decref_all(items);
	return (res);
}

cbor_item_t *
edn_make_app_seq(const char *prefix, struct edn_vec *items, const char **err)
{
	const unsigned char *data;
	size_t len;
	cbor_item_t *res;
	struct edn_buf decoded;

	if (strcmp(prefix, "dt") == 0)
		return (app_seq_known(items, false, true, err));
	if (strcmp(prefix, "DT") == 0)
		return (app_seq_known(items, true, true, err));
	if (strcmp(prefix, "ip") == 0)
		return (app_seq_known(items, false, false, err));
	if (strcmp(prefix, "IP") == 0)
		return (app_seq_known(items, true, false, err));
	if (strcmp(prefix, "h") == 0 || strcmp(prefix, "b64") == 0) {
		if (items->len != 1 ||
		    !get_str_bytes(items->items[0], &data, &len, err)) {
			if (items->len != 1)
				*err = "h/b64<<>> expects a single string";
			vec_decref_all(items);
			return (NULL);
		}
		edn_buf_init(&decoded);
		if (prefix[0] == 'h') {
			if (!edn_decode_hex((const char *)data, len, &decoded,
			    err)) {
				edn_buf_free(&decoded);
				vec_decref_all(items);
				return (NULL);
			}
		} else if (!edn_decode_b64((const char *)data, len, &decoded,
		    err)) {
			edn_buf_free(&decoded);
			vec_decref_all(items);
			return (NULL);
		}
		res = cbor_build_bytestring(edn_buf_data(&decoded),
		    edn_buf_len(&decoded));
		edn_buf_free(&decoded);
		vec_decref_all(items);
		if (res == NULL)
			*err = "out of memory";
		return (res);
	}
	if (strcmp(prefix, "t1") == 0)
		return (edn_make_concat(items, true, err));
	if (strcmp(prefix, "b1") == 0)
		return (edn_make_concat(items, false, err));
	if (strcmp(prefix, "ilts") == 0)
		return (edn_make_ilstring(items, true, err));
	if (strcmp(prefix, "ilbs") == 0)
		return (edn_make_ilstring(items, false, err));
	if (strcmp(prefix, "float") == 0) {
		cbor_item_t *arg;
		bool already;

		if (items->len != 1) {
			*err = "float<<>> expects a single string";
			vec_decref_all(items);
			return (NULL);
		}
		arg = items->items[0];
		already = (cbor_typeof(arg) == CBOR_TYPE_BYTESTRING &&
		    cbor_bytestring_is_definite(arg) &&
		    (cbor_bytestring_length(arg) == 2 ||
		    cbor_bytestring_length(arg) == 4 ||
		    cbor_bytestring_length(arg) == 8));
		if (!get_str_bytes(arg, &data, &len, err)) {
			vec_decref_all(items);
			return (NULL);
		}
		res = edn_make_float_ext(data, len, already, err);
		vec_decref_all(items);
		return (res);
	}
	if (strcmp(prefix, "r") == 0 || strcmp(prefix, "r_b") == 0) {
		if (items->len != 1 ||
		    !get_str_bytes(items->items[0], &data, &len, err)) {
			if (items->len != 1)
				*err = "r<<>> expects a single string";
			vec_decref_all(items);
			return (NULL);
		}
		res = edn_make_rawcbor((const char *)data, len,
		    prefix[1] == '_', err);
		vec_decref_all(items);
		return (res);
	}
	return (build_tag999(prefix, items, err));
}

/* String concatenation (Section 5.1). ------------------------------------- */

void
edn_chunk_list_init(struct edn_chunk_list *l)
{

	l->chunks = NULL;
	l->len = 0;
	l->cap = 0;
}

static struct edn_chunk *
chunk_list_extend(struct edn_chunk_list *l)
{
	struct edn_chunk *p;
	size_t ncap;

	if (l->len == l->cap) {
		ncap = (l->cap == 0) ? 4 : l->cap * 2;
		p = realloc(l->chunks, ncap * sizeof(*p));
		if (p == NULL)
			return (NULL);
		l->chunks = p;
		l->cap = ncap;
	}
	return (&l->chunks[l->len++]);
}

bool
edn_chunk_list_push_str(struct edn_chunk_list *l, struct edn_str *s)
{
	struct edn_chunk *c;

	c = chunk_list_extend(l);
	if (c == NULL)
		return (false);
	c->buf = s->buf;
	c->type = s->type;
	c->ellipsis = false;
	c->front_ind = s->front_ind;
	edn_buf_init(&s->buf);
	return (true);
}

bool
edn_chunk_list_push_ellipsis(struct edn_chunk_list *l)
{
	struct edn_chunk *c;

	c = chunk_list_extend(l);
	if (c == NULL)
		return (false);
	edn_buf_init(&c->buf);
	c->type = EDN_TEXT;
	c->ellipsis = true;
	c->front_ind = EDN_IND_NONE;
	return (true);
}

void
edn_chunk_list_free(struct edn_chunk_list *l)
{
	size_t i;

	for (i = 0; i < l->len; i++)
		edn_buf_free(&l->chunks[i].buf);
	free(l->chunks);
	l->chunks = NULL;
	l->len = 0;
	l->cap = 0;
}

static cbor_item_t *
chunks_join_simple(struct edn_chunk_list *l, const char **err)
{
	struct edn_buf joined;
	enum edn_strtype type;
	cbor_item_t *item;
	size_t i;

	type = l->chunks[0].type;
	edn_buf_init(&joined);
	for (i = 0; i < l->len; i++) {
		if (l->chunks[i].type != type && i != 0 &&
		    type == EDN_BYTES) {
			*err = "cannot concatenate text into byte string";
			edn_buf_free(&joined);
			return (NULL);
		}
		if (!edn_buf_append(&joined,
		    edn_buf_data(&l->chunks[i].buf),
		    edn_buf_len(&l->chunks[i].buf))) {
			*err = "out of memory";
			edn_buf_free(&joined);
			return (NULL);
		}
	}
	if (type == EDN_TEXT)
		item = cbor_build_stringn((const char *)edn_buf_data(&joined),
		    edn_buf_len(&joined));
	else
		item = cbor_build_bytestring(edn_buf_data(&joined),
		    edn_buf_len(&joined));
	edn_buf_free(&joined);
	if (item == NULL)
		*err = "out of memory";
	return (item);
}

/* Build the Diagnostic Notation Ellipsis Tag, 888(null) (Section 4.2). */
static cbor_item_t *
build_elision_null(const char **err)
{
	cbor_item_t *nul, *tag;

	nul = cbor_new_null();
	if (nul == NULL) {
		*err = "out of memory";
		return (NULL);
	}
	tag = cbor_build_tag(EDN_TAG_ELLIPSIS, cbor_move(nul));
	if (tag == NULL)
		*err = "out of memory";
	return (tag);
}

/* Build one string fragment from chunks [lo, hi) (all non-ellipsis). */
static cbor_item_t *
build_fragment(struct edn_chunk_list *l, size_t lo, size_t hi,
    const char **err)
{
	struct edn_buf joined;
	enum edn_strtype type;
	cbor_item_t *item;
	size_t i;

	type = l->chunks[lo].type;
	edn_buf_init(&joined);
	for (i = lo; i < hi; i++) {
		if (l->chunks[i].type != type) {
			*err = "mixed text/byte fragments in elision";
			edn_buf_free(&joined);
			return (NULL);
		}
		if (!edn_buf_append(&joined, edn_buf_data(&l->chunks[i].buf),
		    edn_buf_len(&l->chunks[i].buf))) {
			*err = "out of memory";
			edn_buf_free(&joined);
			return (NULL);
		}
	}
	if (type == EDN_TEXT)
		item = cbor_build_stringn((const char *)edn_buf_data(&joined),
		    edn_buf_len(&joined));
	else
		item = cbor_build_bytestring(edn_buf_data(&joined),
		    edn_buf_len(&joined));
	edn_buf_free(&joined);
	if (item == NULL)
		*err = "out of memory";
	return (item);
}

/*
 * Build the stand-in for a string containing elisions:
 * 888([fragment, 888(null), fragment, ...]) (Section 4.2).  Consecutive
 * non-ellipsis chunks are merged into one fragment; runs of ellipses
 * collapse into a single elision indicator.
 */
static cbor_item_t *
build_elision_array(struct edn_chunk_list *l, const char **err)
{
	struct edn_vec parts;
	cbor_item_t *frag, *elision, *arr, *tag;
	size_t i, lo;

	edn_vec_init(&parts);
	i = 0;
	while (i < l->len) {
		if (l->chunks[i].ellipsis) {
			elision = build_elision_null(err);
			if (elision == NULL)
				goto fail;
			if (!edn_vec_push(&parts, elision)) {
				cbor_decref(&elision);
				*err = "out of memory";
				goto fail;
			}
			while (i < l->len && l->chunks[i].ellipsis)
				i++;
		} else {
			lo = i;
			while (i < l->len && !l->chunks[i].ellipsis)
				i++;
			frag = build_fragment(l, lo, i, err);
			if (frag == NULL)
				goto fail;
			if (!edn_vec_push(&parts, frag)) {
				cbor_decref(&frag);
				*err = "out of memory";
				goto fail;
			}
		}
	}
	arr = edn_make_array(&parts, false);	/* consumes parts */
	if (arr == NULL) {
		*err = "out of memory";
		return (NULL);
	}
	tag = cbor_build_tag(EDN_TAG_ELLIPSIS, cbor_move(arr));
	if (tag == NULL)
		*err = "out of memory";
	return (tag);
fail:
	vec_decref_all(&parts);
	return (NULL);
}

cbor_item_t *
edn_chunks_finish(struct edn_chunk_list *l, const char **err)
{
	cbor_item_t *item;
	bool any_ellipsis;
	size_t i;

	if (l->len == 0) {
		*err = "empty string concatenation";
		return (NULL);
	}
	any_ellipsis = false;
	for (i = 0; i < l->len; i++) {
		if (l->chunks[i].ellipsis) {
			any_ellipsis = true;
			break;
		}
	}
	if (any_ellipsis && !edn_opts_get()->allow_ellipsis) {
		/*
		 * Chairs: "Remove handling of ellipses" (Christian) — the
		 * token may still lex, but ingesting CDN as CBOR is an error.
		 */
		*err = "ellipsis not allowed when ingesting CDN";
		return (NULL);
	}
	/* A lone ellipsis stands in for a whole data item: 888(null). */
	if (l->len == 1 && l->chunks[0].ellipsis)
		return (build_elision_null(err));
	if (!any_ellipsis)
		item = chunks_join_simple(l, err);
	else
		item = build_elision_array(l, err);
	if (item == NULL)
		return (NULL);
	/* Apply a front indicator from h_2'...' / h_2`...`. */
	if (l->len == 1 && !l->chunks[0].ellipsis &&
	    l->chunks[0].front_ind != EDN_IND_NONE &&
	    l->chunks[0].front_ind != EDN_IND_INVALID) {
		if (!edn_apply_indicator(item, l->chunks[0].front_ind, err)) {
			cbor_decref(&item);
			return (NULL);
		}
	}
	return (item);
}

/* Encoding indicators (Section 2.3). -------------------------------------- */

/*
 * Indicators are recorded out of band, keyed by the cbor_item_t pointer they
 * control, because libcbor items carry no slot for them and always emit
 * preferred serialization.  The table is tiny (a handful of indicators per
 * document), so a flat array with linear lookup is sufficient.
 */
struct edn_ind_entry {
	cbor_item_t	*item;
	enum edn_ind	 ind;
};

static struct edn_ind_entry	*g_inds;
static size_t			 g_ninds;
static size_t			 g_inds_cap;

/* Bytestrings marked for raw passthrough (r'', float'', …): no mt2 head. */
static cbor_item_t		**g_raws;
static size_t			 g_nraws;
static size_t			 g_raws_cap;

bool
edn_mark_raw(cbor_item_t *item, const char **err)
{
	cbor_item_t **p;
	size_t ncap;

	if (item == NULL || cbor_typeof(item) != CBOR_TYPE_BYTESTRING ||
	    !cbor_bytestring_is_definite(item)) {
		*err = "raw passthrough requires a definite byte string";
		return (false);
	}
	if (g_nraws == g_raws_cap) {
		ncap = (g_raws_cap == 0) ? 8 : g_raws_cap * 2;
		p = realloc(g_raws, ncap * sizeof(*p));
		if (p == NULL) {
			*err = "out of memory";
			return (false);
		}
		g_raws = p;
		g_raws_cap = ncap;
	}
	g_raws[g_nraws++] = item;
	return (true);
}

bool
edn_is_raw(cbor_item_t *item)
{
	size_t i;

	for (i = 0; i < g_nraws; i++)
		if (g_raws[i] == item)
			return (true);
	return (false);
}

enum edn_ind
edn_spec_parse(const char *text)
{

	/* text starts with '_' (the lexer guarantees this). */
	if (text[1] == '\0')
		return (EDN_IND_INDEF);
	if (text[1] == 'i' && text[2] == '\0')
		return (EDN_IND_IMMEDIATE);
	if (text[2] == '\0') {
		switch (text[1]) {
		case '0':
			return (EDN_IND_AI24);
		case '1':
			return (EDN_IND_AI25);
		case '2':
			return (EDN_IND_AI26);
		case '3':
			return (EDN_IND_AI27);
		default:
			break;
		}
	}
	return (EDN_IND_INVALID);
}

static enum edn_ind
edn_ind_get(cbor_item_t *item)
{
	size_t i;

	for (i = 0; i < g_ninds; i++)
		if (g_inds[i].item == item)
			return (g_inds[i].ind);
	return (EDN_IND_NONE);
}

static bool
edn_ind_set(cbor_item_t *item, enum edn_ind ind, const char **err)
{
	struct edn_ind_entry *p;
	size_t ncap;

	if (g_ninds == g_inds_cap) {
		ncap = (g_inds_cap == 0) ? 8 : g_inds_cap * 2;
		p = realloc(g_inds, ncap * sizeof(*p));
		if (p == NULL) {
			*err = "out of memory";
			return (false);
		}
		g_inds = p;
		g_inds_cap = ncap;
	}
	g_inds[g_ninds].item = item;
	g_inds[g_ninds].ind = ind;
	g_ninds++;
	return (true);
}

size_t
edn_indicator_count(void)
{

	return (g_ninds);
}

/* Largest argument value encodable with the width implied by ind. */
static bool
arg_fits(uint64_t arg, enum edn_ind ind)
{

	switch (ind) {
	case EDN_IND_IMMEDIATE:
		return (arg <= 23);
	case EDN_IND_AI24:
		return (arg <= 0xffULL);
	case EDN_IND_AI25:
		return (arg <= 0xffffULL);
	case EDN_IND_AI26:
		return (arg <= 0xffffffffULL);
	case EDN_IND_AI27:
		return (true);
	default:
		return (false);
	}
}

/* Is d exactly representable in the float precision selected by ind? */
static bool
float_fits(double d, enum edn_ind ind)
{
	float f;
	uint32_t bits;

	if (isnan(d))
		return (true);
	switch (ind) {
	case EDN_IND_AI25:
		f = (float)d;
		memcpy(&bits, &f, sizeof(bits));
		return ((double)f == d && f16_to_double(f32_to_f16(bits)) == d);
	case EDN_IND_AI26:
		return ((double)(float)d == d);
	case EDN_IND_AI27:
		return (true);
	default:
		return (false);
	}
}

bool
edn_apply_indicator(cbor_item_t *item, enum edn_ind ind, const char **err)
{
	uint64_t arg;

	if (ind == EDN_IND_NONE)
		return (true);
	if (ind == EDN_IND_INVALID) {
		*err = "unknown or reserved encoding indicator";
		return (false);
	}
	switch (cbor_typeof(item)) {
	case CBOR_TYPE_UINT:
	case CBOR_TYPE_NEGINT:
		if (ind == EDN_IND_INDEF) {
			*err = "indefinite length is not valid for an integer";
			return (false);
		}
		if (!arg_fits(cbor_get_int(item), ind)) {
			*err = "encoding indicator does not provide enough "
			    "space for the value";
			return (false);
		}
		break;
	case CBOR_TYPE_FLOAT_CTRL:
		if (!cbor_is_float(item)) {
			*err = "encoding indicator is not supported for this "
			    "value";
			return (false);
		}
		if (ind != EDN_IND_AI25 && ind != EDN_IND_AI26 &&
		    ind != EDN_IND_AI27) {
			*err = "a float encoding indicator must be _1, _2 "
			    "or _3";
			return (false);
		}
		if (!float_fits(cbor_float_get_float(item), ind)) {
			*err = "value is not exactly representable at the "
			    "requested float precision";
			return (false);
		}
		break;
	case CBOR_TYPE_BYTESTRING:
		if (cbor_bytestring_is_indefinite(item) ||
		    ind == EDN_IND_INDEF) {
			*err = "use (_ ...) for indefinite-length strings";
			return (false);
		}
		if (!arg_fits(cbor_bytestring_length(item), ind)) {
			*err = "encoding indicator does not provide enough "
			    "space for the length";
			return (false);
		}
		break;
	case CBOR_TYPE_STRING:
		if (cbor_string_is_indefinite(item) || ind == EDN_IND_INDEF) {
			*err = "use (_ ...) for indefinite-length strings";
			return (false);
		}
		if (!arg_fits(cbor_string_length(item), ind)) {
			*err = "encoding indicator does not provide enough "
			    "space for the length";
			return (false);
		}
		break;
	case CBOR_TYPE_ARRAY:
		if (ind == EDN_IND_INDEF)
			return (true);	/* built indefinite already */
		if (!arg_fits(cbor_array_size(item), ind)) {
			*err = "encoding indicator does not provide enough "
			    "space for the element count";
			return (false);
		}
		break;
	case CBOR_TYPE_MAP:
		if (ind == EDN_IND_INDEF)
			return (true);	/* built indefinite already */
		if (!arg_fits(cbor_map_size(item), ind)) {
			*err = "encoding indicator does not provide enough "
			    "space for the pair count";
			return (false);
		}
		break;
	case CBOR_TYPE_TAG:
		if (ind == EDN_IND_INDEF) {
			*err = "indefinite length is not valid for a tag";
			return (false);
		}
		arg = cbor_tag_value(item);
		if (!arg_fits(arg, ind)) {
			*err = "encoding indicator does not provide enough "
			    "space for the tag number";
			return (false);
		}
		break;
	default:
		*err = "encoding indicator is not supported for this value";
		return (false);
	}
	return (edn_ind_set(item, ind, err));
}

/* Custom CBOR serializer honoring recorded encoding indicators. ----------- */

static void
put_be(struct edn_buf *out, uint64_t v, unsigned nbytes)
{
	unsigned char b[8];
	unsigned i;

	for (i = 0; i < nbytes; i++)
		b[nbytes - 1 - i] = (unsigned char)((v >> (8 * i)) & 0xff);
	edn_buf_append(out, b, nbytes);
}

/*
 * Emit the head (initial byte plus argument bytes) for major type mt and
 * argument arg, honoring ind.  EDN_IND_NONE selects the shortest head.
 */
static void
emit_head(struct edn_buf *out, unsigned mt, uint64_t arg, enum edn_ind ind)
{
	unsigned char ib;

	ib = (unsigned char)(mt << 5);
	switch (ind) {
	case EDN_IND_INDEF:
		edn_buf_putc(out, (unsigned char)(ib | 31));
		return;
	case EDN_IND_IMMEDIATE:
		edn_buf_putc(out, (unsigned char)(ib | (unsigned)arg));
		return;
	case EDN_IND_AI24:
		edn_buf_putc(out, (unsigned char)(ib | 24));
		put_be(out, arg, 1);
		return;
	case EDN_IND_AI25:
		edn_buf_putc(out, (unsigned char)(ib | 25));
		put_be(out, arg, 2);
		return;
	case EDN_IND_AI26:
		edn_buf_putc(out, (unsigned char)(ib | 26));
		put_be(out, arg, 4);
		return;
	case EDN_IND_AI27:
		edn_buf_putc(out, (unsigned char)(ib | 27));
		put_be(out, arg, 8);
		return;
	default:
		break;
	}
	/* EDN_IND_NONE: preferred (shortest) head. */
	if (arg <= 23) {
		edn_buf_putc(out, (unsigned char)(ib | (unsigned)arg));
	} else if (arg <= 0xffULL) {
		edn_buf_putc(out, (unsigned char)(ib | 24));
		put_be(out, arg, 1);
	} else if (arg <= 0xffffULL) {
		edn_buf_putc(out, (unsigned char)(ib | 25));
		put_be(out, arg, 2);
	} else if (arg <= 0xffffffffULL) {
		edn_buf_putc(out, (unsigned char)(ib | 26));
		put_be(out, arg, 4);
	} else {
		edn_buf_putc(out, (unsigned char)(ib | 27));
		put_be(out, arg, 8);
	}
}

static void
emit_float(struct edn_buf *out, double d, enum edn_ind ind, int width)
{
	float f;
	uint32_t bits32;
	uint64_t bits64;
	uint16_t h;

	/* ind selects the precision when set; otherwise use the stored one. */
	if (ind == EDN_IND_AI25 || (ind == EDN_IND_NONE && width == 16)) {
		f = (float)d;
		memcpy(&bits32, &f, sizeof(bits32));
		h = isnan(d) ? 0x7e00U : f32_to_f16(bits32);
		edn_buf_putc(out, (unsigned char)0xf9);
		put_be(out, h, 2);
	} else if (ind == EDN_IND_AI26 || (ind == EDN_IND_NONE && width == 32)) {
		f = (float)d;
		memcpy(&bits32, &f, sizeof(bits32));
		edn_buf_putc(out, (unsigned char)0xfa);
		put_be(out, bits32, 4);
	} else {
		memcpy(&bits64, &d, sizeof(bits64));
		edn_buf_putc(out, (unsigned char)0xfb);
		put_be(out, bits64, 8);
	}
}

/* Emit a major-type-7 simple/control value (false, null, simple(n), ...). */
static void
emit_simple(struct edn_buf *out, uint8_t value)
{

	if (value <= 23) {
		edn_buf_putc(out, (unsigned char)(0xe0 | value));
	} else {
		edn_buf_putc(out, (unsigned char)0xf8);
		edn_buf_putc(out, value);
	}
}

static int
float_stored_width(cbor_item_t *item)
{

	switch (cbor_float_get_width(item)) {
	case CBOR_FLOAT_16:
		return (16);
	case CBOR_FLOAT_32:
		return (32);
	default:
		return (64);
	}
}

bool
edn_serialize(cbor_item_t *item, struct edn_buf *out, const char **err)
{
	enum edn_ind ind;
	cbor_item_t **items;
	struct cbor_pair *pairs;
	size_t i, n;

	/* Raw passthrough: splice bytes verbatim (r'', float'', …). */
	if (edn_is_raw(item)) {
		edn_buf_append(out, cbor_bytestring_handle(item),
		    cbor_bytestring_length(item));
		return (true);
	}
	ind = edn_ind_get(item);
	switch (cbor_typeof(item)) {
	case CBOR_TYPE_UINT:
		emit_head(out, 0, cbor_get_int(item), ind);
		return (true);
	case CBOR_TYPE_NEGINT:
		emit_head(out, 1, cbor_get_int(item), ind);
		return (true);
	case CBOR_TYPE_FLOAT_CTRL:
		if (cbor_is_float(item))
			emit_float(out, cbor_float_get_float(item), ind,
			    float_stored_width(item));
		else
			emit_simple(out, cbor_ctrl_value(item));
		return (true);
	case CBOR_TYPE_BYTESTRING:
		if (!cbor_bytestring_is_definite(item)) {
			edn_buf_putc(out, (unsigned char)0x5f);
			items = cbor_bytestring_chunks_handle(item);
			n = cbor_bytestring_chunk_count(item);
			for (i = 0; i < n; i++)
				if (!edn_serialize(items[i], out, err))
					return (false);
			edn_buf_putc(out, (unsigned char)0xff);
			return (true);
		}
		emit_head(out, 2, cbor_bytestring_length(item), ind);
		edn_buf_append(out, cbor_bytestring_handle(item),
		    cbor_bytestring_length(item));
		return (true);
	case CBOR_TYPE_STRING:
		if (!cbor_string_is_definite(item)) {
			edn_buf_putc(out, (unsigned char)0x7f);
			items = cbor_string_chunks_handle(item);
			n = cbor_string_chunk_count(item);
			for (i = 0; i < n; i++)
				if (!edn_serialize(items[i], out, err))
					return (false);
			edn_buf_putc(out, (unsigned char)0xff);
			return (true);
		}
		emit_head(out, 3, cbor_string_length(item), ind);
		edn_buf_append(out, cbor_string_handle(item),
		    cbor_string_length(item));
		return (true);
	case CBOR_TYPE_ARRAY:
		items = cbor_array_handle(item);
		n = cbor_array_size(item);
		if (cbor_array_is_definite(item))
			emit_head(out, 4, n, ind);
		else
			edn_buf_putc(out, (unsigned char)0x9f);
		for (i = 0; i < n; i++)
			if (!edn_serialize(items[i], out, err))
				return (false);
		if (!cbor_array_is_definite(item))
			edn_buf_putc(out, (unsigned char)0xff);
		return (true);
	case CBOR_TYPE_MAP:
		pairs = cbor_map_handle(item);
		n = cbor_map_size(item);
		if (cbor_map_is_definite(item))
			emit_head(out, 5, n, ind);
		else
			edn_buf_putc(out, (unsigned char)0xbf);
		for (i = 0; i < n; i++) {
			if (!edn_serialize(pairs[i].key, out, err))
				return (false);
			if (!edn_serialize(pairs[i].value, out, err))
				return (false);
		}
		if (!cbor_map_is_definite(item))
			edn_buf_putc(out, (unsigned char)0xff);
		return (true);
	case CBOR_TYPE_TAG: {
		cbor_item_t *tagged;
		bool ok;

		emit_head(out, 6, cbor_tag_value(item), ind);
		tagged = cbor_tag_item(item);
		ok = edn_serialize(tagged, out, err);
		cbor_decref(&tagged);
		return (ok);
	}
	default:
		*err = "failed to serialize CBOR item";
		return (false);
	}
}

/* Parser context. --------------------------------------------------------- */

static struct parser_ctx *current_parser_ctx;

void
parser_ctx_set_error(struct parser_ctx *ctx, const char *message)
{

	if (ctx != NULL && !ctx->has_error) {
		ctx->has_error = true;
		ctx->error_message = message;
	}
}

void
parser_set_roots(struct parser_ctx *ctx, struct edn_vec *v)
{

	ctx->items = v->items;
	ctx->nitems = v->len;
	v->items = NULL;
	v->len = 0;
	v->cap = 0;
}

void
parser_set_ctx(struct parser_ctx *ctx)
{

	current_parser_ctx = ctx;
}

struct parser_ctx *
parser_get_ctx(void)
{

	return (current_parser_ctx);
}
