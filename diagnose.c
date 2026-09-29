/*-
 * ediagcbor: CBOR → Extended Diagnostic Notation (EDN) printer.
 *
 * Recovers known application-extension literals from tags (RFC 8949 / 9164
 * and draft-ietf-cbor-edn-literals CPA888/CPA999) for emergency inspection.
 * Pretty-prints containers; prefers '...' over h'' for ASCII-printable
 * byte strings.
 */

#include "ediagcbor.h"

#include <sys/cdefs.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <arpa/inet.h>
#include <ctype.h>
#include <inttypes.h>
#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define	DIAG_INDENT	"  "

static bool	diag_item(cbor_item_t *, struct edn_buf *, int depth,
		    const char **);
static bool	buf_puts(struct edn_buf *, const char *);
static bool	buf_printf(struct edn_buf *, const char *, ...)
		    __printflike(2, 3);

static bool
buf_puts(struct edn_buf *b, const char *s)
{

	return (edn_buf_append(b, s, strlen(s)));
}

static bool
buf_printf(struct edn_buf *b, const char *fmt, ...)
{
	va_list ap;
	char *tmp;
	int n;
	bool ok;

	va_start(ap, fmt);
	n = vasprintf(&tmp, fmt, ap);
	va_end(ap);
	if (n < 0)
		return (false);
	ok = edn_buf_append(b, tmp, (size_t)n);
	free(tmp);
	return (ok);
}

static bool
diag_nl_indent(struct edn_buf *out, int depth)
{
	int i;

	if (!edn_buf_putc(out, '\n'))
		return (false);
	for (i = 0; i < depth; i++) {
		if (!buf_puts(out, DIAG_INDENT))
			return (false);
	}
	return (true);
}

/* True if every byte is ASCII printable (0x20..0x7e). */
static bool
bytes_ascii_printable(const unsigned char *p, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++) {
		if (p[i] < 0x20 || p[i] > 0x7e)
			return (false);
	}
	return (true);
}

/*
 * Byte string as '...' when ASCII-printable (guessed form); otherwise h''.
 * Inside '...', escape \ and ' only (content is already printable).
 */
static bool
diag_bytes(const unsigned char *p, size_t n, struct edn_buf *out)
{
	size_t i;
	unsigned char c;

	if (bytes_ascii_printable(p, n)) {
		if (!edn_buf_putc(out, '\''))
			return (false);
		for (i = 0; i < n; i++) {
			c = p[i];
			if (c == '\\' || c == '\'') {
				if (!edn_buf_putc(out, '\\'))
					return (false);
			}
			if (!edn_buf_putc(out, c))
				return (false);
		}
		return (edn_buf_putc(out, '\''));
	}
	if (!buf_puts(out, "h'"))
		return (false);
	for (i = 0; i < n; i++) {
		if (!buf_printf(out, "%02x", p[i]))
			return (false);
	}
	return (buf_puts(out, "'"));
}

static bool
diag_text_escape(const unsigned char *p, size_t n, struct edn_buf *out)
{
	size_t i;
	unsigned char c;

	if (!edn_buf_putc(out, '"'))
		return (false);
	for (i = 0; i < n; i++) {
		c = p[i];
		switch (c) {
		case '"':
		case '\\':
			if (!edn_buf_putc(out, '\\') || !edn_buf_putc(out, c))
				return (false);
			break;
		case '\n':
			if (!buf_puts(out, "\\n"))
				return (false);
			break;
		case '\r':
			if (!buf_puts(out, "\\r"))
				return (false);
			break;
		case '\t':
			if (!buf_puts(out, "\\t"))
				return (false);
			break;
		default:
			if (c < 0x20 || c == 0x7f) {
				if (!buf_printf(out, "\\u%04x", c))
					return (false);
			} else if (!edn_buf_putc(out, c))
				return (false);
			break;
		}
	}
	return (edn_buf_putc(out, '"'));
}

static bool
get_int64(cbor_item_t *item, int64_t *out)
{
	uint64_t v;

	if (cbor_typeof(item) == CBOR_TYPE_UINT) {
		v = cbor_get_int(item);
		if (v > (uint64_t)INT64_MAX)
			return (false);
		*out = (int64_t)v;
		return (true);
	}
	if (cbor_typeof(item) == CBOR_TYPE_NEGINT) {
		v = cbor_get_int(item);
		if (v >= (uint64_t)INT64_MAX)
			return (false);
		*out = (int64_t)(-1 - (int64_t)v);
		return (true);
	}
	return (false);
}

/* Tag 1 (epoch) → DT'YYYY-MM-DDTHH:MM:SSZ' (UTC, whole seconds). */
static bool
try_diag_dt(cbor_item_t *tagged, struct edn_buf *out, const char **err)
{
	cbor_item_t *content;
	int64_t secs;
	double d;
	time_t t;
	struct tm tm;
	char buf[64];

	content = cbor_tag_item(tagged);
	secs = 0;
	if (cbor_typeof(content) == CBOR_TYPE_FLOAT_CTRL &&
	    cbor_is_float(content)) {
		d = cbor_float_get_float(content);
		if (!isfinite(d) || d < (double)INT64_MIN ||
		    d > (double)INT64_MAX) {
			cbor_decref(&content);
			return (false);
		}
		secs = (int64_t)d;
	} else if (!get_int64(content, &secs)) {
		cbor_decref(&content);
		return (false);
	}
	cbor_decref(&content);
	t = (time_t)secs;
	if (gmtime_r(&t, &tm) == NULL)
		return (false);
	if (strftime(buf, sizeof(buf), "DT'%Y-%m-%dT%H:%M:%SZ'", &tm) == 0) {
		*err = "dt format failed";
		return (false);
	}
	return (buf_puts(out, buf));
}

static bool
try_diag_ip(cbor_item_t *tagged, int af, struct edn_buf *out, const char **err)
{
	cbor_item_t *content, *bs, *plen_item;
	const unsigned char *addr;
	unsigned char full[16];
	char host[INET6_ADDRSTRLEN];
	size_t n, need;
	int64_t plen64;
	long plen;

	(void)err;
	content = cbor_tag_item(tagged);
	need = (af == AF_INET) ? 4 : 16;
	plen = -1;
	bs = NULL;
	memset(full, 0, sizeof(full));

	if (cbor_typeof(content) == CBOR_TYPE_BYTESTRING &&
	    cbor_bytestring_is_definite(content)) {
		addr = cbor_bytestring_handle(content);
		n = cbor_bytestring_length(content);
		if (n > need) {
			cbor_decref(&content);
			return (false);
		}
		memcpy(full, addr, n);
	} else if (cbor_typeof(content) == CBOR_TYPE_ARRAY &&
	    cbor_array_size(content) == 2) {
		plen_item = cbor_array_get(content, 0);
		bs = cbor_array_get(content, 1);
		cbor_decref(&content);
		content = NULL;
		if (plen_item == NULL || bs == NULL ||
		    (cbor_typeof(plen_item) != CBOR_TYPE_UINT &&
		    cbor_typeof(plen_item) != CBOR_TYPE_NEGINT) ||
		    cbor_typeof(bs) != CBOR_TYPE_BYTESTRING ||
		    !cbor_bytestring_is_definite(bs)) {
			if (plen_item != NULL)
				cbor_decref(&plen_item);
			if (bs != NULL)
				cbor_decref(&bs);
			return (false);
		}
		if (!get_int64(plen_item, &plen64)) {
			cbor_decref(&plen_item);
			cbor_decref(&bs);
			return (false);
		}
		plen = (long)plen64;
		cbor_decref(&plen_item);
		addr = cbor_bytestring_handle(bs);
		n = cbor_bytestring_length(bs);
		if (n > need) {
			cbor_decref(&bs);
			return (false);
		}
		memcpy(full, addr, n);
		cbor_decref(&bs);
	} else {
		cbor_decref(&content);
		return (false);
	}
	if (content != NULL)
		cbor_decref(&content);
	if (inet_ntop(af, full, host, sizeof(host)) == NULL)
		return (false);
	if (plen < 0)
		return (buf_printf(out, "IP'%s'", host));
	return (buf_printf(out, "IP'%s/%ld'", host, plen));
}

static bool
try_diag_999(cbor_item_t *tagged, struct edn_buf *out, int depth,
    const char **err)
{
	cbor_item_t *outer, *pfx, *inner, *it;
	const unsigned char *text;
	size_t i, n, len;
	bool ok;

	outer = cbor_tag_item(tagged);
	if (cbor_typeof(outer) != CBOR_TYPE_ARRAY ||
	    cbor_array_size(outer) != 2) {
		cbor_decref(&outer);
		return (false);
	}
	pfx = cbor_array_get(outer, 0);
	inner = cbor_array_get(outer, 1);
	cbor_decref(&outer);
	if (pfx == NULL || inner == NULL ||
	    cbor_typeof(pfx) != CBOR_TYPE_STRING ||
	    !cbor_string_is_definite(pfx) ||
	    cbor_typeof(inner) != CBOR_TYPE_ARRAY) {
		if (pfx != NULL)
			cbor_decref(&pfx);
		if (inner != NULL)
			cbor_decref(&inner);
		return (false);
	}
	text = cbor_string_handle(pfx);
	len = cbor_string_length(pfx);
	for (i = 0; i < len; i++) {
		if (!isalnum(text[i]) && text[i] != '_' && text[i] != '-') {
			cbor_decref(&pfx);
			cbor_decref(&inner);
			return (false);
		}
	}
	ok = edn_buf_append(out, text, len);
	cbor_decref(&pfx);
	if (!ok) {
		cbor_decref(&inner);
		*err = "out of memory";
		return (false);
	}
	n = cbor_array_size(inner);
	if (n == 1) {
		it = cbor_array_get(inner, 0);
		cbor_decref(&inner);
		inner = NULL;
		if (it != NULL && cbor_typeof(it) == CBOR_TYPE_STRING &&
		    cbor_string_is_definite(it)) {
			text = cbor_string_handle(it);
			len = cbor_string_length(it);
			ok = edn_buf_putc(out, '\'');
			for (i = 0; ok && i < len; i++) {
				if (text[i] == '\'' || text[i] == '\\')
					ok = edn_buf_putc(out, '\\');
				if (ok)
					ok = edn_buf_putc(out, text[i]);
			}
			if (ok)
				ok = edn_buf_putc(out, '\'');
			cbor_decref(&it);
			return (ok);
		}
		if (!buf_puts(out, "<<") || it == NULL ||
		    !diag_item(it, out, depth, err) || !buf_puts(out, ">>")) {
			if (it != NULL)
				cbor_decref(&it);
			return (false);
		}
		cbor_decref(&it);
		return (true);
	}
	/* Multi-arg app-sequence: pretty-print contents. */
	if (!buf_puts(out, "<<")) {
		cbor_decref(&inner);
		return (false);
	}
	for (i = 0; i < n; i++) {
		if (!diag_nl_indent(out, depth + 1)) {
			cbor_decref(&inner);
			return (false);
		}
		it = cbor_array_get(inner, i);
		if (it == NULL || !diag_item(it, out, depth + 1, err)) {
			if (it != NULL)
				cbor_decref(&it);
			cbor_decref(&inner);
			return (false);
		}
		cbor_decref(&it);
		if (i + 1 < n && !buf_puts(out, ",")) {
			cbor_decref(&inner);
			return (false);
		}
	}
	cbor_decref(&inner);
	if (!diag_nl_indent(out, depth))
		return (false);
	return (buf_puts(out, ">>"));
}

static bool
try_diag_ellipsis(cbor_item_t *tagged, struct edn_buf *out, int depth,
    const char **err)
{
	cbor_item_t *content, *it;
	size_t i, n;

	content = cbor_tag_item(tagged);
	if (cbor_is_null(content)) {
		cbor_decref(&content);
		return (buf_puts(out, "..."));
	}
	if (cbor_typeof(content) != CBOR_TYPE_ARRAY) {
		cbor_decref(&content);
		return (false);
	}
	if (!buf_puts(out, "888([")) {
		cbor_decref(&content);
		return (false);
	}
	n = cbor_array_size(content);
	for (i = 0; i < n; i++) {
		if (!diag_nl_indent(out, depth + 1)) {
			cbor_decref(&content);
			return (false);
		}
		it = cbor_array_get(content, i);
		if (it == NULL || !diag_item(it, out, depth + 1, err)) {
			if (it != NULL)
				cbor_decref(&it);
			cbor_decref(&content);
			return (false);
		}
		cbor_decref(&it);
		if (i + 1 < n && !buf_puts(out, ",")) {
			cbor_decref(&content);
			return (false);
		}
	}
	cbor_decref(&content);
	if (n > 0 && !diag_nl_indent(out, depth))
		return (false);
	return (buf_puts(out, "])"));
}

static bool
diag_tag(cbor_item_t *item, struct edn_buf *out, int depth, const char **err)
{
	cbor_item_t *content;
	uint64_t tag;

	tag = cbor_tag_value(item);
	if (tag == 1 && try_diag_dt(item, out, err))
		return (true);
	if (tag == 52 && try_diag_ip(item, AF_INET, out, err))
		return (true);
	if (tag == 54 && try_diag_ip(item, AF_INET6, out, err))
		return (true);
	if (tag == EDN_TAG_ELLIPSIS &&
	    try_diag_ellipsis(item, out, depth, err))
		return (true);
	if (tag == EDN_TAG_UNRESOLVED &&
	    try_diag_999(item, out, depth, err))
		return (true);

	content = cbor_tag_item(item);
	if (!buf_printf(out, "%" PRIu64 "(", tag) ||
	    !diag_item(content, out, depth, err) || !buf_puts(out, ")")) {
		cbor_decref(&content);
		return (false);
	}
	cbor_decref(&content);
	return (true);
}

static bool
diag_item(cbor_item_t *item, struct edn_buf *out, int depth, const char **err)
{
	cbor_item_t *it;
	struct cbor_pair *pairs;
	size_t i, n;
	int64_t iv;
	double d;
	uint8_t ctrl;

	if (item == NULL) {
		*err = "null CBOR item";
		return (false);
	}
	switch (cbor_typeof(item)) {
	case CBOR_TYPE_UINT:
		return (buf_printf(out, "%" PRIu64, cbor_get_int(item)));
	case CBOR_TYPE_NEGINT:
		if (!get_int64(item, &iv))
			return (buf_printf(out, "-%" PRIu64,
			    cbor_get_int(item) + 1));
		return (buf_printf(out, "%" PRId64, iv));
	case CBOR_TYPE_BYTESTRING:
		if (!cbor_bytestring_is_definite(item)) {
			*err = "indefinite bytestring not supported in diagnose";
			return (false);
		}
		return (diag_bytes(cbor_bytestring_handle(item),
		    cbor_bytestring_length(item), out));
	case CBOR_TYPE_STRING:
		if (!cbor_string_is_definite(item)) {
			*err = "indefinite text string not supported in diagnose";
			return (false);
		}
		return (diag_text_escape(cbor_string_handle(item),
		    cbor_string_length(item), out));
	case CBOR_TYPE_ARRAY:
		n = cbor_array_size(item);
		if (!buf_puts(out, cbor_array_is_definite(item) ? "[" : "[_"))
			return (false);
		if (n == 0)
			return (buf_puts(out, "]"));
		for (i = 0; i < n; i++) {
			if (!diag_nl_indent(out, depth + 1))
				return (false);
			it = cbor_array_get(item, i);
			if (it == NULL || !diag_item(it, out, depth + 1, err)) {
				if (it != NULL)
					cbor_decref(&it);
				return (false);
			}
			cbor_decref(&it);
			if (i + 1 < n && !buf_puts(out, ","))
				return (false);
		}
		if (!diag_nl_indent(out, depth))
			return (false);
		return (buf_puts(out, "]"));
	case CBOR_TYPE_MAP:
		n = cbor_map_size(item);
		if (!buf_puts(out, cbor_map_is_definite(item) ? "{" : "{_"))
			return (false);
		if (n == 0)
			return (buf_puts(out, "}"));
		pairs = cbor_map_handle(item);
		for (i = 0; i < n; i++) {
			if (!diag_nl_indent(out, depth + 1))
				return (false);
			if (!diag_item(pairs[i].key, out, depth + 1, err) ||
			    !buf_puts(out, ": ") ||
			    !diag_item(pairs[i].value, out, depth + 1, err))
				return (false);
			if (i + 1 < n && !buf_puts(out, ","))
				return (false);
		}
		if (!diag_nl_indent(out, depth))
			return (false);
		return (buf_puts(out, "}"));
	case CBOR_TYPE_TAG:
		return (diag_tag(item, out, depth, err));
	case CBOR_TYPE_FLOAT_CTRL:
		if (cbor_is_bool(item))
			return (buf_puts(out, cbor_get_bool(item) ?
			    "true" : "false"));
		if (cbor_is_null(item))
			return (buf_puts(out, "null"));
		if (cbor_is_undef(item))
			return (buf_puts(out, "undefined"));
		if (cbor_is_float(item)) {
			d = cbor_float_get_float(item);
			if (isnan(d))
				return (buf_puts(out, "NaN"));
			if (isinf(d))
				return (buf_puts(out, d < 0 ?
				    "-Infinity" : "Infinity"));
			return (buf_printf(out, "%.17g", d));
		}
		ctrl = cbor_ctrl_value(item);
		return (buf_printf(out, "simple(%u)", (unsigned)ctrl));
	default:
		*err = "unsupported CBOR type in diagnose";
		return (false);
	}
}

bool
edn_diagnose(cbor_item_t *item, struct edn_buf *out, const char **err)
{

	*err = NULL;
	return (diag_item(item, out, 0, err));
}

bool
edn_diagnose_data(const unsigned char *data, size_t len, struct edn_buf *out,
    const char **err)
{
	struct cbor_load_result lr;
	cbor_item_t *item;
	size_t off, nitems;

	*err = NULL;
	off = 0;
	nitems = 0;
	while (off < len) {
		memset(&lr, 0, sizeof(lr));
		item = cbor_load(data + off, len - off, &lr);
		if (item == NULL || lr.error.code != CBOR_ERR_NONE) {
			*err = "CBOR decode failed";
			return (false);
		}
		if (nitems > 0 && !buf_puts(out, ",\n")) {
			cbor_decref(&item);
			return (false);
		}
		if (!diag_item(item, out, 0, err)) {
			cbor_decref(&item);
			return (false);
		}
		cbor_decref(&item);
		off += lr.read;
		nitems++;
	}
	if (nitems > 0 && !edn_buf_putc(out, '\n'))
		return (false);
	return (true);
}
