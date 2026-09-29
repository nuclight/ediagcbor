/*-
 * edn2cbor: convert CBOR Extended Diagnostic Notation (EDN) to binary CBOR.
 *
 * Implements the string-literal grammar of
 * draft-ietf-cbor-edn-literals-23 (Section 2.5 / Section 5):
 * double-quoted text strings, single-quoted byte strings, raw text
 * strings, and the predefined "h" (base16) and "b64" (base64) prefixed
 * string literals, embedded in a usable item grammar (numbers, simple
 * values, arrays, maps, tags, sequence literals).
 *
 * Application-oriented extension literals (Section 3) are supported as
 * well: the "dt"/"DT" date/time and "ip"/"IP" address extensions are
 * decoded to their target data items, while any other (unknown or
 * unimplemented) application-extension identifier is wrapped in the
 * Unresolved Application-Extension Tag (EDN_TAG_UNRESOLVED / CPA999).
 */

#ifndef EDN2CBOR_H
#define EDN2CBOR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <sys/types.h>
#if defined(EDIAGCBOR_USE_COMPAT_SBUF)
#include "compat/sys/sbuf.h"	/* Ubuntu / non-FreeBSD (see GNUmakefile) */
#else
#include <sys/sbuf.h>		/* FreeBSD native — tracks base sbuf(9) */
#endif

#include <cbor.h>

/*
 * Hard ceiling on raw-string delimiter width (lexer state budget).  The
 * chairs' post-27 default is 8 (issue "Limiting backtick delimiters to
 * maximum of 8"); --raw-delim-max may raise it up to this ceiling.
 */
#define	EDN_RAW_MAX_DELIM	16
#define	EDN_RAW_DEFAULT_DELIM	8

/* Upper bound on the length of an application-extension prefix. */
#define	EDN_APP_PREFIX_MAX	64

/*
 * Stand-in tag numbers (CPA888 / CPA999 in draft -27).  Kept as named
 * constants so an eventual IANA assignment is a one-line change.  Both are
 * off by default after the chairs' removals; enable with --ellipsis /
 * --tag999.
 */
#define	EDN_TAG_ELLIPSIS	888	/* Diagnostic Notation Ellipsis */
#define	EDN_TAG_UNRESOLVED	999	/* Unresolved Application-Extension */

/*
 * Runtime feature flags.  Defaults follow the chairs' post-27 intermediate
 * decision (proposal Subject lines on the CBOR list).  Opt-in flags restore
 * draft -27 behavior for tooling that still needs it.
 */
/* Distinguishes CBOR text strings (major type 3) from byte strings (2). */
enum edn_strtype {
	EDN_TEXT,
	EDN_BYTES
};

/*
 * Encoding indicators (Section 2.3): an underscore that forces the
 * additional-information (ai) field used to encode a data item's argument.
 * "_" is indefinite length (ai=31); "_i" is immediate (ai 0..23);
 * "_0".."_3" select ai 24..27 (1/2/4/8 argument bytes).  Anything else
 * (e.g. "_a", or the reserved "_4".."_7") is invalid.
 */
enum edn_ind {
	EDN_IND_NONE = 0,	/* no indicator: use preferred serialization */
	EDN_IND_INDEF,		/* _   : indefinite length (ai=31) */
	EDN_IND_IMMEDIATE,	/* _i  : ai 0..23 (argument in the head) */
	EDN_IND_AI24,		/* _0  : ai=24, 1 argument byte */
	EDN_IND_AI25,		/* _1  : ai=25, 2 argument bytes */
	EDN_IND_AI26,		/* _2  : ai=26, 4 argument bytes */
	EDN_IND_AI27,		/* _3  : ai=27, 8 argument bytes */
	EDN_IND_INVALID		/* unknown or reserved indicator */
};

struct edn_opts {
	bool	 allow_ellipsis;	/* --ellipsis: ingest ... as CPA888 */
	bool	 allow_tag999;		/* --tag999: unknown apps -> CPA999 */
	bool	 allow_c_comments;	/* --c-comments: block and /.../ */
	bool	 allow_eol_slash;	/* --eol-slash-comments: // */
	bool	 allow_legacy_numbers;	/* --legacy-numbers: 0x/0o/0b, + */
	bool	 indicator_suffix;	/* --indicator-suffix: legacy h''_N */
	size_t	 raw_delim_max;		/* --raw-delim-max=N (default 8) */
};

void			 edn_opts_init(struct edn_opts *);
void			 edn_opts_set(const struct edn_opts *);
const struct edn_opts	*edn_opts_get(void);

/*
 * If prefix ends in a standard encoding indicator (_ / _i / _0.._3), split
 * it into *base (caller buffer) and *ind.  Returns true when a split was
 * made.  Used for front-indicator forms like h_2<<...>> / h_2'ab'.
 */
bool	edn_split_prefix_indicator(const char *prefix, char *base,
	    size_t baselen, enum edn_ind *ind);

/*
 * Growable byte buffer used to collect decoded string content.  It is
 * backed by sbuf(9): callers append with edn_buf_putc()/edn_buf_append()
 * and, once done, read the bytes with edn_buf_data()/edn_buf_len() (which
 * finalize the underlying sbuf).  No appends are allowed after reading.
 */
struct edn_buf {
	struct sbuf	*sb;
	bool		 finished;
};

/*
 * A decoded string literal handed up from the lexer: the already
 * unescaped/decoded bytes plus the resulting CBOR string type.
 */
struct edn_str {
	struct edn_buf	 buf;
	enum edn_strtype type;
	enum edn_ind	 front_ind;	/* from h_2'...' / h_2`...` */
};

/*
 * One element of a string expression (a lone string, ellipsis, or — for the
 * legacy "+" path removed in -27 — a concatenation chunk).  Still used for
 * a lone ellipsis and for t1/b1 fragment assembly.
 */
struct edn_chunk {
	struct edn_buf	 buf;
	enum edn_strtype type;
	bool		 ellipsis;
	enum edn_ind	 front_ind;
};

struct edn_chunk_list {
	struct edn_chunk	*chunks;
	size_t			 len;
	size_t			 cap;
};

/*
 * An application-extension literal handed up from the lexer: decoded
 * content (string form) plus the extension prefix (e.g. "dt", "h", "r_b").
 * front_ind is the EI between prefix and body (h_2'...' / h_2<<>>); NONE
 * when absent.  Sequence form (APPSEQOPEN) leaves buf empty.
 */
struct edn_app {
	char		*prefix;
	struct edn_buf	 buf;
	enum edn_ind	 front_ind;
};

/* A numeric token, retaining the unsigned value for use as a tag number. */
struct edn_num {
	cbor_item_t	*item;
	uint64_t	 tagval;
	bool		 taggable;
};

/* Ordered list of CBOR items (array/sequence content). */
struct edn_vec {
	cbor_item_t	**items;
	size_t		  len;
	size_t		  cap;
};

/* Ordered list of CBOR key/value pairs (map content). */
struct edn_map {
	struct cbor_pair	*pairs;
	size_t			 len;
	size_t			 cap;
};

/*
 * Parser result: the top level of an EDN document is a CBOR sequence
 * (RFC 8742), i.e. zero or more data items.  They are serialized back to
 * back; the common single-item case yields exactly one item.
 */
struct parser_ctx {
	cbor_item_t	**items;
	size_t		  nitems;
	const char	*error_message;
	bool		 has_error;
};

/* Byte-buffer helpers. */
void			 edn_buf_init(struct edn_buf *);
bool			 edn_buf_putc(struct edn_buf *, unsigned char);
bool			 edn_buf_append(struct edn_buf *, const void *,
			    size_t);
const unsigned char	*edn_buf_data(struct edn_buf *);
size_t			 edn_buf_len(struct edn_buf *);
void			 edn_buf_free(struct edn_buf *);

/* Encode a Unicode scalar value as UTF-8 into a buffer. */
bool	edn_utf8_encode(struct edn_buf *, uint32_t);

/*
 * Decoders.  Each consumes the raw inner text of a literal and writes the
 * decoded bytes into *out, returning false (with *errmsg set) on failure.
 */
bool	edn_decode_dq(const char *, size_t, struct edn_buf *,
	    const char **);
bool	edn_decode_sq(const char *, size_t, struct edn_buf *,
	    const char **);
bool	edn_decode_hex(const char *, size_t, struct edn_buf *,
	    const char **);
bool	edn_decode_b64(const char *, size_t, struct edn_buf *,
	    const char **);
/*
 * r'' "raw CBOR" inner notation: a superset of h'' base16 content that also
 * accepts CDDL-style head tokens (#M.N with optional _x width) and inline
 * string literals ("..."/'...') whose decoded content bytes are spliced in.
 * Produces the raw byte sequence; for now r'' wraps it in a CBOR byte string
 * (raw passthrough is deferred).
 */
bool	edn_decode_rawcbor(const char *, size_t, struct edn_buf *,
	    const char **);

/* Numeric construction. */
cbor_item_t	*edn_int_from_str(const char *, int, bool, const char **);
cbor_item_t	*edn_float_from_double(double);
struct edn_num	 edn_num_int(const char *, int, bool, const char **);
struct edn_num	 edn_num_double(double);

/* Container/value constructors. */
void	edn_vec_init(struct edn_vec *);
bool	edn_vec_push(struct edn_vec *, cbor_item_t *);
void	edn_vec_free_items(struct edn_vec *);
void	edn_map_init(struct edn_map *);
bool	edn_map_push(struct edn_map *, cbor_item_t *, cbor_item_t *);
void	edn_map_free_items(struct edn_map *);

cbor_item_t	*edn_make_array(struct edn_vec *, bool indefinite);
cbor_item_t	*edn_make_map(struct edn_map *, bool indefinite);
cbor_item_t	*edn_make_string(struct edn_str *);
cbor_item_t	*edn_make_indefinite_empty(enum edn_strtype);
cbor_item_t	*edn_make_streamstring(struct edn_vec *, const char **);
cbor_item_t	*edn_make_embedded(struct edn_vec *, const char **);
cbor_item_t	*edn_make_simple(unsigned long);

/*
 * Application-extension literals (Section 3 / Section 4.1).  Both consume
 * their content argument: edn_make_app() finalizes *content, while
 * edn_make_app_seq() consumes the item vector like edn_make_embedded().
 * The caller retains ownership of "prefix".
 */
cbor_item_t	*edn_make_app(const char *prefix, struct edn_buf *content,
		    const char **);
cbor_item_t	*edn_make_app_seq(const char *prefix, struct edn_vec *,
		    const char **);

/* String concatenation (Section 5.1). */
void	edn_chunk_list_init(struct edn_chunk_list *);
bool	edn_chunk_list_push_str(struct edn_chunk_list *, struct edn_str *);
bool	edn_chunk_list_push_ellipsis(struct edn_chunk_list *);
void	edn_chunk_list_free(struct edn_chunk_list *);
cbor_item_t	*edn_chunks_finish(struct edn_chunk_list *, const char **);

/*
 * Move the items collected in *v into the parser context as the top-level
 * CBOR sequence.  Consumes *v (its backing array becomes owned by the ctx).
 */
void	parser_set_roots(struct parser_ctx *, struct edn_vec *);

/*
 * Encoding indicators (Section 2.3).  edn_spec_parse() maps the lexed
 * indicator text ("_", "_i", "_2", ...) to an enum edn_ind.
 * edn_apply_indicator() validates the indicator against the item's type and
 * value (rejecting e.g. 256_0 or 1.1_1) and records it for serialization.
 * edn_serialize() writes the binary CBOR for one item, honoring any recorded
 * indicators and otherwise emitting preferred serialization (it delegates
 * indicator-free subtrees to libcbor).  edn_indicator_count() reports how
 * many indicators were recorded.
 */
enum edn_ind		 edn_spec_parse(const char *);
bool			 edn_apply_indicator(cbor_item_t *, enum edn_ind,
			    const char **);
bool			 edn_serialize(cbor_item_t *, struct edn_buf *,
			    const char **);
size_t			 edn_indicator_count(void);

/* Mark a definite bytestring for raw passthrough (no mt2 head on emit). */
bool			 edn_mark_raw(cbor_item_t *, const char **);
bool			 edn_is_raw(cbor_item_t *);

/*
 * CBOR → EDN diagnostic printer.  Known tags are recovered as app-literals
 * where possible (DT'/dt', IP'/ip', ellipsis, CPA999 → prefix'' / prefix<<>>).
 */
bool	edn_diagnose(cbor_item_t *, struct edn_buf *, const char **);
bool	edn_diagnose_data(const unsigned char *, size_t, struct edn_buf *,
	    const char **);

void	parser_ctx_set_error(struct parser_ctx *, const char *);
void	parser_set_ctx(struct parser_ctx *);
struct parser_ctx	*parser_get_ctx(void);

#endif /* EDN2CBOR_H */
