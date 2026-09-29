%{
/*-
 * Grammar for the practical subset of CBOR EDN handled by edn2cbor:
 * a single CBOR item built from numbers, simple values, string literals,
 * arrays, maps, tags, sequence literals and indefinite-length strings.
 * See draft-ietf-cbor-edn-literals (v27 semantics: no "+" concatenation).
 */
#include <stdlib.h>

#include "ediagcbor.h"

int	yylex(void);
void	yyerror(const char *);

#define	FAIL(msg)	do {						\
	parser_ctx_set_error(parser_get_ctx(), (msg));			\
	YYABORT;							\
} while (0)
%}

%union {
	struct edn_num		 num;
	struct edn_str		 str;
	struct edn_app		 app;
	cbor_item_t		*item;
	struct edn_vec		*vec;
	struct edn_map		*map;
	struct edn_chunk_list	*chunks;
	unsigned long		 simple;
	int			 indef;
}

%token <num>	NUMBER
%token <str>	TSTR BSTR
%token <app>	APPSTR APPSEQOPEN
%token <simple>	SIMPLEVAL
%token		KTRUE KFALSE KNULL KUNDEF
%token		INDEF_TSTR_EMPTY INDEF_BSTR_EMPTY
%token		ELLIPSIS SEQOPEN SEQCLOSE LEXERR
%token <indef>	SPEC

%type <item>	item simple_lit array map embedded streamstring number_or_tag
%type <item>	string_expr app_lit
%type <chunks>	chunks
%type <vec>	arr_items seq_items top_items
%type <map>	map_pairs
%type <indef>	opt_indef

%%

input:
	top_items {
		parser_set_roots(parser_get_ctx(), $1);
		free($1);
	}
	;

top_items:
	  /* empty */ {
		$$ = malloc(sizeof(*$$));
		if ($$ == NULL)
			FAIL("out of memory");
		edn_vec_init($$);
	}
	| top_items item {
		if (!edn_vec_push($1, $2)) {
			cbor_decref(&$2);
			edn_vec_free_items($1);
			free($1);
			FAIL("out of memory");
		}
		$$ = $1;
	}
	;

item:
	  number_or_tag		{ $$ = $1; }
	| simple_lit		{ $$ = $1; }
	| string_expr		{ $$ = $1; }
	| app_lit		{ $$ = $1; }
	| array			{ $$ = $1; }
	| map			{ $$ = $1; }
	| embedded		{ $$ = $1; }
	| streamstring		{ $$ = $1; }
	| INDEF_TSTR_EMPTY	{
		$$ = edn_make_indefinite_empty(EDN_TEXT);
		if ($$ == NULL)
			FAIL("out of memory");
	}
	| INDEF_BSTR_EMPTY	{
		$$ = edn_make_indefinite_empty(EDN_BYTES);
		if ($$ == NULL)
			FAIL("out of memory");
	}
	;

number_or_tag:
	  NUMBER {
		$$ = $1.item;
	}
	| NUMBER SPEC {
		const char *err;

		err = NULL;
		$$ = $1.item;
		if (!edn_apply_indicator($$, (enum edn_ind)$2, &err)) {
			cbor_decref(&$$);
			FAIL(err);
		}
	}
	| NUMBER '(' item ')' {
		if (!$1.taggable) {
			cbor_decref(&$1.item);
			cbor_decref(&$3);
			FAIL("tag number must be an unsigned integer");
		}
		cbor_decref(&$1.item);
		$$ = cbor_build_tag($1.tagval, cbor_move($3));
		if ($$ == NULL)
			FAIL("out of memory");
	}
	| NUMBER SPEC '(' item ')' {
		const char *err;

		if (!$1.taggable) {
			cbor_decref(&$1.item);
			cbor_decref(&$4);
			FAIL("tag number must be an unsigned integer");
		}
		cbor_decref(&$1.item);
		$$ = cbor_build_tag($1.tagval, cbor_move($4));
		if ($$ == NULL)
			FAIL("out of memory");
		err = NULL;
		if (!edn_apply_indicator($$, (enum edn_ind)$2, &err)) {
			cbor_decref(&$$);
			FAIL(err);
		}
	}
	;

simple_lit:
	  KTRUE			{ $$ = cbor_build_bool(true); }
	| KFALSE		{ $$ = cbor_build_bool(false); }
	| KNULL			{ $$ = cbor_new_null(); }
	| KUNDEF		{ $$ = cbor_new_undef(); }
	| SIMPLEVAL {
		$$ = edn_make_simple($1);
		if ($$ == NULL)
			FAIL("out of memory");
	}
	;

string_expr:
	  chunks {
		const char *err;

		err = NULL;
		$$ = edn_chunks_finish($1, &err);
		edn_chunk_list_free($1);
		free($1);
		if ($$ == NULL)
			FAIL(err);
	}
	| chunks SPEC {
		const char *err;

		err = NULL;
		$$ = edn_chunks_finish($1, &err);
		edn_chunk_list_free($1);
		free($1);
		if ($$ == NULL)
			FAIL(err);
		if (!edn_apply_indicator($$, (enum edn_ind)$2, &err)) {
			cbor_decref(&$$);
			FAIL(err);
		}
	}
	;

app_lit:
	  APPSTR {
		const char *err;
		enum edn_ind front;

		err = NULL;
		front = $1.front_ind;
		$$ = edn_make_app($1.prefix, &$1.buf, &err);
		free($1.prefix);
		if ($$ == NULL)
			FAIL(err);
		if (front != EDN_IND_NONE && front != EDN_IND_INVALID &&
		    !edn_apply_indicator($$, front, &err)) {
			cbor_decref(&$$);
			FAIL(err);
		}
	}
	| APPSTR SPEC {
		const char *err;
		enum edn_ind front, trail;

		err = NULL;
		front = $1.front_ind;
		trail = (enum edn_ind)$2;
		$$ = edn_make_app($1.prefix, &$1.buf, &err);
		free($1.prefix);
		if ($$ == NULL)
			FAIL(err);
		/*
		 * New (default): trailing SPEC is the argument EI; front EI
		 * on the prefix is the result.  Legacy --indicator-suffix:
		 * trailing SPEC alone is the result EI (draft -27).
		 */
		if (front != EDN_IND_NONE && front != EDN_IND_INVALID) {
			if (!edn_apply_indicator($$, front, &err)) {
				cbor_decref(&$$);
				FAIL(err);
			}
			/* Argument-side trail is accepted but not re-encoded. */
			(void)trail;
		} else if (edn_opts_get()->indicator_suffix) {
			/* Draft -27: trailing EI applies to the app result. */
			if (!edn_apply_indicator($$, trail, &err)) {
				cbor_decref(&$$);
				FAIL(err);
			}
		} else {
			/*
			 * Front-indicator regime (Sent/1035): a lone trailing
			 * SPEC is the argument EI.  Known apps decode content
			 * only; argument EI is accepted without re-encoding.
			 */
			(void)trail;
		}
	}
	| APPSEQOPEN seq_items SEQCLOSE {
		const char *err;
		enum edn_ind front;

		err = NULL;
		front = $1.front_ind;
		$$ = edn_make_app_seq($1.prefix, $2, &err);
		free($1.prefix);
		free($2);
		if ($$ == NULL)
			FAIL(err);
		if (front != EDN_IND_NONE && front != EDN_IND_INVALID &&
		    !edn_apply_indicator($$, front, &err)) {
			cbor_decref(&$$);
			FAIL(err);
		}
	}
	| APPSEQOPEN seq_items SEQCLOSE SPEC {
		const char *err;
		enum edn_ind front;

		if (!edn_opts_get()->indicator_suffix) {
			free($1.prefix);
			edn_vec_free_items($2);
			free($2);
			FAIL("trailing EI on app-sequence needs "
			    "--indicator-suffix; use prefix_EI<<…>>");
		}
		err = NULL;
		front = $1.front_ind;
		$$ = edn_make_app_seq($1.prefix, $2, &err);
		free($1.prefix);
		free($2);
		if ($$ == NULL)
			FAIL(err);
		if (front != EDN_IND_NONE && front != EDN_IND_INVALID &&
		    !edn_apply_indicator($$, front, &err)) {
			cbor_decref(&$$);
			FAIL(err);
		}
		if (!edn_apply_indicator($$, (enum edn_ind)$4, &err)) {
			cbor_decref(&$$);
			FAIL(err);
		}
	}
	;

chunks:
	  TSTR {
		$$ = malloc(sizeof(*$$));
		if ($$ == NULL)
			FAIL("out of memory");
		edn_chunk_list_init($$);
		if (!edn_chunk_list_push_str($$, &$1))
			FAIL("out of memory");
	}
	| BSTR {
		$$ = malloc(sizeof(*$$));
		if ($$ == NULL)
			FAIL("out of memory");
		edn_chunk_list_init($$);
		if (!edn_chunk_list_push_str($$, &$1))
			FAIL("out of memory");
	}
	| ELLIPSIS {
		$$ = malloc(sizeof(*$$));
		if ($$ == NULL)
			FAIL("out of memory");
		edn_chunk_list_init($$);
		if (!edn_chunk_list_push_ellipsis($$))
			FAIL("out of memory");
	}
	;

opt_indef:
	  /* empty */		{ $$ = EDN_IND_NONE; }
	| SPEC			{ $$ = $1; }
	;

array:
	'[' opt_indef arr_items ']' {
		const char *err;

		$$ = edn_make_array($3, (enum edn_ind)$2 == EDN_IND_INDEF);
		free($3);
		if ($$ == NULL)
			FAIL("out of memory");
		err = NULL;
		if ((enum edn_ind)$2 != EDN_IND_NONE &&
		    (enum edn_ind)$2 != EDN_IND_INDEF &&
		    !edn_apply_indicator($$, (enum edn_ind)$2, &err)) {
			cbor_decref(&$$);
			FAIL(err);
		}
	}
	;

arr_items:
	  /* empty */ {
		$$ = malloc(sizeof(*$$));
		if ($$ == NULL)
			FAIL("out of memory");
		edn_vec_init($$);
	}
	| arr_items item {
		if (!edn_vec_push($1, $2)) {
			cbor_decref(&$2);
			edn_vec_free_items($1);
			free($1);
			FAIL("out of memory");
		}
		$$ = $1;
	}
	;

map:
	'{' opt_indef map_pairs '}' {
		const char *err;

		$$ = edn_make_map($3, (enum edn_ind)$2 == EDN_IND_INDEF);
		free($3);
		if ($$ == NULL)
			FAIL("out of memory");
		err = NULL;
		if ((enum edn_ind)$2 != EDN_IND_NONE &&
		    (enum edn_ind)$2 != EDN_IND_INDEF &&
		    !edn_apply_indicator($$, (enum edn_ind)$2, &err)) {
			cbor_decref(&$$);
			FAIL(err);
		}
	}
	;

map_pairs:
	  /* empty */ {
		$$ = malloc(sizeof(*$$));
		if ($$ == NULL)
			FAIL("out of memory");
		edn_map_init($$);
	}
	| map_pairs item ':' item {
		if (!edn_map_push($1, $2, $4)) {
			cbor_decref(&$2);
			cbor_decref(&$4);
			edn_map_free_items($1);
			free($1);
			FAIL("out of memory");
		}
		$$ = $1;
	}
	;

embedded:
	SEQOPEN seq_items SEQCLOSE {
		const char *err;

		err = NULL;
		$$ = edn_make_embedded($2, &err);
		free($2);
		if ($$ == NULL)
			FAIL(err);
	}
	| SEQOPEN seq_items SEQCLOSE SPEC {
		const char *err;

		if (!edn_opts_get()->indicator_suffix) {
			edn_vec_free_items($2);
			free($2);
			FAIL("trailing EI on <<>> needs --indicator-suffix; "
			    "use an app-prefix_EI<<…>> form");
		}
		err = NULL;
		$$ = edn_make_embedded($2, &err);
		free($2);
		if ($$ == NULL)
			FAIL(err);
		if (!edn_apply_indicator($$, (enum edn_ind)$4, &err)) {
			cbor_decref(&$$);
			FAIL(err);
		}
	}
	;

streamstring:
	'(' SPEC seq_items ')' {
		const char *err;

		err = NULL;
		$$ = edn_make_streamstring($3, &err);
		free($3);
		if ($$ == NULL)
			FAIL(err);
	}
	;

seq_items:
	  /* empty */ {
		$$ = malloc(sizeof(*$$));
		if ($$ == NULL)
			FAIL("out of memory");
		edn_vec_init($$);
	}
	| seq_items item {
		if (!edn_vec_push($1, $2)) {
			cbor_decref(&$2);
			edn_vec_free_items($1);
			free($1);
			FAIL("out of memory");
		}
		$$ = $1;
	}
	;

%%

void
yyerror(const char *msg)
{

	parser_ctx_set_error(parser_get_ctx(), msg);
}
