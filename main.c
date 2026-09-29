/*-
 * ediagcbor — emergency diagnostic for CBOR / Extended Diagnostic Notation.
 *
 * Encode EDN → CBOR or decode CBOR → EDN.  Mode can be set with -e/-d or
 * guessed from the input path suffix (*cbor → decode, *dn → encode).
 */

#include <sys/stat.h>

#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include <cbor.h>

#include "ediagcbor.h"

extern FILE	*yyin;
int		 yyparse(void);

enum run_mode {
	MODE_AUTO = 0,
	MODE_ENCODE,	/* EDN → CBOR */
	MODE_DECODE	/* CBOR → EDN */
};

static void
usage(const char *progname)
{

	fprintf(stderr,
	    "usage: %s [-e|-d] [-i input] [-o output] [file] [options]\n"
	    "\n"
	    "Emergency CBOR / EDN converter (ediagcbor).\n"
	    "  -e, --encode     EDN → CBOR (default if input ends with dn)\n"
	    "  -d, --decode     CBOR → EDN (default if input ends with cbor)\n"
	    "  -i path          input file (also: positional file)\n"
	    "  -o path          output file (default: stdout)\n"
	    "\n"
	    "If neither -e nor -d is given, the mode is guessed from the input\n"
	    "path: names ending in \"cbor\" → decode, ending in \"dn\" → encode.\n"
	    "Stdin with no hint defaults to encode.\n"
	    "\n"
	    "EDN ingest options (chairs post-27 defaults; opt-in legacy):\n"
	    "  --ellipsis --tag999 --c-comments --eol-slash-comments\n"
	    "  --legacy-numbers --indicator-suffix --raw-delim-max=N\n",
	    progname);
}

static enum run_mode
guess_mode(const char *path)
{
	size_t n;

	if (path == NULL)
		return (MODE_AUTO);
	n = strlen(path);
	if (n >= 4 && strcmp(path + n - 4, "cbor") == 0)
		return (MODE_DECODE);
	if (n >= 2 && strcmp(path + n - 2, "dn") == 0)
		return (MODE_ENCODE);
	return (MODE_AUTO);
}

static unsigned char *
read_all(FILE *fp, size_t *out_len, const char **err)
{
	unsigned char *buf, *nbuf;
	size_t cap, len, n;

	cap = 4096;
	len = 0;
	buf = malloc(cap);
	if (buf == NULL) {
		*err = "out of memory";
		return (NULL);
	}
	for (;;) {
		if (len + 1 >= cap) {
			cap *= 2;
			nbuf = realloc(buf, cap);
			if (nbuf == NULL) {
				free(buf);
				*err = "out of memory";
				return (NULL);
			}
			buf = nbuf;
		}
		n = fread(buf + len, 1, cap - len, fp);
		len += n;
		if (n == 0) {
			if (ferror(fp)) {
				free(buf);
				*err = "read error";
				return (NULL);
			}
			break;
		}
	}
	*out_len = len;
	return (buf);
}

static int
do_encode(FILE *in, FILE *out)
{
	struct parser_ctx ctx;
	struct edn_buf buf;
	const char *serr;
	size_t i, written;
	int ret;

	memset(&ctx, 0, sizeof(ctx));
	parser_set_ctx(&ctx);
	yyin = in;
	ret = 0;
	edn_buf_init(&buf);
	if (yyparse() != 0 || ctx.has_error) {
		fprintf(stderr, "ediagcbor: parse error: %s\n",
		    ctx.error_message != NULL ? ctx.error_message :
		    "invalid EDN input");
		ret = EX_DATAERR;
		goto out;
	}
	serr = NULL;
	for (i = 0; i < ctx.nitems; i++) {
		if (!edn_serialize(ctx.items[i], &buf, &serr)) {
			warnx("%s", serr != NULL ? serr :
			    "failed to serialize CBOR");
			ret = EX_SOFTWARE;
			goto out;
		}
	}
	written = fwrite(edn_buf_data(&buf), 1, edn_buf_len(&buf), out);
	if (written != edn_buf_len(&buf)) {
		warn("failed to write output");
		ret = EX_IOERR;
	}
out:
	edn_buf_free(&buf);
	for (i = 0; i < ctx.nitems; i++)
		cbor_decref(&ctx.items[i]);
	free(ctx.items);
	return (ret);
}

static int
do_decode(FILE *in, FILE *out)
{
	struct edn_buf buf;
	unsigned char *raw;
	const char *err;
	size_t len, written;
	int ret;

	err = NULL;
	raw = read_all(in, &len, &err);
	if (raw == NULL) {
		warnx("%s", err);
		return (EX_IOERR);
	}
	edn_buf_init(&buf);
	ret = 0;
	if (!edn_diagnose_data(raw, len, &buf, &err)) {
		fprintf(stderr, "ediagcbor: diagnose error: %s\n",
		    err != NULL ? err : "invalid CBOR");
		ret = EX_DATAERR;
		goto out;
	}
	written = fwrite(edn_buf_data(&buf), 1, edn_buf_len(&buf), out);
	if (written != edn_buf_len(&buf)) {
		warn("failed to write output");
		ret = EX_IOERR;
	}
out:
	edn_buf_free(&buf);
	free(raw);
	return (ret);
}

int
main(int argc, char **argv)
{
	static const struct option longopts[] = {
		{ "encode",		no_argument,	   NULL, 'e' },
		{ "decode",		no_argument,	   NULL, 'd' },
		{ "ellipsis",		no_argument,	   NULL, 1 },
		{ "tag999",		no_argument,	   NULL, 2 },
		{ "c-comments",		no_argument,	   NULL, 3 },
		{ "eol-slash-comments",	no_argument,	   NULL, 4 },
		{ "legacy-numbers",	no_argument,	   NULL, 5 },
		{ "indicator-suffix",	no_argument,	   NULL, 6 },
		{ "raw-delim-max",	required_argument, NULL, 7 },
		{ "help",		no_argument,	   NULL, 'h' },
		{ NULL,			0,		   NULL, 0 }
	};
	struct edn_opts opts;
	const char *input_path, *output_path;
	FILE *in, *out;
	enum run_mode mode, guessed;
	unsigned long delim;
	char *end;
	int ch, ret;

	edn_opts_init(&opts);
	input_path = NULL;
	output_path = NULL;
	mode = MODE_AUTO;
	while ((ch = getopt_long(argc, argv, "edi:o:h", longopts, NULL)) !=
	    -1) {
		switch (ch) {
		case 'e':
			mode = MODE_ENCODE;
			break;
		case 'd':
			mode = MODE_DECODE;
			break;
		case 'i':
			input_path = optarg;
			break;
		case 'o':
			output_path = optarg;
			break;
		case 1:
			opts.allow_ellipsis = true;
			break;
		case 2:
			opts.allow_tag999 = true;
			break;
		case 3:
			opts.allow_c_comments = true;
			break;
		case 4:
			opts.allow_eol_slash = true;
			break;
		case 5:
			opts.allow_legacy_numbers = true;
			break;
		case 6:
			opts.indicator_suffix = true;
			break;
		case 7:
			errno = 0;
			delim = strtoul(optarg, &end, 10);
			if (errno != 0 || end == optarg || *end != '\0' ||
			    delim == 0 || delim > EDN_RAW_MAX_DELIM)
				errx(EX_USAGE, "invalid --raw-delim-max "
				    "(1..%d)", EDN_RAW_MAX_DELIM);
			opts.raw_delim_max = (size_t)delim;
			break;
		case 'h':
		default:
			usage(argv[0]);
			return (EX_USAGE);
		}
	}
	if (optind < argc) {
		if (input_path != NULL)
			errx(EX_USAGE, "both -i and positional file given");
		input_path = argv[optind++];
	}
	if (optind < argc)
		errx(EX_USAGE, "extra arguments");
	edn_opts_set(&opts);

	if (mode == MODE_AUTO) {
		guessed = guess_mode(input_path);
		if (guessed != MODE_AUTO)
			mode = guessed;
		else
			mode = MODE_ENCODE;	/* stdin / unknown suffix */
	}

	in = stdin;
	out = stdout;
	if (input_path != NULL) {
		in = fopen(input_path, mode == MODE_DECODE ? "rb" : "r");
		if (in == NULL)
			err(EX_NOINPUT, "cannot open input '%s'", input_path);
	}
	if (output_path != NULL) {
		out = fopen(output_path, mode == MODE_ENCODE ? "wb" : "w");
		if (out == NULL) {
			if (in != stdin)
				fclose(in);
			err(EX_CANTCREAT, "cannot open output '%s'",
			    output_path);
		}
	}

	if (mode == MODE_ENCODE)
		ret = do_encode(in, out);
	else
		ret = do_decode(in, out);

	if (in != stdin)
		fclose(in);
	if (out != stdout)
		fclose(out);
	return (ret);
}
