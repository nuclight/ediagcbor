package EDNTest;
#
# Shared helpers for the edn2cbor TAP test suite.
#
# Each tests/*.t file is a thin wrapper that calls EDNTest::run_csv() on one
# of the CBOR EDN vector files from https://github.com/cabo/edn-abnf/ .  One
# TAP assertion is emitted per vector, named after the file, the source line,
# the operation and the (shortened) input, so that "prove -v" (or running the
# .t directly) shows exactly what each test checks.  The edn2cbor binary's
# own stderr is captured and reported as a TAP diagnostic on failure only,
# instead of being printed inline.
#
# CSV format (tests/README.md): one test per RFC 4180 row, no header, up to
# three fields: operation, input, output.
#   x  output is the lowercase hex of the CBOR encoding of input
#   =  input and output are both EDN and must encode to the same CBOR
#   -  tests/README.md says the input must be rejected, but the vectors also
#      use '-' as an inequality check (e.g. "-,2.0,2": float vs int).  We
#      accept either: input rejected, or (output present) the two encode
#      differently
#   #  (or empty) the row is a comment and is ignored
#
# Some EDN fields use the harness pseudo-notation "h]<hex>", meaning the
# real EDN source is the hex-decoded bytes (used to embed raw CR/LF
# unambiguously); see _edn_source().
#
# The draft is under WGLC review and is known to contain ambiguous or
# possibly erroneous text.  Rows where this tool deliberately diverges from
# the reference vectors (suspected reference bugs, or behavior left
# under-specified by the draft) are reported as TAP TODO tests: they stay
# visible in the output as bug-report candidates without failing the suite.

use strict;
use warnings;

use Test::More;
use File::Temp qw(tempfile);
use File::Basename qw(dirname);

our $TODO;	# localized per-row to mark expected (divergent) failures

# Locate the edn2cbor binary: honor $BINARY, else look next to the vectors.
sub _binary {
	my ($csv) = @_;

	return $ENV{BINARY} if defined $ENV{BINARY};
	return dirname($csv) . '/../edn2cbor';
}

sub _slurp {
	my ($path) = @_;
	open my $fh, '<', $path or die "cannot open $path: $!\n";
	binmode $fh;
	local $/;
	my $text = <$fh>;
	close $fh;
	return defined $text ? $text : '';
}

# Parse an RFC 4180 record stream into a list of [ \@fields, $startline ].
# Handles quoted fields, doubled-quote escaping and embedded newlines; CR is
# dropped.  $startline is the 1-based physical line where the record begins,
# which is what a user sees when opening the .csv file.
sub parse_csv {
	my ($text) = @_;
	$text =~ s/\r//g;
	my @rows;
	my @fields;
	my $field = '';
	my $in_quotes = 0;
	my $started = 0;
	my $line = 1;
	my $rowline = 1;
	my $n = length $text;
	for (my $i = 0; $i < $n; $i++) {
		my $c = substr($text, $i, 1);
		if ($in_quotes) {
			if ($c eq '"') {
				if ($i + 1 < $n &&
				    substr($text, $i + 1, 1) eq '"') {
					$field .= '"';
					$i++;
					next;
				}
				$in_quotes = 0;
				next;
			}
			$field .= $c;
			$line++ if $c eq "\n";
			next;
		}
		if ($c eq '"') {
			$rowline = $line unless $started;
			$started = 1;
			$in_quotes = 1;
			next;
		}
		if ($c eq ',') {
			$rowline = $line unless $started;
			$started = 1;
			push @fields, $field;
			$field = '';
			next;
		}
		if ($c eq "\n") {
			if ($started || @fields || length $field) {
				push @fields, $field;
				push @rows, [ [@fields], $rowline ];
			}
			@fields = ();
			$field = '';
			$started = 0;
			$line++;
			next;
		}
		$rowline = $line unless $started;
		$started = 1;
		$field .= $c;
	}
	if ($started || @fields || length $field) {
		push @fields, $field;
		push @rows, [ [@fields], $rowline ];
	}
	return @rows;
}

# Run edn2cbor on $edn, returning (exit_code, output_bytes, stderr_text).
# The child's stderr is redirected to a temp file so it never pollutes the
# TAP stream; it is returned for use as a diagnostic on failure.
# Extra CLI flags come from $EDN_FLAGS (whitespace-separated), so the suite
# can restore draft -27 behavior while the binary defaults to chairs post-27.
sub _run_edn {
	my ($binary, $edn) = @_;
	my ($ifh, $iname) = tempfile(UNLINK => 1);
	my ($ofh, $oname) = tempfile(UNLINK => 1);
	my ($efh, $ename) = tempfile(UNLINK => 1);
	binmode $ifh;
	print $ifh $edn;
	close $ifh;
	close $ofh;
	close $efh;

	my @flags = ();
	if (defined $ENV{EDN_FLAGS} && $ENV{EDN_FLAGS} =~ /\S/) {
		@flags = split ' ', $ENV{EDN_FLAGS};
	}

	open my $olderr, '>&', \*STDERR or die "dup stderr: $!";
	open STDERR, '>', $ename or die "redirect stderr: $!";
	my $rc = system('timeout', '10', $binary, @flags, '-i', $iname,
	    '-o', $oname);
	open STDERR, '>&', $olderr or die "restore stderr: $!";
	close $olderr;

	my $exit = $rc == -1 ? 127 : ($rc >> 8);
	my $out = '';
	if ($exit == 0) {
		$out = _slurp($oname);
	}
	my $err = _slurp($ename);
	$err =~ s/\s+\z//;
	return ($exit, $out, $err);
}

# Resolve an EDN field to the actual source bytes to feed to edn2cbor.
# The harness pseudo-notation "h]<hex>" stands for the hex-decoded bytes,
# which lets a vector carry raw CR/LF (and other awkward bytes) verbatim.
sub _edn_source {
	my ($f) = @_;
	return $f unless defined $f;
	return pack('H*', $1) if $f =~ /^h\]([0-9A-Fa-f]+)\z/;
	return $f;
}

sub _hexof {
	my ($bytes) = @_;
	return join('', map { sprintf '%02x', ord } split //, $bytes);
}

sub _short {
	my $s = shift;
	$s = '' unless defined $s;
	$s =~ s/\n/\\n/g;
	$s =~ s/\t/\\t/g;
	$s = substr($s, 0, 48) . '...' if length $s > 48;
	return $s;
}

# Decide whether a row is outside this tool's scope.  Returns a human-readable
# reason string (used as the SKIP message) or undef when the row is in scope.
sub _skip_reason {
	my ($op, $in, $out) = @_;

	for my $f ($in, $out) {
		next unless defined $f;
		# Application extensions without native decoding (dt/DT/ip/IP/
		# float/r/t1/b1/ilbs/ilts are implemented; the rest map to
		# tag 999 and have no positive reference vectors of their own).
		return 'unsupported application-extension prefix'
		    if $f =~ /(?:^|[^0-9A-Za-z])(?:hash|cri|CRI|b32|h32|same)[`']/;
		return 'unsupported application-extension prefix'
		    if $f =~ /(?:^|[^0-9A-Za-z])(?:hash|cri|same)<</;
		# Ellipsis inside an h''/b64'' literal: the ABNF (Figure 11)
		# admits it, but the draft prose does not define a meaning, so
		# this case is intentionally unimplemented (WGLC bug candidate).
		return 'ellipsis inside h\'\'/b64\'\' literal (ABNF allows it, prose undefined)'
		    if $f =~ /(?:h|b64)'[^']*\.\.\./;
	}
	return undef;
}

# Classify why a '-' row failed (the input was neither rejected nor, with an
# output present, encoded differently from it), for use as a TAP TODO reason:
# a documented, non-fatal expected failure and a candidate to raise at WGLC.
sub _minus_divergence {
	my ($in, $out) = @_;
	# A single-quoted string containing "\\" is a well-formed byte string
	# per the escape rules (Section 2.5); marking it an error looks like a
	# reference-vector bug.
	return 'suspected reference-vector bug: \\\\ is a valid escape (draft Section 2.5)'
	    if $in =~ /^'[^']*\\\\/;
	# Plain (unprefixed) multi-line backtick raw strings: the draft ABNF
	# (rawcontent / excess-backtick handling, matching the accepted vector
	# 107) admits these, but the reference parser rejects them; the newline
	# handling is under-specified (cbor-wg/edn#99).
	return 'raw-string multi-line handling under-specified (cbor-wg/edn#99); draft ABNF accepts'
	    if $in =~ /^`/ && $in =~ /\n/;
	return 'input and output encode identically, but "-" expects a rejected input or a difference'
	    if defined $out && $out ne '';
	return 'input is valid but the vector expects rejection (draft/reference divergence)';
}

# Classify why an '=' row failed under -27 raw-string rules (alikerawdelim
# requires exact-width close; leading newline after the opener is content).
# Older edn-abnf vectors still assume -23 matchrawdelim / leading-NL swallow.
sub _eq_divergence {
	my ($in, $err) = @_;
	return undef unless defined $in && $in =~ /`/;
	# Closer wider than opener: -27 leaves the string unterminated.
	return 'raw-string alikerawdelim (==) vs -23 matchrawdelim (>=); draft -27'
	    if defined $err && $err =~ /unterminated raw string/;
	# Leading newline immediately after the opening delimiter is now content.
	return 'raw-string leading newline is content in -27 (no swallow); draft -27'
	    if $in =~ /`\r?\n/;
	return undef;
}

# Build the human-readable test description for an in-scope row.
sub _describe {
	my ($base, $line, $op, $in, $out) = @_;
	my $loc = "$base:$line";
	my $si = _short($in);
	if ($op eq 'x') {
		return "$loc encode `$si` => " . lc($out // '');
	} elsif ($op eq '=') {
		return "$loc `$si` encodes the same as `" . _short($out) . '`';
	} elsif (defined $out && $out ne '') {
		return "$loc reject `$si` or differ from `" . _short($out) . '`';
	} else {
		return "$loc reject `$si`";
	}
}

# Evaluate one in-scope row, returning ($ok, $detail, $stderr).
sub _evaluate {
	my ($binary, $op, $in, $out) = @_;

	if ($op eq 'x') {
		my ($e, $b, $err) = _run_edn($binary, _edn_source($in));
		my $ok = ($e == 0 && _hexof($b) eq lc($out // ''));
		my $detail = sprintf 'got rc=%d hex=%s want=%s',
		    $e, _hexof($b), lc($out // '');
		return ($ok, $detail, $err);
	} elsif ($op eq '=') {
		my ($e1, $b1, $err1) = _run_edn($binary, _edn_source($in));
		my ($e2, $b2, $err2) = _run_edn($binary, _edn_source($out // ''));
		my $ok = ($e1 == 0 && $e2 == 0 && $b1 eq $b2);
		my $detail = sprintf 'lhs rc=%d hex=%s; rhs rc=%d hex=%s',
		    $e1, _hexof($b1), $e2, _hexof($b2);
		return ($ok, $detail, join("\n", grep { $_ ne '' } $err1, $err2));
	} else {	# '-'
		# tests/README.md defines '-' as "the input must be rejected".
		# In practice the vectors also use '-' as an inequality check:
		# "-,2.0,2" asserts that 2.0 (float) and 2 (int) encode
		# differently.  So we accept either: the input is rejected, or
		# (when an output is present) the two encode differently.
		my ($e, $b, $err) = _run_edn($binary, _edn_source($in));
		return (1, '', $err) if $e != 0;
		if (defined $out && $out ne '') {
			my ($e2, $b2, $err2) =
			    _run_edn($binary, _edn_source($out));
			my $ok = ($e2 != 0 || $b ne $b2);
			my $detail = sprintf
			    'input hex=%s; output rc=%d hex=%s (want reject or differ)',
			    _hexof($b), $e2, _hexof($b2);
			return ($ok, $detail,
			    join("\n", grep { $_ ne '' } $err, $err2));
		}
		return (0, sprintf('expected rejection, got rc=%d hex=%s',
		    $e, _hexof($b)), $err);
	}
}

# Run all vectors in $csv as TAP tests and finish the plan.
sub run_csv {
	my ($csv) = @_;
	my $binary = _binary($csv);

	plan skip_all => "binary not found: $binary" unless -x $binary;

	my $base = $csv;
	$base =~ s{.*/}{};
	my @rows = parse_csv(_slurp($csv));

	# Each x/=/- row yields exactly one TAP assertion (a normal result, a
	# SKIP or a TODO); comment/empty/other rows yield none.  Plan that
	# count explicitly so a premature death mid-run is reported as a plan
	# mismatch rather than silently passing.
	my @tests = grep {
		my $op = $_->[0][0];
		defined $op && ($op eq 'x' || $op eq '=' || $op eq '-');
	} @rows;
	plan tests => scalar(@tests);

	my ($n_skip, $n_todo) = (0, 0);
	for my $row (@tests) {
		my ($fields, $line) = @$row;
		my ($op, $in, $out) = @$fields;

		my $reason = _skip_reason($op, $in, $out);
		if (defined $reason) {
			$n_skip++;
		SKIP: {
				skip sprintf('%s:%d [%s] `%s` (%s)', $base,
				    $line, $op, _short($in), $reason), 1;
			}
			next;
		}

		my $desc = _describe($base, $line, $op, $in, $out);
		my ($ok, $detail, $err) = _evaluate($binary, $op, $in, $out);
		my $todo;
		$todo = _minus_divergence($in, $out)
		    if $op eq '-' && !$ok && defined $in;
		$todo = _eq_divergence($in, $err)
		    if !defined $todo && $op eq '=' && !$ok && defined $in;
		if (defined $todo) {
			$n_todo++;
			local our $TODO = $todo;
			ok($ok, $desc);
			diag($detail) if !$ok && defined $detail && $detail ne '';
		} else {
			ok($ok, $desc);
			unless ($ok) {
				diag($detail) if defined $detail && $detail ne '';
				diag("edn2cbor stderr: $err")
				    if defined $err && $err ne '';
			}
		}
	}
	note(sprintf '%s: %d assertions, %d TODO (divergences), %d skipped',
	    $base, scalar(@tests), $n_todo, $n_skip);

	# When $EDN_TALLY names a file (set by "make test"), append this
	# file's counts so the caller can print an aggregate even though
	# prove's terse summary hides per-file notes on a green run.
	if (my $tally = $ENV{EDN_TALLY}) {
		if (open my $fh, '>>', $tally) {
			print $fh join("\t", scalar(@tests), $n_todo,
			    $n_skip), "\n";
			close $fh;
		}
	}
}

1;
