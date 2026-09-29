## CSV test vector format

CSV is defined in RFC 4180.
We use this format, modernized with UTF-8 instead of just ASCII, and with LF line endings (CR and newlines are allowed within quoted fields).

[Section 2][CSV] of RFC 4180 explains how quoting works and how newlines, CRs, commas, and double quotes can be included in a field.

- A record (we say row) is defined as a comma-separated sequence of zero or more fields followed by a newline.
- A field can be:
   * unquoted, with no non-printable (newline or CR), comma, or quote inside,
   * or enclosed by double quotes (`"`), where the quoted text can contain commas, double quotes (escaped by doubling as in `‎⁠""`⁠), and nonprintables such as CRs and LFs.

Each row is processed as a test; there is no header row (but header rows tend to be ignored in practice unless they attempt to look like tests).

Note that there is no intent to stay within the CSV dialect that github supports.

[CSV]: https://www.rfc-editor.org/rfc/rfc4180#section-2

An ABNF grammar for the CSV format we use is at:

https://github.com/cabo/edn-abnf/blob/main/tests/testformatgrammar.abnf.orig

... and a tool (available after a local "rake build") for turning one
or more CSV input files into a JSON array of rows, which are in turn
JSON arrays of fields, is in:
https://github.com/cabo/edn-abnf/blob/main/tests/testformat.rb

## Structure of tests

There is one test per CSV row; tests are independent.

Up to three fields are processed per row.
The first one is the "operation", the second one the "input", and the third one the "output".

* If operation is "x", the "output" field is a lowercase hex representation of encoded CBOR; otherwise, it is EDN like the "input" field always is.
* If the operation is "=", the two fields are EDN and need to yield the same CBOR data item.
* If the operation is "-", something needs to throw an error on the "input" field (and any "output" field present is ignored).
* An operation that starts with "#" or that is empty marks a comment row which is ignored.
