" Vim syntax file
" Language:     CBOR Extended Diagnostic Notation (EDN)
" Reference:   draft-ietf-cbor-edn-literals-23
" Based on:     syntax/json.vim (strings, numbers, booleans)

if exists("b:current_syntax")
  finish
endif

" --- JSON-compatible core ---------------------------------------------------

syn match  ednNoise  /[:,]/

syn region ednString matchgroup=ednQuote
      \ start=/"/ skip=/\\"\|\\u{\x\+}\|\\u\x\{4\}\|\\./ end=/"/
      \ contains=ednEscape,@Spell
syn match  ednEscape  "\\\(u{\x\+}\|u\x\{4\}\|\\["\\/bfnrt]\)" contained

syn match  ednNumberDec /-\@<!\<\d\+\%(\.\d*\)\=\%([eE][+-]\=\d\+\)\=\>/
syn match  ednNumberDec /-\@<=\<\d\+\%(\.\d*\)\=\%([eE][+-]\=\d\+\)\=\>/
syn match  ednNumberHex /\<0x\x\+\%(\.\d*\)\=\%([pP][+-]\=\d\+\)\=\>/
syn match  ednNumberOct /\<0o[0-7]\+\>/
syn match  ednNumberBin /\<0b[01]\+\>/
syn keyword ednFloatInf Infinity -Infinity
syn keyword ednFloatNan NaN
syn match  ednEncodingSpec /_\%(\d\|i\|[A-Za-z_][A-Za-z0-9_]*\)\>/

syn keyword ednBoolean true false
syn keyword ednNull    null
syn keyword ednUndef   undefined

syn region ednFold matchgroup=ednBraces start="{" end=/}/ transparent fold
syn region ednFold matchgroup=ednBraces start="\[" end=/]/ transparent fold

" --- EDN extensions ---------------------------------------------------------

syn region ednByteString matchgroup=ednQuote
      \ start=/'/ skip=/\\'\|\\u{\x\+}\|\\u\x\{4\}\|\\./ end=/'/
      \ contains=ednEscapeSq,@Spell
syn match  ednEscapeSq  "\\\(u{\x\+}\|u\x\{4\}\|\\['\\bfnrt]\)" contained

" App-prefixed `...` literals (h, b64, …) — not raw strings.
syn region ednAppLiteral matchgroup=ednAppPrefix
      \ start=/\%(\<[a-z][a-z0-9-]*\)\zs`/ end=/`/
      \ contains=ednAppPrefixBuiltin,@Spell
syn keyword ednAppPrefixBuiltin h b64 dt ip hash cri contained

" Raw strings (draft §2.5.3): N backticks open; close with the same N at the end
" of a backtick run (extra ` before that run are content). Longer runs first.
" ms=e+1 must be glued to start= (see :help :syn-region).
syn region ednRawString6 matchgroup=ednRawDelim start=#``````\ze[^`]#ms=e+1 end=#``````\ze\%($\|[^`]\)# contains=ednRawBacktick,@Spell
syn region ednRawString5 matchgroup=ednRawDelim start=#`````\ze[^`]#ms=e+1 end=#`````\ze\%($\|[^`]\)# contains=ednRawBacktick,@Spell
syn region ednRawString4 matchgroup=ednRawDelim start=#````\ze[^`]#ms=e+1 end=#````\ze\%($\|[^`]\)# contains=ednRawBacktick,@Spell
syn region ednRawString3 matchgroup=ednRawDelim start=#```\ze[^`]#ms=e+1 end=#```\ze\%($\|[^`]\)# contains=ednRawBacktick,@Spell
syn region ednRawString2 matchgroup=ednRawDelim start=#^\s*``\ze[^`]#ms=e+1 end=#``\ze\%($\|[^`]\)# contains=ednRawBacktick,@Spell
syn match ednRawBacktick /`/ contained

syn match  ednSimple   /simple(\s*\d\+\s*)/
syn match  ednTag       /\d\+\ze\_s*(/
syn match  ednEllipsis  /\.\{3,}/
syn match  ednConcat    /[+]/
syn region ednStream    start=/(\s*_\s*/ end=/)/
syn region ednEmbedded  start=/<<\ze\_s*/ end=/>>\ze\_s*/

syn keyword ednTodo  TODO FIXME XXX contained
syn match   ednComment  /#.*$/ contains=ednTodo
syn region  ednComment  start=/\/\// end=/$/ contains=ednTodo
syn region  ednComment  start=/\/\*/ end=/\*\// contains=ednTodo

" --- Highlight links --------------------------------------------------------

hi def link ednString          String
hi def link ednByteString      String
hi def link ednAppLiteral      String
hi def link ednRawString2      String
hi def link ednRawString3      String
hi def link ednRawString4      String
hi def link ednRawString5      String
hi def link ednRawString6      String
hi def link ednRawBacktick     Special
hi def link ednQuote           Quote
hi def link ednRawDelim        Delimiter
hi def link ednEscape          Special
hi def link ednEscapeSq        Special
hi def link ednNumberDec       Number
hi def link ednNumberHex       Number
hi def link ednNumberOct       Number
hi def link ednNumberBin       Number
hi def link ednFloatInf        Float
hi def link ednFloatNan        Float
hi def link ednBoolean         Boolean
hi def link ednNull            Constant
hi def link ednUndef           Constant
hi def link ednSimple          Function
hi def link ednAppPrefix       Type
hi def link ednAppPrefixBuiltin Type
hi def link ednEncodingSpec    Special
hi def link ednTag             Label
hi def link ednEllipsis        PreProc
hi def link ednStream          PreProc
hi def link ednEmbedded        PreProc
hi def link ednComment         Comment
hi def link ednTodo            Todo
hi def link ednNoise           Noise
hi def link ednConcat          Operator
hi def link ednBraces          Delimiter

let b:current_syntax = 'edn'

" vim: ts=8 sw=2 sts=2
