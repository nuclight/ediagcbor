" Recognize CBOR Extended Diagnostic Notation (EDN).
" Note: *.edn is commonly Clojure; use *.cedn / *.edndiag or let this script sniff content.

function! s:DetectEDN()
  for l:n in range(1, min([line('$'), 40]))
    let l:line = getline(l:n)
    if l:line =~ '^\s*$' || l:line =~ '^\s*;' || l:line =~ '^\s*#'
      continue
    endif
    if l:line =~ '\%(h\|b64\)\ze[`' . "'" . ']\|``\|<<\|undefined\|0x\x\|0o[0-7]\|0b[01]\|#\d\+(\|(_\s*)'
      setf edn
      return
    endif
    return
  endfor
endfunction

au BufRead,BufNewFile *.cedn,*.edndiag,*.cbor-diag setfiletype edn
au BufRead,BufNewFile *.edn call s:DetectEDN()
