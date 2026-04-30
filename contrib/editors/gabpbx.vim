" Vim syntax file
" Language:	GABpbx config file
" Maintainer:	tilghman
" Last Change:	2009 Mar 04 
" version 0.5
"
if version < 600
  syntax clear
elseif exists("b:current_syntax")
  finish
endif

syn sync clear
syn sync fromstart

syn keyword     gabpbxTodo            TODO contained
syn match       gabpbxComment         ";.*" contains=gabpbxTodo
syn match       gabpbxContext         "\[.\{-}\]"
syn match       gabpbxExten           "^\s*exten\s*=>\?\s*[^,]\+" contains=gabpbxPattern
syn match       gabpbxExten           "^\s*\(register\|channel\|ignorepat\|include\|\(no\)\?load\)\s*=>\?"
syn match       gabpbxPattern         "_\(\[[[:alnum:]#*\-]\+\]\|[[:alnum:]#*]\)*\.\?" contained
syn match       gabpbxPattern         "[^A-Za-z0-9,]\zs[[:alnum:]#*]\+\ze" contained
syn match       gabpbxApp             ",\zs[a-zA-Z]\+\ze$"
syn match       gabpbxApp             ",\zs[a-zA-Z]\+\ze("
" Digits plus oldlabel (newlabel)
syn match       gabpbxPriority        ",\zs[[:digit:]]\+\(+[[:alpha:]][[:alnum:]_]*\)\?\(([[:alpha:]][[:alnum:]_]*)\)\?\ze," contains=gabpbxLabel
" oldlabel plus digits (newlabel)
syn match       gabpbxPriority        ",\zs[[:alpha:]][[:alnum:]_]*+[[:digit:]]\+\(([[:alpha:]][[:alnum:]_]*)\)\?\ze," contains=gabpbxLabel
" s or n plus digits (newlabel)
syn match       gabpbxPriority        ",\zs[sn]\(+[[:digit:]]\+\)\?\(([[:alpha:]][[:alnum:]_]*)\)\?\ze," contains=gabpbxLabel
syn match       gabpbxLabel           "(\zs[[:alpha:]][[:alnum:]]*\ze)" contained
syn match       gabpbxError           "^\s*#\s*[[:alnum:]]*"
syn match       gabpbxInclude         "^\s*#\s*\(include\|exec\)\s.*"
syn region      gabpbxVar             matchgroup=gabpbxVarStart start="\${" end="}" contains=gabpbxVar,gabpbxFunction,gabpbxExp
syn match       gabpbxVar             "\zs[[:alpha:]][[:alnum:]_]*\ze=" contains=gabpbxVar,gabpbxFunction,gabpbxExp
syn match       gabpbxFunction        "\${_\{0,2}[[:alpha:]][[:alnum:]_]*(.*)}" contains=gabpbxVar,gabpbxFunction,gabpbxExp
syn match       gabpbxFunction        "(\zs[[:alpha:]][[:alnum:]_]*(.\{-})\ze=" contains=gabpbxVar,gabpbxFunction,gabpbxExp
syn region      gabpbxExp             matchgroup=gabpbxExpStart start="\$\[" end="]" contains=gabpbxVar,gabpbxFunction,gabpbxExp
syn match       gabpbxCodecsPermit    "^\s*\(allow\|disallow\)\s*=\s*.*$" contains=gabpbxCodecs
syn match       gabpbxCodecs          "\(g723\|gsm\|ulaw\|alaw\|g726\|adpcm\|slin\|lpc10\|g729\|speex\|speex16\|ilbc\|all\s*$\)"
syn match       gabpbxError           "^\(type\|auth\|permit\|deny\|bindaddr\|host\)\s*=.*$"
syn match       gabpbxType            "^\zstype=\ze\<\(peer\|user\|friend\)\>$" contains=gabpbxTypeType
syn match       gabpbxTypeType        "\<\(peer\|user\|friend\)\>" contained
syn match       gabpbxAuth            "^\zsauth\s*=\ze\s*\<\(md5\|rsa\|plaintext\)\>$" contains=gabpbxAuthType
syn match       gabpbxAuthType        "\<\(md5\|rsa\|plaintext\)\>" contained
syn match       gabpbxAuth            "^\zs\(secret\|inkeys\|outkey\)\s*=\ze.*$"
syn match       gabpbxAuth            "^\(permit\|deny\)\s*=\s*\d\{1,3}\.\d\{1,3}\.\d\{1,3}\.\d\{1,3}/\d\{1,3}\(\.\d\{1,3}\.\d\{1,3}\.\d\{1,3}\)\?\s*$" contains=gabpbxIPRange
syn match       gabpbxIPRange         "\d\{1,3}\.\d\{1,3}\.\d\{1,3}\.\d\{1,3}/\d\{1,3}\.\d\{1,3}\.\d\{1,3}\.\d\{1,3}" contained
syn match       gabpbxIP              "\d\{1,3}\.\d\{1,3}\.\d\{1,3}\.\d\{1,3}" contained
syn match       gabpbxHostname        "\([[:alnum:]\-]*\.\)\+[[:alpha:]]\{2,10}" contained
syn match       gabpbxPort            "\d\{1,5}" contained
syn match       gabpbxSetting         "^\(tcp\|tls\)\?bindaddr\s*=\s*\d\{1,3}\.\d\{1,3}\.\d\{1,3}\.\d\{1,3}$" contains=gabpbxIP
syn match       gabpbxError           "port\s*=.*$"
syn match       gabpbxSetting         "^\(bind\)\?port\s*=\s*\d\{1,5}\s*$" contains=gabpbxPort
syn match       gabpbxSetting         "^host\s*=\s*\(dynamic\|\(\d\{1,3}\.\d\{1,3}\.\d\{1,3}\.\d\{1,3}\)\|\([[:alnum:]\-]*\.\)\+[[:alpha:]]\{2,10}\)" contains=gabpbxIP,gabpbxHostname
syn match		gabpbxError			"[[:space:]]$"

" Define the default highlighting.
" For version 5.7 and earlier: only when not done already
" For version 5.8 and later: only when an item doesn't have highlighting yet
if version >= 508 || !exists("did_conf_syntax_inits")
  if version < 508
    let did_conf_syntax_inits = 1
    command -nargs=+ HiLink hi link <args>
  else
    command -nargs=+ HiLink hi def link <args>
  endif

  HiLink        gabpbxComment         Comment
  HiLink        gabpbxExten           String
  HiLink        gabpbxContext         Preproc
  HiLink        gabpbxPattern         Type
  HiLink        gabpbxApp             Statement
  HiLink        gabpbxInclude         Preproc
  HiLink        gabpbxPriority        Preproc
  HiLink        gabpbxLabel           Type
  HiLink        gabpbxVar             String
  HiLink        gabpbxVarStart        String
  HiLink        gabpbxFunction        Function
  HiLink        gabpbxExp             Type
  HiLink        gabpbxExpStart        Type
  HiLink        gabpbxCodecsPermit    Preproc
  HiLink        gabpbxCodecs          String
  HiLink        gabpbxType            Statement
  HiLink        gabpbxTypeType        Type
  HiLink        gabpbxAuth            String
  HiLink        gabpbxAuthType        Type
  HiLink        gabpbxIPRange         Identifier
  HiLink        gabpbxIP              Identifier
  HiLink        gabpbxPort            Identifier
  HiLink        gabpbxHostname        Identifier
  HiLink        gabpbxSetting         Statement
  HiLink        gabpbxError           Error
 delcommand HiLink
endif
let b:current_syntax = "gabpbx" 
" vim: ts=8 sw=2

