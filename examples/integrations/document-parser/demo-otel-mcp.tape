# Copyright 2026 Aleutian AI
# SPDX-License-Identifier: Apache-2.0
#
# demo-otel-mcp.tape: the loan-application dispute through OpenTelemetry and MCP.
#
#   vhs examples/integrations/document-parser/demo-otel-mcp.tape    (from the repository root)
#
# Writes loan-otel-mcp-demo.gif and .mp4 in the current directory. Needs what
# run-otel-mcp.sh needs. While hidden, it runs run-otel-mcp.sh with
# KEEP=/tmp/proof-loan-otel-demo, so every value shown comes from a real run:
# otel-sink's log, the model's extraction, the bundle, both MCP verdicts. Added
# for the viewer: the captions and cards, a short name for the PDF, colour,
# and a shell function, mcp-verify, that runs mcp_verify.py against proof-mcp
# with the lender's keys bound, drops the version suffix and the proven / not
# proven paragraphs (the closing card states the limits), and colours a few
# phrases. It changes no other character of the output.

Output loan-otel-mcp-demo.gif
Output loan-otel-mcp-demo.mp4

Set Shell "bash"
Set FontSize 24
Set Width 1280
Set Height 800
Set Padding 40
Set Theme "Catppuccin Mocha"
Set TypingSpeed 35ms

Hide
Type `rm -rf /tmp/proof-loan-otel-demo && KEEP=/tmp/proof-loan-otel-demo examples/integrations/document-parser/run-otel-mcp.sh >/tmp/proof-loan-otel-demo.log 2>&1; H=$PWD/examples/integrations/document-parser; cd /tmp/proof-loan-otel-demo && echo READY`
Enter
Wait+Screen@600s /READY/
Type `cp docs/LA-2026-0142.pdf application.pdf && export PATH=/tmp/proof-loan-otel-demo/bin:$PATH PS1='$ '`
Enter
Type `B=$'\e[1m' G=$'\e[1;32m' R=$'\e[1;31m' Y=$'\e[1;33m' D=$'\e[2m' N=$'\e[0m'`
Enter
Type `mcp-verify() { python3 -I "$H/mcp_verify.py" "$1" -- proof-mcp --root dispute --bundle-checkpoint-key dispute/checkpoint.pub --bundle-record-trust dispute/record.pub | sed -e '/^   proven:/,$d' -e 's/aleutianchain [^ ]* /aleutianchain /' -e "s/verdict: OK/${G}verdict: OK$N/" -e "s/verdict: FAILED/${R}verdict: FAILED$N/" -e "s/problem: modified/${Y}problem: modified$N/"; }`
Enter
Type `show-record() { python3 -I "$H/show_record.py" "$@" | sed -e "s/same document/$G&$N/" -e "s/^   OTel log/   ${B}OTel log$N/"; }; edit-income() { python3 -I "$H/edit_bundle.py" "$@" | sed -e "s/→ 4250/→ ${R}4250$N/"; }`
Enter
Type `say() { clear; printf "\n  $B%s$N\n  $D%s$N\n\n" "$1" "$2"; }`
Enter
Type `clear && printf "\n\n  ${B}An AI read a loan application.$N\n  ${B}The applicant disputes what it read.$N\n\n  ${D}The pipeline only emits OpenTelemetry logs. Proof records them,$N\n  ${D}and the auditor's agent checks them over MCP.$N\n"`
Enter
Show
Sleep 6s

Hide
Type `say "The parser logged each extraction with OpenTelemetry." "otel-sink signed each one onto the applicant's own chain:"`
Enter
Show
Type "grep '^request [123]:' otel-sink.log"
Sleep 300ms
Enter
Sleep 4s

Hide
Type `say "The auditor's agent asks proof-mcp, over MCP." "The server holds only the lender's public keys; a tool call cannot add one."`
Enter
Show
Type "mcp-verify bundle.json"
Sleep 300ms
Enter
Sleep 5s

Hide
Type `say "What the AI extracted, against the applicant's own copy of the PDF:"`
Enter
Show
Type "show-record dispute/bundle.json application.pdf"
Sleep 300ms
Enter
Sleep 7s

Hide
Type `say "Someone 'corrects' the income before handing the bundle over:"`
Enter
Show
Type "edit-income dispute/bundle.json dispute/bundle-edited.json"
Sleep 300ms
Enter
Sleep 2s
Type "mcp-verify bundle-edited.json"
Sleep 300ms
Enter
Sleep 6s

Hide
Type `clear && printf "\n\n  ${G}This proves${N} what the model extracted, from which document,\n  and that nobody has changed it since.\n\n  ${Y}It does not prove${N} the model was right, or that every\n  application was recorded.\n\n\n  ${D}github.com/aleutian-ai/proof  ·  Apache-2.0$N\n"`
Enter
Show
Sleep 7s
