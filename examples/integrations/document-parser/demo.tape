# Copyright 2026 Aleutian AI
# SPDX-License-Identifier: Apache-2.0
#
# demo.tape: the loan-application dispute as a GIF and MP4.
#
#   vhs examples/integrations/document-parser/demo.tape    (from the repository root)
#
# Writes loan-demo.gif and loan-demo.mp4 in the current directory. Needs what
# run.sh needs (Go, Python, PyPI, Ollama with the model). While hidden, it runs
# run.sh with KEEP=/tmp/proof-loan-demo, so every value shown comes from a real
# run: the model's extraction, the bundle, both verdicts. Added for the viewer:
# the captions and cards, short names for the two public keys, and colour (a
# shell function named aleutian-verify calls the real one and colours a few
# phrases; it changes no character of the output).

Output loan-demo.gif
Output loan-demo.mp4

Set Shell "bash"
Set FontSize 24
Set Width 1280
Set Height 800
Set Padding 40
Set Theme "Catppuccin Mocha"
Set TypingSpeed 35ms

Hide
Type `rm -rf /tmp/proof-loan-demo && KEEP=/tmp/proof-loan-demo examples/integrations/document-parser/run.sh >/tmp/proof-loan-demo.log 2>&1; H=$PWD/examples/integrations/document-parser; cd /tmp/proof-loan-demo && echo READY`
Enter
Wait+Screen@600s /READY/
Type `cp sink-data.keys/ml-dsa-65-checkpoint-public.pem checkpoint.pub && cp sink-data.keys/ml-dsa-65-record-public.pem record.pub && cp docs/LA-2026-0142.pdf application.pdf && export PS1='$ '`
Enter
Type `B=$'\e[1m' G=$'\e[1;32m' R=$'\e[1;31m' Y=$'\e[1;33m' D=$'\e[2m' N=$'\e[0m'`
Enter
Type `aleutian-verify() { /tmp/proof-loan-demo/auditor/bin/aleutian-verify "$@" | sed -e "s/^Verdict: OK/$G&$N/" -e "s/^Verdict: FAILED/$R&$N/" -e "s/problem: modified/$Y&$N/" -e "s/^Limits:.*/$D&$N/"; }`
Enter
Type `show-record() { python3 -I "$H/show_record.py" "$@" | sed -e "s/same document/$G&$N/"; }; edit-income() { python3 -I "$H/edit_bundle.py" "$@" | sed -e "s/→ 4250/→ ${R}4250$N/"; }`
Enter
Type `say() { clear; printf "\n  $B%s$N\n\n" "$1"; }`
Enter
Type `clear && printf "\n\n  ${B}An AI read a loan application.$N\n  ${B}The applicant disputes what it read.$N\n\n  ${D}The lender hands an auditor a bundle of its records.$N\n"`
Enter
Show
Sleep 5s

Hide
Type `say "The auditor checks the bundle, with only the lender's public keys:"`
Enter
Show
Type "aleutian-verify verify-proof-bundle --checkpoint-key checkpoint.pub --record-key record.pub bundle.json"
Sleep 300ms
Enter
Sleep 6s

Hide
Type `say "What the AI extracted, against the applicant's own copy of the PDF:"`
Enter
Show
Type "show-record bundle.json application.pdf"
Sleep 300ms
Enter
Sleep 7s

Hide
Type `say "Someone 'corrects' the income before handing the bundle over:"`
Enter
Show
Type "edit-income bundle.json bundle-edited.json"
Sleep 300ms
Enter
Sleep 2s
Type "aleutian-verify verify-proof-bundle --checkpoint-key checkpoint.pub --record-key record.pub bundle-edited.json"
Sleep 300ms
Enter
Sleep 6s

Hide
Type `clear && printf "\n\n  ${G}This proves${N} what the model extracted, from which document,\n  and that nobody has changed it since.\n\n  ${Y}It does not prove${N} the model was right, or that every\n  application was recorded.\n\n\n  ${D}github.com/aleutian-ai/proof  ·  Apache-2.0$N\n"`
Enter
Show
Sleep 7s
