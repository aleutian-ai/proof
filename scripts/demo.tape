# Copyright 2026 Aleutian AI
# SPDX-License-Identifier: Apache-2.0
#
# demo.tape: the README quickstart as a GIF, for the website and posts.
#
#   brew install vhs
#   vhs scripts/demo.tape        (from the repository root; writes demo.gif)
#
# It runs the real binary on testdata/demo/, so the text is what the tree
# prints. Two things are added for the viewer and are not the CLI's: the
# captions and cards, and colour. A shell function named proof calls the real
# binary and colours a few phrases; it changes no character of the output.
# Rerun this after a release that changes the output.

Output demo.gif
Output demo.mp4

Set Shell "bash"
Set FontSize 26
Set Width 1280
Set Height 800
Set Padding 40
Set Theme "Catppuccin Mocha"
Set TypingSpeed 35ms

Hide
Type `go build -o /tmp/proof-demo/proof ./cmd/proof && cd testdata/demo && export PS1='$ '`
Enter
Type `B=$'\e[1m' G=$'\e[1;32m' R=$'\e[1;31m' Y=$'\e[1;33m' D=$'\e[2m' N=$'\e[0m'`
Enter
Type `proof() { /tmp/proof-demo/proof "$@" | sed -e "s/^INTACT, ANCHORED/$G&$N/" -e "s/^INTACT /$G&$N/" -e "s/^BROKEN/$R&$N/" -e "s/one altered entry breaks every entry after it/$Y&$N/" -e "s/signature verified/$G&$N/" -e "s/NOT proven:/$Y&$N/"; }`
Enter
Type `say() { clear; printf "\n  $B%s$N\n\n" "$1"; }`
Enter
Type `clear && printf "\n\n  ${B}I changed one timestamp in an audit trail.$N\n  ${B}The verifier caught it.$N\n"`
Enter
Sleep 4s
Show
Sleep 3s

Hide
Type `say "One timestamp, moved by one second:"`
Enter
Show
Type "diff entries.json entries-tampered.json"
Sleep 300ms
Enter
Sleep 3s

Hide
Type `say "The verifier:"`
Enter
Show
Type "proof verify entries-tampered.json"
Sleep 300ms
Enter
Sleep 7s

Hide
Type `clear && printf "\n\n  ${B}Why?$N\n\n  Each entry commits to the one before it.\n  One changed timestamp breaks the chain from that point forward.\n"`
Enter
Show
Sleep 5s

Hide
Type `say "The original, against a signed checkpoint:"`
Enter
Show
Type "proof verify entries.json --anchor anchor.json --key anchor-public.pem --subject demo-chain"
Sleep 300ms
Enter
Sleep 8s

Hide
Type `clear && printf "\n\n  ${G}This proves${N} the exported history matches the signed checkpoint.\n  ${Y}It does not prove${N} it is the whole history: entries after the\n  checkpoint could be missing.\n\n\n  ${D}github.com/aleutian-ai/proof  ·  Apache-2.0$N\n"`
Enter
Show
Sleep 7s
