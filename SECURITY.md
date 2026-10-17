# Security policy

`proof` is a verifier for evidence. A flaw that makes it accept something it
should refuse, or claim more than it checked, is a security issue even when
nothing crashes. Please report those privately.

## Reporting a vulnerability

1. **GitHub private vulnerability reporting** (preferred): on
   [github.com/aleutian-ai/proof](https://github.com/aleutian-ai/proof), open the
   **Security** tab and choose **Report a vulnerability**. The report stays
   private between you and the maintainers.
2. **Email**, if you cannot use GitHub: **security@aleutian.ai**.

Please include the version (`proof version`, or the module version you import),
what you did, what you expected, and what happened. A failing test or a small
input file is the most useful thing you can send. Do not include anyone's real
evidence, keys or personal data.

Please do not open a public issue for a vulnerability, and give us a reasonable
time to fix it before you publish. We will acknowledge a report within five
working days, tell you whether we can reproduce it, and agree a disclosure date
with you. We credit reporters in the changelog unless you ask us not to.

## What is in scope

- The verifiers: a chain, an anchor, an anchor series or an export bundle that
  verifies when it should not, or a result that claims more than was checked.
- The formats and conformance vectors: a vector that an incorrect
  implementation passes.
- The sink and the stores: a way to forge, hide or destroy evidence, or to get
  something signed, without the keys the threat model requires.
- Supported platforms: Linux and macOS. On Windows the store-opening commands
  report that the platform is unsupported; that is not a vulnerability.
- The CLI and the MCP server: reading or writing outside what the user asked
  for, leaking key material, subjects or evidence content, or a crash or hang
  on input from someone else.
- Key handling: `keygen`, key files and the 1Password integration.

## Known limitations

Some weaknesses are known and documented: the permanent limits of the frozen
v2 and v3 formats, and what no format can close (an operator who holds every
key). They are listed in the README under
["What chain format v4 closed, and what is left"](README.md#what-chain-format-v4-closed-and-what-is-left).
A report that one of them is exploitable is welcome only if it goes further
than what is written there.

## Supported versions

While the major version is 0, only the latest release receives fixes. Fixes are
released as a new version and recorded in [CHANGELOG.md](CHANGELOG.md); a
published tag is never moved.
