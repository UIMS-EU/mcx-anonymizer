# Security policy

mcx-anonymizer exists to keep network identities out of shared captures, so a
value that survives anonymisation is a security issue, not an ordinary bug.

## What to report privately

- an original value (address, identity, name, key material, location) that is
  still in an output the tool published;
- a value the tool should have pseudonymised or removed but kept;
- a way to recover originals from an output without the project secret or
  mapping;
- a crash, hang or memory error triggered by a crafted capture;
- anything that makes the tool contact the network.

## How to report

Use GitHub's private vulnerability reporting: the **Report a vulnerability**
button on the [Security tab](https://github.com/UIMS-EU/mcx-anonymizer/security)
of this repository. If that is not possible, write to contact@uims.eu.

**Never attach a real capture, a project mapping or a project secret.** Describe
the protocol, the field and the encoding instead (for example "the IMPU in the
`P-Asserted-Identity` of a MESSAGE, written in a `<entry uri>` of a
resource-lists body"). If a capture is needed, build a synthetic one with
`tools/fixturegen/` or with made-up values. We will ask for more only if the
description is not enough.

Please do not open a public issue for these cases.

## What to expect

- an acknowledgement within 5 working days;
- an assessment and, for a confirmed issue, a fix in a patch release, with
  credit in the release notes if you want it;
- coordinated disclosure: please give us 90 days before publishing details.

## Supported versions

Only the latest release gets security fixes while the project is at 0.x.
