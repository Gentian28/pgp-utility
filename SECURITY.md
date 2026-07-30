# Security

## This has not been independently audited

No third party has reviewed this code. It is one person's work, built on
[BouncyCastle](https://www.bouncycastle.org/), which is itself a mature and widely used library,
but the way this app uses BouncyCastle has had no external scrutiny.

That matters more for a crypto tool than for most software, so it is stated here rather than left
for you to infer. If you are protecting something whose exposure would be seriously harmful, use
something that has been audited, or at minimum do not rely on this alone.

What does exist:

- An automated test suite covering round trips, wrong passphrases, tampered and truncated
  ciphertext, key import and export, file permissions, and a 128 MB streaming case.
- Interoperability tests against GnuPG in both directions, run on Windows, macOS and Linux on
  every change. These would catch a homegrown deviation from the OpenPGP standard, which is the
  most likely way a tool like this goes quietly wrong.
- A CI gate that fails the build on any dependency with a known advisory.

Tests catch the mistakes someone thought to test for. They are not an audit.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Report it through GitHub's private reporting: go to the
[Security tab](https://github.com/Gentian28/pgp-utility/security/advisories/new) and open a draft
advisory. That keeps the report between us until there is a fix.

If that is not available to you, email **gentian.shkembi@gmail.com** with "PGP Utility security"
in the subject.

Useful to include, as much as you have:

- What an attacker can do, in plain terms.
- Steps to reproduce, or a proof of concept.
- The version, from the installer filename or the release you downloaded.
- Your operating system.

What to expect: an acknowledgement within a week, and an honest assessment of whether and when it
will be fixed. This is a personal project and not a funded product, so there is no guaranteed
response time, and pretending otherwise would be worse than saying so. Anything that lets an
attacker read plaintext, forge a signature, or extract a private key will be treated as urgent.

Credit in the release notes if you would like it, and no credit if you would rather not.

## Scope

In scope, and worth reporting:

- Recovering plaintext without the private key and passphrase.
- Forging a signature, or getting an invalid signature reported as valid.
- Extracting private key material, or leaking a passphrase outside the process.
- Producing output the app reports as verified when its integrity check should have failed.
- Private keys or the key store being written with permissions that let other local accounts read
  them.
- Any network traffic at all. This app is not supposed to make any.

Known and out of scope:

- **The releases are not code-signed.** This is a cost decision, documented in the README along
  with the exact warnings you will see. Verify downloads against the published SHA256 sums.
- **Passphrases are not protected against a compromised machine.** They are held as character
  arrays and cleared after use, which narrows the window they are resident for. It does not defeat
  a debugger attached to the process, a memory dump, or the page reaching swap. On the Avalonia
  text field the passphrase also exists as a managed string the app does not control and cannot
  zero.
- **A good signature does not mean a trusted signer.** It proves the bytes have not changed since
  that key signed them. Whether the key belongs to who you think is what fingerprint comparison is
  for, and the app says so where it reports a result.
- Physical access, malware already running as your user, or a compromised build environment.

## Reporting something in a dependency

If the problem is in BouncyCastle, Avalonia or another dependency rather than in this code, report
it to that project first. Tell us too, so the dependency can be bumped here once a patched version
exists.
