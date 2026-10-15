# Product position and adoption evidence

The chosen direction is a free, open-source utility focused on trust and adoption. The product
promise is a successful local OpenPGP exchange without an account, telemetry or keyserver access.
Its useful audience is people who receive an armored message or a file and need to complete an
occasional exchange. Advanced users are a compatibility audience, not evidence that every expert
workflow belongs in this interface.

## Needs the product must meet

| Need | Product response | Evidence of success |
| --- | --- | --- |
| Know which identity a result concerns | Validated certificates and full primary fingerprints | People compare fingerprints and reject a substituted identity |
| Avoid irreversible loss | Preserve outputs, explicit deletion, backup and restore | Original bytes survive failures; a restored private key decrypts an older message |
| Understand an answer | Distinct good, mismatch and unavailable verdicts | People interpret all three correctly without prompting |
| Trust a download | Exact-commit tests, provenance, hashes and honest signing status | A user can trace their downloaded asset to the intended source |
| Complete a first exchange | Short first-use guide and contextual empty states | People exchange a test message without maintainer intervention |
| Keep using an identity | Expiry renewal, passphrase changes and revocation | People update a key without changing its fingerprint or losing old messages |
| Get help without leaking secrets | Reproducible synthetic fixtures and private security intake | Reports identify the failure without attaching real private material |

These are design and engineering responses, not proof of market demand. Adoption, task-completion
rates and willingness to recommend have not been measured in this review.

The regression suite also runs five simulated user journeys: first exchange, file batches,
signature interpretation, backup recovery and key retirement. They exercise commands with real
cryptographic services and synthetic data. They establish functional behavior, not observations of
people, installation usability, task duration or demand. Keep those results separate from the study.

## Small usability study protocol

Recruit five people who have an occasional encryption need and mixed OpenPGP experience. Recruitment
and messages require separate authorization. Use synthetic keys and messages only. Obtain consent
for notes; avoid collecting participant identities or recordings unless necessary and agreed.
No tracking is added to the app.

Ask each person to install a verified build, generate a key, compare fingerprints, import a contact,
exchange encrypted text and a file, interpret three signature outcomes, and restore a backup into
an empty scratch store. Include one deliberate fingerprint mismatch and one unavailable-verification
case. Observe before offering help. Record task completion, elapsed time, misinterpretations,
assistance and recovery success. Ask what made them hesitate and whether they have a repeat use case.

Proposed acceptance criteria are four of five completing a first exchange within ten minutes,
five of five distinguishing unavailable verification from success, no acceptance of a mismatched
fingerprint, and five of five restoring access to an older message. These are targets for a small
formative study, not statistically meaningful conversion estimates. Fix observed failure patterns
before adding features to improve download counts.

## Sustainable maintenance

Maintainer time, patch response, release verification and independent security review are the
scarce resources. Keep one supported release path, simple compatibility rules and reproducible bug
reports. The immediate business need is a supportable trust claim, not a paid tier or an account
system. Optional donations or sponsorship can fund signing and independent review if people show
repeat use. Do not promise service levels, signing eligibility, audit funding or enterprise support
without the people and budget to deliver them.

Use public download counts and issue activity only as rough distribution and support signals.
They do not count active users or prove safety. Independent review, correct user decisions and
successful recovery are stronger evidence for promotion. Future work is maintained in Accession;
this document records the product decision and measurement method, not a second task board.
