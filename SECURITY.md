# Reporting a vulnerability

Mail **security@airdress.co**. We answer; please allow us to fix before
publishing.

## What this repository is responsible for

The MLS (RFC 9420) client every airdress device runs: how a device's
credential is checked against its airdress's root key, how group and
key-package state is sealed at rest, which authenticated data every
application message carries, which group changes the rules allow, and
the C ABI the phone reaches all of it through.

Worth reporting even if it looks small:

- a credential that validates when it should not — a delegation signed
  by the wrong root, an expired or revoked device, a successor identity
  that changes airdress, device or root;
- two distinct delegations with one canonical signing input, or one
  delegation that two consumers canonicalise differently;
- an application message that decrypts under a binding other than the
  one it was sent with (a re-filed ciphertext);
- a group change the rules should refuse — removing another airdress's
  member, adding a duplicate leaf;
- sealed state that opens with the wrong key, or epoch secrets that
  outlive the retention bound;
- anything across the C boundary that reads or frees memory it does not
  own.

## What it is not responsible for

Key custody on the device, transport, and the delivery service. Those
belong to the app and the operator that use it.
