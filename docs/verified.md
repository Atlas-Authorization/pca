# PCA Verified registry

Implementations that hold a signed, third-party-verifiable PCA Verified conformance statement, by profile. Every row was
checked when this page was generated: the statement's signature, the corpus it was made against, that it covers the whole
profile, and the registry's transparency-log receipt. The **tier** says how much the statement proves:

* **CI-attested**: signed by the implementer's key **and** a GitHub Actions workflow of the named repository attested those exact
  bytes (a Sigstore build-provenance attestation, checked offline). It ties the result to a repository and a workflow run.
* **self-attested**: signed by a key, nothing more. It proves which implementation, version, corpus and result, signed by this key;
  who holds the key is for you to decide.

How a profile is defined, what a statement binds and how to get listed: [Get your implementation PCA Verified](./guides/get-pca-verified.md)
and [the protocol](./reference/pca-verified-protocol.md). Check any entry yourself with `pca-verified registry verify`.

<!-- verified:registry:start -->

_No implementation has been registered yet._

<!-- verified:registry:end -->
