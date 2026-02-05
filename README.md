# General-Purpose Zero-Knowledge Proofs for Verifiable Credentials

This repository contains a proof-of-concept implementation of a verifiable credentials infrastructure based on general-purpose zero-knowledge proofs. It is meant as a companion to the master's thesis [General-Purpose Zero-Knowledge Proofs for Verifiable Credentials](GeneralPurposeZeroKnowledgeProofsForVerifiableCredentials.pdf). For the implementation details and how to use it we refer to Section 5 of the thesis.

<span style="color:red">**WARNING**</span>: this is an academic proof-of-concept prototype, and in particular it has received neither careful code review nor extensive testing. This implementation is NOT for production use.

## Building and Running Locally

1. Install [docker](https://www.docker.com/)

2. Build docker image using
    ```text
    make build-docker-image
    ```

3. Run docker image
    ```text
    make run-docker-image
    ```

## Example End-to-End Proof
Go to folder containing example scripts

```text
cd /demo/script
```

Run end-to-end example

```text
./basic_verification.sh
```

## Acknowledgments

Thise repository contains third-party components which are released under different licenses, namely
- `circom` (GLP-3.0)
- `circomlib` (LGLP-3.0)

Additionally, we modified the source code of `circom` to add support for secp256k1
