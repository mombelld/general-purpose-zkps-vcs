#!/bin/bash

# Copy credential to issuer input file
cd ../credential_offers
cp hello_offer.json cred_offer.json

# Issue credential
cd ../src/issuer
mvn spring-boot:run -Dspring-boot.run.profiles=local

# Generate proof input
cd ../python_util
python3 gen_input.py ../../proofs/hello_proof/ 1 ../../credentials/1c2e0220-ac16-493a-9ab8-cdd7c4307309-zk.sdjwt

# Compile circuit and generat witness
cd ../../proofs/hello_proof
circom proof.circom --r1cs --c --prime secq256k1 --O2
cd proof_cpp
make
./proof ../input.json ../witness.wtns

# Prove and verify
cd ../../../src/main
cargo run --release ../../proofs/hello_proof/proof.r1cs ../../proofs/hello_proof/witness.wtns