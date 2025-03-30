#!/bin/bash
PROOF=basic_verification_age_check
CRED_FILE=identity00_offer.json
CRED_ID=1c2e0220-ac16-493a-9ab8-cdd7c4307309

# Copy credential to issuer input file
cd ../credential_offers
cp ${CRED_FILE} cred_offer.json

# Issue credential
cd ../src/issuer
mvn spring-boot:run -Dspring-boot.run.profiles=local

# Generate proof input
cd ../python_util
python3 gen_input.py ../../proofs/${PROOF}/ 1 ../../credentials/${CRED_ID}-zk.sdjwt 

# Compile circuit and generat witness
cd ../../proofs/${PROOF}
circom proof.circom --r1cs --c --prime secq256k1 --O2
cd proof_cpp
make
./proof ../input.json ../witness.wtns

# Prove and verify
cd ../../../src/main
cargo run --release ../../proofs/${PROOF}/proof.r1cs ../../proofs/${PROOF}/witness.wtns