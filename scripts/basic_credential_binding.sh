#!/bin/bash
PROOF=basic_credential_binding
CRED_FILE0=identity00_offer.json
CRED_ID0=1c2e0220-ac16-493a-9ab8-cdd7c4307309
CRED_FILE1=diploma_offer.json
CRED_ID1=85fd7f5c-31cd-43f6-8c43-611bc5dd4714

# Copy credential to issuer input file
cd ../credential_offers
cp ${CRED_FILE0} cred_offer.json

# Issue credential
cd ../src/issuer
mvn spring-boot:run -Dspring-boot.run.profiles=local

cd ../../credential_offers
cp ${CRED_FILE1} cred_offer.json

# Issue credential
cd ../src/issuer
mvn spring-boot:run -Dspring-boot.run.profiles=local

# Generate proof input
cd ../python_util
python3 gen_input.py ../../proofs/${PROOF}/ 2 ../../credentials/${CRED_ID0}-zk.sdjwt ../../credentials/${CRED_ID1}-zk.sdjwt 

# Compile circuit and generat witness
cd ../../proofs/${PROOF}
circom proof.circom --r1cs --c --prime secq256k1 --O2
cd proof_cpp
make
./proof ../input.json ../witness.wtns

# Prove and verify
cd ../../../src/main
cargo run --release ../../proofs/${PROOF}/proof.r1cs ../../proofs/${PROOF}/witness.wtns