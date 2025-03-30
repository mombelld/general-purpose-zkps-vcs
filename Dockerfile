FROM ubuntu:22.04

# Install dependencies
RUN apt update
RUN apt install curl git python3 python3-pip nlohmann-json3-dev libgmp-dev nasm maven openjdk-21-jdk openjdk-21-jre -y
RUN curl --proto '=https' --tlsv1.2 https://sh.rustup.rs -sSf | bash -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

RUN rustup default nightly

RUN mkdir demo
RUN mkdir demo/credentials
# Copying folders
COPY circom /circom
COPY circomlib demo/circomlib
COPY circuits demo/circuits
COPY credential_offers demo/credential_offers
COPY proofs demo/proofs
COPY scripts demo/scripts
COPY src demo/src
COPY status_list demo/status_list


# Building circom
RUN cd /circom; \
    cargo build --release; \
    cargo install --path circom


# Installing python dependencies
COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

#Build prover and verifier
RUN cd demo/src/main; \
    cargo build --release

RUN curl -sSL https://get.docker.com/ | sh