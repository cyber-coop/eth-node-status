##### BUILDER #####
FROM rustlang/rust:nightly as builder

WORKDIR /usr/src/eth-node-status
COPY . .
RUN cargo install --path .

##### RUNNER #####
FROM debian:buster-slim

LABEL author="Lola Rigaut-Luczak <me@laflemme.lol>"
LABEL description="Connect to a node and get the network id."

COPY --from=builder /usr/local/cargo/bin/eth-node-status /usr/local/bin/eth-node-status

RUN apt-get update && rm -rf /var/lib/apt/lists/*

CMD eth-node-status