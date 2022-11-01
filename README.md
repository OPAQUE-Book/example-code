# OPAQUE

This code is a companion to the book, XXXXX.

The book and this code demonstrates the OPAQUE password-derived asymmetric key exchange.

OPAQUE is a way for users to type their username and password to log into a website, but then log in without sending their password across the Internet.

It uses a key-derivation function to facilitate a secure key-exchange between the client and server.

## Setup

Install modules

```console
npm install -g ts-node
npm install
```

## Running

Running demo code

```console
npm run demo
```

The book also demonstrates how to implement OPAQUE in a REST API using [Express](http://expressjs.com/).

To run the demo code, you must run the server and a demo client.

_Run server_

```console
npm run apiserver
```

This runs the `src/restapi/server.ts` script, which runs a REST API that allows for OPAQUE registration and login tests, as well as an encrypted echo endpoint.

_Run client_

```console
npm run apiclient
```

This runs the `src/restapi/client.ts` script, which runs a registration and login tests, then sends an encrypted message to the server's echo test.

## More Information

[OPAQUE-KE Tests in Typescript and Libsodium](https://github.com/backupbrain/opaque-libsodium-sumo-typescript/)

[OPAQUE: An Asymmetric PAKE Protocol Secure Against Pre-Computation Attacks](https://eprint.iacr.org/2018/163.pdf)

[The OPAQUE Asymmetric PAKE Protocol (draft-irtf-cfrg-opaque-09)](https://datatracker.ietf.org/doc/draft-irtf-cfrg-opaque/10/)

[WASM / Typescript Impelementation](https://www.npmjs.com/package/opaque-wasm)
