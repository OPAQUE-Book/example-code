import { CryptoKX, KeyPair } from "libsodium-wrappers";
import * as common from "./common";

export let keyPair: KeyPair | undefined = undefined;

export const createKeyPair = () => {
  const sodium = common.sodium;
  keyPair = sodium.crypto_kx_keypair();
};

export type CreateChallengeResult = {
  opaqueChallenge: Uint8Array;
  randomScalar: Uint8Array;
};
export const createChallenge = (password: string): CreateChallengeResult => {
  const sodium = common.sodium;
  // convert password into a usable data format
  const passwordBytes = Buffer.from(password);
  // create a hash of the password
  const hashLength = sodium.crypto_generichash_BYTES;
  const hashedPassword = sodium.crypto_generichash(hashLength, passwordBytes);
  // treat the hash as a number and calculate
  // the corresponding point on the elliptic curve
  const curveMappedPassword =
    sodium.crypto_core_ed25519_from_uniform(hashedPassword);
  // create a random number
  const randomScalar = sodium.crypto_core_ed25519_scalar_random();
  // derive the point on the curve
  // for that random number
  const randomPointOnCurve =
    sodium.crypto_scalarmult_ed25519_base_noclamp(randomScalar);
  // add the two points to create the challenge
  const opaqueChallenge = sodium.crypto_core_ed25519_add(
    curveMappedPassword,
    randomPointOnCurve
  );
  return { opaqueChallenge, randomScalar };
};

export const randomizePassword = (
  password: string,
  randomScalar: Uint8Array,
  opaquePublicKey: Uint8Array,
  serverChallengeResponse: Uint8Array
): Uint8Array => {
  const sodium = common.sodium;
  // convert the password into a usable data type
  const passwordBytes = Buffer.from(password);
  // invert randomScalar
  const invertedRandomScalar =
    sodium.crypto_core_ed25519_scalar_negate(randomScalar);
  // multiply opaquePublicKey ^ invertedRandomScalar
  const exponentiatedPublicKey = sodium.crypto_scalarmult_ed25519_noclamp(
    invertedRandomScalar,
    opaquePublicKey
  );
  // add the server response and exponentiatedPublicKey
  const challengeResponseResult = sodium.crypto_core_ed25519_add(
    serverChallengeResponse,
    exponentiatedPublicKey
  );
  // combine these data into a single hash
  const randomizedPassword = common.crypto_generichash_batch([
    passwordBytes,
    opaquePublicKey,
    challengeResponseResult,
  ]);
  return randomizedPassword;
};

export const deriveLockboxKey = (
  password: string,
  randomScalar: Uint8Array,
  opaquePublicKey: Uint8Array,
  serverChallengeResponse: Uint8Array
): Uint8Array => {
  const sodium = common.sodium;
  const randomizedPassword = randomizePassword(
    password,
    randomScalar,
    opaquePublicKey,
    serverChallengeResponse
  );
  const hashSalt = Buffer.alloc(sodium.crypto_pwhash_SALTBYTES);
  const derivedLockboxKey = sodium.crypto_pwhash(
    32,
    randomizedPassword,
    hashSalt,
    sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
    sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
    sodium.crypto_pwhash_ALG_DEFAULT
  );
  return derivedLockboxKey;
};

export type CreateRegistrationEnvelopeResult = {
  lockbox: Uint8Array;
  lockboxNonce: Uint8Array;
};
export const createRegistrationEnvelope = (
  password: string,
  randomScalar: Uint8Array,
  opaquePublicKey: Uint8Array,
  serverChallengeResponse: Uint8Array,
  serverPublicKey: Uint8Array
): CreateRegistrationEnvelopeResult => {
  const sodium = common.sodium;
  // derive the lockbox key
  const derivedLockboxKey = deriveLockboxKey(
    password,
    randomScalar,
    opaquePublicKey,
    serverChallengeResponse
  );
  // convert Uint8Arrays to base64 strings
  const lockboxContents = {
    userPublicKey: common.base64Encode(keyPair?.publicKey!),
    userPrivateKey: common.base64Encode(keyPair?.privateKey!),
    serverPublicKey: common.base64Encode(serverPublicKey),
  };
  // serialize the data into a JSON string
  // then convert into a data type usable by libsodium
  const lockboxContentsBytes = Buffer.from(JSON.stringify(lockboxContents));
  // generate a random nonce
  const lockboxNonce = sodium.randombytes_buf(
    sodium.crypto_secretbox_NONCEBYTES
  );
  // encrypt the lockbox
  const lockbox = sodium.crypto_secretbox_easy(
    lockboxContentsBytes,
    lockboxNonce,
    derivedLockboxKey
  );
  return { lockbox, lockboxNonce };
};

export const deriveSessionKeys = (
  password: string,
  randomScalar: Uint8Array,
  opaquePublicKey: Uint8Array,
  serverChallengeResponse: Uint8Array,
  lockbox: Uint8Array,
  lockboxNonce: Uint8Array
): CryptoKX => {
  const sodium = common.sodium;
  // derive lockbox key
  const derivedLockboxKey = deriveLockboxKey(
    password,
    randomScalar,
    opaquePublicKey,
    serverChallengeResponse
  );
  // decrypt lockbox into a Uint8Array
  const lockboxContentsBytes = sodium.crypto_secretbox_open_easy(
    lockbox,
    lockboxNonce,
    derivedLockboxKey
  );
  // convert to a usable format and decode keys
  const lockboxContentsString = Buffer.from(
    lockboxContentsBytes.buffer
  ).toString("utf-8");
  const lockboxContents = JSON.parse(lockboxContentsString);
  const userPublicKey = common.base64Decode(lockboxContents.userPublicKey);
  const userPrivateKey = common.base64Decode(lockboxContents.userPrivateKey);
  const serverPublicKey = common.base64Decode(lockboxContents.serverPublicKey);
  // derive client session keys
  const sessionKeys = sodium.crypto_kx_client_session_keys(
    userPublicKey,
    userPrivateKey,
    serverPublicKey
  );
  return sessionKeys;
};
