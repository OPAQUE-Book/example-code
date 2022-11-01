import { CryptoKX, KeyPair } from "libsodium-wrappers";
import * as common from "./common";

export type User = {
  opaquePublicKey: Uint8Array;
  opaquePrivateKey: Uint8Array;
  opaqueChallenge: Uint8Array;
  clientPublicKey: Uint8Array | null | undefined;
  lockbox: Uint8Array | null | undefined;
  lockboxNonce: Uint8Array | null | undefined;
};
export const userDatabase = new Map<string, User>();

export let keyPair: KeyPair | undefined = undefined;

export const createKeyPair = () => {
  const sodium = common.sodium;
  keyPair = sodium.crypto_kx_keypair();
};

export type CreateChallengeResponseResult = {
  opaqueResponse: Uint8Array;
  opaquePublicKey: Uint8Array;
  serverPublicKey: Uint8Array;
};

const createChallengeResponse = (
  opaqueChallenge: Uint8Array,
  opaquePrivateKey: Uint8Array
): CreateChallengeResponseResult => {
  const sodium = common.sodium;
  // derive OPAQUE public key
  const opaquePublicKey =
    sodium.crypto_scalarmult_ed25519_base(opaquePrivateKey);
  // multiply private key by client challenge
  // to create the response
  const opaqueResponse = sodium.crypto_scalarmult_ed25519(
    opaquePrivateKey,
    opaqueChallenge
  );
  return {
    opaqueResponse,
    opaquePublicKey,
    serverPublicKey: keyPair!.publicKey,
  };
};

export type CreateRegistrationChallengeResponseResult = {
  opaqueResponse: Uint8Array;
  opaquePublicKey: Uint8Array;
  serverPublicKey: Uint8Array;
};
export const createRegistrationChallengeResponse = (
  username: string,
  clientPublicKey: Uint8Array,
  opaqueChallenge: Uint8Array
): CreateRegistrationChallengeResponseResult => {
  const sodium = common.sodium;
  // create OPAQUE public key by picking a random number
  const opaquePrivateKey = sodium.randombytes_buf(
    sodium.crypto_core_ed25519_SCALARBYTES
  );
  // create challenge response
  const { opaqueResponse, opaquePublicKey, serverPublicKey } =
    createChallengeResponse(opaqueChallenge, opaquePrivateKey);
  const userData = userDatabase.get(username);
  if (userData) {
    throw new Error("User already exists");
  }
  userDatabase.set(username, {
    opaquePublicKey,
    opaquePrivateKey,
    opaqueChallenge,
    clientPublicKey,
    lockbox: null,
    lockboxNonce: null,
  });
  return {
    opaqueResponse,
    opaquePublicKey,
    serverPublicKey: keyPair!.publicKey,
  };
};

export const updateClientRegistrationEnvelope = (
  username: string,
  lockbox: Uint8Array,
  lockboxNonce: Uint8Array
): void => {
  const userData = userDatabase.get(username);
  if (!userData) {
    throw Error("User not found");
  }
  userDatabase.set(username, {
    ...userData,
    lockbox,
    lockboxNonce,
  });
};

export type RegistrationEnvelope = {
  lockbox: Uint8Array;
  lockboxNonce: Uint8Array;
};

export type GetLoginChallengeResponseResult = {
  opaqueResponse: Uint8Array;
  opaquePublicKey: Uint8Array;
  serverPublicKey: Uint8Array;
  envelope: RegistrationEnvelope;
};
export const getLoginChallengeResponse = (
  username: string,
  opaqueChallenge: Uint8Array
): GetLoginChallengeResponseResult => {
  // look up user data
  const userData = userDatabase.get(username);
  if (!userData || !userData.lockbox || !userData.lockboxNonce) {
    throw new Error("User not found");
  }
  // generate challenge response
  const opaqueResponse = createChallengeResponse(
    opaqueChallenge,
    userData.opaquePrivateKey
  );
  return {
    ...opaqueResponse,
    envelope: {
      lockbox: userData.lockbox,
      lockboxNonce: userData.lockboxNonce,
    },
    opaquePublicKey: userData.opaquePublicKey,
  };
};

export const deriveSessionKeys = (clientPublicKey: Uint8Array): CryptoKX => {
  const sodium = common.sodium;
  const sessionKeys = sodium.crypto_kx_server_session_keys(
    keyPair?.publicKey,
    keyPair?.privateKey,
    clientPublicKey
  );
  return sessionKeys;
};
