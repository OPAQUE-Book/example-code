import _sodium from "libsodium-wrappers-sumo";

export let sodium: any = null;

export const base64Encode = (bytes: Uint8Array): string => {
  const base64Data = Buffer.from(new Uint8Array(bytes)).toString("base64");
  return base64Data;
};

export const base64Decode = (str: string): Uint8Array => {
  const bytes = Buffer.from(str, "base64");
  const arr = new Uint8Array(bytes);
  return arr;
};

export const crypto_generichash_batch = (arr: Uint8Array[]): Uint8Array => {
  const key = Buffer.alloc(sodium.crypto_generichash_KEYBYTES);
  const state = sodium.crypto_generichash_init(
    key,
    sodium.crypto_generichash_BYTES
  );
  arr.forEach((item) => {
    sodium.crypto_generichash_update(state, item);
  });
  const combinedHash = sodium.crypto_generichash_final(
    state,
    sodium.crypto_generichash_BYTES
  );
  return combinedHash;
};

export type EncryptMessageResult = {
  encryptedMessage: Uint8Array;
  nonce: Uint8Array;
};
export const encryptMessage = (
  message: string,
  sharedTx: Uint8Array
): EncryptMessageResult => {
  // pick a random nonce
  const nonce = sodium.randombytes_buf(
    sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
  );
  const additionData = "";
  // encrypt the message
  const encryptedMessage = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    message,
    additionData,
    null,
    nonce,
    sharedTx
  );
  return { encryptedMessage, nonce };
};

export const decryptMessage = (
  encryptedMessage: Uint8Array,
  nonce: Uint8Array,
  sharedRx: Uint8Array
): string => {
  const additionalData = "";
  // decrypt data
  const decryptedData = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    encryptedMessage,
    additionalData,
    nonce,
    sharedRx
  );
  // convert to string
  const decryptedMessage = Buffer.from(decryptedData).toString("utf-8");
  return decryptedMessage;
};

export const initializeSodium = async () => {
  await _sodium.ready;
  sodium = _sodium;
  return sodium;
};
