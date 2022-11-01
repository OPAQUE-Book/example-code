import { CryptoKX } from "libsodium-wrappers";
import * as client from "./opaque/client";
import * as common from "./opaque/common";
import * as server from "./opaque/server";

let sodium: any = null;

const username = "username@example.com";
const password = "abc123";

let serverSessionKeys: CryptoKX | undefined = undefined;
let clientSessionKeys: CryptoKX | undefined = undefined;

const register = () => {
  // initialize client
  client.createKeyPair();
  // start registration
  const challengeData = client.createChallenge(password);
  const responseData = server.createRegistrationChallengeResponse(
    username,
    client.keyPair?.publicKey!,
    challengeData.opaqueChallenge
  );
  // finish registration
  const registrationEnvelope = client.createRegistrationEnvelope(
    password,
    challengeData.randomScalar,
    responseData.opaquePublicKey,
    responseData.opaqueResponse,
    responseData.serverPublicKey
  );
  server.updateClientRegistrationEnvelope(
    username,
    registrationEnvelope.lockbox,
    registrationEnvelope.lockboxNonce
  );
};

const login = () => {
  // start login
  const challengeData = client.createChallenge(password);
  const responseData = server.getLoginChallengeResponse(
    username,
    challengeData.opaqueChallenge
  );

  // finish login
  const userData = server.userDatabase.get(username);
  // derive server and client session keys
  serverSessionKeys = server.deriveSessionKeys(userData?.clientPublicKey!);
  clientSessionKeys = client.deriveSessionKeys(
    password,
    challengeData.randomScalar,
    responseData.opaquePublicKey,
    responseData.opaqueResponse,
    responseData.envelope.lockbox,
    responseData.envelope.lockboxNonce
  );
};

const sendEncryptedMessages = () => {
  const clientMessage = "Top of the morning to you!";
  // encrypt client message
  const encryptedClientData = common.encryptMessage(
    clientMessage,
    clientSessionKeys?.sharedTx!
  );
  // decrypt client message
  const receivedClientMessage = common.decryptMessage(
    encryptedClientData.encryptedMessage,
    encryptedClientData.nonce,
    serverSessionKeys?.sharedRx!
  );
  // result: Top of the morning to you!
  console.log(`server received: "${receivedClientMessage}"`);

  const serverMessage = "The rest of the afternoon to you!";

  // encrypt server message
  const encryptedServerData = common.encryptMessage(
    serverMessage,
    serverSessionKeys?.sharedTx!
  );
  // decrypt server message
  const receivedServerMessage = common.decryptMessage(
    encryptedServerData.encryptedMessage,
    encryptedServerData.nonce,
    clientSessionKeys?.sharedRx!
  );
  // result: The rest of the afternoon to you!
  console.log(`client received: "${receivedServerMessage}"`);
};

const main = () => {
  // initialize server
  server.createKeyPair();
  console.log("Registering...");
  register();
  console.log("Logging in...");
  login();
  console.log("Sending encrypted messages...");
  sendEncryptedMessages();
};

common.initializeSodium().then((sodium: any) => {
  main();
});
