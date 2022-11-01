// import { server } from "typescript";
import fetch from "node-fetch";
import * as client from "../opaque/client";
import * as common from "../opaque/common";

type StartRegistrationResponse = {
  opaquePublicKey: string;
  opaqueResponse: string;
  serverPublicKey: string;
};
type FinishRegistrationResponse = {
  success: boolean;
};

type OpaqueRegistrationEnvelope = {
  lockbox: string;
  lockboxNonce: string;
};
type StartLoginResponse = {
  envelope: OpaqueRegistrationEnvelope;
  opaqueResponse: string;
  opaquePublicKey: string;
  accessToken: string;
};
type EchoResponse = {
  encryptedMessage: string;
  nonce: string;
};

const username = "user@example.com";
const password = "abc123";
let accessToken: string = "";
let sessionKeys: any = undefined;

const startRegistration = async (
  username: string,
  password: string
): Promise<{
  registerResponse: StartRegistrationResponse;
  randomScalar: Uint8Array;
}> => {
  client.createKeyPair();
  const regStartUrl = "http://localhost:3000/register/start";
  const challengeData = client.createChallenge(password);
  const data = {
    username,
    clientPublicKey: common.base64Encode(client.keyPair?.publicKey!),
    challenge: common.base64Encode(challengeData.opaqueChallenge),
  };
  const response = await fetch(regStartUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json; charset=utf-8",
    },
    body: JSON.stringify(data),
  });
  if (response.status !== 200) {
    throw new Error("Registration failed");
  }
  const registerResponse = (await response.json()) as StartRegistrationResponse;
  return { registerResponse, randomScalar: challengeData.randomScalar };
};

const finishRegistration = async (
  startRegistrationData: StartRegistrationResponse,
  randomScalar: Uint8Array
) => {
  const regFinishUrl = "http://localhost:3000/register/finish";
  const registrationEnvelope = client.createRegistrationEnvelope(
    password,
    randomScalar,
    common.base64Decode(startRegistrationData.opaquePublicKey),
    common.base64Decode(startRegistrationData.opaqueResponse),
    common.base64Decode(startRegistrationData.serverPublicKey)
  );
  const data = {
    username,
    lockbox: common.base64Encode(registrationEnvelope.lockbox),
    lockboxNonce: common.base64Encode(registrationEnvelope.lockboxNonce),
  };
  const response = await fetch(regFinishUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json; charset=utf-8",
    },
    body: JSON.stringify(data),
  });
  if (response.status !== 200) {
    throw new Error("Error: Registration failed");
  }
};

const register = async () => {
  const { registerResponse, randomScalar } = await startRegistration(
    username,
    password
  );
  await finishRegistration(registerResponse, randomScalar);
};

const startLogin = async (
  username: string,
  password: string
): Promise<{ loginResponse: StartLoginResponse; randomScalar: Uint8Array }> => {
  const startLoginUrl = "http://localhost:3000/login/start";
  const challengeData = client.createChallenge(password);
  const data = {
    username,
    challenge: common.base64Encode(challengeData.opaqueChallenge),
  };
  const response = await fetch(startLoginUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json; charset=utf-8",
    },
    body: JSON.stringify(data),
  });
  if (response.status !== 200) {
    throw new Error("Login failed");
  }
  const loginResponse = (await response.json()) as StartLoginResponse;
  accessToken = loginResponse.accessToken;
  return { loginResponse, randomScalar: challengeData.randomScalar };
};

const finishLogin = async (
  loginStartData: StartLoginResponse,
  randomScalar: Uint8Array
) => {
  sessionKeys = client.deriveSessionKeys(
    password,
    randomScalar,
    common.base64Decode(loginStartData.opaquePublicKey),
    common.base64Decode(loginStartData.opaqueResponse),
    common.base64Decode(loginStartData.envelope.lockbox),
    common.base64Decode(loginStartData.envelope.lockboxNonce)
  );
};

const login = async () => {
  const { loginResponse, randomScalar } = await startLogin(username, password);
  await finishLogin(loginResponse, randomScalar);
};

const encryptedEchoTest = async (message: string): Promise<string> => {
  const url = "http://localhost:3000/encryptedecho";
  const encryptedData = common.encryptMessage(message, sessionKeys.sharedTx);
  const data = {
    encryptedMessage: common.base64Encode(encryptedData.encryptedMessage),
    nonce: common.base64Encode(encryptedData.nonce),
  };
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      Authorization: `Bearer ${accessToken}`,
    },
    body: JSON.stringify(data),
  });
  if (response.status !== 200) {
    throw new Error("Echo failed");
  }
  const echoResponseData = (await response.json()) as EchoResponse;
  const decryptedMessage = common.decryptMessage(
    common.base64Decode(echoResponseData.encryptedMessage),
    common.base64Decode(echoResponseData.nonce),
    sessionKeys.sharedRx
  );
  return decryptedMessage;
};

(async () => {
  await common.initializeSodium();
  console.log("Registering...");
  await register();
  console.log("Logging in...");
  await login();
  const echoResponse = await encryptedEchoTest("Hello world!");
  console.log(`Echo response: "${echoResponse}"`);
})();
