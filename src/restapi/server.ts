import express, { NextFunction, Request, Response } from "express";
import { CryptoKX } from "libsodium-wrappers";
import { v4 as uuidv4 } from "uuid";
import * as common from "../opaque/common";
import * as server from "../opaque/server";
const app = express();

const router = express.Router();

app.use(express.json());
const port = 3000;

type Session = {
  username: string;
  sessionKeys: CryptoKX;
};
const sessionDatabase = new Map<string, Session>();

type AuthenticatedRequest = Request & {
  accessToken?: string;
  session?: Session;
  user?: server.User;
};

const requireLogin = (
  request: AuthenticatedRequest,
  _response: Response,
  next: NextFunction
) => {
  const authHeader = request.headers["authorization"];
  if (!authHeader) {
    throw new Error("unauthorized");
  }
  const accessToken = authHeader.split(" ")[1];
  const session = sessionDatabase.get(accessToken);
  if (!session) {
    return next(new Error("unauthorized"));
  }
  const user = server.userDatabase.get(session.username);
  if (!user) {
    return next(new Error("unauthorized"));
  }
  request.accessToken = accessToken;
  request.session = session;
  request.user = user;
  return next();
};

// router methods go here
router.post("/test", (request: Request, response: Response) => {
  response.json(request.body);
});

// router methods go here
router.post("/register/start", (request: Request, response: Response) => {
  const username = request.body.username;
  const clientPublicKey = common.base64Decode(request.body.clientPublicKey);
  const challenge = common.base64Decode(request.body.challenge);
  const responseData = server.createRegistrationChallengeResponse(
    username,
    clientPublicKey,
    challenge
  );
  response.json({
    opaqueResponse: common.base64Encode(responseData.opaqueResponse),
    opaquePublicKey: common.base64Encode(responseData.opaquePublicKey),
    serverPublicKey: common.base64Encode(server.keyPair?.publicKey!),
  });
});

router.post("/register/finish", (request: Request, response: Response) => {
  const username = request.body.username;
  const lockbox = common.base64Decode(request.body.lockbox);
  const lockboxNonce = common.base64Decode(request.body.lockboxNonce);
  try {
    server.updateClientRegistrationEnvelope(username, lockbox, lockboxNonce);
  } catch (error: any) {
    return response.status(400).json({ error: error.message });
  }
  response.json({ success: true });
});

router.post("/login/start", (request: Request, response: Response) => {
  const username = request.body.username;
  const challenge = common.base64Decode(request.body.challenge);
  let responseData: server.GetLoginChallengeResponseResult | undefined =
    undefined;
  try {
    responseData = server.getLoginChallengeResponse(username, challenge);
  } catch (error) {
    return response.status(401).json({ error: "unauthorized" });
  }
  // create a session for this login
  const userData = server.userDatabase.get(username);
  if (
    !userData ||
    !userData.clientPublicKey ||
    !userData.lockbox ||
    !userData.lockboxNonce
  ) {
    return response.status(401).json({ error: "unauthorized" });
  }
  const accessToken = uuidv4();
  const sessionKeys = server.deriveSessionKeys(userData.clientPublicKey);
  sessionDatabase.set(accessToken, {
    username,
    sessionKeys,
  });
  // issue the response to the client
  response.json({
    envelope: {
      lockbox: common.base64Encode(responseData.envelope.lockbox),
      lockboxNonce: common.base64Encode(responseData.envelope.lockboxNonce),
    },
    opaqueResponse: common.base64Encode(responseData.opaqueResponse),
    opaquePublicKey: common.base64Encode(responseData.opaquePublicKey),
    accessToken,
  });
});

router.post(
  "/login/finish",
  requireLogin,
  (request: AuthenticatedRequest, response: Response) => {
    response.json({ success: true });
  }
);

router.post(
  "/encryptedecho",
  requireLogin,
  (request: AuthenticatedRequest, response: Response) => {
    let session: Session | undefined = undefined;
    const encryptedMessage = common.base64Decode(request.body.encryptedMessage);
    const nonce = common.base64Decode(request.body.nonce);
    let decryptedMessage = "";
    try {
      decryptedMessage = common.decryptMessage(
        encryptedMessage,
        nonce,
        request.session!.sessionKeys.sharedRx
      );
    } catch (error) {
      return response.status(401).json({
        error: "unauthorized",
      });
    }
    const reEncryptedData = common.encryptMessage(
      decryptedMessage,
      request.session!.sessionKeys.sharedTx
    );
    response.send({
      encryptedMessage: common.base64Encode(reEncryptedData.encryptedMessage),
      nonce: common.base64Encode(reEncryptedData.nonce),
    });
  }
);

app.use(router);

(async () => {
  await common.initializeSodium();
  server.createKeyPair();
  app.listen(port, () => {
    console.log(`OPAQUE auth server listening on port ${port}`);
  });
})();
