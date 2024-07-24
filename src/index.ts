import * as logger from "./logger"
import * as dotenv from "dotenv"
import {io} from 'socket.io-client'
dotenv.config();

import { ethers } from "ethers";
const provider = new ethers.providers.StaticJsonRpcProvider({url: process.env.NODE_URL || "",skipFetchSetup:true});
const signers: { [index: string]: any } = {};

import {
  preRegistration,
  automateRegistration,
  registerAllSteps,
  signTx,
} from "@intuweb3/exp-node";

(async () => {
  process.env.KEYS!.split(",").forEach(async (privateKey, i) => {
    const wallet = new ethers.Wallet(privateKey);
    const signer = wallet.connect(provider);
    const publicAddress = await signer.getAddress();
    signers[publicAddress] = signer;
    console.log(`Signer ${i + 1}`, publicAddress);

    logger.info(`Signer ${i + 1}`, publicAddress)
  });
})();

console.log("Attempting socket on ", process.env.API_URL)

const socket = io(process.env.API_URL + "/robo", {
  query: {
    apiKey: process.env.API_KEY,
  },
  transports: ["websocket"]
});

socket.on("connect", () => {
  _sendLogToClient(`SaltRobos: connect:success => Connected to WebSocket Robo Namespace`)

  console.log(`Connected to server URL : ${process.env.API_URL}`)
});

socket.on("error", (err:any) => {
  console.log(err)
  logger.error("Log:Error: Error connecting to API Socket Stream", err)
});

socket.on("connect_error", (err:any) => {
  console.log(err)
  logger.error("Log:Error: Error connect_error connecting to API Socket Stream", err)
});

socket.on("preRegister", async (data: { signer: string; accountAddress: string }) => {

  const { accountAddress, signer } = data;
  const responsePayload = { accountAddress, signer };

  try {

    _sendLogToClient(`SaltRobos: preRegistration:start => expect success or failure`, {accountAddress, signer, signer_details: signers[signer], responsePayload})
    const res = await preRegistration(accountAddress, signers[signer])
    _sendLogToClient(`SaltRobos: preRegistration:success => response`, res)

    socket.emit("preRegistrationComplete", {
      ...responsePayload,
      success: true,
      error: null,
    });

  } catch (error) {

    _sendLogToClient(`SaltRobos:Error: preRegistration:failure => error`, {signer, error})

    socket.emit("preRegistrationComplete", {
      ...responsePayload,
      success: false,
      error,
    });

  }
});

socket.on("register", async (data: { signer: string; accountAddress: string }) => {

  _sendLogToClient(`SaltRobos: register => Event Received`, data)

  const { accountAddress, signer } = data;
  const responsePayload = { accountAddress, signer };

  try {
    _sendLogToClient(`SaltRobos: automateRegistration:start => expect success or failure`, {accountAddress, signer, signer_details: signers[signer]})
    const res = await automateRegistration(accountAddress, signer, signers[signer])
    _sendLogToClient(`SaltRobos: automateRegistration:success => response`, res)

  } catch (error) {
    _sendLogToClient(`SaltRobos:Error: automateRegistration:failure => error`, {signer, error})

    emitError(error)
    return
  }


  try {
    _sendLogToClient(`SaltRobos: registerAllSteps:start => expect success or failure`, {accountAddress, signer, signer_details: signers[signer]})
    const res = await registerAllSteps(accountAddress, signers[signer])
    _sendLogToClient(`SaltRobos: registerAllSteps:success => response`, res)
  } catch(error) {
    _sendLogToClient(`SaltRobos:Error: registerAllSteps:failure => error`, {signer, error})

    emitError(error)
    return
  }

  socket.emit("registrationComplete", {
    ...responsePayload,
    success: true,
    error: null,
  });

  function emitError(error)
  {
    socket.emit("registrationComplete", {
      ...responsePayload,
      success: false,
      error,
    });
  }
});

socket.on(
  "proposeTransaction",
  async (data: { signer: string; accountAddress: string; txId: string }) => {

    _sendLogToClient(`SaltRobos: proposeTransaction => Event Received`, data)

    const { accountAddress, txId, signer } = data;
    const responsePayload = { accountAddress, txId, signer };

    try {
      _sendLogToClient(`SaltRobos: proposeTransaction:start => expect success or failure`, {accountAddress, txId: Number(txId), signer, signer_details: signers[signer]})

      const res = await signTx(accountAddress, Number(txId), signers[signer])
      _sendLogToClient(`SaltRobos: proposeTransaction:success => response`, res)

      socket.emit("transactionSigningComplete", {
        ...responsePayload,
        success: true,
        error: null,
      });

    } catch (error) {

      _sendLogToClient(`SaltRobos:Error: proposeTransaction:failure => error`, {signer, error})

      socket.emit("transactionSigningComplete", {
        ...responsePayload,
        success: false,
        error,
      });
    }
  },
);

function _sendLogToClient(message, data = null) {
  console.log(message, data)

  let m = message
  if (data) {
    m = `${message} :: ${JSON.stringify(data)}`
  }

  socket.emit("update", m)
}


const express = require("express");
const app = express();
const listener = app.listen(process.env.PORT || 4300, () => {
  console.log("App is running on port " + listener.address().port);
});
