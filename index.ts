import dotenv from "dotenv";
import logger from "./logger";
dotenv.config();

import { ethers } from "ethers";
const provider = new ethers.providers.JsonRpcProvider(process.env.NODE_URL);
const signers: { [index: string]: any } = {};

const intu = require("@intuweb3/exp-node");

(async () => {
  process.env.KEYS.split(",").forEach(async (privateKey, i) => {
    const wallet = new ethers.Wallet(privateKey);
    const signer = wallet.connect(provider);
    const publicAddress = await signer.getAddress();
    signers[publicAddress] = signer;
    logger.debug(`Signer ${i + 1}`, publicAddress);
  });
})();

const io = require("socket.io-client");

const socket = io(process.env.API_URL + "/robo", {
  query: {
    apiKey: process.env.API_KEY,
  },
});

socket.on("connect", () => {
  logger.debug("Connected to server");
});

socket.on("preRegister", async (data: { signer: string; accountAddress: string }) => {
  console.log("preRegister event listener created :: ", socket.id)
  logger.debug("Pre-register event received:", data);
  const { accountAddress, signer } = data;
  const responsePayload = { accountAddress, signer };

  try {
    console.log("Trying INTU preRegistration for signer : ", signer)
    console.log("Start intu.preRegistration", socket.id);
    await intu.preRegistration(accountAddress, signers[signer])
    console.log("Done intu.preRegistration", socket.id);
    socket.emit("preRegistrationComplete", {
      ...responsePayload,
      success: true,
      error: null,
    });

  } catch (error) {
    console.log("Error PreRegistration for signer : ", signer)
    console.error(error);
    socket.emit("preRegistrationComplete", {
      ...responsePayload,
      success: false,
      error,
    });
  }
});

socket.on("register", async (data: { signer: string; accountAddress: string }) => {
  logger.debug("Register event received:", data);
  const { accountAddress, signer } = data;
  const responsePayload = { accountAddress, signer };

  try {
    await intu.automateRegistration(accountAddress, signer, signers[signer])

    await intu.registerAllSteps(accountAddress, signers[signer])

    socket.emit("registrationComplete", {
      ...responsePayload,
      success: true,
      error: null,
    });

  } catch (error) {
    logger.debug("Error Registration")
    logger.debug(error);
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
    logger.debug("Propose transaction event received:", data);
    const { accountAddress, txId, signer } = data;
    const responsePayload = { accountAddress, txId, signer };

    try {
      await intu.signTx(accountAddress, txId, signers[signer])

      socket.emit("transactionSigningComplete", {
        ...responsePayload,
        success: true,
        error: null,
      });

    } catch (error) {
      logger.debug("Error proposeTransaction")
      logger.debug(error);
      socket.emit("transactionSigningComplete", {
        ...responsePayload,
        success: false,
        error,
      });
    }
  },
);

const express = require("express");
const app = express();
const listener = app.listen(process.env.PORT || 4300, () => {
  logger.debug("App is running on port " + listener.address().port);
});
