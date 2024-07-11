import dotenv from "dotenv";
dotenv.config();

import { ethers } from "ethers";
const provider = new ethers.providers.JsonRpcProvider({url:process.env.NODE_URL!,skipFetchSetup:true});
const signers: { [index: string]: any } = {};

const intu = require("@intuweb3/exp-node");

(async () => {
  process.env.KEYS!.split(",").forEach(async (privateKey, i) => {
    const wallet = new ethers.Wallet(privateKey);
    const signer = wallet.connect(provider);
    const publicAddress = await signer.getAddress();
    signers[publicAddress] = signer;
    console.log(`Signer ${i + 1}`, publicAddress);
  });
})();

const io = require("socket.io-client");

const socket = io(process.env.API_URL + "/robo", {
  query: {
    apiKey: process.env.API_KEY,
  },
});

socket.on("connect", () => {
  console.log("Connected to server");
});

socket.on("preRegister", async (data: { signer: string; accountAddress: string }) => {
  console.log("Pre-register event received:", data);
  const { accountAddress, signer } = data;
  const responsePayload = { accountAddress, signer };

  try {
    await intu.preRegistration(accountAddress, signers[signer])

    socket.emit("preRegistrationComplete", {
      ...responsePayload,
      success: true,
    });

    console.log('emitted preregitration event')

  } catch (error) {
    console.log("Error PreRegistration")
    console.log(error);
    socket.emit("preRegistrationComplete", {
      ...responsePayload,
      success: false,
    });
  }
});

socket.on("register", async (data: { signer: string; accountAddress: string }) => {
  console.log("Register event received:", data);
  const { accountAddress, signer } = data;
  const responsePayload = { accountAddress, signer };

  try {
    await intu.automateRegistration(accountAddress, signer, signers[signer])

    await intu.registerAllSteps(accountAddress, signers[signer])

    socket.emit("registrationComplete", {
      ...responsePayload,
      success: true,
    });

  } catch (error) {
    console.log("Error Registration")
    console.log(error);
    socket.emit("registrationComplete", {
      ...responsePayload,
      success: false,
    });
  }
});

socket.on(
  "proposeTransaction",
  async (data: { signer: string; accountAddress: string; txId: string }) => {
    console.log("Propose transaction event received:", data);
    const { accountAddress, txId, signer } = data;
    const responsePayload = { accountAddress, txId, signer };

    try {
      await intu.signTx(accountAddress, txId, signers[signer])

      socket.emit("transactionSigningComplete", {
        ...responsePayload,
        success: true,
      });

    } catch (error) {
      console.log("Error proposeTransaction")
      console.log(error);
      socket.emit("transactionSigningComplete", {
        ...responsePayload,
        success: false,
      });
    }
  },
);

const express = require("express");
const app = express();
const listener = app.listen(process.env.PORT || 4300, () => {
  console.log("App is running on port " + listener.address().port);
});
