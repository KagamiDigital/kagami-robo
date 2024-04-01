require("dotenv").config();

import { preRegistration } from "@intuweb3/exp-node";
import { ethers } from "ethers";

const provider = new ethers.providers.JsonRpcProvider(process.env.NODE_URL);
const signers: { [index: string]: any } = {};

(async () => {
  process.env.KEYS.split(",").forEach(async (privateKey, i) => {
    const wallet = new ethers.Wallet(privateKey);
    const signer = wallet.connect(provider);
    const publicAddress = await signer.getAddress();
    signers[publicAddress] = signer;
    console.log(`Signer ${i + 1}`, publicAddress);
  });
})();

const io = require("socket.io-client");

const socket = io(process.env.API_URL, {
  query: {
    apiKey: process.env.API_KEY,
  },
});

socket.on("connect", () => {
  console.log("Connected to server");
});

socket.on("preRegister", (data: { signer: string; accountAddress: string }) => {
  console.log("Pre-register event received:", data);
  preRegistration(data.accountAddress, signers[data.signer]);
});
