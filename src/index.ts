import * as logger from "./logger"
import * as dotenv from "dotenv"
import {io} from 'socket.io-client'
dotenv.config();

import { ethers } from "ethers";
const provider = new ethers.providers.StaticJsonRpcProvider({url: process.env.SEPOLIA_NODE_URL || "",skipFetchSetup:true});
const signers: { [index: string]: ethers.Wallet } = {};

import {
  preRegistration,
  automateRegistration,
  registerAllSteps,
  signTx,
  combineSignedTx,
} from "@intuweb3/exp-node";
import { getRPCNodeFromNetworkId } from "./utils";

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

  _sendLogToClient(`SaltRobos: pre-registration:${signer} => Event Received From API`, {}, responsePayload)

  try {

    _sendLogToClient(`SaltRobos: pre-registration:start:${signer} => expect success or failure`, {}, responsePayload)
    const res = await preRegistration(accountAddress, signers[signer])
    _sendLogToClient(`SaltRobos: pre-registration:success:${signer} => response`, {res}, responsePayload)

    socket.emit("preRegistrationComplete", {
      ...responsePayload,
      success: true,
      error: null,
    });

  } catch (error) {

    _sendLogToClient(`SaltRobos:Error: pre-registration:failure:${signer} => error`, {error}, responsePayload)

    logger.error(`Log:Error: Error pre-registration:failure:${signer}`, error)

    socket.emit("preRegistrationComplete", {
      ...responsePayload,
      success: false,
      error,
    });

  }
});

socket.on("register", async (data: { signer: string; accountAddress: string }) => {

  const { accountAddress, signer } = data;
  const responsePayload = { accountAddress, signer };

  _sendLogToClient(`SaltRobos: register:event:received for signer: ${signer}`, {}, responsePayload)

  try {
    _sendLogToClient(`SaltRobos: register:automateRegistration:start:${signer} => expect success or failure`, {}, responsePayload)
    const res = await automateRegistration(accountAddress, signer, signers[signer])
    _sendLogToClient(`SaltRobos: register:automateRegistration:success:${signer} => response`, {res}, responsePayload)

  } catch (error) {
    _sendLogToClient(`SaltRobos:Error: register:automateRegistration:failure:${signer} => error`, {error}, responsePayload)

    logger.error(`Log:Error: Error register:automateRegistration:failure:${signer}`, error)

    emitError(error)
    return
  }


  try {
    _sendLogToClient(`SaltRobos: register:registerAllSteps:start:${signer} => expect success or failure`, {}, responsePayload)
    const res = await registerAllSteps(accountAddress, signers[signer])
    _sendLogToClient(`SaltRobos: register:registerAllSteps:success:${signer} => response`, {res}, responsePayload)
  } catch(error) {
    _sendLogToClient(`SaltRobos:Error: register:registerAllSteps:failure:${signer} => error`, {error}, responsePayload)

    logger.error(`Log:Error: Error register:registerAllSteps:failure:${signer}`, error)

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

    const { accountAddress, txId, signer } = data;
    const responsePayload = { accountAddress, txId, signer };

    _sendLogToClient(`SaltRobos: proposeTransaction:signTx:${signer} => Event Received`, {}, responsePayload)

    try {
      _sendLogToClient(`SaltRobos: proposeTransaction:signTx:start:${signer} => expect success or failure`, {}, responsePayload)

      const res = await signTx(accountAddress, Number(txId), signers[signer])
      _sendLogToClient(`SaltRobos: proposeTransaction:signTx:success:${signer} => response`, {res}, responsePayload)

      socket.emit("transactionSigningComplete", {
        ...responsePayload,
        success: true,
        error: null,
      });

    } catch (error) {

      _sendLogToClient(`SaltRobos:Error: proposeTransaction:signTx:failure:${signer} => error`, {error}, responsePayload)

      logger.error(`Log:Error: Error proposeTransaction:signTx:failure:${signer}`, error)

      socket.emit("transactionSigningComplete", {
        ...responsePayload,
        success: false,
        error,
      });
    }
  },
);

socket.on(
  "broadcastTransaction",
  async (data: { signer: string; accountAddress: string; txId: string, networkId:string }) => {

    const { accountAddress, txId, networkId, signer } = data;
    const responsePayload = { accountAddress, txId, signer, txReceipt: null };

    _sendLogToClient(`SaltRobos: broadcastTransaction:signTx:${signer} => Event Received`, {}, responsePayload); 

    const RPC_NODE_URL = getRPCNodeFromNetworkId(networkId);  
    
    if(!RPC_NODE_URL) {
      
      const _error = `network id is not supported: ${networkId}`; 
      _sendLogToClient(`SaltRobos:Error: broadcastTransaction:failure:${signer} => error`, {_error}, responsePayload)

      logger.error(`Log:Error: Error broadcastTransaction:failure:${signer}`, _error)

      socket.emit("transactionBroadcastingComplete", {
        ...responsePayload,
        success: false,
        _error,
      });

      return; 
    }

    let combineResponse;  

    try {
      _sendLogToClient(`SaltRobos: broadcastTransaction:combineTx:start:${signer} => expect success or failure`, {}, responsePayload)

      combineResponse = await combineSignedTx(accountAddress, Number(txId), signers[signer])
      _sendLogToClient(`SaltRobos: broadcastTransaction:combineTx:success:${signer} => response`, {combineResponse}, responsePayload)

      socket.emit("transactionCombiningComplete", {
        ...responsePayload,
        success: true,
        error: null,
      });
    } catch (error) {

      _sendLogToClient(`SaltRobos:Error: broadcastTransaction:combineTx:failure:${signer} => error`, {error}, responsePayload)

      logger.error(`Log:Error: Error broadcastTransaction:combineTx:failure:${signer}`, error)

      socket.emit("transactionBroadcastingComplete", {
        ...responsePayload,
        success: false,
        error,
      });
      return; 
    }
    try {

      _sendLogToClient(`SaltRobos: broadcastTransaction:sendTx:start:${signer} => expect success or failure`, {}, responsePayload)

      const _provider = new ethers.providers.StaticJsonRpcProvider({url: RPC_NODE_URL || "",skipFetchSetup:true});

      const txResponse = await _provider.sendTransaction(combineResponse.combinedTxHash.finalSignedTransaction); 

      const txReceipt= await txResponse.wait(); 

      responsePayload.txReceipt = txReceipt; 

      _sendLogToClient(`SaltRobos: broadcastTransaction:sendTx:success:${signer} => response`, {}, { responsePayload,txReceipt })

      socket.emit("transactionBroadcastingComplete", {
        ...responsePayload,
        success: true,
        error: null,
      });

    } catch (error) {

      _sendLogToClient(`SaltRobos:Error: broadcastTransaction:sendTx:failure:${signer} => error`, {error}, responsePayload)

      logger.error(`Log:Error: Error broadcastTransaction:sendTx:failure:${signer}`, error)

      socket.emit("transactionBroadcastingComplete", {
        ...responsePayload,
        success: false,
        error,
      });
    } 
  }
)

function _sendLogToClient(message, data, responsePayload) {

  console.error("message:", message)
  console.error("data", message)
  console.error("responsePayload", responsePayload)

  let m = message
  if (data) {
    m = `${message} :: ${JSON.stringify(data)}`
  }

  socket.emit("update", {
    ...responsePayload,
    message: m,
  })
}


const express = require("express");
const app = express();
const listener = app.listen(process.env.PORT || 4300, () => {
  console.log("App is running on port " + listener.address().port);
});
