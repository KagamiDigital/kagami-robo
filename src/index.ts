import * as logger from "./logger"
import * as dotenv from "dotenv"
import {io} from 'socket.io-client'
const https_proxy_agent = require("https-proxy-agent");
import { recoverSeed } from "./recover";

import {
  combineSignedTx,
  preRegistrationWithProxy,
  automateRegistrationWithProxy,
  registerAllStepsWithProxy,
  signTxWithProxy,
  getVaultsWithProxy,
  createProxiedSigner
} from "@intuweb3/sdk";
import { getRPCNodeFromNetworkId } from "./utils";
import { addTransaction, dbScript, getTransactionsForAccount } from "./database";
import { RoboSignerStatus } from "./types/RoboSignerStatus";

dotenv.config();

const proxyUrl = process.env.HTTPS_PROXY; 
const agent = new https_proxy_agent.HttpsProxyAgent(proxyUrl); 

import Web3 from "web3";
import * as HDKey from 'hdkey'; 
import { Account, TransactionReceipt } from "web3-core";

interface ProxiedSigner {
  web3: Web3; 
  account:Account; 
}

let provider:Web3;

const signers: { [index: string]:ProxiedSigner } = {};
let encryptedSeed = '';

( async () => {
  console.log('running db script'); 
  dbScript();
})();


(async () => {
  try {

    let result = await recoverSeed(); 
    let seed_tuple = result.split(",");
    let seed = seed_tuple[0]
    encryptedSeed = seed_tuple[1]; 

    // Create HD wallet
    var hdWallet = HDKey.fromMasterSeed(Buffer.from(seed, 'hex'));
    
    console.log('HTTPS_PROXY:',process.env.HTTPS_PROXY)
    console.log('HTTP_PROXY:',process.env.HTTP_PROXY);
    console.log('httpsProxy:',process.env.httpsProxy);
    console.log('httpProxy:',process.env.httpProxy);
    console.log('rpcUrl', process.env.ORCHESTRATION_NODE_URL)

    // Generate accounts
    for (let i = 0; i < 3 ; i++) {
        const path = `m/44'/60'/0'/0/${i}`;
        const wallet = hdWallet.derive(path);
        const privateKey = '0x' + wallet.privateKey.toString('hex');
        const proxiedSigner:ProxiedSigner = await createProxiedSigner(privateKey,proxyUrl,process.env.ORCHESTRATION_NODE_URL);
        signers[proxiedSigner.account.address] = proxiedSigner;
        console.log(`Signer ${i + 1}`, proxiedSigner.account.address);
        logger.info(`Signer ${i + 1}`, proxiedSigner.account.address)
    }

  } catch (error) {
    console.error('Error recovering seed:', error);
  }

  const socket = io(process.env.API_URL + "/robo", {
    query: {
      apiKey: process.env.API_KEY,
      signers: Object.keys(signers),
      encryptedSeed: encryptedSeed,
    },
    transports: ["websocket"],
    agent: agent
  });

  console.log("Attempting socket on ", process.env.API_URL)

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

  socket.on("accountTransactions", async (data: {signer:string, accountAddress: string }) => {

    const { accountAddress, signer } = data;

    publishUpdateToServer(`SaltRobos: accountTransactions:${signer} => Event Received From API`, {}, {accountAddress, signer})

    try {

      publishUpdateToServer(`SaltRobos: accountTransactions:start:${signer} => expect success or failure`, {}, {accountAddress, signer})
      
      console.log('the account address is '+accountAddress); 
      const transactions = await getTransactionsForAccount(accountAddress);  

      console.log(transactions);

      publishUpdateToServer(`SaltRobos: accountTransactions:success:${signer}`,{}, {accountAddress, signer})
      
        socket.emit("accountTransactions", {
          ...{transactions,accountAddress, signer},
          success: true,
          error: null,
        });

        return; 
    } catch(error) {

      publishUpdateToServer(`SaltRobos:Error: getAccountTransactions:failure:${signer} => error`, {error}, {accountAddress, signer},)

      logger.error(`Log:Error: Error: getAccountTransactions:failure:${signer}`, error)

      socket.emit("accountTransactions", {
        ...{transctions:[],accountAddress, signer},
        success: false,
        error,
      });

      return; 
    }
  });
  /*
  socket.on("accountTransactionsHistoryBuild", async (data: {signer:string, accountAddress: string }) => {

    const { accountAddress, signer } = data;
    let transactions = []
    const responsePayload = { accountAddress, signer };

    publishUpdateToServer(`SaltRobos: accountTransactionsHistoryBuild:${signer} => Event Received From API`, {}, responsePayload)

    
    try {

      publishUpdateToServer(`SaltRobos: accountTransactionsHistoryBuild:start:${signer} => expect success or failure`, {}, responsePayload)
      
      await rebuildTransactionRecordsForAccount(signers[signer],provider,accountAddress);  

      publishUpdateToServer(`SaltRobos: accountTransactionsHistoryBuild:success:${signer}`,{}, responsePayload)
      
        socket.emit("accountTransactionsHistoryBuild", {
          ...responsePayload,
          success: true,
          error: null,
        });

        return; 
    } catch(error) {

      publishUpdateToServer(`SaltRobos:Error: accountTransactionsHistoryBuild:failure:${signer} => error`, {error}, responsePayload)

      logger.error(`Log:Error: Error: accountTransactionsHistoryBuild:failure:${signer}`, error)

      socket.emit("accountTransactionsHistoryBuild", {
        ...responsePayload,
        success: false,
        error,
      });

      return; 
    }
  }); */
    
  socket.on("preRegister", async (data: { signer: string; accountAddress: string }) => {

    const { accountAddress, signer } = data;
    const responsePayload = { accountAddress, signer };

    publishUpdateToServer(`SaltRobos: pre-registration:${signer} => Event Received From API`, {}, responsePayload)

    
    try {

      publishUpdateToServer(`SaltRobos: pre-registration:getPreregistrationStatus:start:${signer} => expect success or failure`, {}, responsePayload)
      
      const preRegisterInfo =  {registered: false} // await getUserPreRegisterInfos(accountAddress,signer,provider); 

      if(preRegisterInfo.registered) { // user is already pre registered, redundant request
        
        publishUpdateToServer(`SaltRobos: pre-registration:getPreregistrationStatus:success:${signer}`, preRegisterInfo.registered, responsePayload)
      
        const status:RoboSignerStatus = {
          accountAddress: accountAddress,
          address:signer,
          preRegistered:true,
        }

        socket.emit("accountSetupUpdate", {
          ...status,
        });

        return; 
      }
    } catch(error) {

      publishUpdateToServer(`SaltRobos:Error: pre-registration:getPreRegistrationSatus:failure:${signer} => error`, {error}, responsePayload)

      logger.error(`Log:Error: Error pre-registration:getPreregistrationStatus:failure:${signer}`, error)

      const status:RoboSignerStatus = {
        accountAddress: accountAddress,
        address:signer,
        preRegistered:false,
      }

      socket.emit("accountSetupUpdate", {
        ...status,
      });

      return; 
    }
    
    try {

      publishUpdateToServer(`SaltRobos: pre-registration:start:${signer} => expect success or failure`, {}, responsePayload)
      
      console.log(signers[signer]);
      const receipt:TransactionReceipt = await preRegistrationWithProxy(accountAddress, signers[signer], proxyUrl) 
      console.log(receipt);
      publishUpdateToServer(`SaltRobos: pre-registration:success:${signer} => response`, {receipt}, responsePayload)

      const status:RoboSignerStatus = {
        accountAddress: accountAddress,
        address:signer,
        preRegistered:true,
      }

      socket.emit("accountSetupUpdate", {
        ...status,
      });

    } catch (error) {

      publishUpdateToServer(`SaltRobos:Error: pre-registration:failure:${signer} => error`, {error}, responsePayload)

      logger.error(`Log:Error: Error pre-registration:failure:${signer}`, error)

      const status:RoboSignerStatus = {
        accountAddress: accountAddress,
        address:signer,
        preRegistered:false,
      }

      socket.emit("accountSetupUpdate", {
        ...status,
      });

    }
  });

  socket.on("register", async (data: { signer: string; accountAddress: string, nostrNode: string }) => {

    const { accountAddress, signer, nostrNode } = data;
    const responsePayload = { accountAddress, signer, nostrNode };
    
    publishUpdateToServer(`SaltRobos: register:event:received for signer: ${signer}`, {}, responsePayload);

    try {

      publishUpdateToServer(`SaltRobos: register:event:getRegistrationStatus:start:${signer} => expect success or failure`, {}, responsePayload);
      
      const vaults = await getVaultsWithProxy(signer,provider,proxyUrl,signers[signer]);
   

      const users = vaults.find(v => v.vaultAddress.toLowerCase() === accountAddress.toLocaleLowerCase())?.users;
      const user = users.find(u => u.address.toLowerCase() === signer.toLowerCase()); 

      if(user && user.isRegistered) { // robo has already registerd, redundant request
        
        publishUpdateToServer(`SaltRobos: register:event:getRegistrationStatus:success:${signer}`, user.isRegistered, responsePayload);
    
        const status:RoboSignerStatus = {
          accountAddress: accountAddress,
          address:signer,
          registered:true,
        }
    
        socket.emit("accountSetupUpdate", {
          ...status,
        });

        return;
      }
    } catch(error) {

      publishUpdateToServer(`SaltRobos: register:event:getRegistrationStatus:failure:${signer}`, {error}, responsePayload);
    
      logger.error(`Log:Error: Error register:event:getRegistrationStatus:failure:${signer}`, error)

      const status:RoboSignerStatus = {
        accountAddress: accountAddress,
        address:signer,
        registered:false,
      }

      socket.emit("accountSetupUpdate", {
        ...status,
      });
      return;
    }

    try {
      publishUpdateToServer(`SaltRobos: register:automateRegistration:start:${signer} => expect success or failure`, {}, responsePayload)
      
      const res = await automateRegistrationWithProxy(accountAddress, signers[signer], proxyUrl,nostrNode, undefined)
      
      publishUpdateToServer(`SaltRobos: register:automateRegistration:success:${signer} => response`, {res}, responsePayload)

    } catch (error) {
      
      publishUpdateToServer(`SaltRobos:Error: register:automateRegistration:failure:${signer} => error`, {error}, responsePayload)

      logger.error(`Log:Error: Error register:automateRegistration:failure:${signer}`, error)

      const status:RoboSignerStatus = {
        accountAddress: accountAddress,
        address:signer,
        registered:false,
      }

      socket.emit("accountSetupUpdate", {
        ...status,
      });

      return; 
    }

    try {
      publishUpdateToServer(`SaltRobos: register:registerAllSteps:start:${signer} => expect success or failure`, {}, responsePayload)
      const receipt = await registerAllStepsWithProxy(accountAddress, signers[signer],proxyUrl,undefined, nostrNode, undefined); 
      console.log(receipt);
      publishUpdateToServer(`SaltRobos: register:registerAllSteps:success:${signer} => response`, {receipt}, responsePayload)
    } catch(error) {
      publishUpdateToServer(`SaltRobos:Error: register:registerAllSteps:failure:${signer} => error`, {error}, responsePayload)

      logger.error(`Log:Error: Error register:registerAllSteps:failure:${signer}`, error)

      const status:RoboSignerStatus = {
        accountAddress: accountAddress,
        address:signer,
        registered:false,
      }

      socket.emit("accountSetupUpdate", {
        ...status,
      });

      return
    }

    const status:RoboSignerStatus = {
      accountAddress: accountAddress,
      address:signer,
      registered:true,
    }

    socket.emit("accountSetupUpdate", {
      ...status,
    });
  });

  socket.on(
    "proposeTransaction",
    async (data: { signer: string; accountAddress: string; txId: string }) => {

      const { accountAddress, txId, signer } = data;
      const responsePayload = { accountAddress, txId, signer };

      publishUpdateToServer(`SaltRobos: proposeTransaction:signTx:${signer} => Event Received`, {}, responsePayload)

      try {
        publishUpdateToServer(`SaltRobos: proposeTransaction:signTx:start:${signer} => expect success or failure`, {}, responsePayload)

        const receipt = await signTxWithProxy(accountAddress, Number(txId), {web3: provider, account: signers[signer]},proxyUrl); 
        console.log(receipt);
        publishUpdateToServer(`SaltRobos: proposeTransaction:signTx:success:${signer} => response`, {receipt}, responsePayload)

        socket.emit("transactionSigningComplete", {
          ...responsePayload,
          success: true,
          error: null,
        });

      } catch (error) {

        publishUpdateToServer(`SaltRobos:Error: proposeTransaction:signTx:failure:${signer} => error`, {error}, responsePayload)

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

      publishUpdateToServer(`SaltRobos: broadcastTransaction:signTx:${signer} => Event Received`, {}, responsePayload); 

      const RPC_NODE_URL = getRPCNodeFromNetworkId(networkId);  
      
      if(!RPC_NODE_URL) {
        
        const _error = `network id is not supported: ${networkId}`; 
        publishUpdateToServer(`SaltRobos:Error: broadcastTransaction:failure:${signer} => error`, {_error}, responsePayload)

        logger.error(`Log:Error: Error broadcastTransaction:failure:${signer}`, _error)

        socket.emit("transactionBroadcastingComplete", {
          ...responsePayload,
          success: false,
          _error,
        });

        return; 
      }

      let combineResponse:string;  

      try {
        publishUpdateToServer(`SaltRobos: broadcastTransaction:combineTx:start:${signer} => expect success or failure`, {}, responsePayload)

        combineResponse = await combineSignedTx(accountAddress, Number(txId), signers[signer] as any);
        publishUpdateToServer(`SaltRobos: broadcastTransaction:combineTx:success:${signer} => response`, {combineResponse}, responsePayload)

        socket.emit("transactionCombiningComplete", {
          ...responsePayload,
          success: true,
          error: null,
        });
      } catch (error) {

        publishUpdateToServer(`SaltRobos:Error: broadcastTransaction:combineTx:failure:${signer} => error`, {error}, responsePayload)

        logger.error(`Log:Error: Error broadcastTransaction:combineTx:failure:${signer}`, error)

        socket.emit("SignatureCombineComplete", {
          ...responsePayload,
          success: false,
          error,
        });
        return; 
      }
      try {

        publishUpdateToServer(`SaltRobos: broadcastTransaction:sendTx:start:${signer} => expect success or failure`, {}, responsePayload)

        const _provider = new Web3(new Web3.providers.HttpProvider(RPC_NODE_URL, {agent: { https: agent, http: agent }}));

        const txReceipt:TransactionReceipt = await _provider.eth.sendSignedTransaction(combineResponse); 

        responsePayload.txReceipt = txReceipt;

        // add the transaction to the db
        addTransaction(accountAddress, Number(txId), networkId,txReceipt.transactionHash); 
  
        publishUpdateToServer(`SaltRobos: broadcastTransaction:sendTx:success:${signer} => response`, {}, { responsePayload,txReceipt })

        socket.emit("transactionBroadcastingComplete", {
          ...responsePayload,
          success: true,
          error: null,
        });

      } catch (error) {

        publishUpdateToServer(`SaltRobos:Error: broadcastTransaction:sendTx:failure:${signer} => error`, {error}, responsePayload)

        logger.error(`Log:Error: Error broadcastTransaction:sendTx:failure:${signer}`, error)

        socket.emit("transactionBroadcastingComplete", {
          ...responsePayload,
          success: false,
          error,
        });
      } 
    }
  )

  function publishUpdateToServer(message:string, data:any, responsePayload:any) {
    console.error("message:", message)
    console.error("data", data)
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
})();



const express = require("express");
const app = express();
const listener = app.listen(process.env.PORT || 4300, () => {
  console.log("App is running on port " + listener.address().port);
});