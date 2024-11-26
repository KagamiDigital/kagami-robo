import * as logger from './logger';
import * as dotenv from 'dotenv';
import { io } from 'socket.io-client';
dotenv.config();

// Parent Instance (Robo) - vsock-client.js
const net = require('net');
const VSOCK_PROXY_PORT = 8000; // Default AWS Nitro Enclaves vsock-proxy port
const ENCLAVE_CID = 16; // Default CID for the first enclave
const ENCLAVE_PORT = 5000; // Port the Signer app listens on
let vsockClient = null;

import { ethers } from 'ethers';
const provider = new ethers.providers.StaticJsonRpcProvider({
  url: process.env.ORCHESTRATION_NODE_URL || '',
  skipFetchSetup: true,
});
const signers: { [index: string]: ethers.Wallet } = {};

import {
  preRegistration,
  automateRegistration,
  registerAllSteps,
  signTx,
  combineSignedTx,
  getUserRegistrationAllInfos,
  getUserPreRegisterInfos,
} from '@intuweb3/exp-node';
import { getRPCNodeFromNetworkId } from './utils';

console.log('Attempting socket on ', process.env.API_URL);

const socket = io(process.env.API_URL + '/robo', {
  query: {
    apiKey: process.env.API_KEY,
  },
  transports: ['websocket'],
});

function newVSockClient() {
  const api = {
    socket: new net.Socket(),
    isConnected: false,
    connect,
    send,
    write,
    close,
  };

  return api;

  function connect() : Promise<void> {
    return new Promise((resolve, reject) => {
      api.socket.connect(
        {
          host: '127.0.0.1', // vsock-proxy listens on localhost
          port: VSOCK_PROXY_PORT,
        },
        () => {
          console.log('Connected to vsock-proxy');

          // Send vsock addressing information
          const addressingInfo = Buffer.alloc(8);
          addressingInfo.writeUInt32LE(ENCLAVE_CID, 0); // CID
          addressingInfo.writeUInt32LE(ENCLAVE_PORT, 4); // Port

          api.socket.write(addressingInfo, (err) => {
            if (err) {
              reject(err);
              return;
            }
            api.isConnected = true;
            resolve();
          });
        }
      );

      api.socket.on('error', (err) => {
        console.error('VSock connection error:', err);
        this.isConnected = false;
        reject(err);
      });

      api.socket.on('close', () => {
        console.log('VSock connection closed');
        this.isConnected = false;
      });
    });
  }

  function send(message) : Promise<void> {
    return new Promise((resolve, reject) => {
      if (!api.isConnected) {
        reject(new Error('Not connected to vsock-proxy'));
        return;
      }

      api.socket.write(message, (err) => {
        if (err) {
          reject(err);
          return;
        }
        resolve();
      });
    });
  }

  function write(action, message) : Promise<void> {

    const socketMessage = JSON.stringify({
      action,
      data: message,
    });

    return new Promise((resolve, reject) : Promise<void> => {
      if (!api.isConnected) {
        reject(new Error('Not connected to vsock-proxy'));
        return;
      }

      api.socket.write(socketMessage, (err) => {
        if (err) {
          reject(err);
          return;
        }
        resolve();
      });
    });
  }

  function close() {
    if (api.isConnected) {
      api.socket.end();
      api.isConnected = false;
    }
  }
}

socket.on('connect', async () => {
  console.log(`Connected to server URL : ${process.env.API_URL}`);
  vsockClient = newVSockClient();

  try {
    await vsockClient.connect();

    // Example: Send a message to the Signer
    await vsockClient.send(
      JSON.stringify({
        action: 'sign',
        data: 'Hello from Robo!',
      })
    );

    // Handle incoming messages
    vsockClient.socket.on('data', (data) => {
      console.log('Received from Signer:', data.toString());
    });
  } catch (error) {
    console.error('Error:', error);
  }
});

socket.on('error', (err: any) => {
  console.log(err);
  logger.error('Log:Error: Error connecting to API Socket Stream', err);
});

socket.on('connect_error', (err: any) => {
  console.log(err);
  logger.error('Log:Error: Error connect_error connecting to API Socket Stream', err);
});

socket.on('preRegister', async (data: { signer: string; signerKeyId: string; accountAddress: string }) => {
  const { accountAddress, signer, signerKeyId } = data;
  const responsePayload = { accountAddress, signer };

  _sendLogToClient(`SaltRobos: pre-registration:${signer} => Event Received From API`, {}, responsePayload);

  vsockClient.write('sign', { payload: responsePayload });

  try {
    _sendLogToClient(
      `SaltRobos: pre-registration:getPreregistrationStatus:start:${signer} => expect success or failure`,
      {},
      responsePayload
    );

    const preRegisterInfo = await getUserPreRegisterInfos(accountAddress, signer, provider);

    if (preRegisterInfo.registered) {
      // user is already pre registered, redundant request

      _sendLogToClient(
        `SaltRobos: pre-registration:getPreregistrationStatus:success:${signer}`,
        preRegisterInfo.registered,
        responsePayload
      );

      socket.emit('preRegistrationComplete', {
        ...responsePayload,
        success: true,
        error: null,
      });

      return;
    }
  } catch (error) {
    _sendLogToClient(
      `SaltRobos:Error: pre-registration:getPreRegistrationSatus:failure:${signer} => error`,
      { error },
      responsePayload
    );

    logger.error(`Log:Error: Error pre-registration:getPreregistrationStatus:failure:${signer}`, error);

    socket.emit('preRegistrationComplete', {
      ...responsePayload,
      success: false,
      error,
    });

    return;
  }

  try {
    _sendLogToClient(`SaltRobos: pre-registration:start:${signer} => expect success or failure`, {}, responsePayload);
    const tx = (await preRegistration(accountAddress, signers[signer])) as ethers.ContractTransaction;
    const res = await tx.wait();

    _sendLogToClient(`SaltRobos: pre-registration:success:${signer} => response`, { res }, responsePayload);

    socket.emit('preRegistrationComplete', {
      ...responsePayload,
      success: true,
      error: null,
    });
  } catch (error) {
    _sendLogToClient(`SaltRobos:Error: pre-registration:failure:${signer} => error`, { error }, responsePayload);

    logger.error(`Log:Error: Error pre-registration:failure:${signer}`, error);

    socket.emit('preRegistrationComplete', {
      ...responsePayload,
      success: false,
      error,
    });
  }
});

socket.on('register', async (data: { signer: string; accountAddress: string; nostrNode: string }) => {
  const { accountAddress, signer, nostrNode } = data;
  const responsePayload = { accountAddress, signer, nostrNode };

  _sendLogToClient(`SaltRobos: register:event:received for signer: ${signer}`, {}, responsePayload);

  try {
    _sendLogToClient(
      `SaltRobos: register:event:getRegistrationStatus:start:${signer} => expect success or failure`,
      {},
      responsePayload
    );

    const res = await getUserRegistrationAllInfos(accountAddress, signer, provider);

    if (res.registered) {
      // robo has already registerd, redundant request

      _sendLogToClient(
        `SaltRobos: register:event:getRegistrationStatus:success:${signer}`,
        res.registered,
        responsePayload
      );

      socket.emit('registrationComplete', {
        ...responsePayload,
        success: true,
        error: null,
      });
      return;
    }
  } catch (error) {
    _sendLogToClient(`SaltRobos: register:event:getRegistrationStatus:failure:${signer}`, { error }, responsePayload);

    logger.error(`Log:Error: Error register:event:getRegistrationStatus:failure:${signer}`, error);

    socket.emit('registrationComplete', {
      ...responsePayload,
      success: false,
      error: null,
    });
    return;
  }

  try {
    _sendLogToClient(
      `SaltRobos: register:automateRegistration:start:${signer} => expect success or failure`,
      {},
      responsePayload
    );

    const res = await automateRegistration(accountAddress, signers[signer], undefined, nostrNode, undefined);

    _sendLogToClient(
      `SaltRobos: register:automateRegistration:success:${signer} => response`,
      { res },
      responsePayload
    );
  } catch (error) {
    _sendLogToClient(
      `SaltRobos:Error: register:automateRegistration:failure:${signer} => error`,
      { error },
      responsePayload
    );

    logger.error(`Log:Error: Error register:automateRegistration:failure:${signer}`, error);

    socket.emit('registrationComplete', {
      ...responsePayload,
      success: false,
      error: null,
    });

    return;
  }

  try {
    _sendLogToClient(
      `SaltRobos: register:registerAllSteps:start:${signer} => expect success or failure`,
      {},
      responsePayload
    );
    const tx = (await registerAllSteps(
      accountAddress,
      signers[signer],
      undefined,
      nostrNode,
      undefined
    )) as ethers.ContractTransaction;
    const res = await tx.wait();

    _sendLogToClient(`SaltRobos: register:registerAllSteps:success:${signer} => response`, { res }, responsePayload);
  } catch (error) {
    _sendLogToClient(
      `SaltRobos:Error: register:registerAllSteps:failure:${signer} => error`,
      { error },
      responsePayload
    );

    logger.error(`Log:Error: Error register:registerAllSteps:failure:${signer}`, error);

    socket.emit('registrationComplete', {
      ...responsePayload,
      success: false,
      error: null,
    });

    return;
  }

  socket.emit('registrationComplete', {
    ...responsePayload,
    success: true,
    error: null,
  });
});

socket.on('proposeTransaction', async (data: { signer: string; accountAddress: string; txId: string }) => {
  const { accountAddress, txId, signer } = data;
  const responsePayload = { accountAddress, txId, signer };

  _sendLogToClient(`SaltRobos: proposeTransaction:signTx:${signer} => Event Received`, {}, responsePayload);

  try {
    _sendLogToClient(
      `SaltRobos: proposeTransaction:signTx:start:${signer} => expect success or failure`,
      {},
      responsePayload
    );

    const tx = (await signTx(accountAddress, Number(txId), signers[signer])) as ethers.ContractTransaction;
    const res = await tx.wait();

    _sendLogToClient(`SaltRobos: proposeTransaction:signTx:success:${signer} => response`, { res }, responsePayload);

    socket.emit('transactionSigningComplete', {
      ...responsePayload,
      success: true,
      error: null,
    });
  } catch (error) {
    _sendLogToClient(
      `SaltRobos:Error: proposeTransaction:signTx:failure:${signer} => error`,
      { error },
      responsePayload
    );

    logger.error(`Log:Error: Error proposeTransaction:signTx:failure:${signer}`, error);

    socket.emit('transactionSigningComplete', {
      ...responsePayload,
      success: false,
      error,
    });
  }
});

socket.on(
  'broadcastTransaction',
  async (data: { signer: string; accountAddress: string; txId: string; networkId: string }) => {
    const { accountAddress, txId, networkId, signer } = data;
    const responsePayload = { accountAddress, txId, signer, txReceipt: null };

    _sendLogToClient(`SaltRobos: broadcastTransaction:signTx:${signer} => Event Received`, {}, responsePayload);

    const RPC_NODE_URL = getRPCNodeFromNetworkId(networkId);

    if (!RPC_NODE_URL) {
      const _error = `network id is not supported: ${networkId}`;
      _sendLogToClient(`SaltRobos:Error: broadcastTransaction:failure:${signer} => error`, { _error }, responsePayload);

      logger.error(`Log:Error: Error broadcastTransaction:failure:${signer}`, _error);

      socket.emit('transactionBroadcastingComplete', {
        ...responsePayload,
        success: false,
        _error,
      });

      return;
    }

    let combineResponse: string;

    try {
      _sendLogToClient(
        `SaltRobos: broadcastTransaction:combineTx:start:${signer} => expect success or failure`,
        {},
        responsePayload
      );

      combineResponse = await combineSignedTx(accountAddress, Number(txId), signers[signer]);
      _sendLogToClient(
        `SaltRobos: broadcastTransaction:combineTx:success:${signer} => response`,
        { combineResponse },
        responsePayload
      );

      socket.emit('transactionCombiningComplete', {
        ...responsePayload,
        success: true,
        error: null,
      });
    } catch (error) {
      _sendLogToClient(
        `SaltRobos:Error: broadcastTransaction:combineTx:failure:${signer} => error`,
        { error },
        responsePayload
      );

      logger.error(`Log:Error: Error broadcastTransaction:combineTx:failure:${signer}`, error);

      socket.emit('SignatureCombineComplete', {
        ...responsePayload,
        success: false,
        error,
      });
      return;
    }
    try {
      _sendLogToClient(
        `SaltRobos: broadcastTransaction:sendTx:start:${signer} => expect success or failure`,
        {},
        responsePayload
      );

      const _provider = new ethers.providers.StaticJsonRpcProvider({
        url: RPC_NODE_URL || '',
        skipFetchSetup: true,
      });

      const txResponse = await _provider.sendTransaction(combineResponse);

      const txReceipt = await txResponse.wait();

      responsePayload.txReceipt = txReceipt;

      _sendLogToClient(
        `SaltRobos: broadcastTransaction:sendTx:success:${signer} => response`,
        {},
        { responsePayload, txReceipt }
      );

      socket.emit('transactionBroadcastingComplete', {
        ...responsePayload,
        success: true,
        error: null,
      });
    } catch (error) {
      _sendLogToClient(
        `SaltRobos:Error: broadcastTransaction:sendTx:failure:${signer} => error`,
        { error },
        responsePayload
      );

      logger.error(`Log:Error: Error broadcastTransaction:sendTx:failure:${signer}`, error);

      socket.emit('transactionBroadcastingComplete', {
        ...responsePayload,
        success: false,
        error,
      });
    }
  }
);

function _sendLogToClient(message, data, responsePayload) {
  console.error('message:', message);
  console.error('data', data);
  console.error('responsePayload', responsePayload);

  let m = message;
  if (data) {
    m = `${message} :: ${JSON.stringify(data)}`;
  }

  socket.emit('update', {
    ...responsePayload,
    message: m,
  });
}

const express = require('express');
const app = express();
const listener = app.listen(process.env.PORT || 4300, () => {
  console.log('App is running on port ' + listener.address().port);
});
