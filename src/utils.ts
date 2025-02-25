import { combineSignedTx, getAllTransactions } from "@intuweb3/exp-node";
import { ethers } from "ethers";
import { addTransaction } from "./database";

export function getRPCNodeFromNetworkId(networkId:string) {
    if(networkId === '11155111') {
        return process.env.SEPOLIA_NODE_URL; 
    } else if(networkId === '80002') {
        return process.env.AMOY_NODE_URL; 
    } else if(networkId === '1287') {
        return process.env.MOONBASE_NODE_URL; 
    } else if(networkId === '84532') {
        return process.env.BASE_SEPOLIA_NODE_URL; 
    } else {
        return ''; 
    }
}

export async function rebuildTransactionRecordsForAccount(signer: ethers.Signer, provider:ethers.providers.JsonRpcProvider,accountAddress:string) {
    const transactions = await getAllTransactions(accountAddress,provider);
    for(let i = 0; i < transactions.length; i++) {
        try {
            const signedTx = await combineSignedTx(accountAddress,transactions[i].id,signer); 
            const txHash = ethers.utils.keccak256(signedTx); 
            addTransaction(accountAddress,Number(transactions[i].id),transactions[i].chainId,txHash); 
        } catch(err) { // not enough signatures to combine, incomplete tx
            console.log(err); 
        }
    }
}