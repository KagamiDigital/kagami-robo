import { combineSignedTx, getAllTransactions } from "@intuweb3/sdk";
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
    } else if (networkId === '50312') {
        return process.env.SOMNIA_SHANNON_NODE_URL;
    } else if (networkId === '421614') {
        return process.env.ORCHESTRATION_NODE_URL;
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
            
            const txReceipt = await provider.getTransactionReceipt(txHash); 
            const tx = await provider.getTransaction(txHash); 
            const block = await provider.getBlock(txReceipt.blockHash); 

            addTransaction(accountAddress,Number(transactions[i].id),transactions[i].chainId,txHash,txReceipt.from,txReceipt.to,txReceipt.status,tx.value.toString(),txReceipt.effectiveGasPrice.toString(),txReceipt.gasUsed.toString(),block.timestamp); 
        } catch(err) { // not enough signatures to combine, incomplete tx
            console.log(err); 
        }
    }
}