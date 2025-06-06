export type TransactionObject = { 
  id:number; 
  accountAddress:string; 
  chainId:string; 
  txId:number; 
  txHash:string;
  fromAddress:string;
  toAddress:string; 
  status:number; 
  value:number; 
  gasPrice:string; 
  gasUsed:string; 
  timestamp:number;
}