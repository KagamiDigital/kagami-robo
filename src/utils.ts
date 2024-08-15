export function getRPCNodeFromNetworkId(networkId:string) {
    if(networkId === '11155111') {
        return process.env.SEPOLIA_NODE_URL; 
    } else if(networkId === '80002') {
        return process.env.AMOY_NODE_URL; 
    } else if(networkId === '1287') {
        return process.env.MOONBASE_NODE_URL; 
    } else {
        return ''; 
    }
}