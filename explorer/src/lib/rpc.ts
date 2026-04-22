/**
 * Quantix JSON-RPC Client
 * Connects to the Quantix node at NEXT_PUBLIC_RPC_URL
 */

// RPC endpoint for the Quantix node
// Default: https://rpc.qpqb.org (testnet)
const RPC_URL = process.env.NEXT_PUBLIC_RPC_URL || 'https://rpc.qpqb.org';

interface RPCRequest {
  jsonrpc: '2.0';
  method: string;
  params: unknown[];
  id: number;
}

interface RPCResponse<T> {
  jsonrpc: '2.0';
  result?: T;
  error?: {
    code: number;
    message: string;
  };
  id: number;
}

let requestId = 1;

/**
 * Make a JSON-RPC call to the Quantix node
 */
export async function rpcCall<T>(method: string, params: unknown[] = []): Promise<T> {
  const request: RPCRequest = {
    jsonrpc: '2.0',
    method,
    params,
    id: requestId++,
  };

  const response = await fetch(RPC_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(request),
    next: { revalidate: 10 }, // Cache for 10 seconds
  });

  if (!response.ok) {
    throw new Error(`RPC request failed: ${response.status} ${response.statusText}`);
  }

  const data: RPCResponse<T> = await response.json();

  if (data.error) {
    throw new Error(`RPC error ${data.error.code}: ${data.error.message}`);
  }

  return data.result as T;
}

/**
 * Batch multiple RPC calls into a single request
 */
export async function rpcBatch<T extends unknown[]>(
  calls: Array<{ method: string; params?: unknown[] }>
): Promise<T> {
  const requests: RPCRequest[] = calls.map((call, index) => ({
    jsonrpc: '2.0',
    method: call.method,
    params: call.params || [],
    id: requestId + index,
  }));
  requestId += calls.length;

  const response = await fetch(RPC_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(requests),
    next: { revalidate: 10 },
  });

  if (!response.ok) {
    throw new Error(`RPC batch request failed: ${response.status}`);
  }

  const data: RPCResponse<unknown>[] = await response.json();

  return data.map((item) => {
    if (item.error) {
      throw new Error(`RPC error ${item.error.code}: ${item.error.message}`);
    }
    return item.result;
  }) as T;
}

// =====================================================
// Quantix-specific RPC Methods
// =====================================================

export interface BlockRPC {
  number: string; // hex
  hash: string;
  parentHash: string;
  timestamp: string; // hex
  miner: string; // validator
  transactionsRoot: string;
  stateRoot: string;
  gasUsed: string; // hex
  gasLimit: string; // hex
  size: string; // hex
  transactions: string[] | TransactionRPC[];
}

export interface TransactionRPC {
  hash: string;
  blockNumber: string; // hex
  blockHash: string;
  from: string;
  to: string;
  value: string; // hex
  gas: string; // hex
  gasPrice: string; // hex
  nonce: string; // hex
  input: string;
  transactionIndex: string; // hex
}

export interface TransactionReceiptRPC {
  transactionHash: string;
  blockNumber: string;
  blockHash: string;
  from: string;
  to: string;
  gasUsed: string;
  status: string; // "0x1" = success, "0x0" = fail
  logs: unknown[];
}

/**
 * Get current block number
 */
export async function getBlockNumber(): Promise<number> {
  const result = await rpcCall<string>('qtx_blockNumber');
  return parseInt(result, 16);
}

/**
 * Get block by number or hash
 */
export async function getBlock(blockId: string | number, includeTxs = false): Promise<BlockRPC | null> {
  const param = typeof blockId === 'number' ? `0x${blockId.toString(16)}` : blockId;
  const method = param.startsWith('0x') && param.length === 66 
    ? 'qtx_getBlockByHash' 
    : 'qtx_getBlockByNumber';
  
  return rpcCall<BlockRPC | null>(method, [param, includeTxs]);
}

/**
 * Get transaction by hash
 */
export async function getTransaction(hash: string): Promise<TransactionRPC | null> {
  return rpcCall<TransactionRPC | null>('qtx_getTransactionByHash', [hash]);
}

/**
 * Get transaction receipt
 */
export async function getTransactionReceipt(hash: string): Promise<TransactionReceiptRPC | null> {
  return rpcCall<TransactionReceiptRPC | null>('qtx_getTransactionReceipt', [hash]);
}

/**
 * Get account balance
 */
export async function getBalance(address: string, block = 'latest'): Promise<string> {
  const result = await rpcCall<string>('qtx_getBalance', [address, block]);
  return BigInt(result).toString();
}

/**
 * Get account transaction count (nonce)
 */
export async function getTransactionCount(address: string, block = 'latest'): Promise<number> {
  const result = await rpcCall<string>('qtx_getTransactionCount', [address, block]);
  return parseInt(result, 16);
}

/**
 * Get code at address (for contracts)
 */
export async function getCode(address: string, block = 'latest'): Promise<string> {
  return rpcCall<string>('qtx_getCode', [address, block]);
}

/**
 * Get gas price
 */
export async function getGasPrice(): Promise<string> {
  const result = await rpcCall<string>('qtx_gasPrice');
  return BigInt(result).toString();
}

/**
 * Get network ID
 */
export async function getNetworkId(): Promise<number> {
  const result = await rpcCall<string>('net_version');
  return parseInt(result);
}

/**
 * Get peer count
 */
export async function getPeerCount(): Promise<number> {
  const result = await rpcCall<string>('net_peerCount');
  return parseInt(result, 16);
}

/**
 * Check if node is syncing
 */
export async function isSyncing(): Promise<boolean | { currentBlock: number; highestBlock: number }> {
  const result = await rpcCall<boolean | { currentBlock: string; highestBlock: string }>('qtx_syncing');
  if (typeof result === 'boolean') return result;
  return {
    currentBlock: parseInt(result.currentBlock, 16),
    highestBlock: parseInt(result.highestBlock, 16),
  };
}

// =====================================================
// Helper Functions
// =====================================================

/**
 * Convert hex string to number
 */
export function hexToNumber(hex: string): number {
  return parseInt(hex, 16);
}

/**
 * Convert hex string to BigInt string
 */
export function hexToBigInt(hex: string): string {
  return BigInt(hex).toString();
}

/**
 * Convert block RPC response to explorer format
 */
export function formatBlock(block: BlockRPC) {
  return {
    number: hexToNumber(block.number),
    hash: block.hash,
    parent_hash: block.parentHash,
    timestamp: new Date(hexToNumber(block.timestamp) * 1000).toISOString(),
    validator: block.miner,
    tx_count: Array.isArray(block.transactions) ? block.transactions.length : 0,
    gas_used: hexToNumber(block.gasUsed),
    gas_limit: hexToNumber(block.gasLimit),
    state_root: block.stateRoot,
    tx_root: block.transactionsRoot,
    size: hexToNumber(block.size),
  };
}

/**
 * Convert transaction RPC response to explorer format
 */
export function formatTransaction(tx: TransactionRPC, receipt?: TransactionReceiptRPC) {
  return {
    hash: tx.hash,
    block_number: hexToNumber(tx.blockNumber),
    block_hash: tx.blockHash,
    from: tx.from,
    to: tx.to,
    value: hexToBigInt(tx.value),
    gas_used: receipt ? hexToNumber(receipt.gasUsed) : hexToNumber(tx.gas),
    gas_price: hexToBigInt(tx.gasPrice),
    nonce: hexToNumber(tx.nonce),
    status: receipt ? (receipt.status === '0x1' ? 'Success' : 'Failed') : 'Pending',
    timestamp: '', // Need to get from block
    type: tx.input === '0x' ? 'transfer' : 'contract_call',
    input: tx.input,
  };
}
