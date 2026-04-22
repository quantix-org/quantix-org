const API_BASE = '/api';

// Types
export interface Block {
  number: number;
  hash: string;
  parent_hash: string;
  timestamp: string;
  validator: string;
  tx_count: number;
  gas_used: number;
  gas_limit: number;
  state_root: string;
  tx_root: string;
  size: number;
}

export interface Transaction {
  hash: string;
  block_number: number;
  block_hash: string;
  from: string;
  to: string;
  value: string;
  gas_used: number;
  gas_price: string;
  nonce: number;
  status: string;
  timestamp: string;
  type: string;
  input?: string;
}

export interface AddressInfo {
  address: string;
  balance: string;
  tx_count: number;
  is_contract: boolean;
  is_validator: boolean;
  staked?: string;
  code?: string;
}

export interface NetworkStats {
  block_height: number;
  total_transactions: number;
  validator_count: number;
  total_staked: string;
  avg_block_time: number;
  tps_24h: number;
  total_supply: string;
  circulating_supply: string;
}

export interface Validator {
  address: string;
  stake: string;
  commission: number;
  uptime: number;
  blocks_proposed: number;
  active: boolean;
}

// API Functions
async function fetchJSON<T>(url: string): Promise<T> {
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`API error: ${res.status}`);
  }
  return res.json();
}

export async function fetchStats(): Promise<NetworkStats> {
  return fetchJSON<NetworkStats>(`${API_BASE}/stats`);
}

export async function fetchBlocks(limit: number = 20, offset: number = 0): Promise<Block[]> {
  return fetchJSON<Block[]>(`${API_BASE}/blocks?limit=${limit}&offset=${offset}`);
}

export async function fetchBlock(id: string): Promise<Block> {
  return fetchJSON<Block>(`${API_BASE}/blocks/${id}`);
}

export async function fetchTransactions(
  limit: number = 20,
  offset: number = 0,
  block?: number
): Promise<Transaction[]> {
  let url = `${API_BASE}/transactions?limit=${limit}&offset=${offset}`;
  if (block !== undefined) {
    url += `&block=${block}`;
  }
  return fetchJSON<Transaction[]>(url);
}

export async function fetchTransaction(hash: string): Promise<Transaction> {
  return fetchJSON<Transaction>(`${API_BASE}/transactions/${hash}`);
}

export async function fetchAddressInfo(address: string): Promise<AddressInfo> {
  return fetchJSON<AddressInfo>(`${API_BASE}/addresses/${address}`);
}

export async function fetchAddressTransactions(
  address: string,
  limit: number = 25
): Promise<Transaction[]> {
  return fetchJSON<Transaction[]>(`${API_BASE}/addresses/${address}/transactions?limit=${limit}`);
}

export async function fetchValidators(): Promise<Validator[]> {
  return fetchJSON<Validator[]>(`${API_BASE}/validators`);
}

export async function search(query: string): Promise<{ type: string; id: string }> {
  return fetchJSON<{ type: string; id: string }>(`${API_BASE}/search?q=${encodeURIComponent(query)}`);
}
