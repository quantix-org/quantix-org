import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatNumber(num: number | bigint): string {
  return new Intl.NumberFormat().format(num);
}

export function formatQTX(value: string | bigint): string {
  const bigValue = typeof value === 'string' ? BigInt(value) : value;
  const qtx = Number(bigValue) / 1e18;
  
  if (qtx === 0) return '0 QTX';
  if (qtx < 0.0001) return '<0.0001 QTX';
  if (qtx < 1) return qtx.toFixed(6) + ' QTX';
  if (qtx < 1000) return qtx.toFixed(4) + ' QTX';
  if (qtx < 1000000) return formatNumber(Math.floor(qtx)) + ' QTX';
  
  return (qtx / 1000000).toFixed(2) + 'M QTX';
}

export function formatGas(gas: number): string {
  if (gas < 1000) return gas.toString();
  if (gas < 1000000) return (gas / 1000).toFixed(1) + 'K';
  return (gas / 1000000).toFixed(2) + 'M';
}

export function formatTimeAgo(timestamp: string): string {
  const now = Date.now();
  const then = new Date(timestamp).getTime();
  const seconds = Math.floor((now - then) / 1000);

  if (seconds < 0) return 'just now';
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  if (seconds < 604800) return `${Math.floor(seconds / 86400)}d ago`;
  
  return new Date(timestamp).toLocaleDateString();
}

export function shortenHash(hash: string, chars: number = 8): string {
  if (!hash) return '';
  if (hash.length <= chars * 2 + 2) return hash;
  return `${hash.slice(0, chars + 2)}...${hash.slice(-chars)}`;
}

export function isValidAddress(address: string): boolean {
  return /^qtx1[a-zA-Z0-9]{38}$/.test(address);
}

export function isValidTxHash(hash: string): boolean {
  return /^0x[a-fA-F0-9]{64}$/.test(hash);
}
