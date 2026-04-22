'use client';

import { useQuery } from '@tanstack/react-query';
import { useParams } from 'next/navigation';
import Link from 'next/link';
import { Wallet, Shield, FileCode, Coins, ArrowUpRight, ArrowDownLeft } from 'lucide-react';
import { fetchAddressInfo, fetchAddressTransactions } from '@/lib/api';
import { formatQTX, formatNumber, formatTimeAgo, shortenHash } from '@/lib/utils';
import { CopyButton } from '@/components/CopyButton';
import { Skeleton } from '@/components/Skeleton';

export default function AddressPage() {
  const params = useParams();
  const address = params.address as string;

  const { data: info, isLoading: infoLoading } = useQuery({
    queryKey: ['address', address],
    queryFn: () => fetchAddressInfo(address),
  });

  const { data: transactions, isLoading: txLoading } = useQuery({
    queryKey: ['address-txs', address],
    queryFn: () => fetchAddressTransactions(address, 25),
  });

  if (infoLoading) {
    return (
      <div className="container-page py-8">
        <Skeleton className="h-10 w-64 mb-8" />
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
          {[...Array(3)].map((_, i) => (
            <Skeleton key={i} className="h-32" />
          ))}
        </div>
        <Skeleton className="h-64" />
      </div>
    );
  }

  if (!info) {
    return (
      <div className="container-page py-8">
        <div className="card p-12 text-center">
          <h2 className="text-2xl font-bold mb-4">Address Not Found</h2>
          <p className="text-dark-400 mb-6">Invalid address format.</p>
          <Link href="/" className="btn-primary">
            Go Home
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="container-page py-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center gap-4 mb-6">
        <div className="p-3 bg-primary-500/10 rounded-xl">
          {info.is_contract ? (
            <FileCode className="w-6 h-6 text-primary-400" />
          ) : info.is_validator ? (
            <Shield className="w-6 h-6 text-primary-400" />
          ) : (
            <Wallet className="w-6 h-6 text-primary-400" />
          )}
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <h1 className="text-xl sm:text-2xl font-bold">
              {info.is_contract ? 'Contract' : info.is_validator ? 'Validator' : 'Address'}
            </h1>
            {info.is_validator && <span className="badge badge-success">Validator</span>}
            {info.is_contract && <span className="badge badge-info">Contract</span>}
          </div>
          <div className="flex items-center gap-2">
            <span className="text-dark-400 text-sm hash truncate">{address}</span>
            <CopyButton text={address} />
          </div>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
        <div className="stat-card">
          <div className="flex items-center gap-3 mb-2">
            <Coins className="w-5 h-5 text-primary-400" />
            <span className="stat-label">Balance</span>
          </div>
          <div className="stat-value">{formatQTX(info.balance)}</div>
        </div>

        <div className="stat-card">
          <div className="flex items-center gap-3 mb-2">
            <ArrowUpRight className="w-5 h-5 text-primary-400" />
            <span className="stat-label">Transactions</span>
          </div>
          <div className="stat-value">{formatNumber(info.tx_count)}</div>
        </div>

        {info.is_validator && (
          <div className="stat-card">
            <div className="flex items-center gap-3 mb-2">
              <Shield className="w-5 h-5 text-primary-400" />
              <span className="stat-label">Staked</span>
            </div>
            <div className="stat-value">{formatQTX(info.staked || '0')}</div>
          </div>
        )}

        {!info.is_validator && (
          <div className="stat-card">
            <div className="flex items-center gap-3 mb-2">
              <Wallet className="w-5 h-5 text-primary-400" />
              <span className="stat-label">Type</span>
            </div>
            <div className="stat-value text-lg">
              {info.is_contract ? 'Smart Contract' : 'External Account'}
            </div>
          </div>
        )}
      </div>

      {/* Transactions */}
      <div className="card">
        <div className="p-4 border-b border-white/10">
          <h2 className="text-lg font-semibold">Transactions</h2>
        </div>
        <div className="table-container">
          {txLoading ? (
            <div className="p-6">
              {[...Array(5)].map((_, i) => (
                <Skeleton key={i} className="h-12 mb-2" />
              ))}
            </div>
          ) : transactions && transactions.length > 0 ? (
            <table>
              <thead>
                <tr>
                  <th>Txn Hash</th>
                  <th>Block</th>
                  <th>Age</th>
                  <th>From</th>
                  <th></th>
                  <th>To</th>
                  <th>Value</th>
                </tr>
              </thead>
              <tbody>
                {transactions.map((tx: any) => {
                  const isIncoming = tx.to?.toLowerCase() === address.toLowerCase();
                  return (
                    <tr key={tx.hash}>
                      <td>
                        <Link href={`/tx/${tx.hash}`} className="link-primary hash">
                          {shortenHash(tx.hash)}
                        </Link>
                      </td>
                      <td>
                        <Link href={`/block/${tx.block_number}`} className="link-primary">
                          {formatNumber(tx.block_number)}
                        </Link>
                      </td>
                      <td className="text-dark-400">{formatTimeAgo(tx.timestamp)}</td>
                      <td>
                        {tx.from?.toLowerCase() === address.toLowerCase() ? (
                          <span className="hash text-dark-400">{shortenHash(tx.from)}</span>
                        ) : (
                          <Link href={`/address/${tx.from}`} className="link-primary hash">
                            {shortenHash(tx.from)}
                          </Link>
                        )}
                      </td>
                      <td>
                        {isIncoming ? (
                          <span className="badge badge-success">
                            <ArrowDownLeft className="w-3 h-3 mr-1" /> IN
                          </span>
                        ) : (
                          <span className="badge badge-pending">
                            <ArrowUpRight className="w-3 h-3 mr-1" /> OUT
                          </span>
                        )}
                      </td>
                      <td>
                        {tx.to?.toLowerCase() === address.toLowerCase() ? (
                          <span className="hash text-dark-400">{shortenHash(tx.to)}</span>
                        ) : (
                          <Link href={`/address/${tx.to}`} className="link-primary hash">
                            {shortenHash(tx.to)}
                          </Link>
                        )}
                      </td>
                      <td className="font-medium">{formatQTX(tx.value)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          ) : (
            <div className="p-12 text-center text-dark-400">
              No transactions found
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
