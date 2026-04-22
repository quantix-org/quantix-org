'use client';

import { useQuery } from '@tanstack/react-query';
import { useParams } from 'next/navigation';
import Link from 'next/link';
import { ArrowRight, Clock, Fuel, Hash, Receipt, Wallet } from 'lucide-react';
import { fetchTransaction } from '@/lib/api';
import { formatNumber, formatTimeAgo, formatQTX, shortenHash } from '@/lib/utils';
import { CopyButton } from '@/components/CopyButton';
import { Skeleton } from '@/components/Skeleton';

export default function TransactionPage() {
  const params = useParams();
  const txHash = params.hash as string;

  const { data: tx, isLoading, error } = useQuery({
    queryKey: ['tx', txHash],
    queryFn: () => fetchTransaction(txHash),
  });

  if (isLoading) {
    return (
      <div className="container-page py-8">
        <Skeleton className="h-10 w-64 mb-8" />
        <div className="card">
          <div className="p-6 space-y-4">
            {[...Array(12)].map((_, i) => (
              <Skeleton key={i} className="h-6 w-full" />
            ))}
          </div>
        </div>
      </div>
    );
  }

  if (error || !tx) {
    return (
      <div className="container-page py-8">
        <div className="card p-12 text-center">
          <h2 className="text-2xl font-bold mb-4">Transaction Not Found</h2>
          <p className="text-dark-400 mb-6">The transaction you&apos;re looking for doesn&apos;t exist.</p>
          <Link href="/" className="btn-primary">
            Go Home
          </Link>
        </div>
      </div>
    );
  }

  const statusBadge = tx.status === 'Success' ? 'badge-success' : 'badge-error';

  return (
    <div className="container-page py-8">
      {/* Header */}
      <div className="flex items-center gap-4 mb-6">
        <div className="p-3 bg-primary-500/10 rounded-xl">
          <Receipt className="w-6 h-6 text-primary-400" />
        </div>
        <div>
          <h1 className="text-2xl font-bold">Transaction Details</h1>
          <p className="text-dark-400 text-sm hash">{shortenHash(tx.hash, 20)}</p>
        </div>
        <span className={`badge ${statusBadge} ml-auto`}>{tx.status}</span>
      </div>

      {/* Transaction Details */}
      <div className="card">
        <div className="p-6">
          <div className="detail-row">
            <span className="detail-label flex items-center gap-2">
              <Hash className="w-4 h-4" /> Transaction Hash
            </span>
            <span className="detail-value hash">
              {tx.hash}
              <CopyButton text={tx.hash} />
            </span>
          </div>

          <div className="detail-row">
            <span className="detail-label">Status</span>
            <span className="detail-value">
              <span className={`badge ${statusBadge}`}>{tx.status}</span>
            </span>
          </div>

          <div className="detail-row">
            <span className="detail-label flex items-center gap-2">
              <Hash className="w-4 h-4" /> Block
            </span>
            <span className="detail-value">
              <Link href={`/block/${tx.block_number}`} className="link-primary">
                {formatNumber(tx.block_number)}
              </Link>
              <span className="text-dark-400 ml-2">
                ({formatTimeAgo(tx.timestamp)})
              </span>
            </span>
          </div>

          <div className="detail-row">
            <span className="detail-label flex items-center gap-2">
              <Clock className="w-4 h-4" /> Timestamp
            </span>
            <span className="detail-value">
              {new Date(tx.timestamp).toLocaleString()}
            </span>
          </div>

          <div className="p-4 bg-dark-900/50 rounded-lg my-4">
            <div className="flex flex-col sm:flex-row items-start sm:items-center gap-4">
              <div className="flex-1">
                <span className="text-dark-400 text-sm block mb-1">From</span>
                <Link href={`/address/${tx.from}`} className="link-primary hash">
                  {tx.from}
                </Link>
                <CopyButton text={tx.from} />
              </div>
              <ArrowRight className="w-5 h-5 text-dark-400 hidden sm:block" />
              <div className="flex-1">
                <span className="text-dark-400 text-sm block mb-1">To</span>
                <Link href={`/address/${tx.to}`} className="link-primary hash">
                  {tx.to}
                </Link>
                <CopyButton text={tx.to} />
              </div>
            </div>
          </div>

          <div className="detail-row">
            <span className="detail-label flex items-center gap-2">
              <Wallet className="w-4 h-4" /> Value
            </span>
            <span className="detail-value font-semibold text-lg">
              {formatQTX(tx.value)}
            </span>
          </div>

          <div className="detail-row">
            <span className="detail-label">Transaction Fee</span>
            <span className="detail-value">
              {formatQTX(BigInt(tx.gas_used) * BigInt(tx.gas_price))}
            </span>
          </div>

          <div className="detail-row">
            <span className="detail-label flex items-center gap-2">
              <Fuel className="w-4 h-4" /> Gas
            </span>
            <span className="detail-value">
              {formatNumber(tx.gas_used)} @ {formatNumber(parseInt(tx.gas_price) / 1e9)} gQTX
            </span>
          </div>

          <div className="detail-row">
            <span className="detail-label">Nonce</span>
            <span className="detail-value">{tx.nonce}</span>
          </div>

          <div className="detail-row">
            <span className="detail-label">Transaction Type</span>
            <span className="detail-value">
              <span className="badge badge-info">{tx.type}</span>
            </span>
          </div>

          {tx.input && tx.input !== '0x' && (
            <div className="detail-row">
              <span className="detail-label">Input Data</span>
              <span className="detail-value">
                <pre className="bg-dark-900 p-3 rounded-lg overflow-x-auto text-xs hash">
                  {tx.input}
                </pre>
              </span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
