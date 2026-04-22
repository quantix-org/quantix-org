'use client';

import Link from 'next/link';
import { Receipt, ArrowRight, ArrowRightLeft } from 'lucide-react';
import { formatQTX, formatTimeAgo, shortenHash } from '@/lib/utils';
import { Skeleton } from './Skeleton';

interface Transaction {
  hash: string;
  from: string;
  to: string;
  value: string;
  timestamp: string;
  block_number: number;
}

interface LatestTransactionsProps {
  transactions?: Transaction[];
  loading?: boolean;
}

export function LatestTransactions({ transactions, loading }: LatestTransactionsProps) {
  return (
    <div className="card">
      <div className="flex items-center justify-between p-4 border-b border-white/10">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-green-500/10 rounded-lg">
            <Receipt className="w-5 h-5 text-green-400" />
          </div>
          <h2 className="font-semibold">Latest Transactions</h2>
        </div>
        <Link
          href="/txs"
          className="flex items-center gap-1 text-sm text-primary-400 hover:text-primary-300 transition-colors"
        >
          View all
          <ArrowRight className="w-4 h-4" />
        </Link>
      </div>

      <div className="divide-y divide-white/5">
        {loading ? (
          [...Array(10)].map((_, i) => (
            <div key={i} className="p-4">
              <Skeleton className="h-14" />
            </div>
          ))
        ) : (
          transactions?.map((tx) => (
            <div
              key={tx.hash}
              className="p-4 hover:bg-white/[0.02] transition-colors"
            >
              <div className="flex items-start gap-4">
                <div className="p-3 bg-dark-700 rounded-lg">
                  <ArrowRightLeft className="w-5 h-5 text-dark-400" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <Link
                      href={`/tx/${tx.hash}`}
                      className="font-medium link-primary hash"
                    >
                      {shortenHash(tx.hash)}
                    </Link>
                    <span className="text-dark-400 text-sm">
                      {formatTimeAgo(tx.timestamp)}
                    </span>
                  </div>
                  <div className="text-sm text-dark-400">
                    <Link href={`/address/${tx.from}`} className="link-primary hash">
                      {shortenHash(tx.from)}
                    </Link>
                    <span className="mx-2">→</span>
                    <Link href={`/address/${tx.to}`} className="link-primary hash">
                      {shortenHash(tx.to)}
                    </Link>
                  </div>
                </div>
                <div className="text-right">
                  <span className="text-sm font-medium">
                    {formatQTX(tx.value)}
                  </span>
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
