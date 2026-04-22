'use client';

import { useState, Suspense } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { Receipt, ChevronLeft, ChevronRight, ArrowRight } from 'lucide-react';
import { fetchTransactions } from '@/lib/api';
import { formatNumber, formatTimeAgo, formatQTX, shortenHash } from '@/lib/utils';
import { Skeleton } from '@/components/Skeleton';

const PAGE_SIZE = 25;

function TransactionsContent() {
  const searchParams = useSearchParams();
  const blockFilter = searchParams.get('block');
  const [page, setPage] = useState(0);

  const { data: transactions, isLoading } = useQuery({
    queryKey: ['transactions', PAGE_SIZE, page * PAGE_SIZE, blockFilter],
    queryFn: () => fetchTransactions(PAGE_SIZE, page * PAGE_SIZE, blockFilter ? parseInt(blockFilter) : undefined),
    refetchInterval: blockFilter ? false : 10000,
  });

  return (
    <>
      {/* Header */}
      <div className="flex items-center gap-4 mb-6">
        <div className="p-3 bg-primary-500/10 rounded-xl">
          <Receipt className="w-6 h-6 text-primary-400" />
        </div>
        <div>
          <h1 className="text-2xl font-bold">Transactions</h1>
          <p className="text-dark-400 text-sm">
            {blockFilter 
              ? `Transactions in block #${formatNumber(parseInt(blockFilter))}`
              : 'Latest transactions on the Quantix network'
            }
          </p>
        </div>
      </div>

      {/* Transactions Table */}
      <div className="card">
        <div className="table-container">
          {isLoading ? (
            <div className="p-6 space-y-3">
              {[...Array(PAGE_SIZE)].map((_, i) => (
                <Skeleton key={i} className="h-12" />
              ))}
            </div>
          ) : (
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
                  <th>Fee</th>
                </tr>
              </thead>
              <tbody>
                {transactions?.map((tx: any) => (
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
                      <Link href={`/address/${tx.from}`} className="link-primary hash">
                        {shortenHash(tx.from)}
                      </Link>
                    </td>
                    <td>
                      <ArrowRight className="w-4 h-4 text-dark-500" />
                    </td>
                    <td>
                      <Link href={`/address/${tx.to}`} className="link-primary hash">
                        {shortenHash(tx.to)}
                      </Link>
                    </td>
                    <td className="font-medium">{formatQTX(tx.value)}</td>
                    <td className="text-dark-400 text-xs">
                      {formatQTX(BigInt(tx.gas_used) * BigInt(tx.gas_price))}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* Pagination */}
        <div className="flex items-center justify-between p-4 border-t border-white/10">
          <button
            onClick={() => setPage(p => Math.max(0, p - 1))}
            disabled={page === 0}
            className="flex items-center gap-2 px-4 py-2 bg-dark-700 hover:bg-dark-600 disabled:opacity-50 disabled:cursor-not-allowed rounded-lg transition-colors"
          >
            <ChevronLeft className="w-4 h-4" />
            Previous
          </button>
          <span className="text-dark-400 text-sm">Page {page + 1}</span>
          <button
            onClick={() => setPage(p => p + 1)}
            className="flex items-center gap-2 px-4 py-2 bg-dark-700 hover:bg-dark-600 rounded-lg transition-colors"
          >
            Next
            <ChevronRight className="w-4 h-4" />
          </button>
        </div>
      </div>
    </>
  );
}

export default function TransactionsPage() {
  return (
    <div className="container-page py-8">
      <Suspense fallback={
        <div className="space-y-4">
          <Skeleton className="h-16 w-64" />
          <Skeleton className="h-96" />
        </div>
      }>
        <TransactionsContent />
      </Suspense>
    </div>
  );
}
