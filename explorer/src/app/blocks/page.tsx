'use client';

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import Link from 'next/link';
import { Cube, ChevronLeft, ChevronRight } from 'lucide-react';
import { fetchBlocks } from '@/lib/api';
import { formatNumber, formatTimeAgo, formatGas, shortenHash } from '@/lib/utils';
import { Skeleton } from '@/components/Skeleton';

const PAGE_SIZE = 25;

export default function BlocksPage() {
  const [page, setPage] = useState(0);

  const { data: blocks, isLoading } = useQuery({
    queryKey: ['blocks', PAGE_SIZE, page * PAGE_SIZE],
    queryFn: () => fetchBlocks(PAGE_SIZE, page * PAGE_SIZE),
    refetchInterval: 10000,
  });

  return (
    <div className="container-page py-8">
      {/* Header */}
      <div className="flex items-center gap-4 mb-6">
        <div className="p-3 bg-primary-500/10 rounded-xl">
          <Cube className="w-6 h-6 text-primary-400" />
        </div>
        <div>
          <h1 className="text-2xl font-bold">Blocks</h1>
          <p className="text-dark-400 text-sm">Latest blocks on the Quantix network</p>
        </div>
      </div>

      {/* Blocks Table */}
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
                  <th>Block</th>
                  <th>Age</th>
                  <th>Txn</th>
                  <th>Validator</th>
                  <th>Gas Used</th>
                  <th>Gas Limit</th>
                  <th>Block Hash</th>
                </tr>
              </thead>
              <tbody>
                {blocks?.map((block: any) => (
                  <tr key={block.number}>
                    <td>
                      <Link href={`/block/${block.number}`} className="link-primary font-medium">
                        {formatNumber(block.number)}
                      </Link>
                    </td>
                    <td className="text-dark-400">{formatTimeAgo(block.timestamp)}</td>
                    <td>
                      <Link href={`/txs?block=${block.number}`} className="link-primary">
                        {block.tx_count}
                      </Link>
                    </td>
                    <td>
                      <Link href={`/address/${block.validator}`} className="link-primary hash">
                        {shortenHash(block.validator)}
                      </Link>
                    </td>
                    <td>{formatGas(block.gas_used)}</td>
                    <td className="text-dark-400">{formatGas(block.gas_limit)}</td>
                    <td>
                      <Link href={`/block/${block.hash}`} className="link-primary hash">
                        {shortenHash(block.hash)}
                      </Link>
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
    </div>
  );
}
