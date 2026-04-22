'use client';

import Link from 'next/link';
import { Cube, ArrowRight } from 'lucide-react';
import { formatNumber, formatTimeAgo, shortenHash } from '@/lib/utils';
import { Skeleton } from './Skeleton';

interface Block {
  number: number;
  hash: string;
  timestamp: string;
  validator: string;
  tx_count: number;
  gas_used: number;
}

interface LatestBlocksProps {
  blocks?: Block[];
  loading?: boolean;
}

export function LatestBlocks({ blocks, loading }: LatestBlocksProps) {
  return (
    <div className="card">
      <div className="flex items-center justify-between p-4 border-b border-white/10">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-blue-500/10 rounded-lg">
            <Cube className="w-5 h-5 text-blue-400" />
          </div>
          <h2 className="font-semibold">Latest Blocks</h2>
        </div>
        <Link
          href="/blocks"
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
          blocks?.map((block) => (
            <div
              key={block.number}
              className="p-4 hover:bg-white/[0.02] transition-colors"
            >
              <div className="flex items-start gap-4">
                <div className="p-3 bg-dark-700 rounded-lg">
                  <Cube className="w-5 h-5 text-dark-400" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <Link
                      href={`/block/${block.number}`}
                      className="font-medium link-primary"
                    >
                      {formatNumber(block.number)}
                    </Link>
                    <span className="text-dark-400 text-sm">
                      {formatTimeAgo(block.timestamp)}
                    </span>
                  </div>
                  <div className="text-sm text-dark-400">
                    Validated by{' '}
                    <Link
                      href={`/address/${block.validator}`}
                      className="link-primary hash"
                    >
                      {shortenHash(block.validator)}
                    </Link>
                  </div>
                </div>
                <div className="text-right">
                  <Link
                    href={`/txs?block=${block.number}`}
                    className="text-sm link-primary"
                  >
                    {block.tx_count} txns
                  </Link>
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
