'use client';

import { useQuery } from '@tanstack/react-query';
import { useParams } from 'next/navigation';
import Link from 'next/link';
import { ArrowLeft, ArrowRight, Cube, Clock, User, Fuel, Hash, Layers } from 'lucide-react';
import { fetchBlock } from '@/lib/api';
import { formatNumber, formatTimeAgo, formatGas } from '@/lib/utils';
import { CopyButton } from '@/components/CopyButton';
import { Skeleton } from '@/components/Skeleton';

export default function BlockPage() {
  const params = useParams();
  const blockId = params.id as string;

  const { data: block, isLoading, error } = useQuery({
    queryKey: ['block', blockId],
    queryFn: () => fetchBlock(blockId),
  });

  if (isLoading) {
    return (
      <div className="container-page py-8">
        <Skeleton className="h-10 w-64 mb-8" />
        <div className="card">
          <div className="p-6 space-y-4">
            {[...Array(10)].map((_, i) => (
              <Skeleton key={i} className="h-6 w-full" />
            ))}
          </div>
        </div>
      </div>
    );
  }

  if (error || !block) {
    return (
      <div className="container-page py-8">
        <div className="card p-12 text-center">
          <h2 className="text-2xl font-bold mb-4">Block Not Found</h2>
          <p className="text-dark-400 mb-6">The block you&apos;re looking for doesn&apos;t exist.</p>
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
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-4">
          <div className="p-3 bg-primary-500/10 rounded-xl">
            <Cube className="w-6 h-6 text-primary-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold">Block #{formatNumber(block.number)}</h1>
            <p className="text-dark-400 text-sm">{formatTimeAgo(block.timestamp)}</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Link
            href={`/block/${block.number - 1}`}
            className="p-2 bg-dark-800 hover:bg-dark-700 rounded-lg transition-colors"
          >
            <ArrowLeft className="w-5 h-5" />
          </Link>
          <Link
            href={`/block/${block.number + 1}`}
            className="p-2 bg-dark-800 hover:bg-dark-700 rounded-lg transition-colors"
          >
            <ArrowRight className="w-5 h-5" />
          </Link>
        </div>
      </div>

      {/* Block Details */}
      <div className="card">
        <div className="p-6">
          <div className="detail-row">
            <span className="detail-label flex items-center gap-2">
              <Cube className="w-4 h-4" /> Block Height
            </span>
            <span className="detail-value font-semibold">
              {formatNumber(block.number)}
            </span>
          </div>

          <div className="detail-row">
            <span className="detail-label flex items-center gap-2">
              <Clock className="w-4 h-4" /> Timestamp
            </span>
            <span className="detail-value">
              {new Date(block.timestamp).toLocaleString()} ({formatTimeAgo(block.timestamp)})
            </span>
          </div>

          <div className="detail-row">
            <span className="detail-label flex items-center gap-2">
              <Layers className="w-4 h-4" /> Transactions
            </span>
            <span className="detail-value">
              <Link href={`/txs?block=${block.number}`} className="link-primary">
                {block.tx_count} transactions
              </Link>
            </span>
          </div>

          <div className="detail-row">
            <span className="detail-label flex items-center gap-2">
              <User className="w-4 h-4" /> Validated By
            </span>
            <span className="detail-value">
              <Link href={`/address/${block.validator}`} className="link-primary hash">
                {block.validator}
              </Link>
              <CopyButton text={block.validator} />
            </span>
          </div>

          <div className="detail-row">
            <span className="detail-label flex items-center gap-2">
              <Hash className="w-4 h-4" /> Block Hash
            </span>
            <span className="detail-value hash">
              {block.hash}
              <CopyButton text={block.hash} />
            </span>
          </div>

          <div className="detail-row">
            <span className="detail-label flex items-center gap-2">
              <Hash className="w-4 h-4" /> Parent Hash
            </span>
            <span className="detail-value">
              <Link href={`/block/${block.parent_hash}`} className="link-primary hash">
                {block.parent_hash}
              </Link>
              <CopyButton text={block.parent_hash} />
            </span>
          </div>

          <div className="detail-row">
            <span className="detail-label flex items-center gap-2">
              <Hash className="w-4 h-4" /> State Root
            </span>
            <span className="detail-value hash">
              {block.state_root}
              <CopyButton text={block.state_root} />
            </span>
          </div>

          <div className="detail-row">
            <span className="detail-label flex items-center gap-2">
              <Fuel className="w-4 h-4" /> Gas Used
            </span>
            <span className="detail-value">
              {formatGas(block.gas_used)} / {formatGas(block.gas_limit)} ({((block.gas_used / block.gas_limit) * 100).toFixed(2)}%)
            </span>
          </div>

          <div className="detail-row">
            <span className="detail-label">Block Size</span>
            <span className="detail-value">
              {formatNumber(block.size)} bytes
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
