'use client';

import { useQuery } from '@tanstack/react-query';
import { StatsGrid } from '@/components/StatsGrid';
import { LatestBlocks } from '@/components/LatestBlocks';
import { LatestTransactions } from '@/components/LatestTransactions';
import { SearchBar } from '@/components/SearchBar';
import { fetchStats, fetchBlocks, fetchTransactions } from '@/lib/api';

export default function HomePage() {
  const { data: stats, isLoading: statsLoading } = useQuery({
    queryKey: ['stats'],
    queryFn: fetchStats,
    refetchInterval: 10000,
  });

  const { data: blocks, isLoading: blocksLoading } = useQuery({
    queryKey: ['blocks', 10],
    queryFn: () => fetchBlocks(10),
    refetchInterval: 10000,
  });

  const { data: transactions, isLoading: txLoading } = useQuery({
    queryKey: ['transactions', 10],
    queryFn: () => fetchTransactions(10),
    refetchInterval: 10000,
  });

  return (
    <div className="container-page py-8">
      {/* Hero Section */}
      <div className="text-center mb-10">
        <h1 className="text-3xl md:text-4xl font-bold mb-4">
          Quantix Blockchain Explorer
        </h1>
        <p className="text-dark-400 mb-8 max-w-2xl mx-auto">
          The post-quantum secure blockchain. Explore blocks, transactions, addresses, and smart contracts on the Quantix network.
        </p>
        <div className="max-w-2xl mx-auto">
          <SearchBar />
        </div>
      </div>

      {/* Stats Grid */}
      <StatsGrid stats={stats} loading={statsLoading} />

      {/* Latest Blocks & Transactions */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mt-8">
        <LatestBlocks blocks={blocks} loading={blocksLoading} />
        <LatestTransactions transactions={transactions} loading={txLoading} />
      </div>
    </div>
  );
}
