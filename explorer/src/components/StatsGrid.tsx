'use client';

import { Cube, Receipt, Shield, Coins, Clock, TrendingUp } from 'lucide-react';
import { formatNumber, formatQTX } from '@/lib/utils';
import { Skeleton } from './Skeleton';

interface Stats {
  block_height: number;
  total_transactions: number;
  validator_count: number;
  total_staked: string;
  avg_block_time: number;
  tps_24h: number;
}

interface StatsGridProps {
  stats?: Stats;
  loading?: boolean;
}

export function StatsGrid({ stats, loading }: StatsGridProps) {
  const items = [
    {
      label: 'Block Height',
      value: stats ? formatNumber(stats.block_height) : '-',
      icon: Cube,
      color: 'text-blue-400',
      bgColor: 'bg-blue-500/10',
    },
    {
      label: 'Transactions',
      value: stats ? formatNumber(stats.total_transactions) : '-',
      icon: Receipt,
      color: 'text-green-400',
      bgColor: 'bg-green-500/10',
    },
    {
      label: 'Validators',
      value: stats ? stats.validator_count.toString() : '-',
      icon: Shield,
      color: 'text-purple-400',
      bgColor: 'bg-purple-500/10',
    },
    {
      label: 'Total Staked',
      value: stats ? formatQTX(stats.total_staked) : '-',
      icon: Coins,
      color: 'text-yellow-400',
      bgColor: 'bg-yellow-500/10',
    },
    {
      label: 'Avg Block Time',
      value: stats ? `${stats.avg_block_time}s` : '-',
      icon: Clock,
      color: 'text-orange-400',
      bgColor: 'bg-orange-500/10',
    },
    {
      label: 'TPS (24h)',
      value: stats ? stats.tps_24h.toFixed(2) : '-',
      icon: TrendingUp,
      color: 'text-primary-400',
      bgColor: 'bg-primary-500/10',
    },
  ];

  return (
    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
      {items.map((item, index) => (
        <div key={index} className="stat-card">
          <div className="flex items-center gap-3 mb-3">
            <div className={`p-2 rounded-lg ${item.bgColor}`}>
              <item.icon className={`w-4 h-4 ${item.color}`} />
            </div>
          </div>
          <div className="stat-label">{item.label}</div>
          {loading ? (
            <Skeleton className="h-8 w-24 mt-1" />
          ) : (
            <div className="stat-value">{item.value}</div>
          )}
        </div>
      ))}
    </div>
  );
}
