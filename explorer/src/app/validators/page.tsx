'use client';

import { useQuery } from '@tanstack/react-query';
import Link from 'next/link';
import { Shield, TrendingUp, CheckCircle, XCircle } from 'lucide-react';
import { fetchValidators } from '@/lib/api';
import { formatQTX, formatNumber, shortenHash } from '@/lib/utils';
import { Skeleton } from '@/components/Skeleton';

export default function ValidatorsPage() {
  const { data: validators, isLoading } = useQuery({
    queryKey: ['validators'],
    queryFn: fetchValidators,
    refetchInterval: 30000,
  });

  return (
    <div className="container-page py-8">
      {/* Header */}
      <div className="flex items-center gap-4 mb-6">
        <div className="p-3 bg-primary-500/10 rounded-xl">
          <Shield className="w-6 h-6 text-primary-400" />
        </div>
        <div>
          <h1 className="text-2xl font-bold">Validators</h1>
          <p className="text-dark-400 text-sm">Active validators securing the Quantix network</p>
        </div>
      </div>

      {/* Stats */}
      {validators && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
          <div className="stat-card">
            <span className="stat-label">Total Validators</span>
            <span className="stat-value">{validators.length}</span>
          </div>
          <div className="stat-card">
            <span className="stat-label">Active</span>
            <span className="stat-value text-green-400">
              {validators.filter((v: any) => v.active).length}
            </span>
          </div>
          <div className="stat-card">
            <span className="stat-label">Total Staked</span>
            <span className="stat-value">
              {formatQTX(validators.reduce((acc: bigint, v: any) => acc + BigInt(v.stake), BigInt(0)).toString())}
            </span>
          </div>
          <div className="stat-card">
            <span className="stat-label">Avg Uptime</span>
            <span className="stat-value">
              {(validators.reduce((acc: number, v: any) => acc + v.uptime, 0) / validators.length).toFixed(2)}%
            </span>
          </div>
        </div>
      )}

      {/* Validators Table */}
      <div className="card">
        <div className="table-container">
          {isLoading ? (
            <div className="p-6 space-y-3">
              {[...Array(10)].map((_, i) => (
                <Skeleton key={i} className="h-14" />
              ))}
            </div>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Rank</th>
                  <th>Validator</th>
                  <th>Stake</th>
                  <th>Commission</th>
                  <th>Uptime</th>
                  <th>Blocks Proposed</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {validators?.map((validator: any, index: number) => (
                  <tr key={validator.address}>
                    <td className="font-medium">{index + 1}</td>
                    <td>
                      <Link href={`/address/${validator.address}`} className="link-primary hash">
                        {shortenHash(validator.address, 12)}
                      </Link>
                    </td>
                    <td className="font-medium">{formatQTX(validator.stake)}</td>
                    <td>{validator.commission}%</td>
                    <td>
                      <div className="flex items-center gap-2">
                        <div className="w-24 h-2 bg-dark-700 rounded-full overflow-hidden">
                          <div
                            className="h-full bg-green-500 rounded-full"
                            style={{ width: `${validator.uptime}%` }}
                          />
                        </div>
                        <span className="text-sm">{validator.uptime.toFixed(1)}%</span>
                      </div>
                    </td>
                    <td>{formatNumber(validator.blocks_proposed)}</td>
                    <td>
                      {validator.active ? (
                        <span className="badge badge-success flex items-center gap-1 w-fit">
                          <CheckCircle className="w-3 h-3" />
                          Active
                        </span>
                      ) : (
                        <span className="badge badge-error flex items-center gap-1 w-fit">
                          <XCircle className="w-3 h-3" />
                          Inactive
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}
