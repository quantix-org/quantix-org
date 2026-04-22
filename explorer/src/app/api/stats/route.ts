import { NextResponse } from 'next/server';

// Mock data - in production, this would call the Quantix RPC
export async function GET() {
  const stats = {
    block_height: 1000000 + Math.floor(Math.random() * 100),
    total_transactions: 5000000 + Math.floor(Math.random() * 1000),
    validator_count: 50,
    total_staked: '1600000000000000000000',
    avg_block_time: 10.2,
    tps_24h: 15.5 + Math.random() * 2,
    total_supply: '5000000000000000000000000000',
    circulating_supply: '4250000000000000000000000000',
  };

  return NextResponse.json(stats);
}
