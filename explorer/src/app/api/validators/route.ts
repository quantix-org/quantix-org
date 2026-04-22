import { NextResponse } from 'next/server';

export async function GET() {
  const validators = [];

  for (let i = 0; i < 50; i++) {
    validators.push({
      address: `qtx1validator${i.toString().padStart(30, '0')}`,
      stake: (BigInt(32 + i * 10) * BigInt(10 ** 18)).toString(),
      commission: 5 + (i % 10),
      uptime: 99.9 - (i * 0.05),
      blocks_proposed: 10000 - i * 100,
      active: i < 45, // Top 45 are active
    });
  }

  // Sort by stake descending
  validators.sort((a, b) => {
    const stakeA = BigInt(a.stake);
    const stakeB = BigInt(b.stake);
    return stakeA > stakeB ? -1 : stakeA < stakeB ? 1 : 0;
  });

  return NextResponse.json(validators);
}
