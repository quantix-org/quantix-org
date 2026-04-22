import { NextRequest, NextResponse } from 'next/server';
import { getBlockNumber, getBlock, formatBlock } from '@/lib/rpc';

export const revalidate = 10;

function generateMockBlock(number: number) {
  const timestamp = new Date(Date.now() - (1000000 - number) * 10000);
  return {
    number,
    hash: `0x${number.toString(16).padStart(64, '0')}`,
    parent_hash: `0x${(number - 1).toString(16).padStart(64, '0')}`,
    timestamp: timestamp.toISOString(),
    validator: `qtx1validator${(number % 50).toString().padStart(32, '0')}00000`,
    tx_count: Math.floor(Math.random() * 50) + 1,
    gas_used: Math.floor(Math.random() * 5000000) + 100000,
    gas_limit: 10000000,
    state_root: `0x${(number * 54321).toString(16).padStart(64, '0')}`,
    tx_root: `0x${(number * 67890).toString(16).padStart(64, '0')}`,
    size: Math.floor(Math.random() * 5000) + 1000,
  };
}

export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;
  const limit = Math.min(parseInt(searchParams.get('limit') || '20'), 100);
  const offset = parseInt(searchParams.get('offset') || '0');

  try {
    // Try to get real data from RPC
    const latestBlock = await getBlockNumber();
    const blocks = [];

    for (let i = 0; i < limit; i++) {
      const blockNum = latestBlock - offset - i;
      if (blockNum <= 0) break;

      const block = await getBlock(blockNum, false);
      if (block) {
        blocks.push(formatBlock(block));
      }
    }

    if (blocks.length > 0) {
      return NextResponse.json(blocks);
    }
  } catch (error) {
    console.error('Blocks API error:', error);
  }

  // Fallback to mock data
  const baseHeight = 1000000 - offset;
  const blocks = [];

  for (let i = 0; i < limit; i++) {
    const number = baseHeight - i;
    if (number > 0) {
      blocks.push(generateMockBlock(number));
    }
  }

  return NextResponse.json(blocks);
}
