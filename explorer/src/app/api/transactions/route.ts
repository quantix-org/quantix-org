import { NextRequest, NextResponse } from 'next/server';

function generateMockTransaction(index: number, blockNumber?: number) {
  const block = blockNumber || 1000000 - Math.floor(index / 10);
  const timestamp = new Date(Date.now() - index * 15000);
  
  return {
    hash: `0x${(Date.now() + index).toString(16).padStart(64, 'a')}`,
    block_number: block,
    block_hash: `0x${block.toString(16).padStart(64, '0')}`,
    from: `qtx1sender${index.toString().padStart(33, '0')}`,
    to: `qtx1receiver${index.toString().padStart(31, '0')}`,
    value: (BigInt(Math.floor(Math.random() * 1000) + 1) * BigInt(10 ** 18)).toString(),
    gas_used: Math.floor(Math.random() * 100000) + 21000,
    gas_price: '1000000000',
    nonce: Math.floor(Math.random() * 100),
    status: Math.random() > 0.05 ? 'Success' : 'Failed',
    timestamp: timestamp.toISOString(),
    type: Math.random() > 0.8 ? 'contract_call' : 'transfer',
  };
}

export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;
  const limit = Math.min(parseInt(searchParams.get('limit') || '20'), 100);
  const offset = parseInt(searchParams.get('offset') || '0');
  const block = searchParams.get('block');

  const transactions = [];
  const blockNumber = block ? parseInt(block) : undefined;

  for (let i = 0; i < limit; i++) {
    transactions.push(generateMockTransaction(offset + i, blockNumber));
  }

  return NextResponse.json(transactions);
}
