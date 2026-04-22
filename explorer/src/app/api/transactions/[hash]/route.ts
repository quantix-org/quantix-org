import { NextRequest, NextResponse } from 'next/server';

export async function GET(
  request: NextRequest,
  { params }: { params: { hash: string } }
) {
  const hash = params.hash;

  if (!hash.startsWith('0x') || hash.length !== 66) {
    return NextResponse.json({ error: 'Invalid transaction hash' }, { status: 400 });
  }

  const timestamp = new Date(Date.now() - Math.floor(Math.random() * 86400000));
  
  const tx = {
    hash,
    block_number: 1000000 - Math.floor(Math.random() * 1000),
    block_hash: `0x${'a'.repeat(64)}`,
    from: 'qtx1sender00000000000000000000000000000000',
    to: 'qtx1receiver000000000000000000000000000000',
    value: (BigInt(Math.floor(Math.random() * 1000) + 1) * BigInt(10 ** 18)).toString(),
    gas_used: Math.floor(Math.random() * 100000) + 21000,
    gas_price: '1000000000',
    nonce: Math.floor(Math.random() * 100),
    status: 'Success',
    timestamp: timestamp.toISOString(),
    type: 'transfer',
    input: '0x',
  };

  return NextResponse.json(tx);
}
