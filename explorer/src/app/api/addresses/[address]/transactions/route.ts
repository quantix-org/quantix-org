import { NextRequest, NextResponse } from 'next/server';

export async function GET(
  request: NextRequest,
  { params }: { params: { address: string } }
) {
  const address = params.address;
  const searchParams = request.nextUrl.searchParams;
  const limit = Math.min(parseInt(searchParams.get('limit') || '25'), 100);

  const transactions = [];

  for (let i = 0; i < limit; i++) {
    const isIncoming = Math.random() > 0.5;
    const timestamp = new Date(Date.now() - i * 3600000);
    
    transactions.push({
      hash: `0x${(Date.now() + i).toString(16).padStart(64, 'a')}`,
      block_number: 1000000 - i * 10,
      from: isIncoming ? `qtx1other${i.toString().padStart(34, '0')}` : address,
      to: isIncoming ? address : `qtx1other${i.toString().padStart(34, '0')}`,
      value: (BigInt(Math.floor(Math.random() * 100) + 1) * BigInt(10 ** 18)).toString(),
      gas_used: 21000 + Math.floor(Math.random() * 50000),
      gas_price: '1000000000',
      timestamp: timestamp.toISOString(),
      status: 'Success',
    });
  }

  return NextResponse.json(transactions);
}
