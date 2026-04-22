import { NextRequest, NextResponse } from 'next/server';

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

export async function GET(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  const id = params.id;
  let number: number;

  // Check if it's a number or hash
  if (/^\d+$/.test(id)) {
    number = parseInt(id);
  } else if (id.startsWith('0x')) {
    // Parse hash back to number (mock behavior)
    number = parseInt(id.slice(2), 16) || 1000000;
  } else {
    return NextResponse.json({ error: 'Invalid block ID' }, { status: 400 });
  }

  if (number <= 0 || number > 1000100) {
    return NextResponse.json({ error: 'Block not found' }, { status: 404 });
  }

  return NextResponse.json(generateMockBlock(number));
}
