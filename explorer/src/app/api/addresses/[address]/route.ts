import { NextRequest, NextResponse } from 'next/server';

export async function GET(
  request: NextRequest,
  { params }: { params: { address: string } }
) {
  const address = params.address;

  if (!address.startsWith('qtx1') || address.length !== 42) {
    return NextResponse.json({ error: 'Invalid address' }, { status: 400 });
  }

  const isValidator = address.includes('validator');
  const isContract = address.includes('contract');

  const info = {
    address,
    balance: (BigInt(Math.floor(Math.random() * 10000) + 1) * BigInt(10 ** 18)).toString(),
    tx_count: Math.floor(Math.random() * 500) + 1,
    is_contract: isContract,
    is_validator: isValidator,
    staked: isValidator ? (BigInt(32) * BigInt(10 ** 18)).toString() : undefined,
  };

  return NextResponse.json(info);
}
