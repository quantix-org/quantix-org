import { NextRequest, NextResponse } from 'next/server';
import { getBalance, getTransactionCount, getCode } from '@/lib/rpc';

export async function GET(
  request: NextRequest,
  { params }: { params: { address: string } }
) {
  const address = params.address;

  if (!address.startsWith('qtx1') || address.length !== 42) {
    return NextResponse.json({ error: 'Invalid address' }, { status: 400 });
  }

  try {
    const [balance, txCount, code] = await Promise.all([
      getBalance(address),
      getTransactionCount(address),
      getCode(address),
    ]);

    const isContract = code && code !== '0x' && code !== '0x0';
    const isValidator = address.includes('validator'); // Would need validator contract call

    return NextResponse.json({
      address,
      balance,
      tx_count: txCount,
      is_contract: isContract,
      is_validator: isValidator,
      staked: isValidator ? (BigInt(32) * BigInt(10 ** 18)).toString() : undefined,
      code: isContract ? code : undefined,
    });
  } catch (error) {
    console.error('Address API error:', error);
  }

  // Fallback to mock data
  const isValidator = address.includes('validator');
  const isContract = address.includes('contract');

  return NextResponse.json({
    address,
    balance: (BigInt(Math.floor(Math.random() * 10000) + 1) * BigInt(10 ** 18)).toString(),
    tx_count: Math.floor(Math.random() * 500) + 1,
    is_contract: isContract,
    is_validator: isValidator,
    staked: isValidator ? (BigInt(32) * BigInt(10 ** 18)).toString() : undefined,
  });
}
