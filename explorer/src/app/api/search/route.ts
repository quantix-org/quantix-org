import { NextRequest, NextResponse } from 'next/server';

export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;
  const query = searchParams.get('q')?.trim();

  if (!query) {
    return NextResponse.json({ type: 'not_found', id: '' });
  }

  // Block number
  if (/^\d+$/.test(query)) {
    return NextResponse.json({ type: 'block', id: query });
  }

  // Transaction hash
  if (/^0x[a-fA-F0-9]{64}$/.test(query)) {
    return NextResponse.json({ type: 'tx', id: query });
  }

  // Quantix address
  if (/^qtx1[a-zA-Z0-9]{38}$/.test(query)) {
    return NextResponse.json({ type: 'address', id: query });
  }

  return NextResponse.json({ type: 'not_found', id: '' });
}
