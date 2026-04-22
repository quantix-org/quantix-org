# Quantix Explorer

A modern, Etherscan-style block explorer for the Quantix blockchain, built with Next.js 14 and deployed on Vercel.

## Features

- 📊 **Dashboard** - Real-time network stats (blocks, TPS, validators, staked)
- 🧱 **Blocks** - Browse and search blocks with pagination
- 💸 **Transactions** - View all transactions with filtering by block
- 👛 **Addresses** - Account balances, transaction history, validator/contract badges
- ✅ **Validators** - Active validator list with stake, uptime, and commission
- 🔍 **Search** - Universal search for blocks, transactions, and addresses
- 📱 **Responsive** - Mobile-first design with dark theme

## Tech Stack

- **Framework**: Next.js 14 (App Router)
- **Styling**: Tailwind CSS
- **State**: TanStack Query (React Query)
- **Icons**: Lucide React
- **Language**: TypeScript
- **Deployment**: Vercel

## Getting Started

### Prerequisites

- Node.js 18+
- npm or yarn

### Installation

```bash
cd explorer
npm install
```

### Development

```bash
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

### Production Build

```bash
npm run build
npm start
```

## Environment Variables

Create a `.env.local` file:

```env
# Quantix node RPC endpoint
NEXT_PUBLIC_RPC_URL=http://localhost:8545

# Network name (mainnet, testnet, devnet)
NEXT_PUBLIC_NETWORK=mainnet
```

## Deploy to Vercel

1. Push to GitHub
2. Import project in [Vercel](https://vercel.com)
3. Set environment variables
4. Deploy!

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/quantix-org/quantix-org/tree/main/explorer)

## Project Structure

```
explorer/
├── src/
│   ├── app/                 # Next.js App Router pages
│   │   ├── api/             # API routes (mock data)
│   │   ├── block/[id]/      # Block detail page
│   │   ├── tx/[hash]/       # Transaction detail page
│   │   ├── address/[addr]/  # Address detail page
│   │   ├── blocks/          # Blocks list page
│   │   ├── txs/             # Transactions list page
│   │   ├── validators/      # Validators list page
│   │   └── page.tsx         # Home page
│   ├── components/          # React components
│   │   ├── Header.tsx
│   │   ├── Footer.tsx
│   │   ├── SearchBar.tsx
│   │   ├── StatsGrid.tsx
│   │   ├── LatestBlocks.tsx
│   │   ├── LatestTransactions.tsx
│   │   └── ...
│   └── lib/                 # Utilities
│       ├── api.ts           # API client
│       └── utils.ts         # Helpers
├── public/                  # Static assets
├── tailwind.config.ts       # Tailwind configuration
└── next.config.js           # Next.js configuration
```

## API Routes

The explorer includes mock API routes for development. In production, these should connect to a Quantix node.

| Endpoint | Description |
|----------|-------------|
| `GET /api/stats` | Network statistics |
| `GET /api/blocks` | List blocks |
| `GET /api/blocks/[id]` | Block by number/hash |
| `GET /api/transactions` | List transactions |
| `GET /api/transactions/[hash]` | Transaction by hash |
| `GET /api/addresses/[addr]` | Address info |
| `GET /api/addresses/[addr]/transactions` | Address transactions |
| `GET /api/validators` | Validator list |
| `GET /api/search?q=...` | Universal search |

## Connecting to a Real Node

Replace the mock API routes with actual RPC calls:

```typescript
// src/lib/rpc.ts
const RPC_URL = process.env.NEXT_PUBLIC_RPC_URL;

export async function rpcCall(method: string, params: any[] = []) {
  const res = await fetch(RPC_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      method,
      params,
      id: 1,
    }),
  });
  const data = await res.json();
  return data.result;
}
```

## License

MIT License - see [LICENSE](../LICENSE)

## Links

- **Website**: https://qpqb.org
- **GitHub**: https://github.com/quantix-org/quantix-org
- **Documentation**: https://docs.qpqb.org
