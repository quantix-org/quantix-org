'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { Search, Loader2 } from 'lucide-react';
import { cn } from '@/lib/utils';

interface SearchBarProps {
  compact?: boolean;
}

export function SearchBar({ compact = false }: SearchBarProps) {
  const router = useRouter();
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!query.trim()) return;

    setLoading(true);
    const q = query.trim();

    try {
      // Block number
      if (/^\d+$/.test(q)) {
        router.push(`/block/${q}`);
        return;
      }

      // Transaction hash (0x + 64 hex chars)
      if (/^0x[a-fA-F0-9]{64}$/.test(q)) {
        router.push(`/tx/${q}`);
        return;
      }

      // Block hash (same format as tx hash, but we'll try tx first via API)
      if (/^0x[a-fA-F0-9]{64}$/.test(q)) {
        router.push(`/tx/${q}`);
        return;
      }

      // Quantix address
      if (/^qtx1[a-zA-Z0-9]{38}$/.test(q)) {
        router.push(`/address/${q}`);
        return;
      }

      // Fallback: try API search
      const res = await fetch(`/api/search?q=${encodeURIComponent(q)}`);
      if (res.ok) {
        const data = await res.json();
        if (data.type === 'block') {
          router.push(`/block/${data.id}`);
        } else if (data.type === 'tx') {
          router.push(`/tx/${data.id}`);
        } else if (data.type === 'address') {
          router.push(`/address/${data.id}`);
        } else {
          alert('No results found');
        }
      }
    } finally {
      setLoading(false);
      setQuery('');
    }
  };

  return (
    <form onSubmit={handleSearch}>
      <div className="relative">
        <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
          {loading ? (
            <Loader2 className="w-5 h-5 text-dark-400 animate-spin" />
          ) : (
            <Search className="w-5 h-5 text-dark-400" />
          )}
        </div>
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder={compact ? 'Search...' : 'Search by Address / Txn Hash / Block'}
          className={cn(
            'w-full bg-dark-800 border border-white/10 rounded-xl text-white placeholder-dark-400 focus:outline-none focus:ring-2 focus:ring-primary-500/50 focus:border-transparent transition-all',
            compact ? 'pl-10 pr-4 py-2 text-sm' : 'pl-12 pr-4 py-3.5'
          )}
        />
      </div>
    </form>
  );
}
