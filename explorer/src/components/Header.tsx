'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Hexagon, Cube, Receipt, Wallet, Shield, Menu, X } from 'lucide-react';
import { useState } from 'react';
import { SearchBar } from './SearchBar';
import { cn } from '@/lib/utils';

const navigation = [
  { name: 'Home', href: '/', icon: Hexagon },
  { name: 'Blocks', href: '/blocks', icon: Cube },
  { name: 'Transactions', href: '/txs', icon: Receipt },
  { name: 'Validators', href: '/validators', icon: Shield },
];

export function Header() {
  const pathname = usePathname();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const network = process.env.NEXT_PUBLIC_NETWORK || 'mainnet';

  return (
    <header className="sticky top-0 z-50 bg-dark-900/80 backdrop-blur-xl border-b border-white/10">
      <div className="container-page">
        <div className="flex items-center justify-between h-16">
          {/* Logo */}
          <Link href="/" className="flex items-center gap-3">
            <div className="p-2 bg-primary-500/10 rounded-lg">
              <Hexagon className="w-6 h-6 text-primary-400" />
            </div>
            <div className="hidden sm:block">
              <span className="font-bold text-lg">Quantix</span>
              <span className="text-dark-400 text-lg ml-1">Explorer</span>
            </div>
          </Link>

          {/* Desktop Navigation */}
          <nav className="hidden md:flex items-center gap-1">
            {navigation.map((item) => {
              const isActive = pathname === item.href;
              return (
                <Link
                  key={item.name}
                  href={item.href}
                  className={cn(
                    'flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors',
                    isActive
                      ? 'bg-primary-500/10 text-primary-400'
                      : 'text-dark-300 hover:text-white hover:bg-white/5'
                  )}
                >
                  <item.icon className="w-4 h-4" />
                  {item.name}
                </Link>
              );
            })}
          </nav>

          {/* Right Side */}
          <div className="flex items-center gap-4">
            {/* Search (desktop) */}
            <div className="hidden lg:block w-64">
              <SearchBar compact />
            </div>

            {/* Network Badge */}
            <div className={cn(
              'px-3 py-1.5 rounded-full text-xs font-semibold uppercase tracking-wide border',
              network === 'mainnet' 
                ? 'bg-green-500/10 text-green-400 border-green-500/30'
                : network === 'testnet'
                ? 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30'
                : 'bg-primary-500/10 text-primary-400 border-primary-500/30'
            )}>
              {network}
            </div>

            {/* Mobile menu button */}
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="md:hidden p-2 rounded-lg hover:bg-white/10"
            >
              {mobileMenuOpen ? (
                <X className="w-6 h-6" />
              ) : (
                <Menu className="w-6 h-6" />
              )}
            </button>
          </div>
        </div>

        {/* Mobile Search */}
        <div className="lg:hidden pb-4">
          <SearchBar />
        </div>
      </div>

      {/* Mobile Navigation */}
      {mobileMenuOpen && (
        <div className="md:hidden border-t border-white/10 bg-dark-900">
          <nav className="container-page py-4 space-y-1">
            {navigation.map((item) => {
              const isActive = pathname === item.href;
              return (
                <Link
                  key={item.name}
                  href={item.href}
                  onClick={() => setMobileMenuOpen(false)}
                  className={cn(
                    'flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-colors',
                    isActive
                      ? 'bg-primary-500/10 text-primary-400'
                      : 'text-dark-300 hover:text-white hover:bg-white/5'
                  )}
                >
                  <item.icon className="w-5 h-5" />
                  {item.name}
                </Link>
              );
            })}
          </nav>
        </div>
      )}
    </header>
  );
}
