import Link from 'next/link';
import { Github, Twitter, MessageCircle, Globe } from 'lucide-react';

export function Footer() {
  return (
    <footer className="bg-dark-900 border-t border-white/10 mt-16">
      <div className="container-page py-12">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
          {/* Brand */}
          <div className="col-span-1 md:col-span-2">
            <div className="flex items-center gap-2 mb-4">
              <div className="p-2 bg-primary-500/10 rounded-lg">
                <span className="text-2xl">⬡</span>
              </div>
              <span className="font-bold text-xl">Quantix Explorer</span>
            </div>
            <p className="text-dark-400 text-sm max-w-md">
              Explore the Quantix post-quantum secure blockchain. View blocks, transactions, 
              addresses, and smart contracts on the network powered by SPHINCS+ signatures 
              and ZK-STARK proofs.
            </p>
            <div className="flex items-center gap-4 mt-6">
              <a
                href="https://github.com/quantix-org/quantix-org"
                target="_blank"
                rel="noopener noreferrer"
                className="p-2 bg-dark-800 hover:bg-dark-700 rounded-lg transition-colors"
              >
                <Github className="w-5 h-5" />
              </a>
              <a
                href="https://twitter.com/quantixprotocol"
                target="_blank"
                rel="noopener noreferrer"
                className="p-2 bg-dark-800 hover:bg-dark-700 rounded-lg transition-colors"
              >
                <Twitter className="w-5 h-5" />
              </a>
              <a
                href="https://discord.gg/quantix"
                target="_blank"
                rel="noopener noreferrer"
                className="p-2 bg-dark-800 hover:bg-dark-700 rounded-lg transition-colors"
              >
                <MessageCircle className="w-5 h-5" />
              </a>
              <a
                href="https://qpqb.org"
                target="_blank"
                rel="noopener noreferrer"
                className="p-2 bg-dark-800 hover:bg-dark-700 rounded-lg transition-colors"
              >
                <Globe className="w-5 h-5" />
              </a>
            </div>
          </div>

          {/* Explorer Links */}
          <div>
            <h3 className="font-semibold mb-4">Explorer</h3>
            <ul className="space-y-3 text-sm">
              <li>
                <Link href="/blocks" className="text-dark-400 hover:text-white transition-colors">
                  Blocks
                </Link>
              </li>
              <li>
                <Link href="/txs" className="text-dark-400 hover:text-white transition-colors">
                  Transactions
                </Link>
              </li>
              <li>
                <Link href="/validators" className="text-dark-400 hover:text-white transition-colors">
                  Validators
                </Link>
              </li>
              <li>
                <a href="/api" className="text-dark-400 hover:text-white transition-colors">
                  API Docs
                </a>
              </li>
            </ul>
          </div>

          {/* Resources */}
          <div>
            <h3 className="font-semibold mb-4">Resources</h3>
            <ul className="space-y-3 text-sm">
              <li>
                <a
                  href="https://qpqb.org"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-dark-400 hover:text-white transition-colors"
                >
                  Website
                </a>
              </li>
              <li>
                <a
                  href="https://docs.qpqb.org"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-dark-400 hover:text-white transition-colors"
                >
                  Documentation
                </a>
              </li>
              <li>
                <a
                  href="https://github.com/quantix-org/quantix-org/blob/main/docs/WHITEPAPER.md"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-dark-400 hover:text-white transition-colors"
                >
                  Whitepaper
                </a>
              </li>
              <li>
                <a
                  href="https://faucet.qpqb.org"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-dark-400 hover:text-white transition-colors"
                >
                  Testnet Faucet
                </a>
              </li>
            </ul>
          </div>
        </div>

        {/* Bottom */}
        <div className="mt-12 pt-8 border-t border-white/10 flex flex-col sm:flex-row items-center justify-between gap-4">
          <p className="text-dark-400 text-sm">
            © {new Date().getFullYear()} Quantix Protocol. All rights reserved.
          </p>
          <div className="flex items-center gap-6 text-sm text-dark-400">
            <a href="/privacy" className="hover:text-white transition-colors">
              Privacy
            </a>
            <a href="/terms" className="hover:text-white transition-colors">
              Terms
            </a>
            <a
              href="https://status.qpqb.org"
              target="_blank"
              rel="noopener noreferrer"
              className="hover:text-white transition-colors"
            >
              Status
            </a>
          </div>
        </div>
      </div>
    </footer>
  );
}
