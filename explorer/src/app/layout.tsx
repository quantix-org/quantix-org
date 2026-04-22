import type { Metadata } from 'next';
import { Inter } from 'next/font/google';
import './globals.css';
import { Header } from '@/components/Header';
import { Footer } from '@/components/Footer';
import { Providers } from '@/components/Providers';

const inter = Inter({ subsets: ['latin'] });

export const metadata: Metadata = {
  title: 'Quantix Testnet Explorer | Post-Quantum Blockchain',
  description: 'Explore the Quantix testnet - blocks, transactions, addresses, and validators on the post-quantum secure network.',
  keywords: ['Quantix', 'blockchain', 'explorer', 'post-quantum', 'SPHINCS+', 'cryptocurrency', 'testnet'],
  metadataBase: new URL('https://testnet.qpqb.org'),
  openGraph: {
    title: 'Quantix Testnet Explorer',
    description: 'Explore the Quantix testnet post-quantum blockchain',
    siteName: 'Quantix Testnet Explorer',
    url: 'https://testnet.qpqb.org',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Quantix Testnet Explorer',
    description: 'Explore the Quantix testnet post-quantum blockchain',
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className={`${inter.className} bg-dark-950 text-white min-h-screen`}>
        <Providers>
          <div className="flex flex-col min-h-screen">
            <Header />
            <main className="flex-1">{children}</main>
            <Footer />
          </div>
        </Providers>
      </body>
    </html>
  );
}
