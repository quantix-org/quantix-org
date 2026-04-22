import type { Metadata } from 'next';
import { Inter } from 'next/font/google';
import './globals.css';
import { Header } from '@/components/Header';
import { Footer } from '@/components/Footer';
import { Providers } from '@/components/Providers';

const inter = Inter({ subsets: ['latin'] });

const siteUrl = process.env.NEXT_PUBLIC_SITE_URL || 'https://testnet.qpqb.org';
const network = process.env.NEXT_PUBLIC_NETWORK || 'testnet';
const isTestnet = network === 'testnet';

export const metadata: Metadata = {
  title: isTestnet 
    ? 'Quantix Testnet Explorer | Post-Quantum Blockchain' 
    : 'Quantix Explorer | Post-Quantum Blockchain',
  description: `Explore the Quantix ${network} - blocks, transactions, addresses, and validators on the post-quantum secure network.`,
  keywords: ['Quantix', 'blockchain', 'explorer', 'post-quantum', 'SPHINCS+', 'cryptocurrency', network],
  metadataBase: new URL(siteUrl),
  openGraph: {
    title: isTestnet ? 'Quantix Testnet Explorer' : 'Quantix Explorer',
    description: `Explore the Quantix ${network} post-quantum blockchain`,
    siteName: isTestnet ? 'Quantix Testnet Explorer' : 'Quantix Explorer',
    url: siteUrl,
  },
  twitter: {
    card: 'summary_large_image',
    title: isTestnet ? 'Quantix Testnet Explorer' : 'Quantix Explorer',
    description: `Explore the Quantix ${network} post-quantum blockchain`,
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
