/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  
  // Environment variables with defaults
  env: {
    NEXT_PUBLIC_RPC_URL: process.env.NEXT_PUBLIC_RPC_URL || 'https://rpc.qpqb.org',
    NEXT_PUBLIC_NETWORK: process.env.NEXT_PUBLIC_NETWORK || 'mainnet',
    NEXT_PUBLIC_SITE_NAME: 'Quantix Explorer',
  },

  // Enable experimental features
  experimental: {
    // Optimize for serverless
    serverMinification: true,
  },

  // API rewrites for CORS issues (if needed)
  async rewrites() {
    return [
      // Proxy RPC requests to avoid CORS (optional, for client-side calls)
      {
        source: '/rpc',
        destination: process.env.NEXT_PUBLIC_RPC_URL || 'https://rpc.qpqb.org',
      },
    ];
  },

  // Headers for security and caching
  async headers() {
    return [
      {
        source: '/api/:path*',
        headers: [
          { key: 'Access-Control-Allow-Origin', value: '*' },
          { key: 'Access-Control-Allow-Methods', value: 'GET, POST, OPTIONS' },
          { key: 'Access-Control-Allow-Headers', value: 'Content-Type' },
          { key: 'Cache-Control', value: 's-maxage=10, stale-while-revalidate=59' },
        ],
      },
      {
        source: '/:path*',
        headers: [
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'Referrer-Policy', value: 'origin-when-cross-origin' },
        ],
      },
    ];
  },

  // Image optimization
  images: {
    domains: ['qpqb.org'],
  },
};

module.exports = nextConfig;
