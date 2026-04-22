/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  env: {
    NEXT_PUBLIC_RPC_URL: process.env.NEXT_PUBLIC_RPC_URL || 'http://localhost:8545',
    NEXT_PUBLIC_NETWORK: process.env.NEXT_PUBLIC_NETWORK || 'mainnet',
    NEXT_PUBLIC_SITE_NAME: 'Quantix Explorer',
  },
  async headers() {
    return [
      {
        source: '/api/:path*',
        headers: [
          { key: 'Access-Control-Allow-Origin', value: '*' },
          { key: 'Access-Control-Allow-Methods', value: 'GET, POST, OPTIONS' },
        ],
      },
    ];
  },
};

module.exports = nextConfig;
