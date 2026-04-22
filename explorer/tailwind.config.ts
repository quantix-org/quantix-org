import type { Config } from 'tailwindcss';

const config: Config = {
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
    './src/app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        primary: {
          50: '#f0fdff',
          100: '#ccf7ff',
          200: '#99eeff',
          300: '#66e4ff',
          400: '#33daff',
          500: '#00d4ff',
          600: '#00a8cc',
          700: '#007d99',
          800: '#005266',
          900: '#002933',
        },
        dark: {
          50: '#f7f7f8',
          100: '#eeeef0',
          200: '#d5d5d9',
          300: '#b0b0b8',
          400: '#8b8b97',
          500: '#6e6e7a',
          600: '#595964',
          700: '#494951',
          800: '#1a1a25',
          900: '#12121a',
          950: '#0a0a0f',
        },
      },
      fontFamily: {
        mono: ['SF Mono', 'Monaco', 'Inconsolata', 'Fira Mono', 'monospace'],
      },
    },
  },
  plugins: [],
};

export default config;
