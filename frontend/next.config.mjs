/** @type {import('next').NextConfig} */
const nextConfig = {
  // Proxy API calls in dev so CORS isn't an issue locally
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: `${process.env.NEXT_PUBLIC_API_URL}/api/:path*`,
      },
    ];
  },
};

export default nextConfig;
