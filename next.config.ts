import type { NextConfig } from "next";

import path from "path";

const nextConfig: NextConfig = {
  turbopack: {
     // Use an absolute path as required by Next.js 15 for the turbopack root
    root: path.resolve(__dirname),
  }
};

export default nextConfig;
