const TOP_PACKAGES = [
  'react', 'express', 'lodash', 'axios', 'webpack', 'typescript', 'moment',
  'chalk', 'debug', 'commander', 'inquirer', 'jest', 'mocha', 'eslint',
  'prettier', 'babel', 'dotenv', 'cors', 'passport', 'mongoose', 'sequelize',
  'socket.io', 'nodemon', 'pm2', 'next', 'nuxt', 'vue', 'angular',
  'bcrypt', 'jsonwebtoken', 'uuid', 'fs-extra', 'glob', 'rimraf',
  'cross-env', 'concurrently', 'node-fetch', 'yargs', 'ora', 'boxen',
  'plaid', 'etherscan', 'tailwind', 'vite', 'rollup', 'esbuild',
  'sumsub', 'blockscan', 'bun', 'passport-js', 'bcryptjs',
];

function levenshtein(a: string, b: string): number {
  const m = a.length, n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[m][n];
}

export function checkTyposquat(packageName: string): { isSuspicious: boolean; similarTo?: string; distance?: number } {
  const name = packageName.toLowerCase().replace(/[^a-z0-9]/g, '');
  for (const known of TOP_PACKAGES) {
    const knownClean = known.toLowerCase().replace(/[^a-z0-9]/g, '');
    if (name === knownClean) continue; // Exact match is fine
    const dist = levenshtein(name, knownClean);
    if (dist > 0 && dist <= 2 && name.length > 3) {
      return { isSuspicious: true, similarTo: known, distance: dist };
    }
  }
  return { isSuspicious: false };
}
