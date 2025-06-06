const path = require('path');
const webpack = require('webpack');
module.exports = {
    target:"node",
  entry: './src/index.ts',
  mode:"production",
  module: {
    rules: [
      {
        test: /\.tsx?$/,
        use: 'ts-loader',
        exclude: /node_modules/,
      },
      {
        test: /\.wasm$/,
        type: 'webassembly/async',
      },
      {
        test: /\.node$/,
        use: 'node-loader', // Handle .node files
    }
    ],
  },
  optimization: {minimize: false},
  resolve: {
    extensions: ['.tsx', '.ts', '.js', '.wasm'],
    fallback: {
        "path": require.resolve("path-browserify"),
        "crypto": require.resolve("crypto-browserify"),
        "stream": require.resolve("stream-browserify"),
        "os": require.resolve("os-browserify/browser"),
        "vm": require.resolve("vm-browserify"),
        "assert": require.resolve("assert-browserify"),
    }
  },
  output: {
    filename: 'bundle.js',
    path: path.resolve(__dirname, 'dist'),
  },
  experiments: {
    asyncWebAssembly: true,
  },
  externals: {
    "utf-8-validate": "commonjs utf-8-validate",
    sqlite3: 'commonjs sqlite3',
  },
  plugins: [
    new webpack.ProvidePlugin({
      TextDecoder: ['util', 'TextDecoder'],
      TextEncoder: ['util', 'TextEncoder'],
    }),
  ],
};