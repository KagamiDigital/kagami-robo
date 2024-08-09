module.exports = {
  apps: [
    {
      name: 'robo-server',
      script: 'dist/bundle.js', // replace with your entry JavaScript file, if needed
      interpreter: 'node',
      watch: false,
      env: {
        NODE_ENV: 'production',
      },
    },
  ],
};

