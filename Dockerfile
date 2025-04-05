FROM node:lts-alpine
# Set working directory
WORKDIR /app

# Copy package.json and package-lock.json (if exists)
COPY package.json ./

# Install dependencies
RUN npm install
RUN npm install -g webpack webpack-cli

# Copy webpack config and tsconfig
COPY webpack.config.js ./
COPY tsconfig.json ./

# Copy source code
COPY src/ ./src/

# Copy environment file
COPY .env ./

# Expose the port your app runs on (adjust if needed)
EXPOSE 4300

# Set environment variables
ENV NODE_ENV=production

# Use ENTRYPOINT instead of CMD
ENTRYPOINT ["sh", "-c", "cd /app && rm -rf dist && webpack && node dist/bundle.js"]