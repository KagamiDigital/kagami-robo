FROM node:lts-alpine
# Set working directory
WORKDIR /app

# Install Python and dependencies
RUN apk add --no-cache python3 py3-boto3

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

# Copy Python scripts
COPY setup/enclave/*.py ./

# Copy KMS keyId
COPY setup/ec2/keyId.txt ./

# Copy seed phrase
COPY setup/ec2/seed.txt ./

# Copy encrypted seed phrase
COPY setup/ec2/encrypted_seed.txt ./

# Copy environment file
COPY .env ./

# Expose the port your app runs on (adjust if needed)
EXPOSE 4300

# Set environment variables
ENV NODE_ENV=production
ENV AWS_DEFAULT_REGION=us-east-1

# Use ENTRYPOINT instead of CMD
ENTRYPOINT ["sh", "-c", "cd /app && rm -rf dist && webpack && node dist/bundle.js"]