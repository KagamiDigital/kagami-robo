FROM node:lts-alpine
# Set working directory
WORKDIR /app

# Install Python and dependencies
RUN apk add --no-cache python3 python3-dev

# Create and activate a Python virtual environment
RUN python3 -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

# Install Python dependencies in the virtual environment
RUN pip3 install --no-cache-dir boto3==1.37.16 mnemonic

# Copy package.json and package-lock.json (if exists)
COPY package.json ./

# Install dependencies
RUN npm install
RUN npm install -g webpack webpack-cli
RUN apk add --no-cache socat

# Copy webpack config and tsconfig
COPY webpack.config.js ./
COPY tsconfig.json ./

# Copy source code
COPY src/ ./src/

# Copy Python scripts
COPY setup/enclave/*.py ./

# Copy KMS keyId
COPY setup/ec2/keyId.txt ./

# Copy encrypted seed phrase
COPY setup/ec2/seed.txt ./

# Copy environment file
COPY .env ./

# Copy socat setup
COPY socat.sh ./
RUN chmod +x /app/socat.sh

# Expose the port your app runs on (adjust if needed)
EXPOSE 4300

# Set environment variables
ENV NODE_ENV=production
ENV AWS_DEFAULT_REGION=us-east-1

# Use ENTRYPOINT instead of CMD
ENTRYPOINT ["sh", "-c", "cd /app && . /app/venv/bin/activate && ./socat.sh && rm -rf dist && webpack && node dist/bundle.js"]