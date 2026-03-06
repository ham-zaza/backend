# 1. Use an official, lightweight Node runtime
FROM node:18-alpine

# 2. Set the working directory inside the container
WORKDIR /app

# 3. Copy ONLY package files first (for caching efficiency)
COPY package*.json ./

# 4. Install dependencies inside the Linux container
RUN npm install

# 5. Copy your specific structure (src, public, server.js) into the container
COPY . .

# 6. Expose the port your Express server runs on
EXPOSE 3000

# 7. Command to start your ZK-Auth server
CMD ["node", "server.js"]