# Use a lightweight Node image
FROM node:22-alpine

# Create app directory
WORKDIR /app

# Copy package.json (and package-lock.json if you have it)
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy the rest of the backend code
COPY . .

# Expose the port your backend uses (adjust if your index.js uses another port)
EXPOSE 5000

# Start the backend (uses "start": "node index.js")
CMD ["npm", "start"]
