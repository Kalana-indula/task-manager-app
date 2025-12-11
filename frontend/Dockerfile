FROM node:22-alpine

WORKDIR /app

# Copy package.json and install deps
COPY package*.json ./
RUN npm install --legacy-peer-deps

# Copy the rest of the frontend code
COPY . .

# Build the React Router app
RUN npm run build

EXPOSE 3000
CMD ["npm", "start"]
