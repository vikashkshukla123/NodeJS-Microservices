# use the official node.js version 18 image with apline linux as the base image
FROM node:18-alpine

#set the working directory in a container so that all the subsequent command run from that directory
WORKDIR /usr/src/app

# Copies:
# package.json
# package-lock.json
COPY package*.json ./

# Installs only production dependencies
# Faster and cleaner than npm install

RUN npm ci --only=production

# Copies all files into container

#Now your app code is inside container

COPY . .

# App listens on port 3000
# Documentation only (not actually opening port)

EXPOSE 3003
# Runs your backend server
CMD ["node", "src/server.js"]