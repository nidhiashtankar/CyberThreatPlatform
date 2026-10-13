# Build Stage
FROM node:20-alpine AS build

WORKDIR /app

# Copy package definitions and install
COPY package*.json ./
RUN npm ci

# Copy sources and compile production bundle
COPY . .
RUN npm run build

# Serve Stage with Nginx
FROM nginx:alpine

# Copy compiled assets to Nginx html directory
COPY --from=build /app/dist /usr/share/nginx/html

# Copy custom Nginx routing configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
