# Multi-stage Dockerfile for Cloud Run
FROM node:22-alpine AS builder

WORKDIR /app
COPY package*.json tsconfig.json ./
RUN npm ci

COPY src/ ./src/
COPY public/ ./public/
RUN npm run build

# Production stage
FROM node:22-alpine AS runner

WORKDIR /app
ENV NODE_ENV=production
ENV PORT=8080

COPY package*.json ./
RUN npm ci --omit=dev

COPY --from=builder /app/dist ./dist
COPY --from=builder /app/public ./public

EXPOSE 8080
CMD ["node", "dist/index.js"]
