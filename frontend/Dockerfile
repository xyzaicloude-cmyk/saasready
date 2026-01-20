FROM node:18-alpine AS builder

WORKDIR /app

# First copy package.json
COPY package.json .

# Then install dependencies
RUN npm install --package-lock-only && npm ci

# Copy the rest of your application code
COPY . .

ENV NEXT_PUBLIC_API_URL=http://localhost:8000/api/v1

RUN npm run build

FROM node:18-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production

COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static

EXPOSE 3000

ENV PORT 3000
ENV HOSTNAME "0.0.0.0"

CMD ["node", "server.js"]