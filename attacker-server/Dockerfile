FROM node:20-alpine
WORKDIR /app
COPY receiver.js .
RUN mkdir -p loot
EXPOSE 8080
CMD ["node", "receiver.js"]
