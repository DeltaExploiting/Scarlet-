FROM node:20-bookworm

RUN apt-get update && apt-get install -y git g++ make pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 https://github.com/zhlynn/zsign.git /opt/zsign && \
    cd /opt/zsign/build/linux && \
    make clean && make && \
    cp ../../bin/zsign /usr/local/bin/zsign && chmod +x /usr/local/bin/zsign

WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev
COPY server.js ./
EXPOSE 3000
CMD ["npm", "start"]