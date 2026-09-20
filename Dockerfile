FROM python:3.11-slim

# Sistem araçlarını, nmap'i ve curl/wget gibi araçları yükle
RUN apt-get update && apt-get install -y \
    nmap \
    curl \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# ProjectDiscovery Nuclei'yi indir ve sisteme kur (Binary olarak)
RUN LATEST_NUCLEI_URL=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep "browser_download_url.*linux_amd64.zip" | cut -d '"' -f 4) && \
    wget -q "$LATEST_NUCLEI_URL" -O nuclei.zip && \
    unzip nuclei.zip && \
    mv nuclei /usr/local/bin/ && \
    rm nuclei.zip

WORKDIR /app

# Python bağımlılıklarını kopyala ve yükle
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Proje kaynak kodlarını kopyala
COPY . .