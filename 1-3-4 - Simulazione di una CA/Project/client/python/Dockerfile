FROM python:3.11

WORKDIR /app

# Copia i requisiti del progetto nel container
COPY requirements.txt .

# Installa le dipendenze del progetto
RUN pip install --no-cache-dir -r requirements.txt

# Copia il contenuto del volume nella directory corrente del container
COPY ./app /app