FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# variáveis padrão (podem ser sobrescritas no docker-compose)
ENV DATABASE_URL=postgresql+psycopg://postgres:postgres@db:5432/assinador \
    SECRET_KEY=S3m1t!@#

EXPOSE 5000

CMD ["python", "app.py"]
