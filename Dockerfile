FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .
COPY demon .

RUN chmod +x demon

EXPOSE 8000

CMD ["python", "main.py"]
