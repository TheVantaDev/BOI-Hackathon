FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/models

ENV MODEL_PATH=/app/models/xgb_risk_model.json

EXPOSE 8016

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8016"]
