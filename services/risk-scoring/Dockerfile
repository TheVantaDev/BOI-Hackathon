FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Copy model files — XGBoost + CNN ensemble:
RUN mkdir -p /app/models
COPY models/xgb_risk_model.json /app/models/xgb_risk_model.json
COPY models/drebin_feature_names.json /app/models/drebin_feature_names.json
COPY models/cnn_malware_model.tflite /app/models/cnn_malware_model.tflite
COPY models/cnn_metadata.json /app/models/cnn_metadata.json

ENV MODEL_PATH=/app/models/xgb_risk_model.json

EXPOSE 8016

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8016"]
