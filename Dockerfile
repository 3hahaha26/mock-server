FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir "fastapi[standard]>=0.136.0" "pydantic>=2.13.1"

COPY mock_server_from_spec_and_mtmt_test05.py .

EXPOSE 8000

CMD ["python", "mock_server_from_spec_and_mtmt_test05.py"]
