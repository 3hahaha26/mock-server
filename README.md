# IoT Mock Server

## 概要

本リポジトリは、IoT Device Monitoring and Control System を対象とした

**脆弱性検証用モックサーバ**です。

FastAPI を用いて REST API を実装しており、

MTMT（Microsoft Threat Modeling Tool）で抽出された脅威を再現するための

脆弱な実装が含まれています。

本モックサーバは、LLMによって生成された攻撃シナリオおよびpytestを実行するための評価環境として利用します。

---

## 開発環境

- Python 3.13

- FastAPI 0.136.3

- Pydantic 2.13.4

- Uvicorn 0.49.0

- Docker

---

## ディレクトリ構成

```

mock-server

├── Dockerfile

├── requirements.txt

├── README.md

└── mock_server_from_spec_and_mtmt_test05.py

```

---

## Dockerによる起動

### イメージ作成

```bash

docker build -t mock-server .

```

### コンテナ起動

```bash

docker run --rm -p 8000:8000 mock-server

```

---

## APIドキュメント

サーバ起動後、以下にアクセスしてください。

Swagger UI

```

http://localhost:8000/docs

```

OpenAPI Specification

```

http://localhost:8000/openapi.json

```

Health Check

```

http://localhost:8000/health

```

---
