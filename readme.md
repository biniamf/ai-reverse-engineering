# Reverse Engineering AI Assistant

Uses a headless Ghidra analysis results exposed as REST API

```bash
docker run --rm -p 9090:9090 -v $(pwd)/data:/data/ghidra_projects biniamfd/ghidra-headless-rest:latest
```

## Setup

- Pull the Docker image and run it
- Set your OpenAI compatible API base URL
- API key
- model name

```bash
python webui/app.py
```

Then access the service at http://localhost:5000


https://github.com/user-attachments/assets/77f1645a-cd8e-470f-826b-585a73e48bf4

