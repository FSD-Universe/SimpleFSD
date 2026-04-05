FROM python:3.12.13-slim

WORKDIR /app

RUN sed -i 's/deb.debian.org/mirrors.ustc.edu.cn/g' /etc/apt/sources.list.d/debian.sources \
    && apt-get update && apt-get install -y --no-install-recommends git curl && rm -rf /var/lib/apt/lists/*

RUN curl -sSL https://pdm-project.org/install-pdm.py | python3 -
ENV PATH="/root/.local/bin:${PATH}"
RUN pdm config python.use_venv False

RUN git clone https://github.com/kyutai-labs/pocket-tts.git .
RUN pdm install
CMD ["pdm", "run", "pocket-tts", "serve", "--host", "0.0.0.0", "--port", "8000"]