FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
RUN useradd --create-home --uid 10001 agent
WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY dashboard ./dashboard
RUN pip install ".[dashboard]"

USER agent
# /data : répertoires à protéger (volume)   /config : policy.yaml (lecture seule)   /state : journal d'audit
VOLUME ["/data", "/state"]
ENTRYPOINT ["cryptagent", "-p", "/config/policy.yaml"]
CMD ["watch"]
