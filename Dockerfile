FROM python:3.12-slim AS builder

WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY rules ./rules
COPY config ./config
RUN python -m pip install --no-cache-dir build==1.2.2.post1 \
    && python -m build --wheel

FROM python:3.12-slim

RUN useradd --create-home --uid 10001 controlforge
WORKDIR /app
COPY --from=builder /build/dist/*.whl /tmp/
RUN python -m pip install --no-cache-dir /tmp/*.whl \
    && rm -f /tmp/*.whl
USER controlforge
EXPOSE 8080
ENTRYPOINT ["uvicorn", "controlforge.api:app", "--host", "0.0.0.0", "--port", "8080"]
