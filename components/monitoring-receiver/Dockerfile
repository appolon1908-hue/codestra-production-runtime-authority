FROM python:3.12.11-slim-bookworm
ARG VCS_REF
ARG SOURCE_URL
ARG VERSION
LABEL org.opencontainers.image.revision=$VCS_REF \
      org.opencontainers.image.source=$SOURCE_URL \
      org.opencontainers.image.version=$VERSION
RUN pip install --no-cache-dir fastapi==0.116.1 uvicorn==0.35.0
WORKDIR /app
COPY app.py /app/app.py
USER 65532:65532
CMD ["uvicorn","app:app","--host","0.0.0.0","--port","8080","--no-access-log"]
