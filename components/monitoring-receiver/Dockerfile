FROM python:3.12.13-slim-bookworm@sha256:4766d8b510c428e595d74b9cc5bbb2fae8e26316fffb4adc89908d79aacd58a2
ARG VCS_REF
ARG SOURCE_URL
ARG VERSION
LABEL org.opencontainers.image.revision=$VCS_REF \
      org.opencontainers.image.source=$SOURCE_URL \
      org.opencontainers.image.version=$VERSION
RUN pip install --no-cache-dir fastapi==0.141.1 starlette==1.6.0 uvicorn==0.52.4
WORKDIR /app
COPY app.py /app/app.py
USER 65532:65532
CMD ["uvicorn","app:app","--host","0.0.0.0","--port","8080","--no-access-log"]
