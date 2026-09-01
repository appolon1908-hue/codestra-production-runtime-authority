FROM python:3.12-alpine
ARG VCS_REF
ARG SOURCE_URL
ARG VERSION
LABEL org.opencontainers.image.revision=$VCS_REF \
      org.opencontainers.image.source=$SOURCE_URL \
      org.opencontainers.image.version=$VERSION
WORKDIR /app
COPY adapter.py /app/adapter.py
ENTRYPOINT ["python", "/app/adapter.py"]
