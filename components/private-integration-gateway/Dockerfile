FROM python:3.12.13-alpine3.24
ARG VCS_REF
ARG SOURCE_URL
ARG VERSION
LABEL org.opencontainers.image.revision=$VCS_REF \
      org.opencontainers.image.source=$SOURCE_URL \
      org.opencontainers.image.version=$VERSION
RUN addgroup -g 10001 gateway && adduser -D -u 10001 -G gateway gateway && mkdir /data && chown 10001:10001 /data
WORKDIR /app
COPY gateway.py /app/gateway.py
USER 10001:10001
EXPOSE 8080
CMD ["python", "/app/gateway.py"]
