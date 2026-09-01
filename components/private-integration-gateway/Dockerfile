FROM python@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df
ARG VCS_REF
ARG SOURCE_URL
ARG VERSION
LABEL org.opencontainers.image.revision=$VCS_REF \
      org.opencontainers.image.source=$SOURCE_URL \
      org.opencontainers.image.version=$VERSION
RUN apk upgrade --no-cache
RUN addgroup -g 10001 gateway && adduser -D -u 10001 -G gateway gateway && mkdir /data && chown 10001:10001 /data
WORKDIR /app
COPY gateway.py /app/gateway.py
USER 10001:10001
EXPOSE 8080
CMD ["python", "/app/gateway.py"]
