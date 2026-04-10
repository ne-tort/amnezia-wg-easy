FROM nginx:alpine
# Alpine apk иногда падает из-за временных проблем с загрузкой индексов.
# Добавляем небольшой retry, чтобы build был стабильнее.
RUN for i in 1 2 3 4 5; do \
  apk add --no-cache openssl && break; \
  echo "[nginx] apk add openssl failed, retry $i/5..." >&2; \
  sleep 2; \
done
COPY panel-legacy.conf.template panel-subpath.conf.template site-exit.conf.template /etc/nginx/conf.d/
COPY entrypoint.sh /entrypoint.sh
RUN sed -i 's/\r$//' /entrypoint.sh /etc/nginx/conf.d/*.template && chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
