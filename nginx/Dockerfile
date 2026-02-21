FROM nginx:alpine
RUN apk add --no-cache openssl
COPY panel.conf.template /etc/nginx/conf.d/panel.conf.template
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
