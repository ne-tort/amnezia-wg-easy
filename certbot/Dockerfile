# Certbot with Docker CLI for deploy-hook (nginx reload). Uses env PANEL_DOMAIN, CERTBOT_EMAIL.
FROM certbot/certbot:v2.8.0
COPY --from=docker:24-cli /usr/local/bin/docker /usr/local/bin/docker
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
