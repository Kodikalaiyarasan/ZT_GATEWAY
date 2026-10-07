FROM alpine:3.20

# Install OPA binary and wget (for healthchecks)
RUN apk add --no-cache wget ca-certificates \
    && wget -q -O /usr/local/bin/opa \
       "https://openpolicyagent.org/downloads/v0.64.1/opa_linux_amd64_static" \
    && chmod 755 /usr/local/bin/opa

COPY policy.rego /policies/policy.rego

EXPOSE 8181
ENTRYPOINT ["opa"]
CMD ["run", "--server", "--addr=0.0.0.0:8181", "--log-level=info", "/policies/policy.rego"]
