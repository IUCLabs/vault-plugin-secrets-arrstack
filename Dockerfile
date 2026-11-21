FROM scratch
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/vault-plugin-secrets-arrstack /vault-plugin-secrets-arrstack
ENTRYPOINT ["/vault-plugin-secrets-arrstack"]
