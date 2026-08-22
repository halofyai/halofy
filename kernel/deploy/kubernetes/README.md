# Kubernetes deployment

This is the supported multi-replica production shape. Provide a managed
Postgres/pgvector `DATABASE_URL`, an RWX encrypted volume for `/app/knowledge`,
and create `halomem-secrets` out of band with keys `database-url`,
`bootstrap-token`, `signing-key`, `cold-kek`, and `source-config-kek`.

Do not commit a Secret manifest. Use an external-secrets operator or your cloud
secret manager. Replace the example image tag and public URL with immutable,
environment-specific values before applying:

```sh
kubectl apply -k deploy/kubernetes
kubectl rollout status deployment/halomem-kernel
```

The kernel deliberately refuses Vercel/Lambda-style ephemeral serverless boot.
Those runtimes cannot preserve cold filesystem, timers, or replica-safe state.
