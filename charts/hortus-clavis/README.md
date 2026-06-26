# Hortus Clavis — Helm chart

Deploy the Hortus Clavis IAM app on Kubernetes. Bring your own PostgreSQL and Redis.

## Quick start

```bash
helm upgrade --install iam ./charts/hortus-clavis \
  --set postgresql.host=mydb.rds.amazonaws.com \
  --set postgresql.password=secret \
  --set redis.host=myredis.cache.amazonaws.com \
  --set secrets.jwtSecret="$(openssl rand -base64 48)"
```

## Configuration

### App image

| Parameter | Default | Description |
|---|---|---|
| `replicaCount` | `2` | Number of app replicas |
| `image.repository` | `ghcr.io/anomalyco/hortus-clavis` | Container image |
| `image.tag` | `""` | Image tag (defaults to Chart appVersion) |
| `image.pullPolicy` | `IfNotPresent` | Image pull policy |

### Secrets

Set these to connect the app to your external services.

| Parameter | Default | Description |
|---|---|---|
| `secrets.jwtSecret` | (random 64-char) | JWT signing key — **change in production** |
| `secrets.bootstrapAdminPassword` | `""` | Auto-created admin password (empty = disabled) |
| `secrets.databaseUrl` | `""` | Full database URL (overrides `postgresql.*`) |
| `secrets.redisUrl` | `""` | Full Redis URL (overrides `redis.*`) |

### PostgreSQL connection

Used when `secrets.databaseUrl` is empty.

| Parameter | Default | Description |
|---|---|---|
| `postgresql.host` | `""` | PostgreSQL hostname |
| `postgresql.port` | `5432` | PostgreSQL port |
| `postgresql.database` | `jardinero` | Database name |
| `postgresql.username` | `jardinero` | Database user |
| `postgresql.password` | `""` | Database password |

### Redis connection

Used when `secrets.redisUrl` is empty.

| Parameter | Default | Description |
|---|---|---|
| `redis.host` | `""` | Redis hostname |
| `redis.port` | `6379` | Redis port |
| `redis.password` | `""` | Redis password |
| `redis.db` | `0` | Redis database number |
| `redis.tls.enabled` | `false` | Enable TLS (rediss://) |

### Application config

| Parameter | Default | Description |
|---|---|---|
| `config.debug` | `false` | SQLAlchemy echo + verbose logging |
| `config.jwtExpiration` | `7200` | Token TTL in seconds |
| `config.bootstrapAdminEmail` | `""` | Auto-create admin on startup (empty = disabled) |
| `config.logLevel` | `info` | Log level |

### Scaling

| Parameter | Default | Description |
|---|---|---|
| `autoscaling.enabled` | `false` | Enable HPA |
| `autoscaling.minReplicas` | `1` | Minimum pods |
| `autoscaling.maxReplicas` | `10` | Maximum pods |
| `autoscaling.targetCPUUtilizationPercentage` | `80` | CPU target |

### Networking

| Parameter | Default | Description |
|---|---|---|
| `service.type` | `ClusterIP` | Kubernetes service type |
| `service.port` | `8000` | Container + service port |
| `ingress.enabled` | `false` | Enable ingress |
| `ingress.className` | `""` | Ingress class name |

### Resources

| Parameter | Default | Description |
|---|---|---|
| `resources.requests.cpu` | `250m` | CPU request |
| `resources.requests.memory` | `256Mi` | Memory request |
| `resources.limits.cpu` | `500m` | CPU limit |
| `resources.limits.memory` | `512Mi` | Memory limit |

### Availability

| Parameter | Default | Description |
|---|---|---|
| `pdb.enabled` | `false` | Enable PodDisruptionBudget |
| `pdb.minAvailable` | `1` | Minimum available pods |

### Security

| Parameter | Default | Description |
|---|---|---|
| `podSecurityContext.fsGroup` | `1000` | Pod fsGroup |
| `securityContext.runAsUser` | `1000` | Container user |
| `securityContext.runAsNonRoot` | `true` | Enforce non-root |
| `serviceAccount.create` | `true` | Create service account |

## Production example

```bash
helm upgrade --install iam ./charts/hortus-clavis \
  --namespace iam --create-namespace \
  --set postgresql.host=prod-db.internal \
  --set postgresql.password=$(aws secretsmanager get-secret-value --secret-id prod/db/password --query SecretString --output text) \
  --set redis.host=prod-redis.internal \
  --set secrets.jwtSecret=$(openssl rand -base64 48) \
  --set secrets.bootstrapAdminPassword=$(openssl rand -base64 24) \
  --set config.jwtExpiration=3600 \
  --set resources.requests.cpu=500m \
  --set resources.requests.memory=512Mi \
  --set autoscaling.enabled=true \
  --set autoscaling.minReplicas=2 \
  --set autoscaling.maxReplicas=20 \
  --set ingress.enabled=true \
  --set ingress.className=nginx \
  --set-string ingress.annotations."cert-manager\.io/cluster-issuer"=letsencrypt-prod \
  --set ingress.hosts[0].host=iam.example.com \
  --set ingress.tls[0].hosts[0]=iam.example.com \
  --set ingress.tls[0].secretName=iam-tls
```

## Local dev example

```bash
# Start PG and Redis however you like
docker run -d --name pg -e POSTGRES_PASSWORD=devpass -p 5432:5432 postgres:16-alpine
docker run -d --name redis -p 6379:6379 redis:7-alpine

# Deploy the app
helm upgrade --install iam ./charts/hortus-clavis \
  --set postgresql.host=host.docker.internal \
  --set postgresql.password=devpass \
  --set redis.host=host.docker.internal \
  --set secrets.jwtSecret=dev-secret-change-in-production
```

## Architecture

```
                    ┌──────────────┐
                    │   Ingress    │
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │   Service    │
                    │   :8000      │
                    └──────┬───────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
        ┌─────▼─────┐ ┌───▼───┐ ┌───▼───┐
        │  iam v1    │ │  v2   │ │  v3   │
        │  :8000     │ │       │ │       │
        └─────┬─────┘ └───────┘ └───────┘
              │
     ┌────────┼────────┐
     │        │        │
  ┌──▼──┐  ┌─▼──┐  ┌──▼──┐
  │ PG  │  │Redis│  │Loki │     ← you bring these
  └─────┘  └─────┘  └─────┘
```

Each pod runs:
1. **Init container**: `alembic upgrade head` — applies DB migrations before the app starts.
2. **Main container**: uvicorn serving the FastAPI app — stateless, horizontally scalable.

Health is checked via `GET /health`. The app is ready as soon as the bootstrap completes.
