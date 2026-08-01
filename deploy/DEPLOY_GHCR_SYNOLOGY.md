# Synology Container Manager image deployment

This deployment path keeps Synology on a Compose/YAML workflow. GitHub builds
the application image; Synology only pulls and recreates the project. Runtime
state, reports, configuration, and secrets remain outside the image.

## 1. Publish an image

Pushing `main` runs `.github/workflows/publish-container.yml` and publishes:

```text
ghcr.io/sagesang/ipquality-node-health:latest
ghcr.io/sagesang/ipquality-node-health:sha-<commit>
```

A tag such as `v0.2.0` additionally publishes `0.2.0` and `0.2`. Keep the GHCR
package public for the simplest Synology pull. For a private package, configure
the `ghcr.io` registry in Container Manager with a GitHub token that has
`read:packages`.

## 2. Prepare persistent files once

Create these paths on Synology:

```text
/volume1/docker/YOUR_PROJECT_DIR/
├── config/
│   ├── config.yaml
│   └── mihomo-bootstrap.yaml
├── data/
├── reports/
└── project/
    ├── compose.yaml
    └── .env
```

Copy `deploy/config/config.example.yaml` to `config/config.yaml`, copy
`deploy/mihomo/bootstrap.yaml` to `config/mihomo-bootstrap.yaml`, and copy
`deploy/compose.synology.yaml` to `project/compose.yaml`. Put a private copy of
`deploy/.env.example` at `project/.env` and set at least:

```dotenv
NODE_HEALTH_API_TOKEN=<long-random-secret>
SUB_STORE_INVENTORY_URL=http://192.0.2.2:3001/download/collection/inventory?target=ClashMeta&noCache=true
LOCAL_SOCKS_ADVERTISE_HOST=<OpenWrt-LAN-IP>
NODE_HEALTH_IMAGE=ghcr.io/sagesang/ipquality-node-health:latest
```

Do not commit `.env`, subscription credentials, `data`, or `reports`.

## 3. Create the Container Manager project

Create a Project using `/volume1/docker/YOUR_PROJECT_DIR/project` as its
path and the supplied Compose YAML. The first deployment pulls both images and
creates the private `ipquality-node-health` Docker network.

Verify after startup:

```text
http://192.0.2.2:18887/healthz
```

## 4. Update and roll back

For convenient updates, keep the image at `latest` and use Container Manager's
project rebuild/redeploy action. `pull_policy: always` makes the recreation pull
the current image.

For controlled production updates, pin a release instead:

```dotenv
NODE_HEALTH_IMAGE=ghcr.io/sagesang/ipquality-node-health:0.2.0
```

Change that one value and redeploy the project. Rollback is the same operation
with the previous tag. The bind-mounted `data`, `reports`, and configuration
directories survive image replacement.

If a DSM release does not honor `pull_policy` from its UI, the equivalent
fallback in the project directory is:

```bash
docker compose pull
docker compose up -d
```

Do not enable unattended Watchtower updates initially. A version can change
ranking policy or persisted-state contracts; publish a release, run tests, and
then advance the pinned image tag.
