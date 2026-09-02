# VIndex SumDB Personality Docker Compose Bundle

This deployment bundle runs a fully functional, self-contained **Verifiable Index (VIndex) personality for the Go Checksum Database (SumDB)**, complete with upstream proxying, WASM MapFn execution, Caddy gateway routing, Prometheus metrics, and a pre-provisioned Grafana dashboard.

## Quickstart

### 1. Launch the Stack
```bash
cd deploy/sumdb
docker compose up -d --build
```

### 2. Service Endpoints (via Gateway Port `8080`)

| Service / Path | URL | Description |
| :--- | :--- | :--- |
| **VIndex Web UI** | `http://localhost:8080/` | Interactive single-page UI for searching modules and exploring log tree state. |
| **Output Log Checkpoint** | `http://localhost:8080/checkpoint` | Current signed tree head for `sumdb.vindex.local`. |
| **Index Lookup** | `http://localhost:8080/index/<key-hash>` | Verifiable inclusion / non-inclusion proofs for module search keys. |
| **SumDB Proxy** | `http://localhost:8080/sumdb/` | Proxied `sum.golang.org` tiles and checkpoints. |
| **Grafana Dashboards** | `http://localhost:8080/grafana/` | Pre-built dashboard (Login: `admin` / `admin`). |

---

## Verifying & Querying the Deployed Index

Use [`sumdbverify`](../../vindex/v1/cmd/sumdbverify) to cryptographically verify queries against the running index:

```bash
# Query a canonical Go module path through the Caddy gateway
go run ./vindex/v1/cmd/sumdbverify \
  --vindex_url="http://localhost:8080" \
  --origin="sumdb.vindex.local" \
  --pubkey="sumdb.vindex.local+9a36b0c7+ASYC8f2R5P54YfkLLnPTWGuizJ97M+8lclIrqqI60nrU" \
  golang.org/x/mod
```

---

## Teardown

To stop all containers and remove persistent volumes:
```bash
docker compose down -v
```
