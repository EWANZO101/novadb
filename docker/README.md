# Build/test container
Nothing is stored on the host: each run clones the repo fresh inside a throw-away container (`--rm`).
Resource-capped so it can't starve the FiveM server on the same VPS.

    # build image (once / when Dockerfile changes)
    docker build -t novadb-builder docker/
    # run full test suite against main (or NOVADB_REF=branch)
    docker run --rm --cpus 2 --memory 3g --pids-limit 512 --security-opt no-new-privileges \
      -e GH_TOKEN="$(gh auth token)" -e FUZZ_SECS=60 novadb-builder

GH_TOKEN is passed at run time only, never baked into the image.
Cluster tests (Stage 8) will use a compose file with 3 nodes on an internal network.
