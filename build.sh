#!/usr/bin/env bash

CLUSTER_NAME="dev-cluster"

build() {
    cargo build --config 'target."cfg(all())".runner="sudo -E"' --target x86_64-unknown-linux-musl
}

copy-binary() {
    docker cp ./target/x86_64-unknown-linux-musl/debug/skopos "k3d-${CLUSTER_NAME}-server-0:/tmp/skopos"
}

enable-tracefs() {

    NODE_NAME="k3d-${CLUSTER_NAME}-server-0"
    NODE_CONTAINER_ID=$(docker inspect k3d-dev-cluster-server-0 --format '{{ .Id }}')
    docker exec ${NODE_CONTAINER_ID} mount -t tracefs nodev /sys/kernel/tracing
}


main() {
    build
    copy-binary
    enable-tracefs

    # export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
}

main "$@"
