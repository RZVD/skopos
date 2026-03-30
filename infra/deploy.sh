#!/usr/bin/env bash

main() {
    # EKS stack infra
    kubectl create -f https://download.elastic.co/downloads/eck/2.13.0/crds.yaml
    kubectl apply -f https://download.elastic.co/downloads/eck/2.13.0/operator.yaml

    kubectl apply -f ./kibana.yaml
    kubectl apply -f ./elastic.yaml

}

main "$@"
