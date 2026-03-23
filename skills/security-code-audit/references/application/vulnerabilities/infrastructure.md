# Infrastructure As Code

Use this module for C12 when Docker, compose, Kubernetes, Helm, Terraform, or cloud manifests exist.

## What To Audit

- containers running as root or privileged
- writable host mounts, docker socket exposure, or broad capabilities
- images pinned to mutable tags instead of digests when immutability matters
- secrets embedded in Dockerfiles, manifests, values files, or Terraform
- public buckets, open security groups, or wildcard IAM policies
- missing network segmentation, resource limits, or security context controls
- unsafe ingress, service, or load balancer exposure
- state files, plan outputs, or artifact bundles containing secrets

## High-Risk Patterns

- `USER root`
- `privileged: true`
- `hostNetwork: true`
- `docker.sock`
- `0.0.0.0/0`
- `*` IAM actions or resources without tight scope
- inline credentials in `ENV`, Helm values, or Terraform variables
- unauthenticated dashboards, admin ports, or metrics endpoints exposed externally

## Audit Method

1. Inventory Docker, compose, k8s, Helm, Terraform, and CI deployment files.
2. Check runtime identity, capability, mount, network, and secret handling controls.
3. Review cloud access scope, public exposure, and data protection defaults.
4. Verify staging or dev defaults do not silently flow into production manifests.
5. Cross-check IaC findings with app-layer findings for compound risk.

## Grep Starters

- `FROM`
- `USER`
- `privileged`
- `hostPath`
- `docker.sock`
- `CAP_`
- `0.0.0.0/0`
- `s3:*`
- `AdministratorAccess`
- `secretKeyRef`
- `value:`

## Safe Patterns

- non-root containers with minimal capabilities
- pinned images and trusted registries
- secrets from dedicated secret stores, not inline values
- least-privilege IAM and restricted network policy
- explicit resource limits, probes, and security contexts
