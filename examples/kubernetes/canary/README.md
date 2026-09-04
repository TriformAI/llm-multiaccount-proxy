# Isolated Kubernetes canary

This Kustomize package is an inert-by-default release-candidate surface. It is
deliberately separate from any legacy Claudeproxy workload:

- names, labels, ServiceAccount, Service, PVC, PDB, and ConfigMap are scoped to
  `llmap-canary`;
- there is no Ingress, LoadBalancer, populated Secret, or production selector;
- client authentication starts in `observe`, and the forward proxy is off;
- a default-deny NetworkPolicy is paired with explicit client, DNS, provider,
  and residential-proxy egress rules;
- `llmap-canary-route` selects `traffic: disabled`, so it has zero endpoints
  until the reviewed active overlay is reconciled.

## Prepare a private GitOps overlay

Do not apply this public example directly. Copy it into the environment's
GitOps repository and review these environment-owned inputs:

1. Set a dedicated namespace that does not host the Python production or
   staging proxy.
2. Replace the all-zero image digest with the exact RC image digest. Do not use
   a mutable tag.
3. Have the external secret controller create `llmap-canary-secrets` with
   `LLMAP_MASTER_KEY` and `LLMAP_ADMIN_PASSWORD`. The master key remains
   separate from database backups.
4. Narrow the egress CIDRs and ports to the configured providers and
   residential proxy endpoints where the CNI supports it.
5. Label only the synthetic-client namespace with
   `llmap-canary-client: "true"`.
6. Render and inspect all three states before committing them to GitOps:

   ```bash
   kubectl kustomize examples/kubernetes/canary/base
   kubectl kustomize examples/kubernetes/canary/overlays/active
   kubectl kustomize examples/kubernetes/canary/overlays/rollback
   ```

The base state is suitable for pod-local health, restore, and synthetic tests.
The headless Service supports StatefulSet identity but is not a caller route.

## Activate and roll back

Activation is a Git commit changing the reconciled path from `base` to
`overlays/active`. The only activation patch changes
`llmap-canary-route` from the impossible `traffic: disabled` selector to the
canary pod's `traffic: candidate` label.

Rollback changes the reconciled path to `overlays/rollback`. That patch returns
the Service selector to `traffic: disabled`; it does not mutate credentials,
the SQLite volume, or the legacy proxy. Verify the Service has zero endpoints
before diagnosing or removing the canary.

Routing real callers, importing real provider credentials, enabling the
forward proxy, or changing `observe` to `enforce` are separate, approval-gated
operations. Record the Git revision, rendered-manifest hash, image digest,
configuration hash, synthetic evidence artifact, activation/rollback times,
and observed endpoints in the release issue.
