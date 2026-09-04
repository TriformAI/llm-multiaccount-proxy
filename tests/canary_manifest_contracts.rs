const BASE_KUSTOMIZATION: &str =
    include_str!("../examples/kubernetes/canary/base/kustomization.yaml");
const CONFIG: &str = include_str!("../examples/kubernetes/canary/base/configmap.yaml");
const WORKLOAD: &str = include_str!("../examples/kubernetes/canary/base/statefulset.yaml");
const SERVICES: &str = include_str!("../examples/kubernetes/canary/base/services.yaml");
const POLICY: &str = include_str!("../examples/kubernetes/canary/base/networkpolicy.yaml");
const ACTIVE: &str =
    include_str!("../examples/kubernetes/canary/overlays/active/service-selector-patch.yaml");
const ROLLBACK: &str =
    include_str!("../examples/kubernetes/canary/overlays/rollback/service-selector-patch.yaml");
const EVIDENCE_RUNNER: &str = include_str!("../scripts/rc1-evidence");
const FORGEJO_CI: &str = include_str!("../.forgejo/workflows/ci.yml");
const GITHUB_CI: &str = include_str!("../.github/workflows/ci.yml");

#[test]
fn canary_is_isolated_private_and_inert_by_default() {
    let base = [BASE_KUSTOMIZATION, CONFIG, WORKLOAD, SERVICES, POLICY].join("\n");

    assert!(BASE_KUSTOMIZATION.contains("serviceaccount.yaml"));
    assert!(BASE_KUSTOMIZATION.contains("poddisruptionbudget.yaml"));
    assert!(!base.contains("kind: Ingress"));
    assert!(!base.contains("kind: Secret"));
    assert!(CONFIG.contains("mode = \"observe\""));
    assert!(CONFIG.contains("enabled = false"));
    assert!(WORKLOAD.contains("name: llmap-canary-secrets"));
    assert!(WORKLOAD.contains("terminationGracePeriodSeconds: 30"));
    assert!(WORKLOAD.contains("readOnlyRootFilesystem: true"));
    assert!(WORKLOAD.contains("runAsNonRoot: true"));
    assert!(WORKLOAD.contains("volumeClaimTemplates:"));
    assert!(
        WORKLOAD
            .contains("@sha256:0000000000000000000000000000000000000000000000000000000000000000")
    );
    assert!(SERVICES.contains("name: llmap-canary-route"));
    assert!(SERVICES.contains("rollout.llmap.dev/traffic: disabled"));
    assert!(POLICY.contains("name: llmap-canary-default-deny"));
    assert!(POLICY.contains("ingress: []"));
    assert!(POLICY.contains("egress: []"));
    assert!(POLICY.contains("llmap-canary-client: \"true\""));
}

#[test]
fn canary_activation_and_rollback_change_only_the_route_selector() {
    for overlay in [ACTIVE, ROLLBACK] {
        assert!(overlay.contains("kind: Service"));
        assert!(overlay.contains("name: llmap-canary-route"));
        assert!(!overlay.contains("image:"));
        assert!(!overlay.contains("kind: StatefulSet"));
        assert!(!overlay.contains("kind: Secret"));
        assert!(!overlay.contains("kind: Ingress"));
    }
    assert!(ACTIVE.contains("rollout.llmap.dev/traffic: candidate"));
    assert!(ROLLBACK.contains("rollout.llmap.dev/traffic: disabled"));
}

#[test]
fn both_authoritative_hosts_publish_the_same_metadata_only_evidence_bundle() {
    assert!(EVIDENCE_RUNNER.contains("cargo test --locked --all-features"));
    assert!(EVIDENCE_RUNNER.contains("synthetic_fault_matrix"));
    assert!(EVIDENCE_RUNNER.contains("restore_and_plaintext_scan"));
    assert!(EVIDENCE_RUNNER.contains("live_provider_requests_not_exercised"));
    assert!(!EVIDENCE_RUNNER.contains("set -x"));
    for workflow in [FORGEJO_CI, GITHUB_CI] {
        assert!(workflow.contains("./scripts/rc1-evidence"));
        assert!(workflow.contains("upload-artifact"));
        assert!(workflow.contains("if: always()"));
    }
}
