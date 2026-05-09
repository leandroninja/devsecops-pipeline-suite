package kubernetes.security

import future.keywords.in
import future.keywords.every

# ─────────────────────────────────────────────
# Deny privileged containers
# ─────────────────────────────────────────────
deny[msg] {
    input.kind in {"Pod", "Deployment", "DaemonSet", "StatefulSet"}
    container := get_containers(input)[_]
    container.securityContext.privileged == true
    msg := sprintf("Container '%v' must not run as privileged", [container.name])
}

# ─────────────────────────────────────────────
# Require non-root user
# ─────────────────────────────────────────────
deny[msg] {
    input.kind in {"Pod", "Deployment", "DaemonSet", "StatefulSet"}
    container := get_containers(input)[_]
    not container.securityContext.runAsNonRoot == true
    not container.securityContext.runAsUser > 0
    msg := sprintf("Container '%v' must not run as root (set runAsNonRoot: true or runAsUser > 0)", [container.name])
}

# ─────────────────────────────────────────────
# Require read-only root filesystem
# ─────────────────────────────────────────────
deny[msg] {
    input.kind in {"Pod", "Deployment", "DaemonSet", "StatefulSet"}
    container := get_containers(input)[_]
    not container.securityContext.readOnlyRootFilesystem == true
    msg := sprintf("Container '%v' must have readOnlyRootFilesystem: true", [container.name])
}

# ─────────────────────────────────────────────
# Require resource limits
# ─────────────────────────────────────────────
deny[msg] {
    input.kind in {"Pod", "Deployment", "DaemonSet", "StatefulSet"}
    container := get_containers(input)[_]
    not container.resources.limits.memory
    msg := sprintf("Container '%v' must define resources.limits.memory", [container.name])
}

deny[msg] {
    input.kind in {"Pod", "Deployment", "DaemonSet", "StatefulSet"}
    container := get_containers(input)[_]
    not container.resources.limits.cpu
    msg := sprintf("Container '%v' must define resources.limits.cpu", [container.name])
}

# ─────────────────────────────────────────────
# Deny latest tag
# ─────────────────────────────────────────────
deny[msg] {
    input.kind in {"Pod", "Deployment", "DaemonSet", "StatefulSet"}
    container := get_containers(input)[_]
    endswith(container.image, ":latest")
    msg := sprintf("Container '%v' must not use ':latest' image tag", [container.name])
}

deny[msg] {
    input.kind in {"Pod", "Deployment", "DaemonSet", "StatefulSet"}
    container := get_containers(input)[_]
    not contains(container.image, ":")
    msg := sprintf("Container '%v' must specify an explicit image tag", [container.name])
}

# ─────────────────────────────────────────────
# Require required labels
# ─────────────────────────────────────────────
required_labels := {"app", "version", "component", "owner"}

deny[msg] {
    input.kind in {"Deployment", "StatefulSet", "DaemonSet"}
    missing := required_labels - {label | input.metadata.labels[label]}
    count(missing) > 0
    msg := sprintf("Missing required labels: %v", [missing])
}

# ─────────────────────────────────────────────
# Deny host namespace sharing
# ─────────────────────────────────────────────
deny[msg] {
    input.kind == "Pod"
    input.spec.hostNetwork == true
    msg := "Pod must not use host network namespace"
}

deny[msg] {
    input.kind == "Pod"
    input.spec.hostPID == true
    msg := "Pod must not share host PID namespace"
}

deny[msg] {
    input.kind == "Pod"
    input.spec.hostIPC == true
    msg := "Pod must not share host IPC namespace"
}

# ─────────────────────────────────────────────
# Deny privilege escalation
# ─────────────────────────────────────────────
deny[msg] {
    input.kind in {"Pod", "Deployment", "DaemonSet", "StatefulSet"}
    container := get_containers(input)[_]
    container.securityContext.allowPrivilegeEscalation == true
    msg := sprintf("Container '%v' must set allowPrivilegeEscalation: false", [container.name])
}

# ─────────────────────────────────────────────
# Require drop ALL capabilities
# ─────────────────────────────────────────────
deny[msg] {
    input.kind in {"Pod", "Deployment", "DaemonSet", "StatefulSet"}
    container := get_containers(input)[_]
    not "ALL" in container.securityContext.capabilities.drop
    msg := sprintf("Container '%v' must drop ALL capabilities", [container.name])
}

# ─────────────────────────────────────────────
# Deny NodePort services (use Ingress instead)
# ─────────────────────────────────────────────
deny[msg] {
    input.kind == "Service"
    input.spec.type == "NodePort"
    msg := "NodePort services are not allowed; use ClusterIP with Ingress"
}

# ─────────────────────────────────────────────
# Deny LoadBalancer with no annotations (require internal)
# ─────────────────────────────────────────────
deny[msg] {
    input.kind == "Service"
    input.spec.type == "LoadBalancer"
    not input.metadata.annotations["service.beta.kubernetes.io/azure-load-balancer-internal"]
    not input.metadata.annotations["service.beta.kubernetes.io/aws-load-balancer-internal"]
    msg := "LoadBalancer services must be internal; add the internal annotation"
}

# ─────────────────────────────────────────────
# Helper functions
# ─────────────────────────────────────────────
get_containers(obj) = containers {
    obj.kind == "Pod"
    containers := obj.spec.containers
} else = containers {
    containers := obj.spec.template.spec.containers
}
