# Suite de Pipelines DevSecOps

![Azure DevOps](https://img.shields.io/badge/Azure_DevOps-Pipelines-0089D6?logo=azure-devops)
![Jenkins](https://img.shields.io/badge/Jenkins-CI/CD-D24939?logo=jenkins)
![OPA](https://img.shields.io/badge/OPA-Policy_as_Code-7B42BC)
![Falco](https://img.shields.io/badge/Falco-Runtime_Security-00ACD7)
![Trivy](https://img.shields.io/badge/Trivy-Container_Scan-1904DA)
![Istio](https://img.shields.io/badge/Istio-Zero_Trust-466BB0?logo=istio)
![Licença](https://img.shields.io/badge/Licença-MIT-green)

> Suite completa de **CI/CD com segurança integrada** para ambientes enterprise. Combina Azure DevOps e Jenkins com varredura SAST, SCA, DAST, análise de container, políticas OPA e segurança Zero Trust com Istio — tudo como código.

---

## Camadas de Segurança

| Camada | Ferramenta | Estágio do Pipeline | Portão de Bloqueio |
|--------|-----------|---------------------|--------------------|
| Detecção de segredos | Gitleaks / detect-secrets | Build | Sim — bloqueia commit |
| SAST | SonarQube + Bandit | Após build | Sim — quality gate |
| SCA | OWASP Dependency Check + pip-audit | Após SAST | Sim — CVE crítica |
| Container lint | Hadolint | Build do container | Sim |
| Varredura de imagem | Trivy (CVE + config) | Após build | Sim — HIGH/CRITICAL |
| Varredura IaC | Checkov + tfsec | Paralelo ao container | Aviso |
| DAST | OWASP ZAP API Scan | Pós-deploy dev | Relatório |
| Políticas K8s | OPA Rego | Pré-deploy | Sim — bloqueia deploy |
| Runtime | Falco custom rules | Em produção | Alerta |
| mTLS | Istio STRICT | Mesh | Sim — nega sem TLS |

---

## Estágios do Pipeline (Azure DevOps)

| Estágio | Duração | Portão de Qualidade |
|---------|---------|---------------------|
| Build + Testes | ~3 min | Cobertura ≥ 80% |
| SAST (SonarQube + OWASP) | ~8 min | Quality Gate verde |
| Build do Container | ~4 min | Hadolint + Trivy OK |
| Varredura IaC | ~2 min | Sem findings CRITICAL |
| Deploy Dev | ~2 min | Health check OK |
| DAST (OWASP ZAP) | ~5 min | Relatório gerado |
| Deploy Prod | ~3 min | Aprovação manual |

---

## Conformidade

- **SOC 2 Tipo II** — rastreabilidade de auditoria em todos os estágios
- **ISO 27001** — gestão de vulnerabilidades e controle de acesso
- **NIST Cybersecurity Framework** — Identificar, Proteger, Detectar, Responder
- **OWASP Top 10** — cobertura via SAST + SCA + DAST

---

## Estrutura do Projeto

```
devsecops-pipeline-suite/
├── azure-devops/
│   └── pipelines/
│       └── main-pipeline.yml       # Pipeline de 7 estágios com portões de segurança
├── jenkins/
│   └── Jenkinsfile                 # Pipeline declarativo com agente Kubernetes
├── security/
│   ├── opa/policies/
│   │   └── k8s-security.rego       # 10 políticas de segurança Kubernetes
│   ├── falco/rules/
│   │   └── custom-rules.yaml       # Detecção: shell em container, escalonamento, mining
│   └── zero-trust/
│       ├── network-policies/       # Deny-all por padrão + allow DNS
│       └── mtls/                   # Istio PeerAuthentication STRICT + AuthorizationPolicy
├── docker/
│   └── Dockerfile.secure           # Multi-stage: usuário não-root uid 10001, healthcheck
├── scripts/
│   └── security-scan.sh            # Varredura local: 6 etapas com saída colorida
└── .pre-commit-config.yaml         # Hooks: gitleaks, bandit, hadolint, tfsec, checkov
```

---

## Início Rápido

```bash
# Instalar hooks de pre-commit
pip install pre-commit
pre-commit install

# Executar varredura de segurança completa localmente
bash scripts/security-scan.sh

# Validar políticas OPA
opa eval --data security/opa/policies/ --input exemplo-pod.json "data.kubernetes.admission.deny"

# Build da imagem segura
docker build -f docker/Dockerfile.secure -t minha-app:segura .

# Verificar vulnerabilidades da imagem
trivy image --severity HIGH,CRITICAL minha-app:segura
```

---

## Política OPA — Exemplos de Regras

```rego
# Nega pods privilegiados
deny[msg] {
    input.spec.containers[_].securityContext.privileged == true
    msg := "Containers privilegiados são proibidos"
}

# Exige execução como não-root
deny[msg] {
    not input.spec.securityContext.runAsNonRoot == true
    msg := "Pods devem executar como não-root"
}

# Bloqueia tag :latest
deny[msg] {
    image := input.spec.containers[_].image
    endswith(image, ":latest")
    msg := sprintf("Imagem '%v' não pode usar a tag :latest", [image])
}
```

---

## Autor

**Leandro Oliveira Moraes**  
Arquiteto Sênior DevOps & Multi-Cloud | Segurança & FinOps  
Certificado: AZ-400, Fortinet NSE, Linux Foundation  
[LinkedIn](https://linkedin.com/in/leandro-oliveira-26b14768)
