#!/usr/bin/env bash
# Script local de varredura de segurança — executa todas as verificações antes do push
set -euo pipefail

REPORT_DIR="./security-reports"
mkdir -p "$REPORT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; FAILED=1; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

FAILED=0

echo "======================================================="
echo "   DevSecOps Security Scan Suite"
echo "======================================================="
echo ""

# 1. Detecção de segredos
echo "─── [1/6] Secret Detection (Gitleaks) ───"
if command -v gitleaks &>/dev/null; then
    if gitleaks detect --source . --report-format json \
        --report-path "$REPORT_DIR/gitleaks.json" --exit-code 1 2>/dev/null; then
        pass "No secrets detected"
    else
        fail "Secrets detected! Check $REPORT_DIR/gitleaks.json"
    fi
else
    warn "gitleaks not installed (brew install gitleaks)"
fi

# 2. SAST com bandit (Python)
echo "─── [2/6] SAST - Bandit (Python) ───"
if command -v bandit &>/dev/null; then
    if bandit -r src/ -ll -f json -o "$REPORT_DIR/bandit.json" 2>/dev/null; then
        pass "Bandit SAST passed"
    else
        HIGH=$(python3 -c "import json; r=json.load(open('$REPORT_DIR/bandit.json')); print(len([x for x in r['results'] if x['issue_severity']=='HIGH']))" 2>/dev/null || echo "?")
        fail "Bandit found HIGH severity issues: $HIGH"
    fi
else
    warn "bandit not installed (pip install bandit)"
fi

# 3. Verificação de vulnerabilidades em dependências
echo "─── [3/6] SCA - Dependency Vulnerabilities ───"
if command -v safety &>/dev/null; then
    if safety check --json --output "$REPORT_DIR/safety.json" 2>/dev/null; then
        pass "No known vulnerabilities in dependencies"
    else
        fail "Vulnerable dependencies found! Check $REPORT_DIR/safety.json"
    fi
elif command -v pip-audit &>/dev/null; then
    if pip-audit --format json --output "$REPORT_DIR/pip-audit.json" 2>/dev/null; then
        pass "pip-audit: no vulnerabilities"
    else
        fail "pip-audit found vulnerabilities"
    fi
else
    warn "safety/pip-audit not installed"
fi

# 4. Linting do Dockerfile
echo "─── [4/6] Dockerfile Security (Hadolint) ───"
if command -v hadolint &>/dev/null; then
    if hadolint docker/Dockerfile.secure --failure-threshold warning 2>/dev/null; then
        pass "Dockerfile follows best practices"
    else
        fail "Dockerfile has security issues"
    fi
else
    warn "hadolint not installed (brew install hadolint)"
fi

# 5. Varredura de IaC
echo "─── [5/6] IaC Security (Checkov + tfsec) ───"
if command -v checkov &>/dev/null; then
    if checkov -d . --framework terraform,kubernetes --compact \
        --hard-fail-on HIGH,CRITICAL --quiet 2>/dev/null; then
        pass "Checkov IaC scan passed"
    else
        fail "Checkov found HIGH/CRITICAL IaC issues"
    fi
else
    warn "checkov not installed (pip install checkov)"
fi

if command -v tfsec &>/dev/null; then
    if tfsec . --minimum-severity HIGH --no-color 2>/dev/null; then
        pass "tfsec scan passed"
    else
        fail "tfsec found HIGH severity issues"
    fi
else
    warn "tfsec not installed"
fi

# 6. Varredura de imagem de container (se a imagem existir)
echo "─── [6/6] Container Image Scan (Trivy) ───"
IMAGE_NAME=$(basename "$PWD"):latest
if command -v trivy &>/dev/null; then
    if docker image inspect "$IMAGE_NAME" &>/dev/null; then
        if trivy image --exit-code 1 --severity CRITICAL,HIGH \
            --format json --output "$REPORT_DIR/trivy.json" \
            "$IMAGE_NAME" 2>/dev/null; then
            pass "Trivy: no CRITICAL/HIGH CVEs in image"
        else
            fail "Trivy found CRITICAL/HIGH CVEs in image"
        fi
    else
        warn "Image $IMAGE_NAME not found locally — build first with: docker build -f docker/Dockerfile.secure -t $IMAGE_NAME ."
    fi
else
    warn "trivy not installed"
fi

echo ""
echo "======================================================="
if [ "$FAILED" -eq 0 ]; then
    echo -e "${GREEN}All security checks passed! ✓${NC}"
    echo "Reports saved to: $REPORT_DIR/"
else
    echo -e "${RED}Security checks FAILED. Fix issues before pushing. ✗${NC}"
    echo "Reports saved to: $REPORT_DIR/"
    exit 1
fi
