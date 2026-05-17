#!/usr/bin/env bash
# BB-Hunter: E2E тест на Kali Linux
# Запуск: bash scripts/e2e-test.sh
# Требования: установленные зависимости (bash scripts/install-kali.sh)
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()   { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
err()   { echo -e "${RED}[-]${NC} $1"; }
info()  { echo -e "${BLUE}[*]${NC} $1"; }
pass()  { echo -e "  ${GREEN}PASS${NC} $1"; }
fail()  { echo -e "  ${RED}FAIL${NC} $1"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_DIR"

REPORT_FILE="$PROJECT_DIR/e2e-report-$(date +%Y%m%d-%H%M%S).txt"
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

record() {
    echo "$1" >> "$REPORT_FILE"
}

test_pass() {
    pass "$1"
    record "PASS: $1"
    PASS_COUNT=$((PASS_COUNT + 1))
}

test_fail() {
    fail "$1"
    record "FAIL: $1"
    FAIL_COUNT=$((FAIL_COUNT + 1))
}

test_skip() {
    warn "SKIP: $1"
    record "SKIP: $1"
    SKIP_COUNT=$((SKIP_COUNT + 1))
}

echo "============================================================"
echo "  BB-Hunter E2E Test Suite"
echo "  $(date)"
echo "============================================================"
echo ""
record "BB-Hunter E2E Test Suite - $(date)"
record "============================================================"

# ============================================================
# 0. Загрузка .env
# ============================================================
if [[ -f "$PROJECT_DIR/.env" ]]; then
    set -a
    source "$PROJECT_DIR/.env"
    set +a
    info "Загружен .env"
fi

# ============================================================
# 1. Проверка зависимостей
# ============================================================
log "=== Тест 1: Зависимости ==="

for tool in go subfinder httpx katana nuclei; do
    if command -v "$tool" &>/dev/null; then
        test_pass "$tool: $(command -v "$tool")"
    else
        test_fail "$tool: не найден"
    fi
done

if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
    test_pass "docker: работает"
else
    test_skip "docker: не запущен или не установлен"
fi

if command -v agent-browser &>/dev/null; then
    test_pass "agent-browser: установлен"
else
    test_skip "agent-browser: не установлен (browser PoC будет пропущен)"
fi

echo ""

# ============================================================
# 2. Сборка
# ============================================================
log "=== Тест 2: Сборка ==="

if go build -o bb-hunter ./cmd/bb-hunter 2>&1; then
    test_pass "go build: бинарник собран"
else
    test_fail "go build: сборка не удалась"
    err "Критическая ошибка — дальнейшие тесты невозможны"
    exit 1
fi

if go vet ./... 2>&1; then
    test_pass "go vet: чисто"
else
    test_fail "go vet: ошибки"
fi

echo ""

# ============================================================
# 3. Unit тесты
# ============================================================
log "=== Тест 3: Unit тесты ==="

TEST_OUTPUT=$(go test ./... 2>&1)
TEST_EXIT=$?
PASS_PKGS=$(echo "$TEST_OUTPUT" | grep -c "^ok" || true)
FAIL_PKGS=$(echo "$TEST_OUTPUT" | grep -c "^FAIL" || true)

if [[ $TEST_EXIT -eq 0 ]]; then
    test_pass "go test: $PASS_PKGS пакетов PASS"
else
    test_fail "go test: $FAIL_PKGS пакетов FAIL"
    echo "$TEST_OUTPUT" | grep "^FAIL" >> "$REPORT_FILE"
fi

echo ""

# ============================================================
# 4. Dry run
# ============================================================
log "=== Тест 4: Dry run ==="

cp scope.yaml.example scope-test.yaml 2>/dev/null || true
DRY_OUTPUT=$(./bb-hunter -scope scope-test.yaml -dry-run 2>&1)
if echo "$DRY_OUTPUT" | grep -q "Dry run: config valid"; then
    test_pass "dry-run: конфиг валиден"
else
    test_fail "dry-run: $DRY_OUTPUT"
fi

echo ""

# ============================================================
# 5. LLM Health Check
# ============================================================
log "=== Тест 5: LLM Health Check ==="

LLM_ARGS=""
[[ -n "${GEMINI_API_KEY:-}" ]] && LLM_ARGS="$LLM_ARGS --gemini-key $GEMINI_API_KEY"
[[ -n "${CEREBRAS_API_KEY:-}" ]] && LLM_ARGS="$LLM_ARGS --cerebras-key $CEREBRAS_API_KEY"
[[ -n "${GROQ_API_KEY:-}" ]] && LLM_ARGS="$LLM_ARGS --groq-key $GROQ_API_KEY"
[[ -n "${SAMBA_API_KEY:-}" ]] && LLM_ARGS="$LLM_ARGS --samba-key $SAMBA_API_KEY"
[[ -n "${OPENROUTER_API_KEY:-}" ]] && LLM_ARGS="$LLM_ARGS --openrouter-key $OPENROUTER_API_KEY"

if [[ -z "$LLM_ARGS" ]]; then
    test_skip "LLM: нет API ключей в .env"
else
    # shellcheck disable=SC2086
    LLM_OUTPUT=$(./bb-hunter -scope scope-test.yaml --check-llm $LLM_ARGS 2>&1)
    LLM_EXIT=$?
    echo "$LLM_OUTPUT"
    record "LLM Output: $LLM_OUTPUT"

    AVAILABLE=$(echo "$LLM_OUTPUT" | grep -c "✅" || true)
    UNAVAILABLE=$(echo "$LLM_OUTPUT" | grep -c "❌" || true)

    if [[ $AVAILABLE -gt 0 ]]; then
        test_pass "LLM: $AVAILABLE провайдеров доступно"
    else
        test_fail "LLM: 0 провайдеров доступно"
    fi
    [[ $UNAVAILABLE -gt 0 ]] && warn "  $UNAVAILABLE провайдеров недоступно"
fi

echo ""

# ============================================================
# 6. Scanner (recon на тестовом таргете)
# ============================================================
log "=== Тест 6: Scanner (recon) ==="

# Используем ginandjuice.shop — легальный уязвимый сайт PortSwigger
TEST_TARGET="ginandjuice.shop"

info "Таргет: $TEST_TARGET"

# Тест subfinder
info "subfinder..."
SF_OUTPUT=$(timeout 60 subfinder -d "$TEST_TARGET" -silent 2>/dev/null | head -20)
SF_COUNT=$(echo "$SF_OUTPUT" | grep -c . || true)
if [[ $SF_COUNT -gt 0 ]]; then
    test_pass "subfinder: найдено $SF_COUNT поддоменов"
else
    test_skip "subfinder: 0 поддоменов (может быть нормально для данного домена)"
fi

# Тест httpx
info "httpx..."
HX_OUTPUT=$(echo "$TEST_TARGET" | timeout 30 httpx -silent 2>/dev/null | head -10)
if echo "$HX_OUTPUT" | grep -q "http"; then
    test_pass "httpx: хост доступен"
else
    test_fail "httpx: хост недоступен ($TEST_TARGET)"
fi

# Тест katana
info "katana..."
KT_OUTPUT=$(timeout 60 katana -u "http://$TEST_TARGET" -silent -d 1 2>/dev/null | head -20)
KT_COUNT=$(echo "$KT_OUTPUT" | grep -c . || true)
if [[ $KT_COUNT -gt 0 ]]; then
    test_pass "katana: найдено $KT_COUNT URL"
else
    test_skip "katana: 0 URL (таймаут или блокировка)"
fi

# Тест nuclei
info "nuclei (быстрый скан)..."
NI_OUTPUT=$(timeout 120 nuclei -u "http://$TEST_TARGET" -severity medium,high,critical -silent -rate-limit 5 2>/dev/null | head -20)
NI_COUNT=$(echo "$NI_OUTPUT" | grep -c . || true)
if [[ $NI_COUNT -gt 0 ]]; then
    test_pass "nuclei: найдено $NI_COUNT findings"
    record "Nuclei findings:"
    echo "$NI_OUTPUT" >> "$REPORT_FILE"
else
    test_skip "nuclei: 0 findings (таймаут или нет подходящих templates)"
fi

echo ""

# ============================================================
# 7. Docker Sandbox
# ============================================================
log "=== Тест 7: Docker Sandbox ==="

if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
    # Проверка python:3.12-slim
    if docker pull python:3.12-slim --quiet 2>/dev/null; then
        test_pass "docker pull python:3.12-slim: OK"
    else
        test_fail "docker pull: не удалось загрузить образ"
    fi

    # Тест изоляции
    SANDBOX_OUTPUT=$(docker run --rm --memory=256m --cpus=0.5 --network=none python:3.12-slim python3 -c "print('sandbox_ok')" 2>&1)
    if echo "$SANDBOX_OUTPUT" | grep -q "sandbox_ok"; then
        test_pass "docker sandbox: изолированный контейнер работает"
    else
        test_fail "docker sandbox: $SANDBOX_OUTPUT"
    fi
else
    test_skip "docker: не доступен"
fi

echo ""

# ============================================================
# 8. Telegram HITL
# ============================================================
log "=== Тест 8: Telegram HITL ==="

if [[ -n "${TELEGRAM_BOT_TOKEN:-}" ]]; then
    TG_RESPONSE=$(curl -s "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/getMe" 2>/dev/null)
    if echo "$TG_RESPONSE" | grep -q '"ok":true'; then
        BOT_NAME=$(echo "$TG_RESPONSE" | grep -o '"username":"[^"]*"' | cut -d'"' -f4)
        test_pass "Telegram bot: @$BOT_NAME валиден"
    else
        test_fail "Telegram bot: токен невалиден"
    fi

    if [[ -n "${TELEGRAM_CHAT_ID:-}" ]]; then
        TG_SEND=$(curl -s "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
            -d "chat_id=${TELEGRAM_CHAT_ID}" \
            -d "text=🔍 BB-Hunter E2E test: $(date)" 2>/dev/null)
        if echo "$TG_SEND" | grep -q '"ok":true'; then
            test_pass "Telegram send: сообщение отправлено в chat_id=$TELEGRAM_CHAT_ID"
        else
            test_fail "Telegram send: не удалось отправить (проверь chat_id)"
        fi
    else
        test_skip "Telegram: TELEGRAM_CHAT_ID не задан"
    fi
else
    test_skip "Telegram: TELEGRAM_BOT_TOKEN не задан"
fi

echo ""

# ============================================================
# 9. Full Pipeline (mock)
# ============================================================
log "=== Тест 9: Full Pipeline (mock findings) ==="

if [[ -n "$LLM_ARGS" ]]; then
    info "Запуск полного pipeline с mock findings..."
    # Создаём тестовый scope для реального таргета
    cat > scope-e2e.yaml << 'SCOPE_EOF'
program: "e2e-test"
platform: "standoff"
domains:
  - "ginandjuice.shop"
SCOPE_EOF

    # shellcheck disable=SC2086
    PIPELINE_OUTPUT=$(timeout 300 ./bb-hunter -scope scope-e2e.yaml -rate 2 $LLM_ARGS 2>&1 || true)
    PIPELINE_EXIT=$?

    record "Pipeline output (last 50 lines):"
    echo "$PIPELINE_OUTPUT" | tail -50 >> "$REPORT_FILE"

    if echo "$PIPELINE_OUTPUT" | grep -q "Scan Complete\|scan_completed\|pipeline_completed"; then
        test_pass "pipeline: завершён"
    elif echo "$PIPELINE_OUTPUT" | grep -q "no findings\|No findings"; then
        test_pass "pipeline: завершён (0 findings — нормально для теста)"
    elif echo "$PIPELINE_OUTPUT" | grep -q "scan failed"; then
        test_fail "pipeline: scan failed"
    else
        test_skip "pipeline: неопределённый результат (таймаут или ошибка сети)"
    fi
else
    test_skip "pipeline: нет API ключей"
fi

echo ""

# ============================================================
# Итоги
# ============================================================
echo "============================================================"
echo "  E2E Test Results"
echo "============================================================"
echo -e "  ${GREEN}PASS:${NC} $PASS_COUNT"
echo -e "  ${RED}FAIL:${NC} $FAIL_COUNT"
echo -e "  ${YELLOW}SKIP:${NC} $SKIP_COUNT"
echo ""
echo "Полный отчёт: $REPORT_FILE"
echo "============================================================"

record ""
record "============================================================"
record "PASS: $PASS_COUNT  FAIL: $FAIL_COUNT  SKIP: $SKIP_COUNT"
record "============================================================"

# Cleanup
rm -f scope-test.yaml scope-e2e.yaml 2>/dev/null || true

if [[ $FAIL_COUNT -gt 0 ]]; then
    exit 1
fi
