#!/usr/bin/env bash
# BB-Hunter: скрипт запуска с проверкой зависимостей
# Использование: ./scripts/run.sh [дополнительные флаги bb-hunter]
# Примеры:
#   ./scripts/run.sh                           # стандартный запуск
#   ./scripts/run.sh -exploit                  # с эксплоитами
#   ./scripts/run.sh -exploit -browser-poc     # с браузером
#   ./scripts/run.sh -dry-run                  # проверка конфигурации
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()   { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
err()   { echo -e "${RED}[-]${NC} $1"; exit 1; }
info()  { echo -e "${BLUE}[*]${NC} $1"; }

# Определить директорию проекта
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_DIR"

# ============================================================
# 1. Проверка зависимостей
# ============================================================
MISSING=()
WARNINGS=()

# Go
if ! command -v go &>/dev/null; then
    MISSING+=("go — нужен для сборки. Установи: bash scripts/install-kali.sh")
fi

# Recon tools
for tool in subfinder httpx katana nuclei; do
    if ! command -v "$tool" &>/dev/null; then
        MISSING+=("$tool — go install github.com/projectdiscovery/$tool/...@latest")
    fi
done

# Бинарник bb-hunter
if [[ ! -f "$PROJECT_DIR/bb-hunter" ]]; then
    info "BB-Hunter не собран, собираем..."
    if command -v go &>/dev/null; then
        go build -o bb-hunter ./cmd/bb-hunter || err "Сборка не удалась"
        log "BB-Hunter собран"
    else
        MISSING+=("bb-hunter binary — go build -o bb-hunter ./cmd/bb-hunter")
    fi
fi

# Docker (для -exploit)
if [[ " $* " == *" -exploit"* ]] || [[ " $* " == *" --exploit"* ]]; then
    if ! command -v docker &>/dev/null; then
        MISSING+=("docker — нужен для -exploit. sudo apt install docker.io")
    elif ! docker info &>/dev/null 2>&1; then
        MISSING+=("docker daemon — sudo systemctl start docker")
    fi
fi

# agent-browser (для -browser-poc)
if [[ " $* " == *" -browser-poc"* ]] || [[ " $* " == *" --browser-poc"* ]]; then
    if ! command -v agent-browser &>/dev/null; then
        WARNINGS+=("agent-browser не установлен. npm install -g agent-browser && agent-browser install")
    fi
fi

# Показать проблемы
if [[ ${#MISSING[@]} -gt 0 ]]; then
    err "Отсутствуют зависимости:"
    for m in "${MISSING[@]}"; do
        echo -e "  ${RED}✗${NC} $m"
    done
    echo ""
    echo "Автоматическая установка: bash scripts/install-kali.sh"
    exit 1
fi

if [[ ${#WARNINGS[@]} -gt 0 ]]; then
    for w in "${WARNINGS[@]}"; do
        warn "$w"
    done
fi

# ============================================================
# 2. Проверка конфигурации
# ============================================================
SCOPE_FILE="${SCOPE_FILE:-scope.yaml}"

if [[ ! -f "$SCOPE_FILE" ]]; then
    err "Файл scope не найден: $SCOPE_FILE"
    echo "  Создай его: nano scope.yaml"
    echo "  Формат:"
    echo "    program: 'program-name'"
    echo "    platform: 'standoff'"
    echo "    domains:"
    echo "      - 'example.com'"
    exit 1
fi

# Проверить что scope не шаблонный
if grep -q 'example\.com' "$SCOPE_FILE" 2>/dev/null; then
    warn "Scope содержит example.com — замени на реальный домен!"
fi

# ============================================================
# 3. Загрузка .env
# ============================================================
if [[ -f "$PROJECT_DIR/.env" ]]; then
    set -a
    source "$PROJECT_DIR/.env"
    set +a
    info "Загружен .env"
fi

# Проверить API ключи
if [[ -z "${GEMINI_API_KEY:-}" ]] && [[ -z "${CEREBRAS_API_KEY:-}" ]] && [[ -z "${GROQ_API_KEY:-}" ]] && [[ -z "${SAMBA_API_KEY:-}" ]]; then
    err "Нет API ключей! Настрой .env файл:"
    echo "  GEMINI_API_KEY=your_key_here"
    exit 1
fi

# Проверить Telegram
if [[ -z "${TELEGRAM_BOT_TOKEN:-}" ]] || [[ -z "${TELEGRAM_CHAT_ID:-}" ]]; then
    warn "Telegram не настроен — HITL этап будет пропущен"
fi

# ============================================================
# 4. Запуск
# ============================================================
info "Scope: $SCOPE_FILE"
info "LLM providers: $(
    providers=""
    [[ -n "${GEMINI_API_KEY:-}" ]] && providers="${providers}gemini "
    [[ -n "${CEREBRAS_API_KEY:-}" ]] && providers="${providers}cerebras "
    [[ -n "${GROQ_API_KEY:-}" ]] && providers="${providers}groq "
    [[ -n "${SAMBA_API_KEY:-}" ]] && providers="${providers}samba "
    echo "$providers"
)"
info "Telegram: $([[ -n "${TELEGRAM_BOT_TOKEN:-}" ]] && echo 'настроен' || echo 'не настроен')"

# Построить аргументы
ARGS=("-scope" "$SCOPE_FILE")

# Rate limit
ARGS+=("-rate" "${RATE:-5}")

# Дополнительные аргументы пользователя
ARGS+=("$@")

log "Запуск BB-Hunter..."
echo ""
exec "$PROJECT_DIR/bb-hunter" "${ARGS[@]}"
