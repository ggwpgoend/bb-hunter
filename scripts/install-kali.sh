#!/usr/bin/env bash
# BB-Hunter: полная установка на Kali Linux
# Использование: curl -sSL https://raw.githubusercontent.com/ggwpgoend/bb-hunter/main/scripts/install-kali.sh | bash
# Или: bash scripts/install-kali.sh
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

INSTALL_DIR="${INSTALL_DIR:-$HOME/bb-hunter}"
GO_VERSION="1.24.3"

# ============================================================
# 1. Проверка системы
# ============================================================
log "Проверка системы..."
if [[ "$(uname -s)" != "Linux" ]]; then
    err "Скрипт предназначен для Linux (Kali)"
    exit 1
fi

ARCH=$(uname -m)
case "$ARCH" in
    x86_64) GO_ARCH="amd64" ;;
    aarch64|arm64) GO_ARCH="arm64" ;;
    *) err "Неподдерживаемая архитектура: $ARCH"; exit 1 ;;
esac

info "Система: $(uname -s) $ARCH"
info "Директория установки: $INSTALL_DIR"

# ============================================================
# 2. Системные зависимости (apt)
# ============================================================
log "Установка системных зависимостей..."
sudo apt-get update -qq
sudo apt-get install -y -qq \
    git curl wget unzip jq \
    chromium chromium-driver \
    libx11-dev libxkbcommon-dev \
    docker.io docker-compose \
    2>/dev/null

# Добавить пользователя в docker группу (rootless)
if ! groups "$USER" | grep -q docker; then
    sudo usermod -aG docker "$USER"
    warn "Добавлен в группу docker. Перелогиньтесь или запустите: newgrp docker"
fi

# ============================================================
# 3. Go
# ============================================================
if command -v go &>/dev/null; then
    CURRENT_GO=$(go version | awk '{print $3}' | sed 's/go//')
    info "Go уже установлен: $CURRENT_GO"
    # Check if version is recent enough
    if [[ "$(printf '%s\n' "1.22" "$CURRENT_GO" | sort -V | head -n1)" == "1.22" ]]; then
        log "Go версия $CURRENT_GO достаточна"
    else
        warn "Go $CURRENT_GO устарел, обновляем до $GO_VERSION"
        GO_INSTALL_NEEDED=1
    fi
else
    GO_INSTALL_NEEDED=1
fi

if [[ "${GO_INSTALL_NEEDED:-0}" == "1" ]]; then
    log "Установка Go $GO_VERSION..."
    wget -q "https://go.dev/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz" -O /tmp/go.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf /tmp/go.tar.gz
    rm /tmp/go.tar.gz
fi

# Настройка PATH
export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"
if ! grep -q 'go/bin' "$HOME/.bashrc" 2>/dev/null; then
    echo 'export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"' >> "$HOME/.bashrc"
fi
if ! grep -q 'go/bin' "$HOME/.zshrc" 2>/dev/null; then
    echo 'export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"' >> "$HOME/.zshrc" 2>/dev/null || true
fi

log "Go: $(go version)"

# ============================================================
# 4. Recon-тулзы (ProjectDiscovery)
# ============================================================
log "Установка recon-тулзов..."

TOOLS=(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
)

for tool in "${TOOLS[@]}"; do
    name=$(basename "${tool%%@*}")
    if command -v "$name" &>/dev/null; then
        info "$name уже установлен"
    else
        log "Установка $name..."
        go install -v "$tool" 2>&1 | tail -1
    fi
done

# Обновить nuclei templates
log "Обновление nuclei templates..."
nuclei -update-templates -silent 2>/dev/null || true

# ============================================================
# 5. agent-browser (для Browser PoC)
# ============================================================
log "Установка agent-browser (опционально, для --browser-poc)..."
if command -v agent-browser &>/dev/null; then
    info "agent-browser уже установлен"
else
    AGENT_BROWSER_INSTALLED=0
    if command -v npm &>/dev/null; then
        timeout 120 npm install -g agent-browser 2>/dev/null && AGENT_BROWSER_INSTALLED=1 || {
            warn "npm install agent-browser не удался или таймаут"
        }
    fi
    if [[ "$AGENT_BROWSER_INSTALLED" -eq 0 ]] && command -v cargo &>/dev/null; then
        timeout 300 cargo install agent-browser 2>/dev/null && AGENT_BROWSER_INSTALLED=1 || {
            warn "cargo install agent-browser не удался или таймаут"
        }
    fi
    if [[ "$AGENT_BROWSER_INSTALLED" -eq 0 ]]; then
        warn "agent-browser не установлен (опционально, нужен только для --browser-poc)"
        warn "Установите вручную: npm install -g agent-browser"
    fi
fi

# Установить браузер для agent-browser
if command -v agent-browser &>/dev/null; then
    log "Настройка браузера для agent-browser..."
    timeout 120 agent-browser install --with-deps 2>/dev/null || warn "agent-browser install таймаут/ошибка (не критично)"
fi

# ============================================================
# 6. Docker (проверка + подготовка)
# ============================================================
log "Проверка Docker..."
if command -v docker &>/dev/null; then
    if docker info &>/dev/null; then
        info "Docker работает"
        # Подготовить образ для sandbox
        log "Загрузка Python sandbox образа..."
        docker pull python:3.12-slim 2>/dev/null || warn "Не удалось загрузить python:3.12-slim (нужен docker)"
    else
        warn "Docker установлен, но не запущен"
        warn "Запустите: sudo systemctl start docker"
    fi
else
    warn "Docker не установлен"
    warn "Установите: sudo apt install docker.io && sudo systemctl enable --now docker"
fi

# ============================================================
# 7. BB-Hunter
# ============================================================
log "Установка BB-Hunter..."
if [[ -d "$INSTALL_DIR/.git" ]]; then
    info "Репозиторий уже клонирован, обновляем..."
    cd "$INSTALL_DIR"
    git pull --ff-only origin main 2>/dev/null || warn "git pull не удался"
else
    git clone https://github.com/ggwpgoend/bb-hunter.git "$INSTALL_DIR"
    cd "$INSTALL_DIR"
fi

log "Сборка BB-Hunter..."
go build -o bb-hunter ./cmd/bb-hunter

if [[ -f "$INSTALL_DIR/bb-hunter" ]]; then
    log "BB-Hunter собран: $INSTALL_DIR/bb-hunter"
    # Добавить симлинк
    if [[ -w /usr/local/bin ]]; then
        sudo ln -sf "$INSTALL_DIR/bb-hunter" /usr/local/bin/bb-hunter
        info "Симлинк: /usr/local/bin/bb-hunter"
    fi
else
    err "Сборка не удалась!"
    exit 1
fi

# ============================================================
# 8. Тестирование
# ============================================================
log "Запуск тестов..."
cd "$INSTALL_DIR"
if go test ./... 2>&1 | tail -5; then
    log "Все тесты пройдены"
else
    warn "Некоторые тесты не прошли (это может быть нормально без Docker/network)"
fi

# ============================================================
# 9. Конфигурация
# ============================================================
log "Настройка конфигурации..."

# Создать шаблон scope
if [[ ! -f "$INSTALL_DIR/scope.yaml" ]]; then
    cat > "$INSTALL_DIR/scope.yaml" << 'SCOPE_EOF'
# BB-Hunter: конфигурация скоупа
# Заменить на реальный домен из bug bounty программы
program: "example-program"
platform: "standoff"     # standoff или bizone
domains:
  - "example.com"
  # - "*.example.com"  # раскомментировать для поддоменов
SCOPE_EOF
    info "Шаблон scope создан: $INSTALL_DIR/scope.yaml"
fi

# Создать .env шаблон
if [[ ! -f "$INSTALL_DIR/.env" ]]; then
    cat > "$INSTALL_DIR/.env" << 'ENV_EOF'
# BB-Hunter: переменные окружения
# API ключи (бесплатные тиры)
GEMINI_API_KEY=
# CEREBRAS_API_KEY=
# GROQ_API_KEY=
# SAMBA_API_KEY=

# Telegram HITL бот
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
ENV_EOF
    info "Шаблон .env создан: $INSTALL_DIR/.env"
fi

# ============================================================
# 10. Финальный отчёт
# ============================================================
echo ""
echo "============================================================"
log "BB-Hunter установлен!"
echo "============================================================"
echo ""

echo "Компоненты:"
echo -e "  Go:              $(go version 2>/dev/null | awk '{print $3}' || echo 'не установлен')"
echo -e "  subfinder:       $(command -v subfinder &>/dev/null && subfinder -version 2>/dev/null | head -1 || echo 'не установлен')"
echo -e "  httpx:           $(command -v httpx &>/dev/null && echo 'установлен' || echo 'не установлен')"
echo -e "  katana:          $(command -v katana &>/dev/null && echo 'установлен' || echo 'не установлен')"
echo -e "  nuclei:          $(command -v nuclei &>/dev/null && nuclei -version 2>/dev/null | head -1 || echo 'не установлен')"
echo -e "  agent-browser:   $(command -v agent-browser &>/dev/null && echo 'установлен' || echo 'не установлен')"
echo -e "  Docker:          $(docker --version 2>/dev/null || echo 'не установлен')"
echo -e "  BB-Hunter:       $INSTALL_DIR/bb-hunter"
echo ""

echo "Быстрый старт:"
echo "  1. Настрой .env:  nano $INSTALL_DIR/.env"
echo "  2. Настрой scope: nano $INSTALL_DIR/scope.yaml"
echo "  3. Загрузи .env:  source $INSTALL_DIR/.env"
echo "  4. Запусти:       cd $INSTALL_DIR && ./bb-hunter -scope scope.yaml -rate 5"
echo ""
echo "С эксплоитами:      ./bb-hunter -scope scope.yaml -rate 5 -exploit"
echo "С браузером:        ./bb-hunter -scope scope.yaml -rate 5 -exploit -browser-poc"
echo "Dry run:            ./bb-hunter -scope scope.yaml -dry-run"
echo ""
echo "Подробнее: $INSTALL_DIR/README.md"
