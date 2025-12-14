# -*- coding: utf-8 -*-

# Kiro OpenAI Gateway
# Copyright (C) 2025 Jwadow
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

"""
Конфигурация Kiro Gateway.

Централизованное хранение всех настроек, констант и маппингов.
Загружает переменные окружения и предоставляет типизированный доступ к ним.
"""

import os
import re
from pathlib import Path
from typing import Dict, List, Optional
from dotenv import load_dotenv

# Загрузка переменных окружения
load_dotenv()


def _get_raw_env_value(var_name: str, env_file: str = ".env") -> Optional[str]:
    """
    Читает значение переменной из .env файла без обработки escape-последовательностей.
    
    Это необходимо для корректной работы с путями на Windows, где обратные слэши
    (например, D:\\Projects\\file.json) могут быть ошибочно интерпретированы
    как escape-последовательности (\\a -> bell, \\n -> newline и т.д.).
    
    Args:
        var_name: Имя переменной окружения
        env_file: Путь к .env файлу (по умолчанию ".env")
    
    Returns:
        Сырое значение переменной или None если не найдено
    """
    env_path = Path(env_file)
    if not env_path.exists():
        return None
    
    try:
        # Читаем файл как есть, без интерпретации
        content = env_path.read_text(encoding="utf-8")
        
        # Ищем переменную с учётом разных форматов:
        # VAR="value" или VAR='value' или VAR=value
        # Паттерн захватывает значение в кавычках или без них
        pattern = rf'^{re.escape(var_name)}=(["\']?)(.+?)\1\s*$'
        
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            
            match = re.match(pattern, line)
            if match:
                # Возвращаем значение как есть, без обработки escape-последовательностей
                return match.group(2)
    except Exception:
        pass
    
    return None

# ==================================================================================================
# Настройки прокси-сервера
# ==================================================================================================

# API ключ для доступа к прокси (клиенты должны передавать его в Authorization header)
PROXY_API_KEY: str = os.getenv("PROXY_API_KEY", "changeme_proxy_secret")

# ==================================================================================================
# Kiro API Credentials
# ==================================================================================================

# Refresh token для обновления access token
REFRESH_TOKEN: str = os.getenv("REFRESH_TOKEN", "")

# Profile ARN для AWS CodeWhisperer
PROFILE_ARN: str = os.getenv("PROFILE_ARN", "")

# Регион AWS (по умолчанию us-east-1)
REGION: str = os.getenv("KIRO_REGION", "us-east-1")

# Путь к файлу с credentials (опционально, альтернатива .env)
# Читаем напрямую из .env чтобы избежать проблем с escape-последовательностями на Windows
# (например, \a в пути D:\Projects\adolf интерпретируется как bell character)
_raw_creds_file = _get_raw_env_value("KIRO_CREDS_FILE") or os.getenv("KIRO_CREDS_FILE", "")
# Нормализуем путь для кроссплатформенной совместимости
KIRO_CREDS_FILE: str = str(Path(_raw_creds_file)) if _raw_creds_file else ""

# ==================================================================================================
# Kiro API URL Templates
# ==================================================================================================

# URL для обновления токена
KIRO_REFRESH_URL_TEMPLATE: str = "https://prod.{region}.auth.desktop.kiro.dev/refreshToken"

# Хост для основного API (generateAssistantResponse)
KIRO_API_HOST_TEMPLATE: str = "https://codewhisperer.{region}.amazonaws.com"

# Хост для Q API (ListAvailableModels)
KIRO_Q_HOST_TEMPLATE: str = "https://q.{region}.amazonaws.com"

# ==================================================================================================
# Настройки токенов
# ==================================================================================================

# Время до истечения токена, когда нужно обновить (в секундах)
# По умолчанию 10 минут - обновляем токен заранее, чтобы избежать ошибок
TOKEN_REFRESH_THRESHOLD: int = 600

# ==================================================================================================
# Retry конфигурация
# ==================================================================================================

# Максимальное количество попыток при ошибках
MAX_RETRIES: int = 3

# Базовая задержка между попытками (секунды)
# Используется exponential backoff: delay * (2 ** attempt)
BASE_RETRY_DELAY: float = 1.0

# ==================================================================================================
# Маппинг моделей
# ==================================================================================================

# Внешние имена моделей (OpenAI-совместимые) -> внутренние ID Kiro
# Клиенты используют внешние имена, а мы конвертируем их во внутренние
MODEL_MAPPING: Dict[str, str] = {
    # Claude Opus 4.5 - топовая модель
    "claude-opus-4-5": "claude-opus-4.5",
    "claude-opus-4-5-20251101": "claude-opus-4.5",
    
    # Claude Haiku 4.5 - быстрая модель
    "claude-haiku-4-5": "claude-haiku-4.5",
    "claude-haiku-4.5": "claude-haiku-4.5",  # Прямой проброс
    
    # Claude Sonnet 4.5 - улучшенная модель
    "claude-sonnet-4-5": "CLAUDE_SONNET_4_5_20250929_V1_0",
    "claude-sonnet-4-5-20250929": "CLAUDE_SONNET_4_5_20250929_V1_0",
    
    # Claude Sonnet 4 - сбалансированная модель
    "claude-sonnet-4": "CLAUDE_SONNET_4_20250514_V1_0",
    "claude-sonnet-4-20250514": "CLAUDE_SONNET_4_20250514_V1_0",
    
    # Claude 3.7 Sonnet - legacy модель
    "claude-3-7-sonnet-20250219": "CLAUDE_3_7_SONNET_20250219_V1_0",
    
    # Алиасы для удобства
    "auto": "claude-sonnet-4.5",
}

# Список доступных моделей для эндпоинта /v1/models
# Эти модели будут отображаться клиентам как доступные
AVAILABLE_MODELS: List[str] = [
    "claude-opus-4-5",
    "claude-opus-4-5-20251101",
    "claude-haiku-4-5",
    "claude-sonnet-4-5",
    "claude-sonnet-4-5-20250929",
    "claude-sonnet-4",
    "claude-sonnet-4-20250514",
    "claude-3-7-sonnet-20250219",
]

# ==================================================================================================
# Настройки кэша моделей
# ==================================================================================================

# TTL кэша моделей в секундах (1 час)
MODEL_CACHE_TTL: int = 3600

# Максимальное количество input токенов по умолчанию
DEFAULT_MAX_INPUT_TOKENS: int = 200000

# ==================================================================================================
# Tool Description Handling (Kiro API Limitations)
# ==================================================================================================

# Kiro API возвращает ошибку 400 "Improperly formed request" при слишком длинных
# описаниях инструментов в toolSpecification.description.
#
# Решение: Tool Documentation Reference Pattern
# - Если description ≤ лимита → оставляем как есть
# - Если description > лимита:
#   * В toolSpecification.description → ссылка на system prompt:
#     "[Full documentation in system prompt under '## Tool: {name}']"
#   * В system prompt добавляется секция "## Tool: {name}" с полным описанием
#
# Модель видит явную ссылку и точно понимает, где искать полную документацию.

# Максимальная длина description для tool в символах.
# Описания длиннее этого лимита будут перенесены в system prompt.
# Установите 0 для отключения (не рекомендуется - вызовет ошибки Kiro API).
TOOL_DESCRIPTION_MAX_LENGTH: int = int(os.getenv("TOOL_DESCRIPTION_MAX_LENGTH", "10000"))

# ==================================================================================================
# Logging Settings
# ==================================================================================================

# Log level for the application
# Available levels: TRACE, DEBUG, INFO, WARNING, ERROR, CRITICAL
# Default: INFO (recommended for production)
# Set to DEBUG for detailed troubleshooting
LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO").upper()

# ==================================================================================================
# First Token Timeout Settings (Streaming Retry)
# ==================================================================================================

# Таймаут ожидания первого токена от модели (в секундах).
# Если модель не отвечает в течение этого времени, запрос будет отменён и повторён.
# Это помогает справиться с "зависшими" запросами, когда модель долго думает.
# По умолчанию: 30 секунд (рекомендуется для production)
# Установите меньшее значение (например, 10-15) для более агрессивного retry.
FIRST_TOKEN_TIMEOUT: float = float(os.getenv("FIRST_TOKEN_TIMEOUT", "30"))

# Максимальное количество попыток при таймауте первого токена.
# После исчерпания всех попыток будет возвращена ошибка.
# По умолчанию: 3 попытки
FIRST_TOKEN_MAX_RETRIES: int = int(os.getenv("FIRST_TOKEN_MAX_RETRIES", "3"))

# ==================================================================================================
# Debug Settings
# ==================================================================================================

# If True, the last request will be logged in detail to DEBUG_DIR
# Enable via .env: DEBUG_LAST_REQUEST=true
DEBUG_LAST_REQUEST: bool = os.getenv("DEBUG_LAST_REQUEST", "false").lower() in ("true", "1", "yes")

# Directory for debug log files
DEBUG_DIR: str = os.getenv("DEBUG_DIR", "debug_logs")

# ==================================================================================================
# Версия приложения
# ==================================================================================================

APP_VERSION: str = "1.0.2"
APP_TITLE: str = "Kiro API Gateway"
APP_DESCRIPTION: str = "OpenAI-compatible interface for Kiro API (AWS CodeWhisperer). Made by @jwadow"


def get_kiro_refresh_url(region: str) -> str:
    """Возвращает URL для обновления токена для указанного региона."""
    return KIRO_REFRESH_URL_TEMPLATE.format(region=region)


def get_kiro_api_host(region: str) -> str:
    """Возвращает хост API для указанного региона."""
    return KIRO_API_HOST_TEMPLATE.format(region=region)


def get_kiro_q_host(region: str) -> str:
    """Возвращает хост Q API для указанного региона."""
    return KIRO_Q_HOST_TEMPLATE.format(region=region)


def get_internal_model_id(external_model: str) -> str:
    """
    Конвертирует внешнее имя модели во внутренний ID Kiro.
    
    Args:
        external_model: Внешнее имя модели (например, "claude-sonnet-4-5")
    
    Returns:
        Внутренний ID модели для Kiro API
    """
    return MODEL_MAPPING.get(external_model, external_model)