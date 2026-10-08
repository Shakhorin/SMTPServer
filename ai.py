# ai.py
import json
import requests

CFG = json.load(open("config.json"))["ai"]

# Что вернуть, если модель недоступна или выдала мусор.
# is_threat=false безопаснее: сбой ИИ не должен блокировать почту.
FALLBACK = {
    "is_threat": False,
    "category": 0,
    "confidence": 0.0,
    "reason": "classifier unavailable",
}

#Модуль прогрева модели перед первым письмом

def warmup() -> bool:
    """
    Прогревает модель в Ollama: заставляет загрузить веса в память
    и выполнить одну короткую генерацию, чтобы первый реальный
    запрос не ждал загрузки.

    Возвращает True при успехе, False при ошибке.
    """
    if not CFG.get("enabled"):
        print("[ai] прогрев пропущен: ai.enabled = false")
        return True

    try:
        r = requests.post(
            CFG["url"],
            json={
                "model": CFG["model"],
                "prompt": "ping",
                "stream": False,
                "format": CFG["schema"],       # та же схема, что в проде
                "keep_alive": CFG.get("keep_alive", "30m"),
                "options": {
                    "temperature": 0,
                    "num_predict": 16,         # минимум, чтобы получить валидный JSON
                    "num_ctx": 512,            # маленький контекст → быстрый prefill
                },
            },
            timeout=CFG.get("timeout", 120),
        )
        r.raise_for_status()
        print(f"[ai] модель {CFG['model']} прогрета")
        return True
    except Exception as e:
        print(f"[ai] прогрев не удался: {e!r}")
        return False

#Модуль непосредственной работы ии

def classify(subject: str, body: str) -> dict:
    """
    Отправляет письмо в Ollama, возвращает распарсенный JSON как dict:
        {"is_threat": bool, "category": int, "confidence": float, "reason": str}
    При любой ошибке возвращает FALLBACK.
    """
    if not CFG.get("enabled"):
        return dict(FALLBACK)

    prompt = CFG["prompt"].replace("{subject}", subject).replace("{body}", body)

    payload = {
        "model": CFG["model"],
        "prompt": prompt,
        "stream": False,
        "format": CFG["schema"],# Ollama гарантирует структуру ответа
        "keep_alive": CFG["keep_alive"],  # ← сбрасывает таймер
        "options": {
            "temperature": 0,      # стабильный ответ, без креатива
            "num_predict": 256,    # хватит на 4 поля JSON с русским reason
        },
    }

    try:
        r = requests.post(CFG["url"], json=payload, timeout=CFG["timeout"])
        r.raise_for_status()
        raw = r.json().get("response", "")
    except Exception as e:
        print(f"[ai] сетевая ошибка: {e!r}")
        return dict(FALLBACK)

    return _parse(raw)


def _parse(raw: str) -> dict:
    """
    Парсит ответ модели в dict. Если JSON битый — пробует вытащить {...}.
    Если и это не удалось — возвращает FALLBACK.
    """
    raw = (raw or "").strip()

    # Попытка 1: как есть
    try:
        return _normalize(json.loads(raw))
    except json.JSONDecodeError:
        pass

    # Попытка 2: вытащить первый {...} на случай, если модель что-то добавила
    start = raw.find("{")
    end = raw.rfind("}")
    if start != -1 and end > start:
        try:
            return _normalize(json.loads(raw[start:end + 1]))
        except json.JSONDecodeError:
            pass

    print(f"[ai] не удалось распарсить ответ: {raw!r}")
    return dict(FALLBACK)


def _normalize(data: dict) -> dict:
    """Приводит поля к нужным типам и валидирует диапазоны."""
    is_threat = bool(data.get("is_threat", False))

    try:
        category = int(data.get("category", 0))
    except (TypeError, ValueError):
        category = 0
    if category not in (0, 1, 2, 3, 4):
        category = 0

    try:
        confidence = float(data.get("confidence", 0.0))
    except (TypeError, ValueError):
        confidence = 0.0
    if not (0.0 <= confidence <= 1.0):
        confidence = max(0.0, min(1.0, confidence))

    reason = str(data.get("reason", "")).strip()

    # Если модель сказала is_threat=false — категория и уверенность обнуляются.
    if not is_threat:
        category = 0

    return {
        "is_threat": is_threat,
        "category": category,
        "confidence": confidence,
        "reason": reason,
    }