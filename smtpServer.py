#!/usr/bin/env python3
import asyncio
import json
import smtplib
import ssl
import os
import storage
import time
from aiosmtpd.controller import Controller
import email
from email.policy import default as email_policy
import html as html_mod
import re
from email.header import decode_header, make_header
from ai import *

CFG = json.load(open("config.json"))["relay"]
PRINT = json.load(open("config.json"))["print"]
REDIRECT = json.load(open("config.json"))["securityAddresses"]

#Модуль для работы с письмом (для преобразования письма в кортеж (темы, полный текст))

def _decode_header_value(value) -> str:
    """'=?utf-8?b?...?=' → 'Письмо1'."""
    if value is None:
        return ""
    try:
        return str(make_header(decode_header(str(value))))
    except Exception:
        return str(value)


def _html_to_text(html: str) -> str:
    """Грубо вырезает теги и раскрывает HTML-сущности."""
    html = re.sub(r"(?is)<(script|style).*?>.*?</\1>", "", html)
    html = re.sub(r"(?i)<br\s*/?>", "\n", html)
    html = re.sub(r"(?i)</p>", "\n", html)
    html = re.sub(r"<[^>]+>", "", html)
    return html_mod.unescape(html)

def extract_message_id(raw: bytes) -> str:
    """Берёт Message-ID из заголовка письма. Если его нет — генерирует свой."""
    msg = email.message_from_bytes(raw, policy=email_policy)
    mid = (msg.get("Message-ID") or "").strip().strip("<>")
    if mid:
        return mid
    return f"{int(time.time() * 1000)}-{os.urandom(4).hex()}"

def parse_mail(raw: bytes) -> tuple[str, str]:
    """
    Принимает сырое письмо (bytes), возвращает (тема, полный текст).

    - тема декодируется из encoded-words;
    - тело декодируется из base64 / quoted-printable и правильной кодировки;
    - multipart: собираются все text/plain части через перенос строки;
    - если text/plain нет — берётся text/html и из него вырезаются теги;
    - вложения и нетекстовые части пропускаются.
    """
    msg = email.message_from_bytes(raw, policy=email_policy)

    subject = _decode_header_value(msg.get("Subject"))

    texts: list[str] = []

    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_maintype() != "text":
                continue
            if part.get_content_type() == "text/plain":
                try:
                    texts.append(part.get_content())
                except Exception:
                    payload = part.get_payload(decode=True) or b""
                    charset = part.get_content_charset() or "utf-8"
                    texts.append(payload.decode(charset, errors="replace"))

        if not texts:
            for part in msg.walk():
                if part.get_content_type() == "text/html":
                    try:
                        texts.append(_html_to_text(part.get_content()))
                    except Exception:
                        payload = part.get_payload(decode=True) or b""
                        charset = part.get_content_charset() or "utf-8"
                        texts.append(_html_to_text(payload.decode(charset, errors="replace")))
    else:
        ctype = msg.get_content_type()
        try:
            content = msg.get_content()
        except Exception:
            payload = msg.get_payload(decode=True) or b""
            charset = msg.get_content_charset() or "utf-8"
            content = payload.decode(charset, errors="replace")

        if ctype == "text/html":
            texts.append(_html_to_text(content))
        else:
            texts.append(content)

    body = "\n".join(t for t in texts if t)
    body = body.replace("\r\n", "\n").replace("\r", "\n").strip()

    return subject, body

#Модуль вывода в консоль в нормальном виде (в конфиге лежит количество выводимых байт)

def now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def body_preview(data: bytes) -> str:
    """Декодированное тело письма, первые N символов одной строкой."""
    if not PRINT.get("show_body"):
        return ""

    try:
        msg = email.message_from_bytes(data, policy=email_policy)

        # Достаём декодированный текст: email сам разберёт base64 / quoted-printable
        # и подставит правильную кодировку (utf-8, koi8-r, cp1251 и т.п.).
        if msg.is_multipart():
            # Если письмо составное — берём первую текстовую часть.
            body = ""
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    body = part.get_content()
                    break
            if not body:
                # Если text/plain нет, берём text/html и грубо срезаем теги.
                for part in msg.walk():
                    if part.get_content_type() == "text/html":
                        import re
                        body = re.sub(r"<[^>]+>", "", part.get_content())
                        break
        else:
            body = msg.get_content()

        if not isinstance(body, str):
            body = str(body)

    except Exception as e:
        # Если что-то пошло не так — показываем хотя бы метку, а не падаем.
        return f"(не удалось разобрать письмо: {e!r})"

    body = body.replace("\r", "").replace("\n", " ").strip()
    n = PRINT["body_chars"]
    return body[:n] + ("…" if len(body) > n else "")

#ММодуль анализа ответ ии

def aiResponseAnalise(aiResponse: dict) -> tuple[str, str]:
    if aiResponse.get("is_threat") is True:
        direct = REDIRECT.get(str(aiResponse.get("category")), "")
        subject = (f" [УГРОЗА {aiResponse.get('category')}, "
                   f"conf={aiResponse.get('confidence', 0):.2f}]")
        return direct, subject
    return "", ""

#Перезапись темы

def rewrite_subject(raw: bytes, new_subject: str) -> bytes:
    """Заменяет Subject в шапке письма."""
    msg = email.message_from_bytes(raw, policy=email_policy)
    if msg.get("Subject"):
        msg.replace_header("Subject", new_subject)
    else:
        msg["Subject"] = new_subject
    return msg.as_bytes(policy=email_policy)

#Модуль принятия письмы и его пересылки

class Relay:
    async def handle_RCPT(self, server, session, envelope, address, opts):
        domain = address.rsplit("@", 1)[-1].lower()
        peer = session.peer[0]

        if domain not in CFG["allowed_recipient_domains"]:
            print(f"{now()} [relay] RCPT отклонён  "
                  f"from={envelope.mail_from} peer={peer} rcpt={address}")
            return "550 Relay access denied"

        envelope.rcpt_tos.append(address)
        print(f"{now()} [relay] RCPT принят    "
              f"from={envelope.mail_from} peer={peer} rcpt={address}")
        return "250 OK"

    # Обработка + взаимодействие с бд
    async def handle_DATA(self, server, session, envelope):
        peer = session.peer[0]
        size = len(envelope.content)

        print(f"{now()} [relay] Письмо получено "
              f"from={envelope.mail_from} peer={peer} "
              f"rcpt={','.join(envelope.rcpt_tos)} size={size}B")

        preview = body_preview(envelope.content)
        if preview:
            print(f"{now()} [relay]   тело         {preview}")

        # Тема и текст письма
        subject, body = parse_mail(envelope.content)

        # Message-ID — тот же, что у клиента, иначе web-интерфейс не найдёт запись
        message_id = extract_message_id(envelope.content)
        print(f"{now()} [relay] Message-ID: {message_id}")

        # Анализ ИИ
        aiResponse = await asyncio.to_thread(classify, subject, body)
        print(f"{now()} [relay] AI: {aiResponse}")

        storage.add_event(message_id, "received",
                          sender=envelope.mail_from,
                          recipient=",".join(envelope.rcpt_tos),
                          subject=subject)
        storage.add_event(message_id, "ai_classified",
                          category=aiResponse["category"],
                          confidence=aiResponse["confidence"],
                          reason=aiResponse["reason"])

        # Решение
        direct, subject_add = aiResponseAnalise(aiResponse)

        if direct:
            action = "quarantine"
            final_recipient = direct
        else:
            action = "deliver"
            final_recipient = envelope.rcpt_tos[0] if envelope.rcpt_tos else ""

        # Перенаправление
        if direct:
            envelope.rcpt_tos = [direct]
            print(f"{now()} [relay] ПЕРЕНАПРАВЛЕНО на {direct}")
            storage.add_event(message_id, "quarantined", target=direct)

        # Дополнение темы
        if subject_add:
            new_subject = subject + subject_add
            envelope.content = rewrite_subject(envelope.content, new_subject)
            print(f"{now()} [relay] ТЕМА дополнена     → {new_subject!r}")
            storage.add_event(message_id, "subject_rewritten", new_subject=new_subject)

        # Карантин
        eml_path = None
        if action == "quarantine":
            eml_path = storage.save_quarantine(message_id, envelope.content)
            print(f"{now()} [relay] КАРАНТИН           → {eml_path}")

        # Метаданные в базу
        storage.add_message(
            message_id=message_id,
            sender=envelope.mail_from,
            recipient=final_recipient,
            subject=subject,
            body=body,
            category=aiResponse["category"],
            confidence=aiResponse["confidence"],
            reason=aiResponse["reason"],
            action=action,
            eml_path=eml_path,
        )

        # Пересылка
        try:
            await asyncio.to_thread(self._forward, envelope)
        except Exception as e:
            print(f"{now()} [relay] ОШИБКА пересылки: {e!r}")
            storage.add_event(message_id, "error", message=str(e))
            return "451 Try again later"

        storage.add_event(message_id, "delivered", target=final_recipient)
        print(f"{now()} [relay] Переслано на "
              f"{CFG['upstream_host']}:{CFG['upstream_port']}")
        return "250 Message accepted for delivery"

    def _forward(self, envelope):
        # Подключаемся к upstream: либо SSL, либо обычный SMTP + STARTTLS.
        if CFG["upstream_port"] == 465:
            client = smtplib.SMTP_SSL(CFG["upstream_host"], CFG["upstream_port"])
        else:
            client = smtplib.SMTP(CFG["upstream_host"], CFG["upstream_port"])
            if CFG["use_starttls"]:
                client.starttls(context=ssl.create_default_context())

        if CFG["upstream_user"]:
            client.login(CFG["upstream_user"], CFG["upstream_password"])

        client.sendmail(envelope.mail_from, envelope.rcpt_tos, envelope.content)
        client.quit()


if __name__ == "__main__":

    warmup() #Прогрев модели

    controller = Controller(Relay(), hostname=CFG["listen_host"], port=CFG["listen_port"])
    controller.start()
    print(f"{now()} [relay] Запущен на {CFG['listen_host']}:{CFG['listen_port']}, "
          f"пересылает на {CFG['upstream_host']}:{CFG['upstream_port']}")
    print("Enter для выхода.")
    try:
        input()
    finally:
        controller.stop()
        print(f"{now()} [relay] Остановлен")