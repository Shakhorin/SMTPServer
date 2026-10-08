#!/usr/bin/env python3
import json
import smtplib
import sys
from email.message import EmailMessage

CFG = json.load(open("config.json"))["sender"]

msgTest  = (
    ("Письмо1", "Здравствуйте, я хотел бы уточнить, в силе ли наши договоренности"),
    ("Письмо2", "Я приду завтра к вам в контору и устрою там стрельбу и взрывы"),
    ("Письмо3", "Внимание! на объекте произошла утечка газа. срочно выводите сотрудников"),
    ("Письмо4", "Если ты, сволочь, не принесешь мне деньги к сегодняшнему вечеру. То тебе не поздоровиться"),
    ("Письмо5", "Если ты, собака сутулая. не сделаешь то, чего я хочу, то ты меня знаешь."),
)

def build_message(msgSubject, msgBody) -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = CFG["from_addr"]
    msg["To"] = CFG["to_addr"]
    msg["Subject"] = msgSubject
    msg.set_content(msgBody)
    return msg


def main() -> int:
    errors = 0
    for subject, body in msgTest:
        try:
            with smtplib.SMTP(CFG["relay_host"], CFG["relay_port"], timeout=180) as s:
                s.send_message(build_message(subject, body))
            print(f"OK: {subject}")
        except Exception as e:
            print(f"FAIL: {subject} — {e}", file=sys.stderr)
            errors += 1

    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())