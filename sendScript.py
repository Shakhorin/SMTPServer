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
    for subject, body in msgTest:
        msg = build_message(subject, body)
        try:
            with smtplib.SMTP(CFG["relay_host"], CFG["relay_port"], timeout=10) as s:
                s.set_debuglevel(0)          # поставьте 1, чтобы видеть SMTP-диалог
                s.send_message(msg)
        except Exception as e:
            print(f"Не удалось отправить: {e}", file=sys.stderr)
            return 1

        print(f"OK: письмо от {CFG['from_addr']} к {CFG['to_addr']} "
              f"передано на {CFG['relay_host']}:{CFG['relay_port']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())