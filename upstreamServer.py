#!/usr/bin/env python3
import json
import os
import re
import time

from aiosmtpd.controller import Controller

CFG = json.load(open("config.json"))["upstream"]


class Upstream:
    async def handle_RCPT(self, server, session, envelope, address, opts):
        domain = address.rsplit("@", 1)[-1].lower()
        if domain not in CFG["local_domains"]:
            return "550 Relay access denied"
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope):
        for rcpt in envelope.rcpt_tos:
            # Имя каталога = сам адрес, но без «опасных» символов.
            safe = re.sub(r"[^A-Za-z0-9_.@+-]", "_", rcpt)
            directory = os.path.join(CFG["mailbox_dir"], safe)
            os.makedirs(directory, exist_ok=True)

            # Имя файла = время + случайное число, чтобы не перетирались.
            filename = f"{time.strftime('%Y%m%d-%H%M%S')}-{os.urandom(3).hex()}.eml"
            with open(os.path.join(directory, filename), "wb") as f:
                f.write(envelope.content)

            print(f"Принято от {envelope.mail_from} для {rcpt} → {directory}/{filename}")

        return "250 Message accepted for delivery"


if __name__ == "__main__":
    os.makedirs(CFG["mailbox_dir"], exist_ok=True)
    controller = Controller(Upstream(), hostname=CFG["listen_host"], port=CFG["listen_port"])
    controller.start()
    print(f"Upstream слушает {CFG['listen_host']}:{CFG['listen_port']}. Enter для выхода.")
    input()
    controller.stop()