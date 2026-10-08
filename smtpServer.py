#!/usr/bin/env python3
import asyncio
import json
import smtplib
import ssl

from aiosmtpd.controller import Controller

CFG = json.load(open("config.json"))["relay"]


class Relay:
    async def handle_RCPT(self, server, session, envelope, address, opts):
        domain = address.rsplit("@", 1)[-1].lower()
        if domain not in CFG["allowed_recipient_domains"]:
            return "550 Relay access denied"
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope):
        try:
            await asyncio.to_thread(self._forward, envelope)
        except Exception as e:
            print("Ошибка пересылки:", e)
            return "451 Try again later"
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
    controller = Controller(Relay(), hostname=CFG["listen_host"], port=CFG["listen_port"])
    controller.start()
    print(f"Relay слушает {CFG['listen_host']}:{CFG['listen_port']} → "
          f"{CFG['upstream_host']}:{CFG['upstream_port']}. Enter для выхода.")
    input()
    controller.stop()