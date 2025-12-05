from websocket import (
    WebSocketApp,
    WebSocketConnectionClosedException as ClosedEx,
    WebSocket,
)
from base64 import (
    b64encode as b64e,
    b64decode as b64d,
    urlsafe_b64encode as url_b64e,
)
from Crypto.Cipher import PKCS1_OAEP
from rich.console import Console
from Crypto.PublicKey import RSA
from typing import Protocol, Any
from rich.syntax import Syntax
from Crypto.Hash import SHA256
from json import dumps, loads
from time import sleep, time
from threading import Thread
from functools import wraps
from qrcode import make
from httpx import post
from os import getenv


class CustomLogger:
    @staticmethod
    def fmt_json(data, type=None):
        syntax = Syntax(
            dumps(data, indent=4), "json", theme="monokai", line_numbers=False
        )
        console = Console()
        if type:
            print(f"[{type}]")
        console.print(syntax)

    @staticmethod
    def send_header(centered_text: str):
        print("-" * 22, f"| {centered_text.center(18)} |", "-" * 22, sep="\n")


class DiscordUser:
    def __init__(self, values: dict[str, str]):
        self.id = values.get("id")
        self.username = values.get("username")
        self.avatar_hash = values.get("avatar_hash")
        self.token = values.get("token")

    def initalize(self, payload: str):
        self.id, self.discrim, self.avatar_hash, self.username = payload.split(":")

    def pretty_print(self):
        out = "\n"
        out += "==== Discord User Info ====\n"
        out += f"User:              {self.username} ({self.id})\n"
        out += f"Avatar URL:        https://cdn.discordapp.com/avatars/{self.id}/{self.avatar_hash}.png\n"
        out += f"Token (SECRET!):   {self.token}\n"
        out += "===========================\n"
        return out


class DiscordAuth:
    def __init__(self):
        self.key = RSA.generate(2048)
        self.cipher = PKCS1_OAEP.new(self.key, hashAlgo=SHA256)

    @staticmethod
    def exchange_ticket(ticket):
        req = post(
            "https://discord.com/api/v9/users/@me/remote-auth/login",
            json={"ticket": ticket},
        )
        if not req.status_code == 200:
            return None
        return req.json().get("encrypted_token")

    @property
    def public_key(self):
        pub_key = self.key.publickey()
        return "".join(pub_key.export_key().decode("utf-8").split("\n")[1:-1])

    def encrypt(self, message: str, decode=True) -> str | bytes:
        encrypted = self.cipher.encrypt(message.encode())
        encoded = b64e(encrypted)
        return encoded.decode() if decode else encoded

    def decrypt(self, encrypted_message: str, decode=True) -> str | bytes:
        decoded = b64d(encrypted_message)
        decrypted = self.cipher.decrypt(decoded)
        return decrypted.decode() if decode else decrypted


class HeartbeatManager:
    def __init__(self, ws: DiscordAuthWebsocket, interval: int):
        self.ws = ws
        self.interval = interval
        self.last = time()

    def handler(self):
        while True:
            sleep(0.5)

            current_time = time()
            time_passed = current_time - self.last + 1
            if time_passed >= 30:
                try:
                    self.ws.send("heartbeat")
                except ClosedEx:
                    return
                self.last = current_time

    def start(self):
        thread = Thread(target=self.handler)
        thread.daemon = True
        thread.start()


class DiscordQRCode:
    def __init__(self):
        self.img = None

    def generate(self, fingerprint: str):
        self.img = make(f"https://discordapp.com/ra/{fingerprint}")
        self.img.show(title="Discord QR Code")


class DiscordAuthWebsocket(WebSocketApp):
    def __init__(self, debug: bool = False):
        super().__init__(
            "wss://remote-auth-gateway.discord.gg/?v=2",
            header={"Origin": "https://discord.com"},
            on_close=self.on_close,
            on_open=self.on_open,
            on_message=self.on_message,
            on_error=self.on_error,
        )

        self.handlers: dict[str, HandlerProtocol] = {}
        self.debug = debug
        self.heart_mgr = HeartbeatManager(self, 41250)

        self.auth = DiscordAuth()
        self.qr = DiscordQRCode()
        self.user = DiscordUser({})

    def add_condition(self, op: str):
        def decorator(func: HandlerProtocol):
            if self.debug: print(f"[DEBUG] Registering handler for operation: {op}")
            self.handlers.update({f"{op}": func()})

            @wraps(func)
            def wrapper(*args, **kwargs):
                if self.debug: print(f"[DEBUG] Handling operation: {op}")
                return func(*args, **kwargs)

            return wrapper

        return decorator

    def cus_send(self, op: str, data=None):
        payload = {"op": op}
        if data is not None:
            payload.update(**data)
        self.send(dumps(payload))
        if self.debug:
            CustomLogger.fmt_json(payload, type="Send")

    def on_open(self, *args, **kwargs):
        CustomLogger.send_header("Connection opened")

    def on_close(self, *args, **kwargs):
        CustomLogger.send_header("Connection closed")

    def on_message(self, ws: WebSocket, message, *args, **kwargs):
        payload: dict = loads(message)
        if self.debug:
            CustomLogger.fmt_json(payload, type="Recv")
        self.handlers[payload["op"]](self, payload)

    def on_error(self, ws: WebSocket, *args, **kwargs):
        if isinstance(args[0], KeyboardInterrupt):
            return
        CustomLogger.send_header("An error occurred")
        print(*args)


class HandlerProtocol(Protocol):
    def __call__(self, ws: DiscordAuthWebsocket, payload: dict) -> Any:
        """
        Docstring for __call__

        :param self: The instance of the class
        :param ws: The WebSocketApp instance
        :type ws: DiscordAuthWebsocket
        :param payload: The payload received from the WebSocket
        :type payload: dict
        :return: Any
        :rtype: Any
        """
        pass


AuthWebsocket = DiscordAuthWebsocket(debug=bool(getenv("PY_DEBUG", False)))


@AuthWebsocket.add_condition("hello")
class HelloHandler(HandlerProtocol):
    def __call__(self, ws, payload):
        ws.heart_mgr.start()

        ws.cus_send("init", data={"encoded_public_key": ws.auth.public_key})


@AuthWebsocket.add_condition("nonce_proof")
class NonceProofHandler(HandlerProtocol):
    def __call__(self, ws, payload):
        ws.cus_send(
            "nonce_proof",
            data={
                "proof": url_b64e(
                    SHA256.new(
                        data=ws.auth.decrypt(
                            payload.get("encrypted_nonce"), decode=False
                        )
                    ).digest()
                )
                .decode()
                .rstrip("=")
            },
        )


@AuthWebsocket.add_condition("pending_remote_init")
class PendingRemoteInitHandler(HandlerProtocol):
    def __call__(self, ws, payload):
        ws.qr.generate(payload.get("fingerprint"))


@AuthWebsocket.add_condition("pending_ticket")
class PendingTicketHandler(HandlerProtocol):
    def __call__(self, ws, payload):
        ws.user.initalize(ws.auth.decrypt(payload.get("encrypted_user_payload")))


@AuthWebsocket.add_condition("pending_login")
class PendingLoginHandler(HandlerProtocol):
    def __call__(self, ws, payload):
        0 if ws.qr is None else ws.qr.img.close()
        ticket_exchange = DiscordAuth.exchange_ticket(payload.get("ticket"))
        ws.user.token = ws.auth.decrypt(ticket_exchange)
        print(ws.user.pretty_print())
        ws.close()


if __name__ == "__main__":
    AuthWebsocket.run_forever()
