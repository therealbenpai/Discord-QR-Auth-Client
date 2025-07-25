import base64, json, threading, time, inquirer, httpx, qrcode, websocket, os
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

DEBUG = bool(os.getenv('PY_DEBUG', False))

class Messages:
    HEARTBEAT = 'heartbeat'
    HELLO = 'hello'
    INIT = 'init'
    NONCE_PROOF = 'nonce_proof'
    PENDING_REMOTE_INIT = 'pending_remote_init'
    PENDING_TICKET = 'pending_ticket'
    PENDING_LOGIN = 'pending_login'


class DiscordUser:
    def __init__(self, values: dict[str, str]):
        self.id = values.get('id')
        self.username = values.get('username')
        self.discrim = values.get('discrim')
        self.avatar_hash = values.get('avatar_hash')
        self.token = values.get('token')

    @classmethod
    def from_payload(cls, payload: str):
        return cls(dict(zip(('id', 'discrim', 'avatar_hash', 'username'), payload.split(':'))))

    def pretty_print(self):
        out = ''
        out += f'User:            {self.username} ({self.id})\n'
        out += f'Avatar URL:      https://cdn.discordapp.com/avatars/{self.id}/{self.avatar_hash}.png\n'
        out += f'Token (SECRET!): {self.token}\n'

        return out


class DiscordAuthWebsocket:
    WS_ENDPOINT = 'wss://remote-auth-gateway.discord.gg/?v=2'
    LOGIN_ENDPOINT = 'https://discord.com/api/v9/users/@me/remote-auth/login'

    def __init__(self, debug=False):
        self.debug = debug
        self.ws = websocket.WebSocketApp(self.WS_ENDPOINT,
            on_open=self.on_open,
            on_message=self.on_message,
            on_error=self.on_error,
            on_close=self.on_close,
            header={'Origin': 'https://discord.com'})

        self.key = RSA.generate(2048)
        self.cipher = PKCS1_OAEP.new(self.key, hashAlgo=SHA256)

        self.heartbeat_interval = self.last_heartbeat = self.qr_image = self.user = None

    @property
    def public_key(self):
        return ''.join(self.key.publickey().export_key().decode('utf-8').split('\n')[1:-1])

    def heartbeat_sender(self):
        while True:
            time.sleep(0.5)  # we don't need perfect accuracy

            current_time = time.time()
            time_passed = current_time - self.last_heartbeat + 1  # add a second to be on the safe side
            if time_passed >= self.heartbeat_interval:
                try: self.send(Messages.HEARTBEAT)
                except websocket.WebSocketConnectionClosedException: return
                self.last_heartbeat = current_time

    def run(self): self.ws.run_forever()

    def send(self, op, data=None):
        payload = {'op': op}
        if data is not None: payload.update(**data)
        if self.debug: print(f'Send: {payload}')
        self.ws.send(json.dumps(payload))

    def exchange_ticket(self, ticket):
        print(f'Exch ticket: {ticket}')
        r = httpx.post(self.LOGIN_ENDPOINT, json={'ticket': ticket})
        if not r.status_code == 200: return None
        return r.json().get('encrypted_token')

    def decrypt_payload(self, encrypted_payload): return self.cipher.decrypt(base64.b64decode(encrypted_payload))

    def generate_qr_code(self, fingerprint):
        self.qr_image = img = qrcode.make(f'https://discordapp.com/ra/{fingerprint}')
        img.show(title='Discord QR Code')

    def on_open(self, ws): pass

    def on_message(self, ws, message):
        if self.debug: print(f'Recv: {message}')
        data = json.loads(message)
        op = data.get('op')
        match op:
            case Messages.HELLO:
                print('Attempting server handshake...')

                self.heartbeat_interval = data.get('heartbeat_interval') / 1000
                self.last_heartbeat = time.time()

                thread = threading.Thread(target=self.heartbeat_sender)
                thread.daemon = True
                thread.start()

                self.send(Messages.INIT, {'encoded_public_key': self.public_key})
            case Messages.NONCE_PROOF:
                self.send(
                    Messages.NONCE_PROOF,
                    {
                        'proof': base64.urlsafe_b64encode(
                            SHA256.new(data=self.decrypt_payload(data.get('encrypted_nonce'))).digest()
                        ).decode().rstrip('=')
                    }
                )
            case Messages.PENDING_REMOTE_INIT:
                self.generate_qr_code(data.get('fingerprint'))
            case Messages.PENDING_TICKET:
                self.user = DiscordUser.from_payload(self.decrypt_payload(data.get('encrypted_user_payload')).decode())
            case Messages.PENDING_LOGIN:
                if self.qr_image is not None: self.qr_image.close()
                self.user.token = self.decrypt_payload(self.exchange_ticket(data.get('ticket'))).decode()
                out = ''
                out += f'User:            {self.user.username} ({self.user.id})\n'
                out += f'Avatar URL:      https://cdn.discordapp.com/avatars/{self.user.id}/{self.user.avatar_hash}.png\n'
                out += f'Token (SECRET!): {self.user.token}\n'
                print(out)
                self.ws.close()

    def on_error(self, ws, error): print(error)

    def on_close(self, *args, **kwargs): print('-' * 22, f'Connection closed', '-' * 22, sep="\n")


if __name__ == '__main__':
    auth_ws = DiscordAuthWebsocket(debug=DEBUG)
    auth_ws.run()

    answer = inquirer.prompt([
        inquirer.Confirm('save', message='Save to info.txt?')
    ])

    if answer['save']:
        open('info.txt', 'w+').write(auth_ws.user.pretty_print())
        print('Saved.')
