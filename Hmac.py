from SHA import SHA

class Hmac:
    def hmac(message, key):
        auth = int(SHA.hash(key), 16)
        data = str(auth ^ int.from_bytes(("5c"*16).encode(), "big"))
        data += str(auth ^ int.from_bytes(("36"*16).encode(), "big"))
        data += message
        return SHA.hash(data)

    def verHmac(message, tag, key):
        return tag == Hmac.hmac(message, key)
