from Crypto.Cipher import AES
import base64

BLOCK_SIZE = 16

def pad_message(msg):
    """Pads the message to make its length a multiple of BLOCK_SIZE."""
    pad_len = BLOCK_SIZE - (len(msg) % BLOCK_SIZE)
    return msg + chr(pad_len) * pad_len

def encrypt(key, msg):
    """Encrypts the message using AES in ECB mode."""
    aes = AES.new(key, AES.MODE_ECB)
    padded_msg = pad_message(msg)
    encrypted = aes.encrypt(padded_msg.encode())
    encrypted_base64 = base64.b64encode(encrypted).decode()
    return encrypted_base64

def decrypt(key, encrypted_base64):
    """Decripts the message using AES in ECB mode."""
    encrypted = base64.b64decode(encrypted_base64.encode())
    aes = AES.new(key, AES.MODE_ECB)
    return aes.decrypt(encrypted)