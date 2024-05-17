from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


def generate_key_pair(key_length=2048):
    key = RSA.generate(key_length)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return public_key, private_key


def encrypt_message(public_key, message):
    rsa_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    encrypted_message = cipher_rsa.encrypt(message.encode())
    return encrypted_message


def decrypt_message(private_key, encrypted_message):
    rsa_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    decrypted_message = cipher_rsa.decrypt(encrypted_message)
    return decrypted_message.decode()


def main():
    public_key, private_key = generate_key_pair()

    message = "Hello, RSA encryption!"
    print("Original Message:", message)
    encrypted_message = encrypt_message(public_key, message)
    print("Encrypted Message:", encrypted_message.hex())
    decrypted_message = decrypt_message(private_key, encrypted_message)
    print("Decrypted Message:", decrypted_message)


if __name__ == '__main__':
    main()
