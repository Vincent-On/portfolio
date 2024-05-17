from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


def aes_encrypt(plaintext, key):

    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = pad(plaintext, AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)

    return iv + ciphertext


def aes_decrypt(ciphertext, key):

    iv = ciphertext[:AES.block_size]
    actual_ciphertext = ciphertext[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(actual_ciphertext)
    plaintext = unpad(padded_plaintext, AES.block_size)

    return plaintext


def aes_encrypt_file(file_path, output_path, key):
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    with open(output_path, 'wb') as f:
        f.write(iv + ciphertext)
    print(f"File '{file_path}' encrypted and saved as '{output_path}'")


def aes_decrypt_file(file_path, output_path, key):
    with open(file_path, 'rb') as f:
        iv = f.read(16)
        ciphertext = f.read()

    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

    with open(output_path, 'wb') as f:
        f.write(plaintext)
    print(f"File '{file_path}' decrypted and saved as '{output_path}'")


def main():
    key = get_random_bytes(16)
    plaintext = b"Hello, this is a secret message!"
    ciphertext = aes_encrypt(plaintext, key)
    print(key)
    print(f"Ciphertext (hex): {ciphertext.hex()}")
    decrypted_plaintext = aes_decrypt(ciphertext, key)
    print(f"Decrypted plaintext: {decrypted_plaintext.decode('utf-8')}")

    input_file_path = 'files/google.jpg'
    encrypted_file_path = 'files/google_encrypted.enc'
    decrypted_file_path = 'files/google_decrypted.jpg'

    aes_encrypt_file(input_file_path, encrypted_file_path, key)
    aes_decrypt_file(encrypted_file_path, decrypted_file_path, key)


if __name__ == '__main__':
    main()
