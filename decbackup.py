#!/usr/bin/env python3
import argparse
import sys
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # for PBKDF2 key derivation
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

CHUNK_SIZE  = 0x4000

def parse_header(header_text: str) -> dict:
    """
    Parse the header (a text block) into a dictionary.
    Lines in the header are of the form: key=value
    Lines starting with '[' are ignored.
    """
    header = {}
    for line in header_text.splitlines():
        line = line.strip()
        if not line or line.startswith("["):
            continue
        if "=" in line:
            key, value = line.split("=", 1)
            header[key.strip()] = value.strip().strip('"')
    return header

def fwcrypto_derivekey(password: str, salt: bytes, iterations: int) -> bytes:
    """
    For majversion 2:
      key is generated with PBKDF2_HMAC using SHA256.
      (Key length for AES-128 is 16 bytes.)
    """
    backend = default_backend()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=16,
        salt=salt,
        iterations=iterations,
        backend=backend
    )
    key = kdf.derive(password)
    return key

def decrypt_backup(backup_file, output_path: str, password: str):
    """
    Decrypts the backup file.
      - Reads the first 0x400 bytes as header.
      - Parses header to determine majversion.
      - For majversion==2, extracts iv, salt, pbkdf_iterations from the header
        and derives the key using PBKDF2_HMAC (SHA256).
      - Computes the encrypted payload offset
      - Then decrypts the remaining data using AES-128-CBC.
      - Removes PKCS7 padding and writes the result to output_file.
    """
    # Read header (assume header is 0x400 bytes)
    header_bytes = backup_file.read(0x400)
    try:
        header_text = header_bytes.decode("utf-8")
    except UnicodeDecodeError:
        # If decoding fails, try ignoring errors.
        header_text = header_bytes.decode("utf-8", errors="ignore")
    header = parse_header(header_text)

    # Get majversion and algo (should be 1 or 2; algo must be 1 for AES128-CBC)
    majversion = int(header.get("majversion", "1"))
    algo = int(header.get("algo", "1"))
    if algo != 1:
        raise ValueError("Unsupported algorithm (only AES128-CBC supported)")

    if majversion == 2:
        # For majversion 2, read iv, salt, and pbkdf_iterations from the header.
        # For example, from your hook output:
        #   iv=eb289d61ffae487dee5444947f1688ff
        #   salt=f332ae41630e85aabc0b764431868f51
        #   pbkdf_iterations=10000
        iv = bytes.fromhex(header["iv"])
        salt = bytes.fromhex(header["salt"])
        iterations = int(header["pbkdf_iterations"])
        key = fwcrypto_derivekey(password or b'', salt, iterations)[:16]
    else:
        raise ValueError("Unsupported majversion: {}".format(majversion))

    # Compute encrypted data offset
    backup_file.seek(0)
    chunk = backup_file.read(CHUNK_SIZE)
    offset = chunk[0x402] << 8 | chunk[0x401] << 0x10 | chunk[0x400] << 0x18
    if offset < CHUNK_SIZE:
        offset = chunk[0x403] + offset + 0x408
    backup_file.seek(offset)

    # Now decrypt the remaining file using AES128-CBC.
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

    try:
        with open(output_path, "wb") as output_file:
            while True:
                chunk = backup_file.read(CHUNK_SIZE)
                if not chunk:
                    break
                dec_chunk = decryptor.update(chunk)
                unpadded_data = unpadder.update(dec_chunk)
                output_file.write(unpadded_data)

            dec_final = decryptor.finalize()
            unpadded_final = unpadder.update(dec_final) + unpadder.finalize()
            output_file.write(unpadded_final)
    except Exception as e:
        sys.stderr.write(f"Error processing backup file: {e}\n")
        raise

    print("Decryption complete. Output written to:", output_file)

def main():
    parser = argparse.ArgumentParser(description="Decrypt backup file using firmware algorithm")
    parser.add_argument("-i", "--input", required=True, help="Input backup file")
    parser.add_argument("-o", "--output", required=True, help="Output decrypted archive file")
    parser.add_argument("-p", "--password", required=False, help="Password for decryption")
    args = parser.parse_args()

    with open(args.input, "rb") as fin:
        decrypt_backup(fin, args.output, args.password)

if __name__ == "__main__":
    main()
