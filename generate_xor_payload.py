import base64
import sys

def xor_encrypt(data: bytes, key: int) -> bytes:
    return bytes([b ^ key for b in data])

def create_payload(plaintext: str, key: int) -> str:
    encrypted = xor_encrypt(plaintext.encode(), key)
    b64_encoded = base64.b64encode(encrypted).decode()
    return b64_encoded

def main(input_file, key, output_file):
    with open(input_file, "r", encoding="utf-8") as f:
        plaintext = f.read()

    payload = create_payload(plaintext, key)

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(payload)
    
    print(f"[+] Payload written to {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(f"Usage: python3 {sys.argv[0]} <input.txt> <xor_key> <output.txt>")
        sys.exit(1)
    input_file = sys.argv[1]
    xor_key = int(sys.argv[2])
    output_file = sys.argv[3]
    main(input_file, xor_key, output_file)
