# Decrypt Burp Suite Payloads

This project provides Python scripts to decrypt and analyze Burp Suite JSON payloads, which may be encoded or obfuscated using methods such as XOR encryption, Caesar cipher, Base64, URL encoding, and hex encoding.

---

## Folder Structure
``` 
.
├── burp.json                 # Sample Burp Suite JSON file with captured requests/responses
├── decrypt_burp.py           # Main script to decrypt Burp Suite JSON payloads
├── download_wordlists.py     # Utility script to download wordlists for plaintext scoring
├── generate_xor_payload.py   # Helper script to generate XOR encoded payloads for testing
└── wordlist                  # Example custom wordlist file (one word per line)
``` 

---

## Features

- Automatically tries multiple decoding and decryption techniques:
  - Base64 decoding
  - XOR brute force (keys 0-255)
  - Caesar cipher shifts (1-25)
  - URL decoding
  - Hex decoding
  - String reversal
- Uses scoring based on printable characters and common word matches to identify likely plaintext results.
- Supports custom wordlists for improved plaintext detection.
- Multi-threaded processing for speed.
- Batch processing of multiple Burp Suite JSON files.
- Save decrypted results to JSON files.

---

## Usage

1. **Download or create a wordlist**  
   You can use the included `download_wordlists.py` script to fetch a wordlist:
  
   python download_wordlists.py

This will save a wordlist file (e.g., english_words.txt) which can be used for scoring.

2. Run the decryptor

    python decrypt_burp.py <burp_json_file> -o output_dir --min-score 0.6 --max-results 3 --verbose --wordlist wordlist

    Replace <burp_json_file> with your Burp Suite JSON filename.

     *  Use -o to specify output directory for decrypted results.

     *  Use --min-score to adjust the plaintext score threshold.

     *  Use --max-results to limit the number of results shown per entry.

     *  Use --verbose to enable debug logging.

     *  Use --wordlist to specify a custom wordlist file.

## Dependencies

    Python 3.6+

    requests (for downloading wordlists)

Install dependencies with:

pip install requests

## Notes

    The scoring mechanism depends on the quality of the wordlist; you can improve detection by supplying larger or domain-specific wordlists.

    The XOR brute-force and Caesar cipher try all possible keys/shifts, so processing large files can take time.

    This tool is designed for Burp Suite JSON export files that contain captured HTTP request and response bodies.

## License

This project is provided as-is under the MIT License.