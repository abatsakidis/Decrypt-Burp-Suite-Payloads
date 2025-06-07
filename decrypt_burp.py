import sys
import json
import base64
import string
import re
import logging
import argparse
import os
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

# ----------------- Setup logging -----------------
logger = logging.getLogger("decryptor")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter("[%(levelname)s] %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)

# ----------------- Globals -----------------
PRINTABLE_SET = set(string.printable)
COMMON_WORDS = {
    "hello", "world", "test", "password", "login", "user",
    "admin", "secret", "api", "token", "error", "success",
    "message", "data", "value", "name", "id", "email"
}

# ----------------- Utility functions -----------------
# ... (πάνω μέρος κώδικα όπως πριν)

# ----------------- Utility functions -----------------

def load_wordlist(filepath=None):
    if filepath and os.path.isfile(filepath):
        logger.info(f"Loading wordlist from {filepath}")
        with open(filepath, "r", encoding="utf-8") as f:
            return set(line.strip().lower() for line in f if line.strip())
    else:
        return COMMON_WORDS

def is_mostly_printable(text, threshold=0.9):
    if not text:
        return False
    count_printable = sum(c in PRINTABLE_SET for c in text)
    return (count_printable / len(text)) >= threshold

# Προσθέτω wordlist παράμετρο
def contains_common_words(text, wordlist, min_count=1):
    words = re.findall(r'\b[a-zA-Z]{3,}\b', text.lower())
    count = sum(1 for w in words if w in wordlist)
    return count >= min_count

def score_plaintext(text, wordlist):
    if not text:
        return 0
    printable_score = sum(c in PRINTABLE_SET for c in text) / len(text)
    words = re.findall(r'\b[a-zA-Z]{3,}\b', text.lower())
    word_count = sum(1 for w in words if w in wordlist)
    word_score = min(word_count / 5, 1)
    return (printable_score * 0.6) + (word_score * 0.4)

def xor_decrypt(data_bytes, key):
    return bytes([b ^ key for b in data_bytes])

def caesar_decrypt(text, shift):
    def shift_char(c):
        if 'a' <= c <= 'z':
            return chr((ord(c) - ord('a') - shift) % 26 + ord('a'))
        elif 'A' <= c <= 'Z':
            return chr((ord(c) - ord('A') - shift) % 26 + ord('A'))
        else:
            return c
    return ''.join(shift_char(c) for c in text)

# Στις παρακάτω συναρτήσεις περνάω το wordlist ως παράμετρο

def try_xor_key(raw, key, wordlist):
    try:
        decrypted_bytes = xor_decrypt(raw, key)
        decoded = decrypted_bytes.decode(errors='ignore')
        score = score_plaintext(decoded, wordlist)
        return ("xor", key, decoded, score)
    except Exception as e:
        logger.debug(f"XOR decode error key={key}: {e}")
        return None

def try_base64_decode(text, wordlist):
    try:
        decoded = base64.b64decode(text).decode(errors='ignore')
        score = score_plaintext(decoded, wordlist)
        return ("base64", None, decoded, score)
    except Exception:
        return None

def try_url_decode(text, wordlist):
    try:
        decoded = urllib.parse.unquote(text)
        score = score_plaintext(decoded, wordlist)
        return ("url_decode", None, decoded, score)
    except Exception:
        return None

def try_hex_decode(text, wordlist):
    clean_text = re.sub(r'0x| ', '', text)
    try:
        bytes_data = bytes.fromhex(clean_text)
        decoded = bytes_data.decode(errors='ignore')
        score = score_plaintext(decoded, wordlist)
        return ("hex_decode", None, decoded, score)
    except Exception:
        return None

def try_reverse(text, wordlist):
    try:
        reversed_text = text[::-1]
        score = score_plaintext(reversed_text, wordlist)
        return ("reverse", None, reversed_text, score)
    except Exception:
        return None

def try_caesar_shifts(base_text, wordlist):
    results = []
    rot13_text = caesar_decrypt(base_text, 13)
    results.append(("caesar", 13, rot13_text, score_plaintext(rot13_text, wordlist)))
    for shift in range(1, 26):
        if shift == 13:
            continue
        caesar_text = caesar_decrypt(base_text, shift)
        results.append(("caesar", shift, caesar_text, score_plaintext(caesar_text, wordlist)))
    return results

# ----------------- Core decrypt function -----------------

def try_decrypt(payload_b64, wordlist):
    results = []
    try:
        raw = base64.b64decode(payload_b64)
    except Exception:
        logger.debug("Base64 decode failed")
        return results

    # XOR 0..255 (parallel)
    with ThreadPoolExecutor(max_workers=16) as executor:
        futures = [executor.submit(try_xor_key, raw, k, wordlist) for k in range(256)]
        for future in as_completed(futures):
            res = future.result()
            if res:
                results.append(res)

    base64_res = try_base64_decode(payload_b64, wordlist)
    if base64_res:
        results.append(base64_res)

    try:
        base_text = raw.decode(errors='ignore')
        results.extend(try_caesar_shifts(base_text, wordlist))
    except Exception:
        pass

    for func in [try_url_decode, try_hex_decode, try_reverse]:
        res = func(payload_b64, wordlist)
        if res:
            results.append(res)

    return results

def filter_likely_plaintexts(results, wordlist, min_score=0.6):
    filtered = [r for r in results if r[3] >= min_score]
    filtered.sort(key=lambda x: x[3], reverse=True)
    return filtered

# ----------------- Processing multiple files -----------------

def process_file(filepath, wordlist, min_score=0.6, max_results=3):
    logger.info(f"Processing {filepath} ...")
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    all_results = []

    for entry in data:
        method = entry.get("method")
        url = entry.get("url")
        logger.info(f"URL: {url}  Method: {method}")
        
        entry_result = {
            "url": url,
            "method": method,
            "request": [],
            "response": []
        }

        req_body = entry.get("request", {}).get("body")
        if req_body:
            logger.info(" Trying to decrypt request body...")
            req_results = try_decrypt(req_body, wordlist)
            filtered_req = filter_likely_plaintexts(req_results, wordlist, min_score)
            if filtered_req:
                for method_, key, text, score in filtered_req[:max_results]:
                    logger.info(f"  - Method: {method_}, Key: {key}, Score: {score:.2f}")
                    entry_result["request"].append({
                        "method": method_,
                        "key": key,
                        "score": score,
                        "plaintext": text
                    })
            else:
                logger.info("  No likely plaintext found.")
        else:
            logger.info("  No request body.")

        resp_body = entry.get("response", {}).get("body")
        if resp_body:
            logger.info(" Trying to decrypt response body...")
            resp_results = try_decrypt(resp_body, wordlist)
            filtered_resp = filter_likely_plaintexts(resp_results, wordlist, min_score)
            if filtered_resp:
                for method_, key, text, score in filtered_resp[:max_results]:
                    logger.info(f"  - Method: {method_}, Key: {key}, Score: {score:.2f}")
                    entry_result["response"].append({
                        "method": method_,
                        "key": key,
                        "score": score,
                        "plaintext": text
                    })
            else:
                logger.info("  No likely plaintext found.")
        else:
            logger.info("  No response body.")

        all_results.append(entry_result)

    return all_results

def batch_process(files, wordlist, min_score=0.6, max_results=3, output_dir=None):
    all_files_results = {}
    with ThreadPoolExecutor(max_workers=min(len(files), 8)) as executor:
        futures = {executor.submit(process_file, f, wordlist, min_score, max_results): f for f in files}
        for future in as_completed(futures):
            fpath = futures[future]
            try:
                result = future.result()
                all_files_results[fpath] = result
                logger.info(f"Completed processing {fpath}")
                if output_dir:
                    if not os.path.exists(output_dir):
                        os.makedirs(output_dir)
                    base_name = os.path.basename(fpath)
                    out_file = os.path.join(output_dir, base_name + ".decrypted.json")
                    with open(out_file, "w", encoding="utf-8") as outf:
                        json.dump(result, outf, indent=2, ensure_ascii=False)
                    logger.info(f"Saved results to {out_file}")
            except Exception as e:
                logger.error(f"Error processing {fpath}: {e}")
    return all_files_results

def main():
    parser = argparse.ArgumentParser(description="Decrypt Burp Suite JSON payloads with XOR, Caesar, etc.")
    parser.add_argument("files", nargs="+", help="One or more Burp JSON files to process")
    parser.add_argument("-o", "--output-dir", help="Directory to save decrypted results JSON files")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--min-score", type=float, default=0.6, help="Minimum score threshold for plaintext filtering")
    parser.add_argument("--max-results", type=int, default=3, help="Max number of results per entry body to display/save")
    parser.add_argument("--wordlist", help="Path to custom wordlist file (one word per line)")

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    wordlist = load_wordlist(args.wordlist)

    batch_process(args.files, wordlist, args.min_score, args.max_results, args.output_dir)

if __name__ == "__main__":
    main()
