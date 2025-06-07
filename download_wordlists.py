import requests

def download_wordlist(url, filename):
    try:
        print(f"Downloading wordlist from {url} ...")
        response = requests.get(url)
        response.raise_for_status()
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(response.text)
        print(f"Saved wordlist to {filename}")
    except Exception as e:
        print(f"Error downloading wordlist: {e}")

if __name__ == "__main__":
    url = "https://raw.githubusercontent.com/dwyl/english-words/master/words.txt"
    filename = "english_words.txt"
    download_wordlist(url, filename)
