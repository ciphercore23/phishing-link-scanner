import re
import logging
from urllib.parse import urlparse
from colorama import init, Fore

# Initialize colorama
init(autoreset=True)

# Logging setup
logging.basicConfig(
    filename='phishing_detector.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

# Suspicious phishing keywords
phishing_keywords = [
    "login", "secure", "account", "update", "verify", "confirm",
    "bank", "password", "signin", "safety", "suspicious",
    "alert", "suspended", "click", "here"
]

# URL shorteners
shorteners = [
    "bit.ly",
    "tinyurl.com",
    "rb.gy",
    "goo.gl",
    "ow.ly",
    "cutt.ly",
    "t.co"
]

# Suspicious TLDs
suspicious_tlds = [
    ".xyz",
    ".fun",
    ".store",
    ".top",
    ".click",
    ".club",
    ".online",
    ".buzz"
]


# Validate URL
def is_valid_url(url):
    regex = re.compile(
        r'^(https?|ftp)://'
        r'([a-zA-Z0-9.-]+)'
        r'(\.[a-zA-Z]{2,})'
        r'(:[0-9]+)?'
        r'(\/.*)?$'
    )

    return re.match(regex, url)


# Main detection function
def detect_phishing(url):
    score = 0
    reasons = []

    if not is_valid_url(url):
        print(Fore.RED + "\n[!] Invalid URL!")
        return

    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    # 1. Insecure HTTP
    if url.startswith("http://"):
        score += 2
        reasons.append("Uses insecure HTTP")

    # 2. Too many subdomains
    if domain.count(".") > 3:
        score += 1
        reasons.append("Too many subdomains")

    # 3. Suspicious symbols
    if "@" in url:
        score += 2
        reasons.append("Uses '@' symbol")

    if "-" in domain:
        score += 1
        reasons.append("Uses hyphen in domain")

    # 4. Long URL
    if len(url) > 70:
        score += 2
        reasons.append("URL is unusually long")

    # 5. Encoded characters
    if "%" in url:
        score += 1
        reasons.append("Uses encoded characters")

    # 6. Phishing keywords
    for word in phishing_keywords:
        if word in url.lower():
            score += 1
            reasons.append(f"Suspicious keyword: {word}")

    # 7. URL shorteners
    for shortener in shorteners:
        if shortener in url:
            score += 3
            reasons.append("Uses URL shortener")

    # 8. Suspicious TLDs
    for tld in suspicious_tlds:
        if domain.endswith(tld):
            score += 1
            reasons.append(f"Suspicious TLD: {tld}")

    # Risk level
    if score >= 5:
        risk_level = "High Risk"
    elif score >= 2:
        risk_level = "Suspicious"
    else:
        risk_level = "Safe"

    # Save logs
    logging.info(
        f"URL: {url} | Score: {score} | Reasons: {', '.join(reasons)}"
    )

    # Output
    print(Fore.CYAN + "\n==============================")
    print("PHISHING URL ANALYSIS")
    print("==============================")
    print(f"URL: {url}")
    print(f"Risk Score: {score}")
    print(f"Status: {risk_level}")

    if reasons:
        print(Fore.YELLOW + "\nDetection Reasons:")
        for reason in reasons:
            print(Fore.WHITE + f" - {reason}")

    print(Fore.CYAN + "==============================\n")


# Main program
def main():
    print(Fore.CYAN + "\n=== PHISHING DETECTION SYSTEM ===")

    while True:
        url = input("Enter URL to scan (press Enter to exit): ")

        if url == "":
            print("Exiting detector...")
            break

        detect_phishing(url)


if __name__ == "__main__":
    main()
