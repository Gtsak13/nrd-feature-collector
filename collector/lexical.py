"""Lexical features (offline, σε όλα τα domains).

Όλα υπολογίζονται απευθείας από το string του domain, χωρίς δίκτυο.
"""
from __future__ import annotations

import difflib
import json
import math
import re
from collections import Counter

import tldextract

from collector import config

VOWELS = set("aeiou")

# --- TLD risk list ---
# Πηγή: Al Messabi et al., "Malware Detection using DNS Records and Domain Name
# Features", ICFNDS'18, Table 2 (Suspicious Top Level Domains).
# Τα .xyz, .buzz, .ml, .cf, .ga προστέθηκαν από παρατήρηση (Spamhaus abuse stats).
TLD_RISK: dict[str, set[str]] = {
    "high":   {"tk", "top", "xyz", "buzz", "gq", "ml", "cf", "ga"},
    "medium": {"info", "online", "site", "click", "link"},
    # ό,τι δεν εμπίπτει σε καμία κατηγορία → "low"
}

# --- Suspicious keyword list ---
# Βασίζεται σε παρατηρήσεις και διαδικτυακά reports και Al Messabi et al.
# λέξεις που χρησιμοποιούνται σε phishing URLs).
SUSPICIOUS_KEYWORDS: set[str] = {
    "login", "secure", "verify", "account", "update", "bank",
    "paypal", "signin", "confirm", "webscr",
}

# Το ngram baseline φορτώνεται μία φορά (lazy) και κρατιέται εδώ.
_ngram_baseline: dict | None = None

# Η λίστα brand SLDs (από τα Tranco top domains) φορτώνεται μία φορά (lazy),
# όπως και το ngram baseline. Χτίζεται από το scripts/ngram_baseline/.
_brand_slds: list[str] | None = None


def shannon_entropy(text: str) -> float:
    """Υπολογίζει την εντροπία Shannon ενός string.

    Υψηλή τιμή σημαίνει πιο 'τυχαίο' κείμενο — χαρακτηριστικό των DGA
    domains (π.χ. 'xk3j9f2m' έχει υψηλή entropy).
    """
    if not text:
        return 0.0
    counts = Counter(text)        # πόσες φορές εμφανίζεται κάθε χαρακτήρας
    n = len(text)
    entropy = 0.0
    for count in counts.values():
        p = count / n             # πιθανότητα εμφάνισης του χαρακτήρα
        entropy -= p * math.log2(p)
    return entropy


def _load_ngram_baseline() -> dict:
    """Φορτώνει (μία φορά) το baseline συχνοτήτων από resources/ngram_baseline.json.
    """
    global _ngram_baseline
    if _ngram_baseline is None:
        if config.NGRAM_BASELINE_FILE.exists():
            _ngram_baseline = json.loads(
                config.NGRAM_BASELINE_FILE.read_text(encoding="utf-8")
            )
        else:
            _ngram_baseline = {}
    return _ngram_baseline


def _ngrams(text: str, n: int) -> list[str]:
    """Επιστρέφει όλα τα n-grams (συνεχόμενα κομμάτια μήκους n) ενός string."""
    ngrams = []
    for i in range(len(text) - n + 1):
        ngrams.append(text[i : i + n])
    return ngrams


def ngram_score(sld: str) -> float | None:
    """Μέση log-πιθανότητα των bi/trigrams του SLD ως προς baseline corpus.

    Χαμηλό score = το domain μοιάζει 'αφύσικο' σε σχέση με τα legit domains
    του baseline (χτισμένο από Tranco top-100k). Επιστρέφει None αν δεν
    υπάρχει baseline ή το SLD είναι πολύ μικρό.
    """
    baseline = _load_ngram_baseline()
    if not baseline or len(sld) < 3:
        return None

    logps: list[float] = []
    for g in _ngrams(sld, 2):
        logps.append(baseline["bigrams"].get(g, baseline["bigram_floor"]))
    for g in _ngrams(sld, 3):
        logps.append(baseline["trigrams"].get(g, baseline["trigram_floor"]))

    if not logps:
        return None
    return sum(logps) / len(logps)


def _load_brand_slds() -> list[str]:
    """Φορτώνει (μία φορά) τη λίστα brand SLDs από resources/brand_slds.json.
    """
    global _brand_slds
    if _brand_slds is None:
        if config.BRAND_SLDS_FILE.exists():
            _brand_slds = json.loads(
                config.BRAND_SLDS_FILE.read_text(encoding="utf-8")
            )
        else:
            _brand_slds = []
    return _brand_slds


def typosquatting_similarity(sld: str) -> float | None:
    """Μέγιστη ομοιότητα (0–1) του SLD με γνωστά brand SLDs (Tranco top-500).

    Πιάνει typosquatting phishing που το keyword matching χάνει: το 'paypa1'
    ΔΕΝ περιέχει τη λέξη 'paypal', αλλά της μοιάζει πολύ. Χρησιμοποιούμε το
    difflib.SequenceMatcher της standard library: ratio = 2*M/T, όπου M =
    πλήθος χαρακτήρων που ταιριάζουν και T = άθροισμα μηκών των δύο strings.
    1.0 = ταυτόσημα strings.

    Σημείωση: ΔΕΝ εξαιρούμε το exact match (ratio 1.0) — ένα NRD με SLD
    ολόιδιο με γνωστό brand (π.χ. 'google.xyz') είναι το ισχυρότερο σήμα.

    Πηγές: Szurdi et al. 2014 (typosquatting)· Yadav et al. 2010.
    Επιστρέφει None αν δεν υπάρχει brand list ή το SLD είναι <3 χαρακτήρες.
    """
    brands = _load_brand_slds()
    if not brands or len(sld) < 3:
        return None

    best_ratio = 0.0
    for brand in brands:
        ratio = difflib.SequenceMatcher(None, sld, brand).ratio()
        if ratio > best_ratio:
            best_ratio = ratio
    return round(best_ratio, 4)


def longest_consonant_run(sld: str) -> int:
    """Το μεγαλύτερο σερί συνεχόμενων συμφώνων μέσα στο SLD.

    Τα DGA strings έχουν συχνά αφύσικα μεγάλα σερί συμφώνων (π.χ. το
    'xkjbrq' έχει σερί 6), ενώ οι φυσικές λέξεις σπάνια ξεπερνούν τα 3-4
    (π.χ. 'str' στο 'string'). Ψηφία, παύλες και φωνήεντα μηδενίζουν το
    τρέχον σερί. Πηγή: FANCI (Schüppen et al., USENIX Security 2018).
    """
    longest = 0
    current = 0
    for ch in sld:
        is_consonant = ch.isalpha() and ch not in VOWELS
        if is_consonant:
            current += 1
            if current > longest:
                longest = current
        else:
            current = 0
    return longest


def tld_risk_category(tld: str) -> str:
    """Επιστρέφει 'high' / 'medium' / 'low' ανάλογα με το TLD (TLD_RISK)."""
    if tld in TLD_RISK["high"]:
        return "high"
    if tld in TLD_RISK["medium"]:
        return "medium"
    return "low"


def idn_punycode_flag(domain: str) -> bool:
    """True αν το domain χρησιμοποιεί IDN/punycode ή non-ASCII χαρακτήρες.

    Τα domain names επιτρέπουν μόνο ASCII (γράμματα, ψηφία, παύλα). Για να
    υποστηριχθούν μη-λατινικοί χαρακτήρες (π.χ. κυριλλικά, ελληνικά, αραβικά)
    χρησιμοποιείται το πρότυπο IDN (Internationalized Domain Names): κάθε
    non-ASCII τμήμα κωδικοποιείται σε ASCII με το πρόθεμα 'xn--'.
    Παράδειγμα: 'παράδειγμα.gr' → 'xn--hxajbheg2az3al.gr'.

    Αυτό εκμεταλλεύονται οι επιτιθέμενοι σε *homograph attacks*: καταχωρούν
    domain με χαρακτήρες άλλου αλφαβήτου που οπτικά ταυτίζονται με λατινικά
    (π.χ. κυριλλικό 'а' ≡ λατινικό 'a'), ώστε το 'раypal.com' να φαίνεται
    πανομοιότυπο με 'paypal.com' στον browser.
    """
    return ("xn--" in domain) or (not domain.isascii())


def suspicious_keyword_flag(domain: str) -> bool:
    """True αν το domain περιέχει κάποιο keyword από SUSPICIOUS_KEYWORDS."""
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in domain:
            return True
    return False


def compute_lexical(domain: str) -> dict:
    """Υπολογίζει ΟΛΑ τα lexical features για ένα domain (#1–#14).

    Όλοι οι υπολογισμοί γίνονται αποκλειστικά πάνω στο string, χωρίς
    δικτυακές κλήσεις. Αυτό τα κάνει ιδανικά για real-time pipeline.

    Args:
        domain: Πλήρες domain string (π.χ. 'mail.example.co.uk').

    Returns:
        Dict με 14 features έτοιμο να ενωθεί με τα υπόλοιπα features.
    """
    # Κανονικοποίηση σε πεζά: όλα τα παρακάτω (regex, φωνήεντα, keywords)
    # υποθέτουν lowercase. Η λίστα του whoisds είναι ήδη lowercase, αλλά έτσι
    # η συνάρτηση δουλεύει σωστά και αν κληθεί μόνη της με κεφαλαία.
    domain = domain.lower()

    # Χρησιμοποιούμε tldextract ώστε να χωρίσουμε σωστά ακόμα και σύνθετα
    # suffixes όπως .co.uk, .com.br κ.λπ. (το rsplit('.', 1) δεν αρκεί).
    ext = tldextract.extract(domain)
    subdomain, sld, tld = ext.subdomain, ext.domain.lower(), ext.suffix

    # Συνολικός αριθμός χαρακτήρων του domain (feature #1).
    n = len(domain)

    # --- Feature #3: digit_ratio ---
    # Μετράμε τα ψηφία σε ΟΛΟ το domain (subdomain + SLD + TLD).
    # Υψηλό ποσοστό ψηφίων (π.χ. 'a1b2c3d4.xyz') είναι χαρακτηριστικό DGA.
    digits = 0
    for ch in domain:
        if ch.isdigit():
            digits += 1

    # --- Feature #7: vowel_consonant_ratio ---
    # Μετράμε φωνήεντα & σύμφωνα ΜΟΝΟ στο SLD (χωρίς αριθμούς/σύμβολα).
    # Legit domains τείνουν σε φυσική αναλογία φωνηέντων/συμφώνων (~0.4–0.8).
    # DGA strings με τυχαία γράμματα αποκλίνουν σημαντικά από αυτό το εύρος.
    vowels = 0
    consonants = 0
    for ch in sld:
        if ch in VOWELS:
            vowels += 1
        elif ch.isalpha():      # αλφαβητικός χαρακτήρας που δεν είναι φωνήεν
            consonants += 1

    # --- Feature #14: unique_char_ratio ---
    # Πόσοι ΔΙΑΦΟΡΕΤΙΚΟΙ χαρακτήρες / συνολικό μήκος του SLD. Φυσικά ονόματα
    # επαναλαμβάνουν γράμματα (π.χ. 'google' -> 4/6 ≈ 0.67)· τυχαία strings
    # τείνουν στο 1.0 (όλοι οι χαρακτήρες διαφορετικοί).
    # Πηγή: EXPOSURE (Bilge et al.) και phishing feature sets.
    if sld:
        unique_char_ratio = len(set(sld)) / len(sld)
    else:
        unique_char_ratio = 0.0

    return {
        # Feature #1 — Μήκος domain
        # Πολύ μεγάλα domains (>50 χαρ.) συνδέονται συχνά με
        # auto-generated ή obfuscated ονόματα.
        "domain_length": n,

        # Feature #2 — Εντροπία Shannon του SLD
        # Μετράει την «τυχαιότητα» του SLD. Τιμές >3.5 υποδηλώνουν
        # DGA-like strings (π.χ. 'xk3j9f2m'); legit domains είναι
        # συνήθως <3.0 (βλ. συνάρτηση shannon_entropy παραπάνω).
        "shannon_entropy": shannon_entropy(sld),

        # Feature #3 — Αναλογία ψηφίων προς συνολικό μήκος
        # digit_ratio = #ψηφία / len(domain). Π.χ. '192abc.xyz' → 0.333.
        # Τιμές >0.3 θεωρούνται ύποπτες.
        "digit_ratio": digits / n if n else 0.0,

        # Feature #4 — Αριθμός παυλών ('-') στο πλήρες domain
        # Μία παύλα είναι συνηθισμένη (π.χ. 'my-site.com'), αλλά
        # πολλές παύλες (>3) χαρακτηρίζουν phishing patterns
        # (π.χ. 'secure-paypal-login-verify.com').
        "hyphen_count": domain.count("-"),

        # Feature #5 — Αριθμός «ειδικών» χαρακτήρων
        # Αναζητάμε οτιδήποτε ΔΕΝ είναι [a-z0-9.-].
        # Ένα domain δεν υποτίθεται να έχει τέτοιους χαρακτήρες σε
        # κανονική μορφή· παρουσία τους μπορεί να υποδηλώνει encoding
        # tricks ή άκυρο/obfuscated domain.
        "special_char_count": len(re.findall(r"[^a-z0-9.-]", domain)),

        # Feature #6 — Αριθμός υπό-τομέων (subdomains)
        # π.χ. 'a.b.evil.com' → subdomain='a.b' → split('.') → 2.
        # Βαθιά nesting (>3) είναι ασυνήθιστο για legit sites και
        # χρησιμοποιείται για να κρύψει το πραγματικό SLD.
        "subdomain_count": len(subdomain.split(".")) if subdomain else 0,

        # Feature #7 — Αναλογία φωνηέντων/συμφώνων στο SLD
        # Legit domains: ~0.4–0.8. Η max(1, consonants) αποτρέπει
        # division-by-zero σε ακραίες περιπτώσεις (π.χ. 'aaaa').
        "vowel_consonant_ratio": vowels / max(1, consonants),

        # Feature #8 — N-gram score (log-πιθανότητα)
        # Συγκρίνει τα bigrams/trigrams του SLD με baseline από legit
        # domains (Tranco top-100k). Χαμηλές αρνητικές τιμές (π.χ. -8)
        # σημαίνουν «αφύσικο» SLD. None αν δεν υπάρχει baseline ή
        # το SLD είναι <3 χαρακτήρες (βλ. ngram_score παραπάνω).
        "ngram_score": ngram_score(sld),

        # Feature #9 — Κατηγορία επικινδυνότητας TLD
        # 'high' / 'medium' / 'low' βάσει λίστας TLD_RISK (στην κορυφή του αρχείου).
        # TLDs όπως .xyz, .top, .tk κατατάσσονται ως 'high' λόγω
        # εκτεταμένης κατάχρησής τους από κακόβουλους.
        "tld_risk_category": tld_risk_category(tld),

        # Feature #10 — IDN / Punycode flag
        # True αν το domain χρησιμοποιεί punycode ('xn--') ή
        # non-ASCII χαρακτήρες. Αξιοποιείται σε homograph attacks
        # (π.χ. κυριλλικό 'а' αντί λατινικού 'a') — βλ. idn_punycode_flag.
        "idn_punycode_flag": idn_punycode_flag(domain),

        # Feature #11 — Ύποπτο keyword flag
        # True αν το domain περιέχει λέξη από SUSPICIOUS_KEYWORDS (στην κορυφή του αρχείου)
        # (π.χ. 'login', 'secure', 'paypal', 'verify', 'update').
        # Το flag είναι binary και χρησιμοποιείται ως ισχυρός
        # ενδείκτης phishing intent (βλ. suspicious_keyword_flag).
        "suspicious_keyword_flag": suspicious_keyword_flag(domain),

        # Feature #12 — Ομοιότητα με γνωστά brands (typosquatting)
        # Μέγιστο similarity ratio (0–1) του SLD με τα Tranco top brand SLDs.
        # Πιάνει ό,τι χάνει το keyword flag: το 'paypa1' μοιάζει στο 'paypal'
        # χωρίς να περιέχει τη λέξη. Βλ. typosquatting_similarity παραπάνω.
        "typosquatting_similarity": typosquatting_similarity(sld),

        # Feature #13 — Μεγαλύτερο σερί συμφώνων στο SLD
        # Τα DGA strings έχουν αφύσικα μεγάλα σερί (π.χ. 'xkjbrq' → 6)·
        # φυσικές λέξεις σπάνια >4. Βλ. longest_consonant_run παραπάνω.
        "longest_consonant_run": longest_consonant_run(sld),

        # Feature #14 — Αναλογία μοναδικών χαρακτήρων του SLD
        # (υπολογίζεται λίγο παραπάνω — βλ. το σχόλιο εκεί).
        "unique_char_ratio": unique_char_ratio,
    }

