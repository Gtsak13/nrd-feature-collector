"""Χτίσιμο του n-gram baseline για το feature #6 (ngram_score) ΚΑΙ
εξαγωγή της λίστας brand SLDs για το feature #8 (typosquatting_similarity).

Τρέχει ΜΙΑ φορά (όχι μέρος της ημερήσιας ροής): κατεβάζει τη λίστα Tranco top
sites, μετράει τα bigrams/trigrams των SLDs και σώζει τις log-πιθανότητές τους
στο resources/ngram_baseline.json. Παράλληλα, εξάγει τα top-500 unique SLDs στο
resources/brand_slds.json, ώστε το lexical.py να τα χρησιμοποιεί για
typosquatting detection. Μετά, το lexical.py τα φορτώνει lazy.

Αναλυτική εξήγηση (τι είναι n-gram, γιατί log-πιθανότητες, τι είναι το
smoothing) και όλες οι πηγές/links: βλ. README.md σε αυτόν τον φάκελο.

Εκτέλεση από το root του project (nrd-feature-collector/):
    python -m scripts.ngram_baseline.build_ngram_baseline
"""
from __future__ import annotations

import io
import json
import math
import zipfile

import requests
import tldextract

from collector import config
# Χρησιμοποιούμε το ΙΔΙΟ _ngrams με το lexical.py, ώστε το baseline να
# «τεμαχίζει» τα strings ακριβώς όπως θα τα τεμαχίσει αργότερα το scoring.
from collector.lexical import _ngrams

# Σταθερό permanent URL της λίστας Tranco (CSV μέσα σε ZIP: γραμμές "rank,domain").
TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"

# Πόσα domains από την κορυφή της λίστας θα χρησιμοποιήσουμε για το baseline.
TOP_N = 100_000

# Πόσα unique brand SLDs θα εξαχθούν για typosquatting similarity.
BRAND_TOP_N = 500

# Πόσες φορές υποθέτουμε ότι εμφανίστηκε ένα ΑΓΝΩΣΤΟ gram (smoothing floor).
FLOOR_COUNT = 0.1


def download_tranco_domains(limit: int) -> list[str]:
    """Κατεβάζει τη λίστα Tranco και επιστρέφει τα πρώτα `limit` domains.

    Η λίστα έρχεται ως ZIP που μέσα έχει ένα CSV με γραμμές της μορφής
    "rank,domain" (π.χ. "1,google.com"). Το ανοίγουμε στη μνήμη (όπως και
    στο download.py) και κρατάμε μόνο τη στήλη domain.
    """
    print(f"Κατέβασμα Tranco list από {TRANCO_URL} ...")
    resp = requests.get(TRANCO_URL, timeout=60)
    resp.raise_for_status()

    # Το resp.content είναι τα bytes του ZIP· το io.BytesIO τα κάνει να
    # «μοιάζουν» με αρχείο ώστε το zipfile να τα διαβάσει από τη μνήμη.
    with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
        # Βρίσκουμε το πρώτο .csv μέσα στο ZIP, όποιο όνομα κι αν έχει.
        csv_name = None
        for name in zf.namelist():
            if name.endswith(".csv"):
                csv_name = name
                break
        if csv_name is None:
            raise RuntimeError("Δεν βρέθηκε .csv μέσα στο Tranco ZIP.")
        text = zf.read(csv_name).decode("utf-8", errors="ignore")

    # Κρατάμε το domain από κάθε γραμμή, μέχρι να μαζέψουμε `limit` domains.
    domains = []
    for line in text.splitlines():
        # κάθε γραμμή: "rank,domain" -> split στο πρώτο κόμμα
        parts = line.split(",")
        if len(parts) < 2:
            continue
        domain = parts[1].strip().lower()
        if domain:
            domains.append(domain)
        if len(domains) >= limit:
            break

    print(f"Κρατήθηκαν {len(domains)} domains από τη λίστα.")
    return domains


def extract_brand_slds(domains: list[str], limit: int) -> list[str]:
    """Εξάγει τα πρώτα `limit` unique SLDs από τη λίστα domains.

    Χρησιμοποιείται για typosquatting detection — τα πιο δημοφιλή SLDs είναι
    αυτά που οι επιτιθέμενοι μιμούνται (π.χ. 'google', 'paypal', 'amazon').
    Κρατάμε μόνο SLDs με μήκος ≥3, γιατί τα πιο κοντά (π.χ. 'fb') δίνουν
    πολλά false positives στο similarity matching.
    """
    seen = set()
    brand_slds = []
    for domain in domains:
        sld = tldextract.extract(domain).domain.lower()
        if len(sld) < 3:
            continue
        if sld in seen:
            continue
        seen.add(sld)
        brand_slds.append(sld)
        if len(brand_slds) >= limit:
            break

    print(f"Εξήχθησαν {len(brand_slds)} unique brand SLDs (≥3 χαρακτήρες).")
    return brand_slds


def count_ngrams(domains: list[str], n: int) -> dict[str, int]:
    """Μετράει πόσες φορές εμφανίζεται κάθε n-gram στα SLDs όλων των domains.

    Επιστρέφει dict { n-gram -> πλήθος εμφανίσεων }.
    """
    counts: dict[str, int] = {}
    for domain in domains:
        # Κρατάμε ΜΟΝΟ το SLD (π.χ. 'google' από 'google.com'), όπως ακριβώς
        # κάνει και το ngram_score στο lexical.py.
        sld = tldextract.extract(domain).domain.lower()
        # Για κάθε n-gram του SLD, αυξάνουμε τον μετρητή του κατά 1.
        for gram in _ngrams(sld, n):
            counts[gram] = counts.get(gram, 0) + 1
    return counts


def counts_to_logprobs(counts: dict[str, int]) -> tuple[dict[str, float], float]:
    """Μετατρέπει τις συχνότητες (counts) σε log-πιθανότητες.

    Επιστρέφει (logprobs, floor):
      - logprobs: dict { n-gram -> ln(P(gram)) }
      - floor:    η log-πιθανότητα ενός ΑΓΝΩΣΤΟΥ gram (smoothing)
    """
    # Σύνολο όλων των εμφανίσεων (ο παρονομαστής της πιθανότητας).
    total = 0
    for count in counts.values():
        total += count

    # ln(P(gram)) για κάθε gram που είδαμε. Στρογγυλοποιούμε στα 4 δεκαδικά
    # για να μη φουσκώνει το JSON αρχείο.
    logprobs: dict[str, float] = {}
    for gram, count in counts.items():
        probability = count / total
        logprobs[gram] = round(math.log(probability), 4)

    # Floor: ένα άγνωστο gram «σαν να» εμφανίστηκε FLOOR_COUNT φορές.
    floor = round(math.log(FLOOR_COUNT / total), 4)
    return logprobs, floor


def build_baseline() -> None:
    """Ολόκληρη η διαδικασία: download -> μέτρημα -> log-πιθανότητες -> save JSON.

    Εξάγει ΔΥΟ αρχεία στο resources/:
      1. ngram_baseline.json — bi/trigram log-πιθανότητες (feature #6)
      2. brand_slds.json     — top-500 unique SLDs (feature #8, typosquatting)
    """
    domains = download_tranco_domains(TOP_N)

    # --- Brand SLDs (feature #8: typosquatting_similarity) ---
    brand_slds = extract_brand_slds(domains, BRAND_TOP_N)
    config.RESOURCES_DIR.mkdir(exist_ok=True)
    config.BRAND_SLDS_FILE.write_text(
        json.dumps(brand_slds, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"Η λίστα brand SLDs σώθηκε στο {config.BRAND_SLDS_FILE}")

    # --- N-gram baseline (feature #6: ngram_score) ---
    print("Μέτρημα bigrams ...")
    bigram_counts = count_ngrams(domains, 2)
    bigram_logprobs, bigram_floor = counts_to_logprobs(bigram_counts)

    print("Μέτρημα trigrams ...")
    trigram_counts = count_ngrams(domains, 3)
    trigram_logprobs, trigram_floor = counts_to_logprobs(trigram_counts)

    # Η δομή του JSON είναι ΑΚΡΙΒΩΣ αυτή που περιμένει το lexical.ngram_score:
    # bigrams / trigrams (τα dictionaries) + τα δύο floors για άγνωστα grams.
    baseline = {
        "bigrams": bigram_logprobs,
        "trigrams": trigram_logprobs,
        "bigram_floor": bigram_floor,
        "trigram_floor": trigram_floor,
        # μερικά metadata, καθαρά για τεκμηρίωση (το lexical.py τα αγνοεί):
        "_source": "Tranco top sites list (https://tranco-list.eu/)",
        "_domains_used": len(domains),
        "_distinct_bigrams": len(bigram_logprobs),
        "_distinct_trigrams": len(trigram_logprobs),
    }

    # Βεβαιωνόμαστε ότι υπάρχει ο φάκελος resources/ και γράφουμε το αρχείο.
    config.NGRAM_BASELINE_FILE.write_text(
        json.dumps(baseline, ensure_ascii=False), encoding="utf-8"
    )
    print(f"Το baseline σώθηκε στο {config.NGRAM_BASELINE_FILE}")
    print(
        f"  {len(bigram_logprobs)} bigrams, {len(trigram_logprobs)} trigrams, "
        f"από {len(domains)} domains."
    )


if __name__ == "__main__":
    build_baseline()
