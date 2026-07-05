"""Κεντρικές ρυθμίσεις του collector.

Εδώ μαζεύονται όλα τα paths, τα API keys (από το αρχείο .env) και οι
σταθερές που χρησιμοποιούν τα υπόλοιπα modules.
"""
from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

# Φορτώνει τις μεταβλητές από το αρχείο .env στο root του project.
load_dotenv()

# --- Paths -----------------------------------------------------------------
# ROOT = ο φάκελος nrd-feature-collector/ (ένα επίπεδο πάνω από το collector/).
ROOT = Path(__file__).resolve().parent.parent
RESOURCES_DIR = ROOT / "resources"   # στατικά δεδομένα (baselines, λίστες, mmdb)
RAW_DIR = ROOT / "raw"               # cache των ημερήσιων whoisds .txt
OUTPUT_DIR = ROOT / "output"         # τα ημερήσια csv αποτελέσματα

# Συγκεκριμένα αρχεία resources.
NGRAM_BASELINE_FILE = RESOURCES_DIR / "ngram_baseline.json"
BRAND_SLDS_FILE = RESOURCES_DIR / "brand_slds.json"
GEOLITE_ASN_DB = RESOURCES_DIR / "geolite2" / "GeoLite2-ASN.mmdb"
GEOLITE_COUNTRY_DB = RESOURCES_DIR / "geolite2" / "GeoLite2-Country.mmdb"

# --- API keys (από .env) ---------------------------------------------------
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
MAXMIND_LICENSE_KEY = os.getenv("MAXMIND_LICENSE_KEY")

# Spamhaus DQS (Data Query Service) key. Αν οριστεί, τα Spamhaus queries πάνε
# σε ειδικές ζώνες *.dq.spamhaus.net με τον key μέσα στο όνομα — δουλεύουν μέσω
# οποιουδήποτε resolver (300k queries/μέρα free).
SPAMHAUS_DQS_KEY = os.getenv("SPAMHAUS_DQS_KEY")

# Fallback: custom resolver IP για τα public Spamhaus zones (zen/dbl.spamhaus.org).
# Χρησιμοποιείται ΜΟΝΟ όταν ΔΕΝ υπάρχει DQS key.
SPAMHAUS_RESOLVER = os.getenv("SPAMHAUS_RESOLVER")

# --- Σταθερές συλλογής -----------------------------------------------------
SAMPLE_SIZE = 1000          # πόσα domains διαλέγουμε τυχαία κάθε μέρα
DNS_TIMEOUT = 5             # seconds, timeout για τα DNS queries
REPUTATION_SLEEP = 0.5     # seconds, απλό rate limit ανάμεσα σε reputation κλήσεις

# Παύση ανάμεσα στα WHOIS queries. Οι WHOIS servers (ειδικά της Verisign για
# τα .com) κόβουν προσωρινά IPs που κάνουν πολλά συνεχόμενα port-43 queries.
WHOIS_SLEEP = 0.5          # seconds

# Το AbuseIPDB επιστρέφει ένα "Confidence Score" (0-100). Επιλέγουμε το 50 
# ως όριο (threshold) για να χαρακτηριστεί μια IP ως κακόβουλη (malicious). 
ABUSEIPDB_THRESHOLD = 50

# --- Ετικέτες ----------------------------------------------------------------
LABEL_COLUMNS = ["label", "label_reason"]
