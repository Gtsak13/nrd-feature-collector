# nrd-feature-collector — Daily NRD Feature Collector

Τρέχει **μία φορά τη μέρα**: κατεβάζει τη λίστα Newly Registered Domains (NRDs) από το whoisds.com, διαλέγει 1000 τυχαία domains, υπολογίζει **34 features** σε 3 ομάδες (ανά πηγή δεδομένων), βγάζει ένα ασθενές (weak) **label** (benign / malicious / unknown) και τα σώζει σε CSV.

## Δομή

```
collector/
├── config.py            # ρυθμίσεις, paths, API keys (.env), σταθερές
├── download.py          # κατέβασμα + parsing whoisds ZIP
├── lexical.py           # features από το string (offline) — #1–#14
├── dns_records.py       # DNS records — #15–#23
├── enrichment.py        # GeoIP/ASN + WHOIS + reputation (+ MX rep) — #24–#34
├── labeling.py          # ο κανόνας για το weak label
└── main.py              # ενώνει τα πάντα + σώζει το αρχείο
scripts/ngram_baseline/           # one-time: baseline για feature #8 + brand SLDs για #12
resources/   # στατικά δεδομένα (baselines, brand SLDs, GeoLite2 mmdb)
raw/         # cache των ημερήσιων whoisds .txt
output/      # features_YYYY-MM-DD.csv
```

Κάθε αρχείο έχει μία βασική συνάρτηση `compute_*(domain, ...) -> dict`.
Έτσι κάθε αρχείο δοκιμάζεται μόνο του και αντιστοιχεί σε ένα κεφάλαιο της
διπλωματικής.

## Εγκατάσταση (Clean Install)

Ακολουθούν αναλυτικές οδηγίες για την πλήρη εγκατάσταση του project, είτε βρίσκεστε σε περιβάλλον **Windows** είτε σε **Linux / macOS**.

### Προαπαιτούμενα
1. **Python 3.10** ή νεότερη έκδοση. Βεβαιωθείτε ότι είναι περασμένη στο PATH του συστήματός σας (για Windows επιλέξτε "Add Python to PATH" κατά την εγκατάσταση).
2. **Git** (για την κλωνοποίηση του αποθετηρίου).

### Βήμα 1: Λήψη του κώδικα (Clone)
Ανοίξτε το τερματικό σας (Command Prompt/PowerShell για Windows, ή το Terminal για Linux/macOS) και τρέξτε:
```bash
git clone https://github.com/Gtsak13/nrd-feature-collector.git
cd nrd-feature-collector
```

### Βήμα 2: Δημιουργία και Ενεργοποίηση Virtual Environment
Συστήνεται θερμά η χρήση εικονικού περιβάλλοντος (virtual environment) για την απομόνωση των βιβλιοθηκών.

**Για Windows (PowerShell / Command Prompt):**
```powershell
python -m venv .venv
# Για PowerShell:
.\.venv\Scripts\Activate.ps1
# Ή για Command Prompt (cmd.exe):
.\.venv\Scripts\activate.bat
```

**Για Linux / macOS:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```
*(Αν όλα πήγαν καλά, το όνομα `.venv` θα εμφανιστεί στην αρχή της γραμμής εντολών σας).*

### Βήμα 3: Εγκατάσταση Εξαρτήσεων
Με το περιβάλλον ενεργοποιημένο, εγκαταστήστε τις απαιτούμενες βιβλιοθήκες της Python (όπως `requests`, `dnspython`, `tqdm`, `geoip2`, κλπ):
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### Βήμα 4: Ρύθμιση Κλειδιών (API Keys)
Ο κώδικας χρειάζεται κλειδιά πρόσβασης για εξωτερικές υπηρεσίες. Δημιουργήστε το δικό σας `.env` αρχείο με βάση το παράδειγμα:

**Για Windows:**
```powershell
copy .env.example .env
```
**Για Linux / macOS:**
```bash
cp .env.example .env
```
Ανοίξτε το αρχείο `.env` με έναν text editor και συμπληρώστε τα κλειδιά:
- `ABUSEIPDB_API_KEY`: Δωρεάν κλειδί από το AbuseIPDB.
- `SPAMHAUS_DQS_KEY`: Δωρεάν κλειδί από το Spamhaus Data Query Service.
- *Σημείωση: Αν δεν ορίσετε κλειδιά, τα αντίστοιχα features/labels απλά θα παρακάμπτονται.*

### Βήμα 5: Κατέβασμα Τοπικών Βάσεων (GeoLite2)
Για την εύρεση της τοποθεσίας (χώρα) και του δικτύου (ASN) των διευθύνσεων IP, το project χρησιμοποιεί τις δωρεάν βάσεις της MaxMind (GeoLite2).
1. Κατεβάστε τα αρχεία **GeoLite2-ASN.mmdb** και **GeoLite2-Country.mmdb** (απαιτείται δωρεάν εγγραφή στο MaxMind).
2. Δημιουργήστε τον φάκελο `resources/` στον κεντρικό φάκελο (αν δεν υπάρχει ήδη) και τοποθετήστε τα δύο αρχεία μέσα.

> ⚠️ **ΣΗΜΑΝΤΙΚΟ**: Η άδεια χρήσης της MaxMind **απαγορεύει** τη δημόσια διανομή αυτών των αρχείων! Μην τα κάνετε ποτέ commit σε δημόσιο GitHub repository. Βεβαιωθείτε ότι το `.gitignore` περιλαμβάνει τον κανόνα `*.mmdb` (ή τον ίδιο τον φάκελο `resources/`).

### Βήμα 6: Αρχικοποίηση Μοντέλων Αναφοράς (N-grams & Brands)
Το στάδιο των Λεξιλογικών χαρακτηριστικών χρειάζεται κάποια baselines που χτίζονται τοπικά βάσει μεγάλων λιστών εγκυρότητας (Tranco list).
Τρέξτε το παρακάτω script **μία φορά** για να κατεβάσει αυτόματα τη λίστα Tranco και να δημιουργήσει τα αρχεία `ngram_baseline.json` και `brand_slds.json` στον φάκελο `resources/`:
```bash
python -m scripts.ngram_baseline.build_ngram_baseline
```

Είστε έτοιμοι! Μπορείτε πλέον να προχωρήσετε στην Εκτέλεση.

## Εκτέλεση

```powershell
python -m collector.main                      # για σήμερα
python -m collector.main --date 2026-06-01    # συγκεκριμένη μέρα
python -m collector.main --limit 100          # test run με 100 domains
```

Κάθε domain γράφεται στο CSV **αμέσως** μόλις υπολογιστεί (όχι στο τέλος) —
έτσι μια διακοπή στη μέση ενός run δεν χάνει τη μέχρι τότε δουλειά.

