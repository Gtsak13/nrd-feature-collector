# nrd-feature-collector — Daily NRD Feature Collector

Τρέχει **μία φορά τη μέρα**: κατεβάζει τη λίστα Newly Registered Domains (NRDs) από το whoisds.com, διαλέγει 1000 τυχαία domains, υπολογίζει **29 features** σε 3 ομάδες (ανά πηγή δεδομένων), βγάζει ένα ασθενές (weak) **label** (benign / malicious / unknown) και τα σώζει σε CSV.

## Δομή

```
collector/
├── config.py            # ρυθμίσεις, paths, API keys (.env), σταθερές
├── download.py          # κατέβασμα + parsing whoisds ZIP
├── lexical.py           # features από το string (offline) — #1–#10
├── dns_records.py       # DNS records — #11–#18
├── enrichment.py        # GeoIP/ASN + WHOIS + reputation (+ MX rep) — #19–#29
├── labeling.py          # ο κανόνας για το weak label
└── main.py              # ενώνει τα πάντα + σώζει το αρχείο
scripts/ngram_baseline/           # one-time: baseline για feature #6 + brand SLDs για #8
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

## Εξαγόμενα Χαρακτηριστικά (Extracted Features)

Ο συλλέκτης εξάγει 29 διακριτά χαρακτηριστικά, χωρισμένα σε τρεις βασικές κατηγορίες: Λεξιλογικά (Lexical), DNS, και Υποδομής/Φήμης (Host-based).

| # | Όνομα Χαρακτηριστικού | Τύπος | Περιγραφή |
|---|---|---|---|
| **Λεξιλογικά** | | | |
| 1 | `domain_length` | int | Μήκος του πλήρους ονόματος τομέα |
| 2 | `shannon_entropy` | float | Εντροπία Shannon του κύριου ονόματος (SLD) |
| 3 | `digit_ratio` | float | Αναλογία ψηφίων προς το συνολικό μήκος |
| 4 | `hyphen_count` | int | Αριθμός παυλών ('-') στο πλήρες όνομα τομέα |
| 5 | `vowel_consonant_ratio` | float | Αναλογία φωνηέντων/συμφώνων στο SLD |
| 6 | `ngram_score` | float | Βαθμολογία n-gram (λογαριθμική πιθανότητα) |
| 7 | `tld_risk_category` | string | Κατηγορία επικινδυνότητας του TLD (π.χ. HIGH, LOW) |
| 8 | `typosquatting_similarity` | float | Βαθμολογία ομοιότητας με τα 500 κορυφαία domains του Tranco |
| 9 | `longest_consonant_run` | int | Το μεγαλύτερο σερί συνεχόμενων συμφώνων στο SLD |
| 10 | `unique_char_ratio` | float | Αναλογία μοναδικών χαρακτήρων στο SLD |
| **DNS** | | | |
| 11 | `resolves_flag` | boolean | Αν το domain αναλύεται σε τουλάχιστον μία διεύθυνση IP |
| 12 | `num_a_records` | int | Αριθμός εγγραφών A (IPv4) |
| 13 | `min_ttl` | int | Ελάχιστος χρόνος ζωής (TTL) μεταξύ των εγγραφών A |
| 14 | `mx_count` | int | Αριθμός εγγραφών διακομιστή αλληλογραφίας (MX) |
| 15 | `num_ns` | int | Αριθμός εγγραφών διακομιστή ονομάτων (NS) |
| 16 | `has_spf` | boolean | Αν υπάρχει εγγραφή TXT για Sender Policy Framework (SPF) |
| 17 | `cname_present` | boolean | Αν υπάρχει εγγραφή Canonical Name (CNAME) |
| 18 | `num_aaaa_records` | int | Αριθμός εγγραφών AAAA (IPv6) |
| **Υποδομής/Φήμης** | | | |
| 19 | `asn` | int | Αυτόνομο Σύστημα (ASN) της διεύθυνσης IP φιλοξενίας |
| 20 | `geo_country` | string | Κωδικός χώρας (GeoIP) της διεύθυνσης IP φιλοξενίας |
| 21 | `ptr_present` | boolean | Αν η IP φιλοξενίας έχει εγγραφή αντίστροφης ανάλυσης (PTR) |
| 22 | `registrar` | string | Όνομα του καταχωρητή (Registrar) από τα δεδομένα WHOIS |
| 23 | `domain_age_days` | int | Ηλικία του domain σε ημέρες |
| 24 | `registration_duration_days` | int | Συνολική διάρκεια καταχώρησης σε ημέρες |
| 25 | `privacy_protection_flag` | boolean | Αν είναι ενεργοποιημένη η προστασία ιδιωτικότητας στο WHOIS |
| 26 | `abuseipdb_score` | int | Δείκτης κατάχρησης της IP (0-100) από το AbuseIPDB |
| 27 | `spamhaus_zen_listed` | boolean | Αν η IP φιλοξενίας βρίσκεται στη λίστα Spamhaus ZEN |
| 28 | `spamhaus_dbl_listed` | boolean | Αν το όνομα του domain βρίσκεται στη λίστα Spamhaus DBL |
| 29 | `mx_spamhaus_zen_listed` | boolean | Αν κάποια IP από τους MX servers βρίσκεται στη λίστα Spamhaus ZEN |

## Παράδειγμα Ροής Ανάλυσης

Παρακάτω ακολουθεί ένα διάγραμμα που αναπαριστά τη ροή ανάλυσης για ένα υποθετικό κακόβουλο domain (`secure-login-paypal-update.com`).

<table style="width: 100%; text-align: left; border-collapse: collapse;">
  <thead>
    <tr>
      <th style="width: 50%; text-align: center; border-bottom: 2px solid #ddd; padding-bottom: 10px;">Ροή Επεξεργασίας</th>
      <th style="width: 50%; border-bottom: 2px solid #ddd; padding-bottom: 10px;">Εξαγόμενα Χαρακτηριστικά</th>
    </tr>
  </thead>
  <tbody>
    <!-- Domain -->
    <tr>
      <td style="text-align: center; padding: 15px;">
        <code style="font-size: 1.1em; background-color: #e6f2ff; padding: 5px 10px; border-radius: 5px; color: #0056b3;">secure-login-paypal-update.com</code><br><br>
        ⬇
      </td>
      <td></td>
    </tr>
    <!-- Lexical -->
    <tr>
      <td style="text-align: center; padding: 15px; border-right: 2px dashed #ddd;">
        <div style="background-color: #f0fdf4; border: 1px solid #bbf7d0; padding: 10px; border-radius: 5px;">
          <strong>Τοπικός Υπολογισμός</strong><br>
          <small>(Λεξιλογικά Χαρακτηριστικά)</small>
        </div>
      </td>
      <td style="padding: 15px;">
        <code style="font-size: 0.85em;">
        #1 domain_length = 30<br>
        #2 shannon_entropy = 3.45<br>
        #3 digit_ratio = 0.0<br>
        #4 hyphen_count = 3<br>
        #5 vowel_consonant_ratio = 0.73<br>
        #6 ngram_score = -45.2<br>
        #7 tld_risk_category = "HIGH"<br>
        #8 typosquatting_similarity = 0.85<br>
        #9 longest_consonant_run = 3<br>
        #10 unique_char_ratio = 0.65
        </code>
      </td>
    </tr>
    <tr>
      <td style="text-align: center;">⬇</td>
      <td></td>
    </tr>
    <!-- DNS -->
    <tr>
      <td style="text-align: center; padding: 15px; border-right: 2px dashed #ddd;">
        <div style="background-color: #f0fdf4; border: 1px solid #bbf7d0; padding: 10px; border-radius: 5px;">
          <strong>Ερωτήματα DNS</strong><br>
          <small>(A, NS, MX, CNAME, TXT)</small>
        </div>
      </td>
      <td style="padding: 15px;">
        <code style="font-size: 0.85em;">
        #11 resolves_flag = True<br>
        #12 num_a_records = 1<br>
        #13 min_ttl = 300<br>
        #14 mx_count = 1<br>
        #15 num_ns = 2<br>
        #16 has_spf = False<br>
        #17 cname_present = False<br>
        #18 num_aaaa_records = 0
        </code>
      </td>
    </tr>
    <tr>
      <td style="text-align: center; padding: 10px;">
        ⬇<br>
        <code style="background-color: #fffbeb; padding: 3px 6px; border: 1px solid #fde68a; border-radius: 4px; font-size: 0.9em; color: #92400e;">IP: 198.51.100.42</code><br>
        <code style="background-color: #fffbeb; padding: 3px 6px; border: 1px solid #fde68a; border-radius: 4px; font-size: 0.9em; color: #92400e; margin-top: 4px; display: inline-block;">MX IP: 203.0.113.10</code><br>
        ⬇
      </td>
      <td></td>
    </tr>
    <!-- GeoIP & ASN -->
    <tr>
      <td style="text-align: center; padding: 15px; border-right: 2px dashed #ddd;">
        <div style="background-color: #f0fdf4; border: 1px solid #bbf7d0; padding: 10px; border-radius: 5px;">
          <strong>Τοπικές Βάσεις</strong><br>
          <small>(GeoLite2, ASN)</small>
        </div>
      </td>
      <td style="padding: 15px;">
        <code style="font-size: 0.85em;">
        #19 asn = 20473<br>
        #20 geo_country = "RU"<br>
        #21 ptr_present = False
        </code>
      </td>
    </tr>
    <tr>
      <td style="text-align: center;">⬇</td>
      <td></td>
    </tr>
    <!-- WHOIS -->
    <tr>
      <td style="text-align: center; padding: 15px; border-right: 2px dashed #ddd;">
        <div style="background-color: #f0fdf4; border: 1px solid #bbf7d0; padding: 10px; border-radius: 5px;">
          <strong>Πρωτόκολλο WHOIS</strong><br>
          <small>(Καταχώρηση)</small>
        </div>
      </td>
      <td style="padding: 15px;">
        <code style="font-size: 0.85em;">
        #22 registrar = "CheapName LLC"<br>
        #23 domain_age_days = 0<br>
        #24 registration_duration_days = 365<br>
        #25 privacy_protection_flag = True
        </code>
      </td>
    </tr>
    <tr>
      <td style="text-align: center;">⬇</td>
      <td></td>
    </tr>
    <!-- Reputation -->
    <tr>
      <td style="text-align: center; padding: 15px; border-right: 2px dashed #ddd;">
        <div style="background-color: #f0fdf4; border: 1px solid #bbf7d0; padding: 10px; border-radius: 5px;">
          <strong>Υπηρεσίες Φήμης</strong><br>
          <small>(AbuseIPDB, Spamhaus)</small>
        </div>
      </td>
      <td style="padding: 15px;">
        <code style="font-size: 0.85em;">
        #26 abuseipdb_score = 85<br>
        #27 spamhaus_zen_listed = True<br>
        #28 spamhaus_dbl_listed = False<br>
        #29 mx_spamhaus_zen_listed = True
        </code>
      </td>
    </tr>
    <tr>
      <td style="text-align: center;">⬇</td>
      <td></td>
    </tr>
    <!-- Label -->
    <tr>
      <td style="text-align: center; padding: 15px; border-right: 2px dashed #ddd;">
        <div style="background-color: #fef2f2; border: 1px solid #fecaca; padding: 10px; border-radius: 5px; color: #991b1b;">
          <strong>Κανόνας Ετικέτας</strong><br>
          <small>(ZEN==True) Ή (AbuseIPDB &ge; 50) Ή (DBL==True)</small>
        </div>
      </td>
      <td style="padding: 15px;">
        <strong style="color: #991b1b;">Τελική Ετικέτα:</strong> <code>True</code> (Κακόβουλο)
      </td>
    </tr>
  </tbody>
</table>
