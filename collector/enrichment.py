"""External Enrichment — features & label sources (passive, σε ένα αρχείο).

Εμπλουτισμός από εξωτερικές/τρίτες πηγές για το ήδη resolved domain/IP —
καμία σύνδεση στον host.

  ── FEATURES ──────────────────────────────────────────────────────────
  (a) Infrastructure : GeoIP/ASN + reverse DNS (PTR)   -> μόνο resolved
  (b) WHOIS          : Registrar, dates (age)          -> όλα
  (c) Reputation     : AbuseIPDB / Spamhaus            -> μόνο resolved
  (d) MX Reputation  : Spamhaus ZEN στις MX IPs        -> όσα έχουν MX

"""
from __future__ import annotations

import datetime
import time

import geoip2.database
import dns.resolver
import dns.reversename

from collector import config

import requests
import whois

# Cache reputation ανά IP — ζει μόνο όσο τρέχει το script. Πολλά NRDs
# μοιράζονται την ίδια IP, οπότε γλιτώνουμε API calls.
ip_cache: dict[str, dict] = {}

# Οι GeoLite2 readers ανοίγουν ΜΙΑ φορά (lazy) και μένουν ανοιχτοί.
_asn_reader = None
_country_reader = None

# Resolver για το reverse DNS (PTR), με timeout ώστε να μην κολλάει.
_resolver = dns.resolver.Resolver()
_resolver.timeout = config.DNS_TIMEOUT
_resolver.lifetime = config.DNS_TIMEOUT

# Resolver για τα Spamhaus queries. Με DQS key δουλεύει ΟΠΟΙΟΣΔΗΠΟΤΕ resolver
# (ο key κάνει το authentication), οπότε ο system resolver αρκεί. Χωρίς DQS, τα
# public zones δεν απαντούν μέσω public resolvers (8.8.8.8 κ.λπ.) — γι' αυτό
# επιτρέπουμε custom resolver IP μέσω config.SPAMHAUS_RESOLVER.
_spamhaus_resolver = dns.resolver.Resolver()
if config.SPAMHAUS_RESOLVER:
    _spamhaus_resolver.nameservers = [config.SPAMHAUS_RESOLVER]
_spamhaus_resolver.timeout = config.DNS_TIMEOUT
_spamhaus_resolver.lifetime = config.DNS_TIMEOUT


# --- (a) Infrastructure ----------------------------------------------------
def _open_readers() -> None:
    """Ανοίγει (μία φορά) τις GeoLite2 βάσεις ASN & Country από το resources/."""
    global _asn_reader, _country_reader
    if _asn_reader is None:
        _asn_reader = geoip2.database.Reader(str(config.GEOLITE_ASN_DB))
        _country_reader = geoip2.database.Reader(str(config.GEOLITE_COUNTRY_DB))


def _lookup_asn(ip: str) -> int | None:
    """ASN (αριθμός) της IP από τη GeoLite2-ASN βάση, ή None αν δεν βρεθεί."""
    try:
        return _asn_reader.asn(ip).autonomous_system_number
    except Exception:
        return None


def _lookup_country(ip: str) -> str | None:
    """ISO κωδικός χώρας (π.χ. 'US') της IP από τη GeoLite2-Country βάση, ή None.

    Αν λείπει η χώρα (π.χ. anycast IPs όπως το 1.1.1.1), πέφτουμε πίσω στη
    'registered_country' (τη χώρα εγγραφής του δικτύου).
    """
    try:
        response = _country_reader.country(ip)
    except Exception:
        return None
    country = response.country.iso_code
    if country is None:
        country = response.registered_country.iso_code
    return country


def _has_ptr(ip: str) -> bool:
    """True αν η IP έχει reverse DNS (PTR) record."""
    try:
        reversed_name = dns.reversename.from_address(ip)
        _resolver.resolve(reversed_name, "PTR")
        return True
    except Exception:
        return False


def lookup_infrastructure(ip: str) -> dict:
    """GeoIP/ASN + PTR για μία IP (features #19–#21).

    Τα asn/geo_country διαβάζονται από ΤΟΠΙΚΑ .mmdb (offline)· μόνο το PTR
    κάνει ένα DNS query.
    """
    _open_readers()
    return {
        # Feature #19 — ASN (≈ hosting provider/δίκτυο). Ορισμένα ASN
        # φιλοξενούν δυσανάλογο abuse (bulletproof hosting).
        "asn": _lookup_asn(ip),

        # Feature #20 — Χώρα φιλοξενίας της IP (ISO code, π.χ. 'US').
        "geo_country": _lookup_country(ip),

        # Feature #21 — Έχει η IP reverse DNS (PTR); Legit infra συνήθως ναι.
        "ptr_present": _has_ptr(ip),
    }


# --- (b) WHOIS -------------------------------------------------------------
def lookup_whois(domain: str) -> dict:
    """WHOIS best-effort (features #22–#25).

    Το WHOIS είναι το «ληξιαρχείο» των domains: ποιος το καταχώρησε, πότε, για
    πόσο. Τι σημαίνει κάθε feature:
      - #22 registrar: η εταιρεία καταχώρησης (π.χ. GoDaddy). Κάποιοι registrars
        χρησιμοποιούνται δυσανάλογο για abuse.
      - #23 domain_age_days: μέρες από την καταχώρηση. Για NRDs είναι ~0 —
        χρήσιμο ως sanity check ότι όντως μιλάμε για νέο domain.
      - #24 registration_duration_days: για πόσο καταχωρήθηκε. Τα κακόβουλα
        domains συχνά παίρνονται για τον ελάχιστο χρόνο (1 χρόνο) — φθηνά &
        αναλώσιμα.
      - #25 privacy_protection_flag: αν τα στοιχεία ιδιοκτήτη είναι κρυμμένα
        πίσω από privacy/proxy service.

    Προσοχή: το WHOIS format αλλάζει ανά TLD και πολλά πεδία είναι πλέον κρυμμένα
    λόγω GDPR -> περιμένουμε πολλά None. Γι' αυτό είναι best-effort.
    """
    result = {
        "registrar": None,
        "domain_age_days": None,
        "registration_duration_days": None,
        "privacy_protection_flag": None,
    }
    
    try:
        w = whois.whois(domain)
        
        # Registrar
        registrar = w.get("registrar")
        if isinstance(registrar, list):
            registrar = registrar[0]
        result["registrar"] = registrar
        
        # Dates (creation, expiration)
        creation_date = w.get("creation_date")
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        expiration_date = w.get("expiration_date")
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
            
        now = datetime.datetime.now()
        
        if isinstance(creation_date, datetime.datetime):
            # Αφαιρούμε το timezone (αν υπάρχει) για να συγκρίνουμε σωστά με το now
            creation_date_naive = creation_date.replace(tzinfo=None)
            age = (now - creation_date_naive).days
            result["domain_age_days"] = age
            
            if isinstance(expiration_date, datetime.datetime):
                expiration_date_naive = expiration_date.replace(tzinfo=None)
                duration = (expiration_date_naive - creation_date_naive).days
                if duration > 0:
                    result["registration_duration_days"] = duration
                    
        # Privacy Flag (Απλό heuristic: ψάχνουμε γνωστές λέξεις σε όλο το whois string).
        # Αντί για μονογραμμικό any(...), ανοίγουμε το loop ώστε να φαίνεται καθαρά
        # ότι αρκεί ΕΣΤΩ ΜΙΑ από τις λέξεις-κλειδιά για να ανάψει το flag.
        text = str(w).lower()
        privacy_keywords = ["privacy", "redacted", "proxy", "protect", "hidden"]
        privacy_found = False
        for keyword in privacy_keywords:
            if keyword in text:
                privacy_found = True
                break
        result["privacy_protection_flag"] = privacy_found
            
    except Exception as e:
        print(f"  WHOIS error για {domain}: {e}")

    # Παύση ανάμεσα στα WHOIS queries
    time.sleep(config.WHOIS_SLEEP)
        
    return result


# ═══════════════════════════════════════════════════════════════════════════
# REPUTATION FEATURES (#26 – #29)
# ═══════════════════════════════════════════════════════════════════════════

# --- (c) Reputation --------------------------------------------------------
def query_abuseipdb(ip: str) -> int | None:
    """abuseConfidenceScore (0–100) από το AbuseIPDB API (feature #26 ΚΑΙ πηγή του weak label).

    Το AbuseIPDB είναι μια κοινοτική βάση όπου χρήστες αναφέρουν IPs που
    είδαν να κάνουν επιθέσεις. Το score 0–100 είναι η «βεβαιότητα» ότι η IP
    είναι κακόβουλη (0 = καθαρή, 100 = σίγουρα κακόβουλη). Στο labeling
    θεωρούμε malicious όταν ξεπερνά το config.ABUSEIPDB_THRESHOLD.
    """
    if not config.ABUSEIPDB_API_KEY:
        return None
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": config.ABUSEIPDB_API_KEY
    }
    try:
        r = requests.get(url, headers=headers, params={"ipAddress": ip}, timeout=10)
        if r.status_code == 200:
            return r.json()["data"]["abuseConfidenceScore"]
        else:
            print(f"  AbuseIPDB σφάλμα {r.status_code}: {r.text[:50]}")
            return None
    except Exception as e:
        print(f"  AbuseIPDB exception: {e}")
        return None


def _spamhaus_listed(query_name: str) -> bool | None:
    """Κάνει ένα DNSBL query στο Spamhaus και ερμηνεύει το αποτέλεσμα.

    Πώς δουλεύει ένα DNSBL: ρωτάς για A record ενός ειδικού ονόματος. Επιστρέφει:
      - True  -> listed (πραγματική απάντηση στο 127.0.x.x)
      - False -> ΟΧΙ listed (NXDOMAIN)
      - None  -> σφάλμα/timeout, ή κωδικός σφάλματος (δεν ξέρουμε)
    Κοινό για zen (IP) και dbl (domain), γι' αυτό είναι ξεχωριστή συνάρτηση.
    """
    try:
        answer = _spamhaus_resolver.resolve(query_name, "A")
    except dns.resolver.NXDOMAIN:
        return False
    except Exception:
        return None

    # Οι έγκυρες απαντήσεις listing είναι στο 127.0.x.x. Οι κωδικοί 127.255.255.x
    # ΔΕΝ είναι listing — σημαίνουν σφάλμα (π.χ. λάθος/ληγμένο DQS key, υπέρβαση
    # ορίου, query μέσω μη-εξουσιοδοτημένου resolver). Τους θεωρούμε «δεν ξέρουμε»
    # ώστε να ΜΗΝ βάλουμε κατά λάθος malicious label.
    for rdata in answer:
        if rdata.address.startswith("127.255.255."):
            return None
    return True


def query_spamhaus_zen(ip: str) -> bool | None:
    """DNSBL check στο Spamhaus ZEN για μία IP (feature #27 ΚΑΙ πηγή label· IP-level)."""
    # Το zen θέλει την IP με αντεστραμμένα τα octets, π.χ. 1.2.3.4 -> '4.3.2.1'.
    reversed_ip = ".".join(reversed(ip.split(".")))
    if config.SPAMHAUS_DQS_KEY:
        # DQS: ο key μπαίνει ανάμεσα στα δεδομένα και τη ζώνη .dq.spamhaus.net.
        query_name = f"{reversed_ip}.{config.SPAMHAUS_DQS_KEY}.zen.dq.spamhaus.net"
    else:
        query_name = f"{reversed_ip}.zen.spamhaus.org"   # public zone (fallback)
    return _spamhaus_listed(query_name)


def query_spamhaus_dbl(domain: str) -> bool | None:
    """DNSBL check στο Spamhaus DBL για το domain (feature #28 ΚΑΙ πηγή label· domain-level).

    Σε αντίθεση με το zen (που ελέγχει IP), το DBL (Domain Block List) ελέγχει
    το ΙΔΙΟ το domain. Έτσι πιάνει κακόβουλα domains ακόμη κι αν φιλοξενούνται
    σε «καθαρή» IP.
    """
    if config.SPAMHAUS_DQS_KEY:
        query_name = f"{domain}.{config.SPAMHAUS_DQS_KEY}.dbl.dq.spamhaus.net"
    else:
        query_name = f"{domain}.dbl.spamhaus.org"        # public zone (fallback)
    return _spamhaus_listed(query_name)


def check_ip_reputation(ip: str) -> dict:
    """Ελέγχει μια IP στα reputation services, με cache ανά IP.

    Αν την έχουμε ξαναδεί σήμερα, επιστρέφει την αποθηκευμένη τιμή. Σε
    αποτυχία/εξάντληση ορίου: βάζει None και προχωράει (try/except).
    """
    if ip in ip_cache:
        return ip_cache[ip]

    result = {
        "abuseipdb_score": None,
        "spamhaus_zen_listed": None,
    }
    try:
        result["abuseipdb_score"] = query_abuseipdb(ip)
        result["spamhaus_zen_listed"] = query_spamhaus_zen(ip)
    except Exception as e:  # noqa: BLE001 — θέλουμε να συνεχίσουμε ό,τι κι αν γίνει
        print(f"  reputation error για {ip}: {e}")

    time.sleep(config.REPUTATION_SLEEP)  # απλό rate limit
    ip_cache[ip] = result
    return result


# Cache των MX-reputation ελέγχων ανά IP. Πολλά domains μοιράζονται τον ίδιο
# mail provider (π.χ. Google/Outlook), οπότε γλιτώνουμε επαναλαμβανόμενα queries.
mx_zen_cache: dict[str, bool | None] = {}


def mx_reputation(mx_ips: list[str] | None) -> bool | None:
    """True αν ΟΠΟΙΑΔΗΠΟΤΕ IP των mail servers (MX) είναι listed στο Spamhaus ZEN.

    Feature #29 (mx_spamhaus_zen_listed) — ΜΟΝΟ feature, ΔΕΝ μπαίνει στο label.
    Ελέγχει τη reputation της mail υποδομής (σε αντίθεση με το #27 που ελέγχει
    την web IP). Χρησιμοποιεί Spamhaus ZEN (γρήγορο DNS query, IP-level).

    Επιστρέφει:
      - True  -> τουλάχιστον μία MX IP είναι listed (κόκκινη σημαία)
      - False -> ελέγξαμε MX IP(s) και καμία δεν είναι listed
      - None  -> δεν υπήρχαν MX IPs, ή δεν μπορέσαμε να ελέγξουμε καμία
    """
    if not mx_ips:
        return None

    any_checked = False
    for ip in mx_ips:
        if ip not in mx_zen_cache:
            mx_zen_cache[ip] = query_spamhaus_zen(ip)
        listed = mx_zen_cache[ip]
        if listed is None:
            continue                     # error σε αυτό το IP — δοκίμασε τα άλλα
        any_checked = True
        if listed:
            return True                  # μία «βρώμικη» MX αρκεί
    if any_checked:
        return False
    return None


# --- Orchestration ---------------------------------------------------------
def compute_enrichment(domain: str, ips: list[str] | None,
                       mx_ips: list[str] | None) -> dict:
    """Ενώνει όλα τα enrichment features (#19–#29) για ένα domain.

    `ips`    = οι IPs των A records (web/hosting) — ή None/[] αν δεν αναλύεται.
    `mx_ips` = οι IPs των MX (mail servers) — ή None/[] αν δεν έχει MX.
    Τα IP-based features υπολογίζονται μόνο αν υπάρχει IP· το WHOIS και το
    spamhaus_dbl (domain-level) τρέχουν σε όλα· το mx reputation (#29) όσα έχουν MX.
    """
    # Το τελικό λεξικό ξεκινά με None παντού· ό,τι καταφέρουμε να βρούμε
    # παρακάτω το γράφει από πάνω (result.update). Έτσι, αν κάποια πηγή
    # αποτύχει, το αντίστοιχο feature μένει απλώς None αντί να λείπει.
    result = {
        # ── FEATURES ──────────────────────────────────────────────────
        # (a) Infrastructure — βλ. lookup_infrastructure
        "asn": None,                        # Feature #19
        "geo_country": None,                # Feature #20
        "ptr_present": None,                # Feature #21
        # (b) WHOIS — βλ. lookup_whois
        "registrar": None,                  # Feature #22
        "domain_age_days": None,            # Feature #23
        "registration_duration_days": None, # Feature #24
        "privacy_protection_flag": None,    # Feature #25
        # (c) Reputation Features (web/hosting IP + domain)
        "abuseipdb_score": None,            # Feature #26
        "spamhaus_zen_listed": None,        # Feature #27
        "spamhaus_dbl_listed": None,        # Feature #28
        # (d) MX Reputation Feature — mail υποδομή (ΟΧΙ label, χωρίς leakage)
        "mx_spamhaus_zen_listed": None,     # Feature #29
    }

    # ── 1. FEATURES ───────────────────────────────────────────────────
    # IP-based (Infrastructure) — μόνο αν το domain αναλύθηκε σε IP.
    if ips:
        first_ip = ips[0]
        infra = lookup_infrastructure(first_ip)         # (a) Infrastructure
        result.update(infra)

    # Domain-based (WHOIS) — τρέχει σε ΟΛΑ τα domains
    result.update(lookup_whois(domain))                  # (b) WHOIS

    # ── 2. REPUTATION FEATURES ────────────────────────────────────────
    # IP-based (Reputation) — μόνο αν υπάρχει IP
    if ips:
        first_ip = ips[0]
        reputation = check_ip_reputation(first_ip)      # (c) Reputation (IP)
        result.update(reputation)

    # Domain-based (Spamhaus DBL) — τρέχει σε ΟΛΑ τα domains
    result["spamhaus_dbl_listed"] = query_spamhaus_dbl(domain)

    # ── 3. MX REPUTATION FEATURE (#29) ────────────────────────────────
    # Reputation των mail servers (MX IPs) στο Spamhaus ZEN. Feature-only —
    # ΔΕΝ μπαίνει στο labeling, οπότε δεν εισάγει leakage.
    result["mx_spamhaus_zen_listed"] = mx_reputation(mx_ips)

    return result
