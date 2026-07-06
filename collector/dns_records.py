"""DNS Record features (ένα DNS query ανά domain, σε όλα).

Χρησιμοποιεί dnspython με timeout (config.DNS_TIMEOUT). Για NRDs, πολλά
domains δεν αναλύονται ακόμη (NXDOMAIN)· αυτό ΔΕΝ είναι σφάλμα αλλά
πληροφορία (feature resolves_flag).

Σε αποτυχία/απουσία record: try/except -> κενές/None τιμές, δεν ρίχνουμε
το script.
"""
from __future__ import annotations

import concurrent.futures
import dns.exception
import dns.resolver

from collector import config

# Ο resolver είναι αυτός που ρωτάει τους DNS servers «ποια είναι τα records
# αυτού του domain;». Φτιάχνουμε έναν για όλο το module, με timeout ώστε να
# μην κολλάει το script σε αργά/άρρωστα domains.
_resolver = dns.resolver.Resolver()
_resolver.timeout = config.DNS_TIMEOUT     # timeout ανά nameserver
_resolver.lifetime = config.DNS_TIMEOUT    # συνολικό timeout του query


def _query(domain: str, record_type: str):
    """Κάνει ένα DNS query και επιστρέφει το answer, ή None αν δεν υπάρχει record.

    Καλύπτει όλες τις «κανονικές» αποτυχίες (NXDOMAIN, χωρίς record, timeout)
    επιστρέφοντας None — ο caller το ερμηνεύει ως «δεν υπάρχει αυτό το record».
    """
    # Το resolve() σηκώνει διάφορα exceptions (δεν υπάρχει domain, δεν υπάρχει
    # αυτό το record, timeout κ.λπ.). Εδώ τα αντιμετωπίζουμε όλα το ίδιο:
    # «δεν βρέθηκε record» -> None. Η ξεχωριστή διάκριση γίνεται μόνο για τα A
    # records (βλ. _query_a), όπου το rcode μάς ενδιαφέρει.
    try:
        return _resolver.resolve(domain, record_type)
    except Exception:
        return None


def _query_a(domain: str) -> tuple[list[str], int | None, str]:
    """A query με λεπτομέρεια: επιστρέφει (ips, min_ttl, rcode).

    Το rcode μας λέει ΓΙΑΤΙ δεν αναλύθηκε ένα domain (NXDOMAIN/timeout/...),
    που είναι χρήσιμη πληροφορία για NRDs.
    """
    try:
        answer = _resolver.resolve(domain, "A")
    except dns.resolver.NXDOMAIN:
        return [], None, "NXDOMAIN"          # το domain δεν υπάρχει
    except dns.resolver.NoAnswer:
        return [], None, "NOERROR"           # υπάρχει το domain αλλά χωρίς A record
    except dns.resolver.NoNameservers:
        return [], None, "SERVFAIL"
    except dns.exception.Timeout:
        return [], None, "timeout"
    except Exception:
        return [], None, "error"

    # Το answer είναι μια συλλογή από A records. Κάθε ένα (rdata) έχει ένα
    # πεδίο .address με την IP — τις μαζεύουμε όλες σε μια λίστα.
    ips = []
    for rdata in answer:
        ips.append(rdata.address)

    # όλα τα A records μοιράζονται ένα TTL (το TTL του rrset)
    min_ttl = answer.rrset.ttl
    return ips, min_ttl, "NOERROR"


def _count(answer) -> int:
    """Πλήθος records σε ένα answer (0 αν είναι None)."""
    if answer is None:
        return 0
    return len(answer)


def _has_spf(txt_answer) -> bool:
    """True αν κάποιο TXT record είναι SPF (ξεκινά με 'v=spf1')."""
    if txt_answer is None:
        return False
    for rdata in txt_answer:
        # ένα TXT record μπορεί να έρθει σε κομμάτια (strings) — τα ενώνουμε
        parts = []
        for chunk in rdata.strings:
            parts.append(chunk.decode("utf-8", errors="ignore"))
        text = "".join(parts)
        if text.startswith("v=spf1"):
            return True
    return False


def _resolve_mx_ips(mx_answer) -> list[str]:
    """Βρίσκει τις IPs των mail servers (MX hosts) ενός domain.

    Κάθε MX record δείχνει σε ένα hostname (π.χ. 'mail.example.com'). Για κάθε
    ένα κάνουμε ένα A query ώστε να βρούμε την IP του — αυτές τις IPs θα τις
    ελέγξει το enrichment στο Spamhaus ZEN (feature #29, mx reputation).
    Επιστρέφει λίστα με ΜΟΝΑΔΙΚΕΣ IPs (κενή αν δεν υπάρχουν MX ή δεν αναλύονται).
    """
    if mx_answer is None:
        return []
    mx_ips = []
    for rdata in mx_answer:
        # Το .exchange είναι το hostname του mail server (με τελεία στο τέλος).
        host = str(rdata.exchange).rstrip(".")
        a_answer = _query(host, "A")
        if a_answer is None:
            continue
        for a_rdata in a_answer:
            ip = a_rdata.address
            if ip not in mx_ips:        # κράτα μόνο μοναδικές IPs
                mx_ips.append(ip)
    return mx_ips


def compute_dns(domain: str) -> dict:
    """Υπολογίζει ΟΛΑ τα DNS features για ένα domain (features #11–#18).

    Στο dict περιλαμβάνονται και οι IPs των A records (βοηθητικό πεδίο 'ips'),
    γιατί τις χρειάζεται το enrichment (τρέχει μόνο σε resolved domains).
    """
    # --- Εκτέλεση όλων των DNS queries ταυτόχρονα (Concurrency) ---
    # Κάθε query έχει timeout config.DNS_TIMEOUT δευτερόλεπτα. Αν γίνονταν
    # σειριακά, ένα εντελώς νεκρό domain θα περίμενε 6 * 5 = 30 δευτερόλεπτα.
    # Με το ThreadPoolExecutor, όλα τρέχουν παράλληλα και ο μέγιστος χρόνος
    # αναμονής πέφτει στα 5 δευτερόλεπτα.
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        future_a = executor.submit(_query_a, domain)
        future_mx = executor.submit(_query, domain, "MX")
        future_ns = executor.submit(_query, domain, "NS")
        future_txt = executor.submit(_query, domain, "TXT")
        future_cname = executor.submit(_query, domain, "CNAME")
        future_aaaa = executor.submit(_query, domain, "AAAA")

        # --- A records (καθορίζει αν αναλύεται το domain) ---
        ips, min_ttl, rcode = future_a.result()
        num_a_records = len(ips)
        resolves_flag = num_a_records > 0

        # --- MX ---
        mx_answer = future_mx.result()
        mx_count = _count(mx_answer)

        # --- NS ---
        ns_answer = future_ns.result()
        num_ns = _count(ns_answer)

        # --- TXT / SPF ---
        txt_answer = future_txt.result()
        has_spf = _has_spf(txt_answer)

        # --- CNAME ---
        cname_answer = future_cname.result()
        cname_present = cname_answer is not None

        # --- AAAA (IPv6) ---
        # Τα AAAA records δίνουν τις IPv6 διευθύνσεις. Πολλά εφήμερα κακόβουλα
        # domains δεν ρυθμίζουν IPv6.
        aaaa_answer = future_aaaa.result()
        num_aaaa_records = _count(aaaa_answer)

    # --- MX IPs (βοηθητικό πεδίο, ΟΧΙ feature) ---
    # Οι IPs των mail servers. Χρειάζονται ένα δεύτερο επίπεδο DNS (MX host ->
    # A record), γι' αυτό γίνονται εκτός του παραπάνω block. Το enrichment θα
    # ελέγξει τη reputation τους στο Spamhaus ZEN (feature #29).
    mx_ips = _resolve_mx_ips(mx_answer)

    return {
        # Feature #11 — Αν αναλύεται το domain + ο κωδικός απάντησης (rcode)
        # resolves_flag = True αν πήραμε έστω ένα A record. Το rcode είναι
        # ΠΛΗΡΟΦΟΡΙΑΚΟ πεδίο (ΟΧΙ feature): εξηγεί το «γιατί όχι» ('NXDOMAIN',
        # 'timeout', 'SERVFAIL') και δεν τροφοδοτεί το μοντέλο.
        "resolves_flag": resolves_flag,
        "rcode": rcode,

        # Feature #12 — Πλήθος A records
        # Πόσες IPs επέστρεψε το domain. 0 αν δεν αναλύεται.
        "num_a_records": num_a_records,

        # Feature #13 — Ελάχιστο TTL των A records
        # Το TTL λέει για πόσα δευτερόλεπτα «ζει» μια εγγραφή στην cache.
        # Πολύ μικρό TTL συνδέεται με fast-flux (συχνή αλλαγή IP). None αν
        # δεν αναλύεται.
        "min_ttl": min_ttl,

        # Feature #14 — Πλήθος MX records
        # Τα MX records δείχνουν ποιος server δέχεται email για το domain. Η
        # τιμή > 0 σημαίνει ότι το domain μπορεί να στέλνει/λαμβάνει email
        # (δηλαδή το πλήθος κωδικοποιεί και το boolean «έχει MX»).
        "mx_count": mx_count,

        # Feature #15 — Πλήθος NS records
        # Οι NS (name servers) είναι οι servers που «φιλοξενούν» το DNS του
        # domain. Πολύ λίγοι/περίεργοι NS μπορεί να είναι ένδειξη.
        "num_ns": num_ns,

        # Feature #16 — Ύπαρξη SPF record
        # Το SPF (TXT που ξεκινά με 'v=spf1') δηλώνει ποιοι επιτρέπεται να
        # στέλνουν email για το domain — η ύπαρξή του δείχνει πιο «σοβαρή» ρύθμιση.
        "has_spf": has_spf,

        # Feature #17 — Ύπαρξη CNAME
        # Το CNAME είναι «ψευδώνυμο» που δείχνει σε άλλο domain (alias).
        "cname_present": cname_present,

        # Feature #18 — Πλήθος AAAA records (IPv6)
        # Τα AAAA records δίνουν IPv6 διευθύνσεις. Η τιμή > 0 δείχνει πιο ώριμη
        # υποδομή (κωδικοποιεί και το boolean «έχει IPv6») — τα εφήμερα malicious
        # domains σπάνια ρυθμίζουν IPv6.
        "num_aaaa_records": num_aaaa_records,

        # Βοηθητικά πεδία (ΟΧΙ features): οι IPs των A records και των MX mail
        # servers. Τα περνάμε στο enrichment — τα A IPs για GeoIP/reputation,
        # τα MX IPs για το mx reputation (feature #29).
        "ips": ips,
        "mx_ips": mx_ips,
    }
