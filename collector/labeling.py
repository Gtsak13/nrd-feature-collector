"""Στρατηγική weak labeling (spec §10).

Η λίστα NRDs δεν έχει έτοιμη ετικέτα. Παράγουμε ασθενές (weak) label από
τα reputation σήματα της υποδομής. Κρατάμε ΚΑΙ το `reason` ώστε να φαίνεται
στη διπλωματική ΠΟΙΟ σήμα χαρακτήρισε κάθε domain.

Θεωρητικό υπόβαθρο (για το κεφάλαιο):
  - Οι κανόνες παρακάτω είναι «labeling functions» στο πλαίσιο του *weak
    supervision / data programming*: Mintz et al. 2009· Ratner et al. 2016.
  - Η χρήση blocklists/reputation ως πηγή label είναι standard στον χώρο
    (label-then-classify): Zhauniarovich et al. 2018 §3.3· EXPOSURE (Bilge
    et al.)· Lewis et al. 2020 (AbuseIPDB).

Περιορισμοί:
  - Absence ≠ benign -> γι' αυτό υπάρχει η κλάση `unknown` (Sinha et al. 2008).
"""
from __future__ import annotations

from collector import config


def label_domain(row: dict, threshold: int = config.ABUSEIPDB_THRESHOLD) -> tuple[str, str]:
    """Δίνει ασθενές label σε ένα domain από τα reputation σήματα.

    Επιστρέφει (label, reason) με label ∈ {malicious, benign, unknown}:
      - malicious: αν ΟΠΟΙΟΔΗΠΟΤΕ σήμα ανάψει (spamhaus zen/dbl,
        abuseipdb >= threshold).
      - benign: μόνο αν είχαμε όντως reputation δεδομένα και κανένα κακό σήμα.
      - unknown: καμία κάλυψη reputation (θεμιτή κλάση — δεν τη ζορίζουμε
        σε benign).
    """
    if row.get("spamhaus_zen_listed"):
        return "malicious", "spamhaus_zen"
    if (row.get("abuseipdb_score") or 0) >= threshold:
        return "malicious", "abuseipdb"
    if row.get("spamhaus_dbl_listed"):
        return "malicious", "spamhaus_dbl"

    # benign μόνο αν υπήρξε ΕΣΤΩ ΕΝΑ πραγματικό reputation δεδομένο.
    # Αρκεί οποιαδήποτε πηγή να απάντησε επιτυχώς (όχι None) — δεν χρειάζεται
    # και οι τρεις. Το None σημαίνει «δεν μπορέσαμε να ρωτήσουμε» (αποτυχία/
    # χωρίς key), ενώ το False σημαίνει «ρωτήσαμε και δεν είναι listed».
    has_abuseipdb = row.get("abuseipdb_score") is not None
    has_zen = row.get("spamhaus_zen_listed") is not None
    has_dbl = row.get("spamhaus_dbl_listed") is not None
    if has_abuseipdb or has_zen or has_dbl:
        return "benign", "no_adverse_signal"
    return "unknown", "no_reputation_coverage"
