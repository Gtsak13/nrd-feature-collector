"""Κατέβασμα των GeoLite2 βάσεων (.mmdb) από τη MaxMind — τρέχει ΜΙΑ φορά.

Το 4a Infrastructure βήμα (asn, geo_country) διαβάζει τοπικά αρχεία .mmdb:
αυτές είναι offline βάσεις που χαρτογραφούν IP -> ASN και IP -> χώρα. Δεν
γίνεται query σε εξωτερικό API ανά IP· τα αρχεία ζουν στο resources/geolite2/.

Η MaxMind τα δίνει δωρεάν (GeoLite2) με signup. Αυτό το script τα κατεβάζει
χρησιμοποιώντας το license key από το .env (config.MAXMIND_LICENSE_KEY).

Πηγή: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data

Εκτέλεση από το root του project (nrd-feature-collector/):
    python -m scripts.download_geolite
"""
from __future__ import annotations

import io
import tarfile

import requests

from collector import config

# Permanent download endpoint της MaxMind· δίνει ένα .tar.gz ανά edition.
DOWNLOAD_URL = "https://download.maxmind.com/app/geoip_download"

# Ποια editions θέλουμε και πού σώζεται το .mmdb του καθενός.
EDITIONS = {
    "GeoLite2-ASN": config.GEOLITE_ASN_DB,
    "GeoLite2-Country": config.GEOLITE_COUNTRY_DB,
}


def download_edition(edition: str, destination) -> bool:
    """Κατεβάζει ένα GeoLite2 edition και σώζει το .mmdb στο destination.

    Επιστρέφει True σε επιτυχία. Το .tar.gz περιέχει έναν φάκελο με ημερομηνία
    (π.χ. 'GeoLite2-ASN_20260601/GeoLite2-ASN.mmdb') — βγάζουμε μόνο το .mmdb.
    """
    params = {
        "edition_id": edition,
        "license_key": config.MAXMIND_LICENSE_KEY,
        "suffix": "tar.gz",
    }
    print(f"Κατέβασμα {edition} ...")
    resp = requests.get(DOWNLOAD_URL, params=params, timeout=120)
    if resp.status_code != 200:
        # 401 -> λάθος/ανενεργό key (το νέο key θέλει ~5 λεπτά να ενεργοποιηθεί).
        print(f"  Αποτυχία: HTTP {resp.status_code} — {resp.text[:120]}")
        return False

    # Ανοίγουμε το .tar.gz στη μνήμη και βρίσκουμε το .mmdb μέσα του.
    mmdb_bytes = None
    with tarfile.open(fileobj=io.BytesIO(resp.content), mode="r:gz") as tar:
        for member in tar.getmembers():
            if member.name.endswith(f"{edition}.mmdb"):
                extracted = tar.extractfile(member)
                mmdb_bytes = extracted.read()
                break

    if mmdb_bytes is None:
        print(f"  Δεν βρέθηκε .mmdb μέσα στο {edition} tar.gz")
        return False

    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(mmdb_bytes)
    print(f"  OK -> {destination}  ({len(mmdb_bytes) // 1024} KB)")
    return True


def main() -> None:
    """Κατεβάζει όλα τα editions (ASN + Country)."""
    if not config.MAXMIND_LICENSE_KEY:
        print("Λείπει το MAXMIND_LICENSE_KEY από το .env — δες .env.example.")
        return

    for edition, destination in EDITIONS.items():
        download_edition(edition, destination)


if __name__ == "__main__":
    main()
