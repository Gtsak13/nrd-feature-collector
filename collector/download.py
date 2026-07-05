"""Κατέβασμα και parsing της ημερήσιας λίστας NRDs από το whoisds.com.

Το whoisds δίνει ένα ZIP ανά μέρα, που μέσα έχει ένα .txt με ένα domain ανά
γραμμή.
"""
from __future__ import annotations

import base64
import io
import zipfile
from datetime import date

import requests

from collector import config

BASE_URL = "https://www.whoisds.com/whois-database/newly-registered-domains"


def build_download_url(day: date) -> str:
    """Φτιάχνει το URL του ZIP για τη συγκεκριμένη ημέρα (base64 της ημερομηνίας)."""
    filename = f"{day.isoformat()}.zip"               # π.χ. "2026-06-07.zip"
    # Το whoisds κρύβει το όνομα του αρχείου σε base64. Το .encode() γυρνά το
    # string σε bytes (το base64 δουλεύει με bytes), και το .decode() ξαναγυρνά
    # το αποτέλεσμα σε string για να μπει στο URL.
    encoded = base64.b64encode(filename.encode()).decode()
    return f"{BASE_URL}/{encoded}/nrd"


def _parse_lines(text: str) -> list[str]:
    """Καθαρίζει το περιεχόμενο του .txt -> list[str] (lowercase, χωρίς κενά)."""
    domains = []
    for line in text.splitlines():
        cleaned = line.strip().lower()
        if cleaned:                       # πετάμε κενές γραμμές
            domains.append(cleaned)
    return domains


def download_nrd_list(day: date) -> list[str]:
    """Κατεβάζει (ή διαβάζει από cache) τη λίστα NRDs για τη δοσμένη ημέρα.

    Επιστρέφει list[str] με τα domains. Αν το αρχείο της μέρας δεν έχει ανέβει
    ακόμη ή κάτι αποτύχει, τυπώνει καθαρό μήνυμα και επιστρέφει κενή λίστα —
    ΔΕΝ κάνει crash.
    """
    cache_file = config.RAW_DIR / f"{day.isoformat()}.txt"
    if cache_file.exists():
        print(f"Χρήση cache: {cache_file.name}")
        return _parse_lines(cache_file.read_text(encoding="utf-8"))

    url = build_download_url(day)
    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()           # αν ο server γύρισε σφάλμα (π.χ. 404), σήκωσε exception
    except requests.RequestException as e:
        print(f"Αποτυχία download για {day}: {e}")
        return []

    try:
        with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
            txt_name = None
            for name in zf.namelist():
                if name.endswith(".txt"):
                    txt_name = name
                    break
            if txt_name is None:
                print(f"Δεν βρέθηκε .txt μέσα στο zip της {day}.")
                return []
            text = zf.read(txt_name).decode("utf-8", errors="ignore")
    except zipfile.BadZipFile as e:
        print(f"Το αρχείο της {day} δεν είναι έγκυρο zip (ίσως δεν ανέβηκε ακόμη): {e}")
        return []

    domains = _parse_lines(text)

    config.RAW_DIR.mkdir(exist_ok=True)
    cache_file.write_text("\n".join(domains), encoding="utf-8")
    print(f"Κατέβηκαν {len(domains)} domains για {day}.")

    return domains
