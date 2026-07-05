"""Τρέχει μία φορά τη μέρα και ενώνει όλα τα στάδια.

Ροή:
  1. download + τυχαίο sample (config.SAMPLE_SIZE)
  2. Lexical       -> όλα
  3. DNS           -> όλα (χωρίζει resolved / μη)
  4. Enrichment    -> IP-based μόνο σε resolved· WHOIS σε όλα
  5. labeling + εγγραφή μιας γραμμής CSV ανά domain

Εκτέλεση:  python -m collector.main [--date YYYY-MM-DD]
"""
from __future__ import annotations

import argparse
import csv
from datetime import date
from pathlib import Path

import random

from tqdm import tqdm

from collector import config
from collector import download, lexical, dns_records
from collector import enrichment, labeling


def parse_args() -> argparse.Namespace:
    """Διαβάζει τα command-line arguments."""
    parser = argparse.ArgumentParser(description="Daily NRD feature collector")
    parser.add_argument(
        "--date",
        type=date.fromisoformat,
        default=date.today(),
        help="Ημέρα συλλογής (YYYY-MM-DD). Default: σήμερα.",
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=config.SAMPLE_SIZE,
        help=f"Πόσα domains να συλλέξει (default: {config.SAMPLE_SIZE}). ",
    )
    return parser.parse_args()



def csv_path_for(day: date) -> Path:
    """Το path του ημερήσιου CSV αρχείου."""
    return config.OUTPUT_DIR / f"features_{day.isoformat()}.csv"


def collect_for_day(day: date, limit: int = config.SAMPLE_SIZE) -> None:
    """Κάνει ολόκληρη τη συλλογή για μία ημέρα και σώζει το αποτέλεσμα.

    Για κάθε domain χτίζει ένα row (dict) ενώνοντας τα dictionaries των
    σταδίων, βάζει label, και γράφει μια γραμμή CSV αμέσως (όχι στο τέλος).
    `limit` = πόσα domains να δειγματοληπτήσει.
    """
    # 1. Λήψη όλων των domains για την ημέρα
    print(f"Λήψη NRDs για {day.isoformat()} ...")
    domains_all = download.download_nrd_list(day)
    if not domains_all:
        print(f"Δεν βρέθηκαν domains για την ημερομηνία {day.isoformat()}.")
        return

    # Σταθερό random seed βασισμένο στη μέρα για επαναληψιμότητα
    random.seed(day.toordinal())
    sample_size = min(limit, len(domains_all))
    sample = random.sample(domains_all, sample_size)
    print(f"Επιλέχθηκαν τυχαία {sample_size} domains για συλλογή features.")

    config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    csv_path = csv_path_for(day)
    writer = None
    rows_written = 0

    # 2. Για κάθε domain: υπολογισμός των features + άμεση εγγραφή στο CSV.
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        for domain in tqdm(sample, desc="Συλλογή NRDs", unit="domain"):
            row = {"domain": domain, "date_collected": day.isoformat()}

            # --- Στάδιο 2: Lexical ---
            row.update(lexical.compute_lexical(domain))

            # --- Στάδιο 3: DNS ---
            dns_res = dns_records.compute_dns(domain)
            # Βγάζουμε τα βοηθητικά πεδία "ips" και "mx_ips" (lists) ώστε να μην
            # πάνε στο output, αλλά τα κρατάμε για το enrichment.
            ips = dns_res.pop("ips", None)
            mx_ips = dns_res.pop("mx_ips", None)
            row.update(dns_res)

            # --- Στάδιο 4: Enrichment ---
            # Τρέχει πάντα, αλλά τα IP-features θέλουν resolved IPs.
            row.update(enrichment.compute_enrichment(domain, ips, mx_ips))

            # --- Στάδιο 5: Labeling ---
            label, reason = labeling.label_domain(row)
            row["label"] = label
            row["label_reason"] = reason

            if writer is None:
                writer = csv.DictWriter(f, fieldnames=list(row.keys()))
                writer.writeheader()

            writer.writerow(row)
            f.flush()   # γράφε στο δίσκο αμέσως, όχι μόνο όταν κλείσει το αρχείο
            rows_written += 1

    print(f"Επιτυχία! Αποθηκεύτηκαν {rows_written} εγγραφές στο: {csv_path}")

def main() -> None:
    """Entry point: διαβάζει args, τρέχει τον collector."""
    args = parse_args()
    collect_for_day(args.date, limit=args.limit)

if __name__ == "__main__":
    main()
