# resources/

Στατικά δεδομένα που διαβάζουν τα στάδια συλλογής.

| Αρχείο | Για | Πώς το φτιάχνεις |
|---|---|---|
| `ngram_baseline.json` | feature #8 (`ngram_score`) | `python -m scripts.ngram_baseline.build_ngram_baseline` |
| `geolite2/GeoLite2-ASN.mmdb` | feature #24 (`asn`) | Δωρεάν από MaxMind (signup) |
| `geolite2/GeoLite2-Country.mmdb` | feature #25 (`geo_country`) | Δωρεάν από MaxMind (signup) |

Οι λίστες TLD-risk και suspicious-keywords (lexical) έχουν ενσωματωθεί στο 
`collector/lexical.py` μαζί με τις βιβλιογραφικές τους πηγές.
