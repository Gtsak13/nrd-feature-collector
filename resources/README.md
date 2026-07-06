# resources/

Στατικά δεδομένα που διαβάζουν τα στάδια συλλογής.

| Αρχείο | Για | Πώς το φτιάχνεις |
|---|---|---|
| `ngram_baseline.json` | feature #6 (`ngram_score`) | `python -m scripts.ngram_baseline.build_ngram_baseline` |
| `brand_slds.json` | feature #8 (`typosquatting_similarity`) | `python -m scripts.ngram_baseline.build_ngram_baseline` |
| `geolite2/GeoLite2-ASN.mmdb` | feature #19 (`asn`) | Δωρεάν από MaxMind (signup) |
| `geolite2/GeoLite2-Country.mmdb` | feature #20 (`geo_country`) | Δωρεάν από MaxMind (signup) |

Η λίστα TLD-risk (lexical) έχει ενσωματωθεί στο `collector/lexical.py` μαζί με 
τις βιβλιογραφικές της πηγές.
