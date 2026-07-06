# scripts/ngram_baseline/

Χτίζει το **n-gram baseline** που χρειάζεται το feature #6 (`ngram_score`)
στο [`collector/lexical.py`](../../collector/lexical.py).

## Τι κάνει

Το feature #6 απαντά στο ερώτημα: «πόσο φυσικό μοιάζει αυτό το domain name;».
Ένα legit domain (π.χ. `facebook`) αποτελείται από συλλαβές που συναντάμε
συχνά στη γλώσσα, ενώ ένα DGA domain (π.χ. `xkqzjf`) έχει αλληλουχίες γραμμάτων
που σπάνια εμφανίζονται μαζί.

Για να το μετρήσουμε χρειαζόμαστε ένα **σημείο αναφοράς (baseline)**: πόσο
συχνά εμφανίζεται κάθε ζευγάρι (bigram) και κάθε τριάδα (trigram) γραμμάτων στα
πραγματικά, νόμιμα domains. Το baseline το χτίζουμε **μία φορά** από τη λίστα
**Tranco** top sites και το σώζουμε σε `resources/ngram_baseline.json`. Μετά,
το `lexical.py` το φορτώνει και βαθμολογεί κάθε νέο domain ως προς αυτό.

## Τι είναι n-gram

n-gram = συνεχόμενο κομμάτι n χαρακτήρων ενός string. Για το SLD `google`:

| n | n-grams |
|---|---|
| bigrams (n=2)  | `go`, `oo`, `og`, `gl`, `le` |
| trigrams (n=3) | `goo`, `oog`, `ogl`, `gle` |

Μετράμε πόσες φορές εμφανίζεται κάθε n-gram σε **όλα** τα Tranco domains και
μετατρέπουμε τις συχνότητες σε **log-πιθανότητες**:

```
P(gram)    = count(gram) / (σύνολο όλων των grams)
logP(gram) = ln( P(gram) )
```

**Γιατί λογάριθμος;** Για να βαθμολογήσουμε ένα ολόκληρο domain παίρνουμε τον
μέσο όρο των `logP` όλων των grams του (αυτό κάνει το `ngram_score`). Με
λογαρίθμους, το «γινόμενο πιθανοτήτων» γίνεται «άθροισμα», που είναι αριθμητικά
σταθερό — αλλιώς, πολλαπλασιάζοντας πολλά μικρά κλάσματα, φτάνουμε σε underflow.

**Αποτέλεσμα:** ένα φυσικό domain έχει grams με υψηλή πιθανότητα → `logP` κοντά
στο 0· ένα DGA domain έχει σπάνια grams → πολύ αρνητικό `logP`. Στην πράξη
βλέπουμε ξεκάθαρο διαχωρισμό:

| domain | ngram_score |
|---|---|
| `google.com`             | ≈ −6.6 |
| `facebook.com`           | ≈ −6.8 |
| `xkqzjfwbvm.com`         | ≈ −11.7 |
| `ku1r5ey4.lol`           | ≈ −12.2 |

## Smoothing / floor

Τι γίνεται με ένα gram που **δεν** εμφανίστηκε ποτέ στο baseline (count = 0);
Το `ln(0)` είναι −άπειρο, που θα χαλούσε τον μέσο όρο. Γι' αυτό ορίζουμε ένα
«πάτωμα» (floor): υποθέτουμε ότι το άγνωστο gram εμφανίστηκε `0.1` φορές, ώστε
να πάρει μια πολύ χαμηλή — αλλά πεπερασμένη — log-πιθανότητα, χαμηλότερη από
κάθε πραγματικό gram. Αυτή η τεχνική λέγεται **smoothing**.

## Εκτέλεση (μία φορά)

Από το root του project (`nrd-feature-collector/`):

```powershell
.\.venv\Scripts\python.exe -m scripts.ngram_baseline.build_ngram_baseline
```

Κατεβάζει τη λίστα Tranco (~25 MB ZIP), κρατά τα top 100.000 domains, μετράει
τα n-grams και γράφει το JSON. Το `resources/ngram_baseline.json` είναι
gitignored (αναπαράγεται με αυτό το script).

## Πηγές / Links

### Tranco (η λίστα από όπου χτίζεται το baseline)
- Ιστότοπος & download: <https://tranco-list.eu/>
- Permanent CSV: <https://tranco-list.eu/top-1m.csv.zip>
- **Paper:** V. Le Pochat, T. Van Goethem, S. Tajalizadehkhoob, M. Korczyński,
  W. Joosen, *"Tranco: A Research-Oriented Top Sites Ranking Hardened Against
  Manipulation"*, NDSS 2019.
  PDF: <https://tranco-list.eu/assets/tranco-ndss19.pdf> ·
  arXiv: <https://arxiv.org/abs/1806.01156>

### tldextract (SLD/TLD split)
- <https://github.com/john-kurkowski/tldextract>

### N-gram language models (η θεωρία πίσω από το score)
- D. Jurafsky & J. H. Martin, *Speech and Language Processing* (3rd ed.),
  Ch. 3 "N-gram Language Models": <https://web.stanford.edu/~jurafsky/slp3/3.pdf>

### Χρήση n-grams για ανίχνευση DGA/malicious domains
- B. Yu et al., *"Character Level Based Detection of DGA Domain Names"*,
  IJCNN 2018: <https://doi.org/10.1109/IJCNN.2018.8489147>
