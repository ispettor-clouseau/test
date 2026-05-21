# Installazione una-tantum (Windows e Mac uguale)
pip install openpyxl

# Uso: lancia semgrep e passa l'output allo script
semgrep --config p/owasp-top-ten . --json | python3 semgrep2excel.py

# Se vuoi il CSV invece (apre in Excel senza installare nulla)
semgrep --config p/owasp-top-ten . --json | python3 semgrep2excel.py --csv

# Con nome file personalizzato
semgrep --config p/owasp-top-ten . --json | python3 semgrep2excel.py -o report_gruppoA.xlsx
