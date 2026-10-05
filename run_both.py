# run_both.py
# [PORTABLE] Lance les deux apps Flask en parallèle via threading.
# use_reloader=False → indispensable, sinon le reloader tente de relancer
# deux fois chaque app (conflit de ports, problème connu sur Windows).

import threading
import time

from app_vulnerable import app as app_vuln
from app_securisee  import app as app_secure
from config import PORT_VULN, PORT_SECURE


def _serve(app, port: int, label: str) -> None:
    print(f"[*] Démarrage {label} sur http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port,
            threaded=True, use_reloader=False, debug=False)


def main() -> None:
    t1 = threading.Thread(target=_serve,
                          args=(app_vuln, PORT_VULN, "VULNÉRABLE"),
                          daemon=True)
    t2 = threading.Thread(target=_serve,
                          args=(app_secure, PORT_SECURE, "SÉCURISÉE"),
                          daemon=True)
    t1.start()
    time.sleep(0.5)
    t2.start()

    print("\n===============================================")
    print(f"  VULNÉRABLE : http://127.0.0.1:{PORT_VULN}")
    print(f"  SÉCURISÉE  : http://127.0.0.1:{PORT_SECURE}")
    print("  Ctrl+C pour quitter.")
    print("===============================================\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Arrêt demandé.")


if __name__ == "__main__":
    main()
