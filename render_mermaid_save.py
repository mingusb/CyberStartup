import base64
import json
import urllib.request
import re
import sys

with open('README.md', 'r') as f:
    text = f.read()

diagrams = re.findall(r'```mermaid\n(.*?)```', text, re.DOTALL)

for i, d in enumerate(diagrams):
    state = {
        "code": d,
        "mermaid": {
            "theme": "default"
        }
    }
    j = json.dumps(state)
    payload = base64.urlsafe_b64encode(j.encode('utf-8')).decode('utf-8')
    url = f"https://mermaid.ink/img/{payload}"
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    try:
        data = urllib.request.urlopen(req).read()
        with open(f"diagram_{i}.png", "wb") as img_file:
            img_file.write(data)
        print(f"Saved diagram_{i}.png")
    except Exception as e:
        print(f"Failed diagram_{i}: {e}")
        sys.exit(1)
