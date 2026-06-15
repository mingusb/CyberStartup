import os
import time
import json
import urllib.request
from playwright.sync_api import sync_playwright

with open('README.md', 'r') as f:
    text = f.read()

# GitHub API to render markdown
url = "https://api.github.com/markdown"
data = json.dumps({"text": text, "mode": "gfm"}).encode("utf-8")
req = urllib.request.Request(url, data=data, headers={"Accept": "application/vnd.github.v3+json", "User-Agent": "Mozilla/5.0"})
try:
    response = urllib.request.urlopen(req).read().decode('utf-8')
except Exception as e:
    print(f"GitHub API failed: {e}")
    # fallback
    response = "<pre>" + text + "</pre>"

html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/github-markdown-css/5.2.0/github-markdown.min.css">
    <style>
        body {{ background-color: #fff; }}
        .markdown-body {{
            box-sizing: border-box;
            min-width: 200px;
            max-width: 980px;
            margin: 0 auto;
            padding: 45px;
        }}
    </style>
    <script type="module">
        import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs';
        mermaid.initialize({{ startOnLoad: true }});
    </script>
    <script>
      MathJax = {{
        tex: {{
          inlineMath: [['$', '$'], ['\\\\(', '\\\\)']]
        }}
      }};
    </script>
    <script id="MathJax-script" async src="https://cdn.jsdelivr.net/npm/mathjax@3/es5/tex-chtml.js"></script>
    <script type="module">
        document.querySelectorAll('.highlight-source-mermaid pre, pre[lang="mermaid"] code, pre code.language-mermaid').forEach(el => {{
            const container = el.tagName.toLowerCase() === 'pre' ? el.parentElement : el.parentElement.parentElement;
            const div = document.createElement('div');
            div.className = 'mermaid';
            div.textContent = el.textContent;
            container.replaceWith(div);
        }});
    </script>
</head>
<body class="markdown-body">
{response}
</body>
</html>
"""

html_path = os.path.abspath('rendered.html')
with open(html_path, 'w') as f:
    f.write(html_content)

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True, channel="chrome", args=['--no-sandbox'])
    page = browser.new_page()
    page.goto(f"file://{html_path}")
    # wait for mermaid to render
    page.wait_for_timeout(3000)
    
    # take chunked screenshots
    viewport_height = page.viewport_size['height']
    total_height = page.evaluate("document.body.scrollHeight")
    chunks = int(total_height / viewport_height) + 1
    
    for i in range(chunks):
        page.evaluate(f"window.scrollTo(0, {i * viewport_height})")
        page.wait_for_timeout(500)
        page.screenshot(path=f"readme_part_{i}.png")
        
    browser.close()
    print(f"Saved {{chunks}} screenshots.")
