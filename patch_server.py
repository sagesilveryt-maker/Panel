import re

with open('server.py', 'r', encoding='utf-8') as f:
    content = f.read()

with open('panel.html', 'r', encoding='utf-8') as f:
    new_html = f.read()

new_content = re.sub(r'HTML_TEMPLATE = \"\"\"[\s\S]*?\"\"\"', f'HTML_TEMPLATE = \"\"\"{new_html}\"\"\"', content, 1)

with open('server.py', 'w', encoding='utf-8') as f:
    f.write(new_content)
