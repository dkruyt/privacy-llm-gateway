import re, sys
src, dst = sys.argv[1], sys.argv[2]
s = open(src).read()
def sub(pat, repl):
    global s
    s, n = re.subn(pat, repl, s, count=1)
    assert n == 1, pat
sub(r'(data-composition-frame-label="LOCAL: your machine / network"[^>]*class="c-region)"', r'\1 zone-local"')
sub(r'(data-composition-frame-label="CLOUD"[^>]*class="c-region)"', r'\1 zone-cloud"')
sub(r'(data-composition-frame-label="LOCAL: your machine / network">\s*)<rect data-graph-role="structural-frame-label-mask"[^>]*/>', r'\1')
fy = float(re.search(r'data-composition-frame-label="LOCAL: your machine / network" x="[0-9.]+" y="([0-9.]+)"', s).group(1))
sub(r'(<text data-boundary-label="" x="[0-9.]+" )y="[0-9.]+"( class="t-cloud" font-size="9" font-weight="600">LOCAL: your machine / network</text>)',
    lambda m: f'{m.group(1)}y="{fy + 22:g}"{m.group(2)}')
sub(r'class="t-cloud" font-size="9" font-weight="600">LOCAL: your machine / network</text>',
    'class="t-cloud zone-local-label" font-size="11" font-weight="700">LOCAL · your machine / network · data stays here</text>')
sub(r'class="t-cloud" font-size="9" font-weight="600">CLOUD</text>',
    'class="t-cloud zone-cloud-label" font-size="11" font-weight="700">CLOUD · public LLM</text>')
sub(r'<rect width="100%" height="100%" fill="url\(#grid\)"/>', '')
extra = """
.zone-local { fill: color-mix(in srgb, var(--backend-fill) 40%, transparent) !important; stroke: var(--backend-stroke) !important; stroke-width: 2px; stroke-dasharray: none !important; }
.zone-local-label { fill: var(--backend-stroke) !important; }
.zone-cloud { stroke: var(--cloud-stroke) !important; stroke-width: 2px; }
.zone-cloud-label { fill: var(--cloud-stroke) !important; }
"""
i = s.index("</style>"); s = s[:i] + extra + s[i:]
open(dst, "w").write(s)
print("wrote", dst, len(s))
