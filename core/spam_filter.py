"""
core/spam_filter.py — Advanced Spam Filter & Content Bypass Engine
====================================================================
Layers:
  1. Spam word replacement   — semantic substitution of SA-scored words
  2. Zero-font injection     — invisible junk text breaks content fingerprinting
  3. Comment injection       — HTML comments between words break keyword scanning
  4. Homoglyph encoding      — Unicode lookalikes replace spam trigger chars
  5. Font randomisation      — per-word font-family rotation breaks ML recognition
  6. Invisible padding       — zero-width chars in subject break hash matching
  7. Noise pixel             — unique 1x1 GIF per email breaks identical-content detection
  8. Style variation         — micro CSS changes give each email a unique fingerprint
  9. Shuffle resolution      — {{(a|b|c)}} syntax picks random variant per send
"""

import re
import random
import string


# ═══════════════════════════════════════════════════════════════════════════
# 1. SPAM WORD MAP
# ═══════════════════════════════════════════════════════════════════════════

SPAM_WORD_MAP = {
    "security warning":      "account notice",
    "security alert":        "account update",
    "unusual activity":      "unrecognized activity",
    "suspicious":            "unrecognized",
    "suspicious login":      "sign-in attempt",
    "suspicious activity":   "unrecognized activity",
    "unauthorized":          "unrecognized",
    "unauthorized access":   "unrecognized access",
    "account suspended":     "account restricted",
    "account locked":        "account limited",
    "account compromised":   "account affected",
    "hacked":                "accessed",
    "breach":                "incident",
    "data breach":           "security incident",
    "immediately":           "promptly",
    "urgent":                "time-sensitive",
    "act now":               "take action",
    "act immediately":       "review now",
    "click here":            "review details",
    "click now":             "view now",
    "verify your account":   "confirm your account",
    "verify now":            "confirm now",
    "verify immediately":    "confirm promptly",
    "verify your identity":  "confirm your identity",
    "confirm your identity": "review your account",
    "your account has been": "your account was",
    "at risk":               "needs attention",
    "risk":                  "concern",
    "threat":                "issue",
    "malicious":             "unrecognized",
    "phishing":              "unauthorized",
    "fraud":                 "unusual",
    "fraudulent":            "unrecognized",
    "stolen":                "compromised",
    "warning":               "notice",
    "alert":                 "notification",
    "danger":                "concern",
    "critical":              "important",
    "emergency":             "urgent matter",
    "free":                  "complimentary",
    "free money":            "bonus credit",
    "cash":                  "funds",
    "prize":                 "reward",
    "winner":                "recipient",
    "you won":               "you have been selected",
    "congratulations":       "great news",
    "limited time":          "time-sensitive",
    "limited offer":         "special offer",
    "exclusive deal":        "exclusive offer",
    "discount":              "savings",
    "% off":                 "% savings",
    "earn money":            "earn rewards",
    "make money":            "generate income",
    "extra income":          "additional earnings",
    "no cost":               "at no charge",
    "no fee":                "fee-free",
    "money back":            "refund available",
    "guarantee":             "assurance",
    "guaranteed":            "assured",
    "lowest price":          "best rate",
    "best price":            "best rate",
    "special promotion":     "special offer",
    "double your":           "increase your",
    "million dollars":       "significant amount",
    "credit card":           "payment method",
    "credit score":          "financial profile",
    "loan":                  "financing",
    "mortgage":              "home loan",
    "debt":                  "balance",
    "income":                "earnings",
    "investment":            "opportunity",
    "profit":                "return",
    "revenue":               "earnings",
    "order now":             "get started",
    "buy now":               "purchase",
    "apply now":             "get started",
    "sign up now":           "create an account",
    "subscribe now":         "subscribe",
    "download now":          "download",
    "get started now":       "get started",
    "don't miss":            "don\u2019t miss out on",
    "don't delete":          "please review",
    "important information": "account information",
    "this is not spam":      "",
    "not spam":              "",
    "remove from list":      "unsubscribe",
    "opt out":               "unsubscribe",
    "password":              "credentials",
    "username":              "account name",
    "social security":       "identification",
    "bank account":          "financial account",
    "wire transfer":         "transfer",
    "lottery":               "drawing",
    "casino":                "entertainment",
    "pharmacy":              "health provider",
    "medication":            "treatment",
    "weight loss":           "wellness",
    "lose weight":           "improve wellness",
    "work from home":        "remote work",
    "be your own boss":      "independent work",
    "100% free":             "complimentary",
    "100% satisfied":        "fully satisfied",
    "as seen on":            "featured in",
}

_PATTERNS = None

def _get_patterns():
    global _PATTERNS
    if _PATTERNS is not None:
        return _PATTERNS
    items = sorted(SPAM_WORD_MAP.items(), key=lambda x: len(x[0]), reverse=True)
    _PATTERNS = [
        (re.compile(r'(?<![a-zA-Z])' + re.escape(k) + r'(?![a-zA-Z])', re.IGNORECASE), v)
        for k, v in items if k
    ]
    return _PATTERNS

def _preserve_case(original, replacement):
    if not replacement:
        return replacement
    if original.isupper():
        return replacement.upper()
    if original and original[0].isupper():
        return replacement[0].upper() + replacement[1:]
    return replacement

def replace_spam_words_text(text):
    if not text:
        return text
    for pat, repl in _get_patterns():
        text = pat.sub(lambda m, r=repl: _preserve_case(m.group(0), r), text)
    return text

def _walk_text_nodes(html, fn):
    """Apply fn() to text nodes only, skip style/script/tags."""
    out = []
    i = 0
    while i < len(html):
        if html[i:i+7].lower() == '<style':
            end = html.find('</style>', i)
            if end == -1: out.append(html[i:]); break
            out.append(html[i:end+8]); i = end+8; continue
        if html[i:i+7].lower() == '<script':
            end = html.find('</script>', i)
            if end == -1: out.append(html[i:]); break
            out.append(html[i:end+9]); i = end+9; continue
        if html[i] == '<':
            end = html.find('>', i)
            if end == -1: out.append(html[i:]); break
            out.append(html[i:end+1]); i = end+1; continue
        end = html.find('<', i)
        if end == -1: out.append(fn(html[i:])); break
        out.append(fn(html[i:end])); i = end
    return ''.join(out)

def replace_spam_words_html(html):
    return _walk_text_nodes(html, replace_spam_words_text) if html else html


# ═══════════════════════════════════════════════════════════════════════════
# 2. ZERO-FONT INJECTION  (F-Mailer: zeroFont_letter)
# ═══════════════════════════════════════════════════════════════════════════
# <u> tags styled to zero-width carry noise words invisible to readers
# but visible to content scanners — dilutes spam word density.

_ZF_CSS = ('<style type="text/css">'
           'u{display:inline-block;width:0;overflow:hidden;white-space:nowrap;'
           'font-size:0;max-height:0;mso-hide:all;visibility:hidden}'
           '</style>')

_NOISE = ["the","and","for","with","this","that","from","your","our","have",
          "been","will","are","was","has","not","but","all","can","its",
          "about","which","their","they","more","when","there","some","would",
          "other","into","than","then","these","could","also","time","only"]

def inject_zero_font(html, intensity=2):
    if not html or '<' not in html:
        return html
    # Inject CSS
    if '<head>' in html.lower():
        html = re.sub(r'(<head>)', r'\1' + _ZF_CSS, html, flags=re.IGNORECASE, count=1)
    elif '<body' in html.lower():
        html = re.sub(r'(<body[^>]*>)', _ZF_CSS + r'\1', html, flags=re.IGNORECASE, count=1)
    else:
        html = _ZF_CSS + html
    freq = {1:5, 2:3, 3:1}.get(intensity, 3)
    def _inject(text):
        words = text.split(' ')
        out = []
        for idx, w in enumerate(words):
            out.append(w)
            if w.strip() and idx % freq == 0 and idx < len(words)-1:
                out.append(f'<u>{random.choice(_NOISE)}</u>')
        return ' '.join(out)
    return _walk_text_nodes(html, _inject)


# ═══════════════════════════════════════════════════════════════════════════
# 3. HTML COMMENT INJECTION  (F-Mailer: commentFont)
# ═══════════════════════════════════════════════════════════════════════════

_CMT_VALS = ["", " ", "a", "b", "x", "ok", "safe", "pass", "noinspect"]

def inject_html_comments(html, freq=4):
    if not html or '<' not in html:
        return html
    def _inject(text):
        words = text.split(' ')
        out = []
        for idx, w in enumerate(words):
            out.append(w)
            if w.strip() and (idx+1) % freq == 0 and idx < len(words)-1:
                out.append(f'<!--{random.choice(_CMT_VALS)}-->')
        return ' '.join(out)
    return _walk_text_nodes(html, _inject)


# ═══════════════════════════════════════════════════════════════════════════
# 4. HOMOGLYPH ENCODING  (F-Mailer: homograph_encLetter / encode_homograph)
# ═══════════════════════════════════════════════════════════════════════════

_HG = {
    'a':'\u0430','e':'\u0435','o':'\u043e','p':'\u0440','c':'\u0441',
    'x':'\u0445','i':'\u0456','A':'\u0391','B':'\u0392','E':'\u0395',
    'H':'\u0397','I':'\u0399','K':'\u039a','M':'\u039c','N':'\u039d',
    'O':'\u039f','P':'\u03a1','T':'\u03a4','X':'\u03a7','Y':'\u03a5',
}

_HG_TARGETS = {
    "free","cash","prize","winner","urgent","warning","alert","verify",
    "confirm","click","login","password","security","account","bank",
    "credit","discount","offer","deal","buy","win","earn","money",
    "profit","guaranteed","limited","exclusive","congratulations",
    "selected","approved","loan","debt","investment",
}

def _hg_word(word, rate=0.4):
    return ''.join(_HG.get(c, c) if random.random() < rate else c for c in word)

def apply_homoglyph_encoding(text, rate=0.4):
    if not text: return text
    return re.sub(r'\b[a-zA-Z]+\b',
                  lambda m: _hg_word(m.group(0), rate) if m.group(0).lower() in _HG_TARGETS else m.group(0),
                  text)

def apply_homoglyph_html(html, rate=0.4):
    return _walk_text_nodes(html, lambda t: apply_homoglyph_encoding(t, rate)) if html else html


# ═══════════════════════════════════════════════════════════════════════════
# 5. FONT RANDOMISATION  (F-Mailer: beautifyFont / changeFont_letter)
# ═══════════════════════════════════════════════════════════════════════════

_FONTS = ["Arial","Helvetica","Verdana","Tahoma","Trebuchet MS","Georgia",
          "Times New Roman","Palatino","Garamond","Courier New","Calibri",
          "Cambria","Segoe UI","Century Gothic","Franklin Gothic Medium"]

def apply_font_randomisation(html, freq=3):
    if not html or '<' not in html: return html
    def _fontify(text):
        words = text.split(' ')
        out = []
        for idx, w in enumerate(words):
            if w.strip() and idx % freq == 0:
                f = random.choice(_FONTS)
                out.append(f'<span style="font-family:{f}">{w}</span>')
            else:
                out.append(w)
        return ' '.join(out)
    return _walk_text_nodes(html, _fontify)


# ═══════════════════════════════════════════════════════════════════════════
# 6. SUBJECT ENCODING  (11 methods — matches Ghost Hacker OS text_encoding_method 0-11)
# ═══════════════════════════════════════════════════════════════════════════

# Method constants
ENC_NONE          = 0   # as-is
ENC_QP            = 1   # quoted-printable =?utf-8?Q?...?=
ENC_BASE64        = 2   # base64 =?utf-8?B?...?=
ENC_HOMOGLYPH     = 3   # homoglyph substitution (already in section 4)
ENC_ZERO_WIDTH    = 4   # zero-width chars between letters
ENC_UNICODE_NORM  = 5   # NFD decomposition (adds combining chars)
ENC_MIXED_SCRIPT  = 6   # mix Latin + Cyrillic lookalikes at word level
ENC_MATH_ALPHA    = 7   # mathematical alphanumeric symbols (𝗛𝗲𝗹𝗹𝗼)
ENC_FULL_WIDTH    = 8   # full-width ASCII (Ｈｅｌｌｏ)
ENC_ADVANCED_ZWJ  = 9   # advanced ZWJ combinator sequences
ENC_COMBINING     = 10  # combining diacritical marks
ENC_MATH_BOLD     = 11  # mathematical bold (same block as 7 but bold weight)

# Mathematical alphanumeric symbol maps
_MATH_BOLD_MAP = {
    'A':'𝐀','B':'𝐁','C':'𝐂','D':'𝐃','E':'𝐄','F':'𝐅','G':'𝐆','H':'𝐇',
    'I':'𝐈','J':'𝐉','K':'𝐊','L':'𝐋','M':'𝐌','N':'𝐍','O':'𝐎','P':'𝐏',
    'Q':'𝐐','R':'𝐑','S':'𝐒','T':'𝐓','U':'𝐔','V':'𝐕','W':'𝐖','X':'𝐗',
    'Y':'𝐘','Z':'𝐙',
    'a':'𝐚','b':'𝐛','c':'𝐜','d':'𝐝','e':'𝐞','f':'𝐟','g':'𝐠','h':'𝐡',
    'i':'𝐢','j':'𝐣','k':'𝐤','l':'𝐥','m':'𝐦','n':'𝐧','o':'𝐨','p':'𝐩',
    'q':'𝐪','r':'𝐫','s':'𝐬','t':'𝐭','u':'𝐮','v':'𝐯','w':'𝐰','x':'𝐱',
    'y':'𝐲','z':'𝐳',
}

_MATH_SANS_BOLD_MAP = {
    'A':'𝗔','B':'𝗕','C':'𝗖','D':'𝗗','E':'𝗘','F':'𝗙','G':'𝗚','H':'𝗛',
    'I':'𝗜','J':'𝗝','K':'𝗞','L':'𝗟','M':'𝗠','N':'𝗡','O':'𝗢','P':'𝗣',
    'Q':'𝗤','R':'𝗥','S':'𝗦','T':'𝗧','U':'𝗨','V':'𝗩','W':'𝗪','X':'𝗫',
    'Y':'𝗬','Z':'𝗭',
    'a':'𝗮','b':'𝗯','c':'𝗰','d':'𝗱','e':'𝗲','f':'𝗳','g':'𝗴','h':'𝗵',
    'i':'𝗶','j':'𝗷','k':'𝗸','l':'𝗹','m':'𝗺','n':'𝗻','o':'𝗼','p':'𝗽',
    'q':'𝗾','r':'𝗿','s':'𝘀','t':'𝘁','u':'𝘂','v':'𝘃','w':'𝘄','x':'𝘅',
    'y':'𝘆','z':'𝘇',
}

_FULL_WIDTH_MAP = {c: chr(ord(c) + 0xFEE0) for c in string.printable[:-5] if ' ' < c < '~'}
_FULL_WIDTH_MAP[' '] = '　'  # ideographic space

# Combining diacritical marks pool
_COMBINING = [
    '̀','́','̂','̃','̄','̆','̇','̈',
    '̊','̋','̌','̣','̤','̥','̧','̨',
]

# ZWJ sequences for advanced combinator
_ZWJ_CHARS = ['‍','‌','​','⁠','﻿']


def _encode_qp(text: str) -> str:
    """Quoted-printable RFC 2047 encoded word."""
    import quopri
    encoded = quopri.encodestring(text.encode('utf-8'), quotetabs=True).decode('ascii')
    encoded = encoded.replace(' ', '_').replace('\n', '').replace('\r', '')
    return f"=?utf-8?Q?{encoded}?="


def _encode_b64_word(text: str) -> str:
    """Base64 RFC 2047 encoded word."""
    import base64 as _b
    b64 = _b.b64encode(text.encode('utf-8')).decode('ascii')
    return f"=?utf-8?B?{b64}?="


def _encode_unicode_norm(text: str) -> str:
    """NFD normalization — adds invisible combining chars to letters."""
    import unicodedata
    result = []
    for ch in text:
        result.append(ch)
        if ch.isalpha() and random.random() < 0.3:
            result.append(random.choice(_COMBINING))
    return ''.join(result)


def _encode_mixed_script(text: str) -> str:
    """Mix Latin and Cyrillic lookalikes at word boundaries."""
    # Map of Latin → visually-identical Cyrillic
    _CYR = {'a':'а','c':'с','e':'е','o':'о',
             'p':'р','s':'ѕ','x':'х','y':'у'}
    words = text.split(' ')
    out   = []
    for w in words:
        if random.random() < 0.5:
            out.append(''.join(_CYR.get(c, c) for c in w))
        else:
            out.append(w)
    return ' '.join(out)


def _encode_math_alpha(text: str, bold_sans=False) -> str:
    """Mathematical alphanumeric symbols."""
    m = _MATH_SANS_BOLD_MAP if bold_sans else _MATH_BOLD_MAP
    return ''.join(m.get(c, c) for c in text)


def _encode_full_width(text: str) -> str:
    """Full-width ASCII characters."""
    return ''.join(_FULL_WIDTH_MAP.get(c, c) for c in text)


def _encode_advanced_zwj(text: str) -> str:
    """Insert ZWJ/ZWNJ sequences between characters at low frequency."""
    out = []
    for i, ch in enumerate(text):
        out.append(ch)
        if ch.isalpha() and i % random.randint(3, 7) == 0:
            out.append(random.choice(_ZWJ_CHARS))
    return ''.join(out)


def _encode_combining(text: str) -> str:
    """Add combining diacritical marks to alphabetic characters."""
    out = []
    for ch in text:
        out.append(ch)
        if ch.isalpha() and random.random() < 0.25:
            out.append(random.choice(_COMBINING))
    return ''.join(out)


def encode_subject(text: str, method: int = ENC_NONE) -> str:
    """
    Encode a subject line using the specified method.
    Methods 0-11 match Ghost Hacker OS text_encoding_method values.
    """
    if not text:
        return text
    try:
        if method == ENC_NONE:      return text
        if method == ENC_QP:        return _encode_qp(text)
        if method == ENC_BASE64:    return _encode_b64_word(text)
        if method == ENC_HOMOGLYPH: return apply_homoglyph_encoding(text)
        if method == ENC_ZERO_WIDTH:return inject_invisible_chars(text)
        if method == ENC_UNICODE_NORM: return _encode_unicode_norm(text)
        if method == ENC_MIXED_SCRIPT: return _encode_mixed_script(text)
        if method == ENC_MATH_ALPHA:   return _encode_math_alpha(text, bold_sans=False)
        if method == ENC_FULL_WIDTH:   return _encode_full_width(text)
        if method == ENC_ADVANCED_ZWJ: return _encode_advanced_zwj(text)
        if method == ENC_COMBINING:    return _encode_combining(text)
        if method == ENC_MATH_BOLD:    return _encode_math_alpha(text, bold_sans=True)
    except Exception:
        pass
    return text  # fallback to plain on any error


def inject_invisible_chars(text, freq=4):
    """
    Inject safe subject entropy using thin/hair spaces and invisible Unicode.
    Uses THIN SPACE (U+2009) and HAIR SPACE (U+200A) — email-safe, not flagged.
    Zero-width chars (U+200B etc) are penalised by Gmail/EOP/Talos since 2024.
    """
    if not text: return text
    _SAFE_INVIS = ['\u2009', '\u200a', '\u00ad', '\u2060']
    out = []; count = 0
    for ch in text:
        out.append(ch)
        if ch.strip():
            count += 1
            if count % freq == 0:
                out.append(random.choice(_SAFE_INVIS))
    return ''.join(out)


# ═══════════════════════════════════════════════════════════════════════════
# 7. NOISE PIXEL  (unique binary fingerprint per email)
# ═══════════════════════════════════════════════════════════════════════════

_GIF1x1 = "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"

def inject_noise_pixel(html):
    if not html: return html
    rid = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
    px = (f'<img src="data:image/gif;base64,{_GIF1x1}" '
          f'width="1" height="1" alt="" id="t{rid}" '
          f'style="display:block;width:1px;height:1px;border:0;margin:0;padding:0">')
    if '</body>' in html.lower():
        return re.sub(r'(</body>)', px + r'\1', html, flags=re.IGNORECASE, count=1)
    return html + px


# ═══════════════════════════════════════════════════════════════════════════
# 8. STYLE VARIATION  (unique CSS fingerprint per email)
# ═══════════════════════════════════════════════════════════════════════════

def inject_style_variation(html):
    if not html: return html
    ls = round(random.uniform(-0.01, 0.03), 3)
    lh = round(random.uniform(1.42, 1.62), 2)
    ws = round(random.uniform(-0.01, 0.02), 3)
    rc = ''.join(random.choices(string.ascii_lowercase, k=5))
    s = (f'<style type="text/css">'
         f'.{rc}{{letter-spacing:{ls}em;line-height:{lh};word-spacing:{ws}em}}'
         f'</style>')
    if '<head>' in html.lower():
        return re.sub(r'(<head>)', r'\1' + s, html, flags=re.IGNORECASE, count=1)
    if '<body' in html.lower():
        return re.sub(r'(<body[^>]*>)', s + r'\1', html, flags=re.IGNORECASE, count=1)
    return s + html


# ═══════════════════════════════════════════════════════════════════════════
# 9. SHUFFLE TAG RESOLUTION  (F-Mailer: {{(opt1|opt2|opt3)}} syntax)
# ═══════════════════════════════════════════════════════════════════════════

def resolve_shuffle_tags(text):
    if not text: return text
    return re.sub(r'\{\{\(([^)]+)\)\}\}',
                  lambda m: random.choice(m.group(1).split('|')).strip(), text)


# ═══════════════════════════════════════════════════════════════════════════
# 10. ADVANCED HTML MUTATION  (anti-fingerprint)
# ═══════════════════════════════════════════════════════════════════════════

_ADJECTIVES = ['main','primary','core','inner','outer','top','mid','low',
               'wrap','body','cont','item','text','box','row','col','el']
_NOUNS      = ['section','block','panel','area','zone','layer','frame',
               'group','unit','part','slot','cell','tile','card']

def mutate_html_classes(html: str) -> str:
    """
    Replace CSS class names with random strings to break fingerprinting.
    Preserves structure while making each email unique to hash-based scanners.
    """
    if not html or '<' not in html: return html
    def _rand_cls():
        return random.choice(_ADJECTIVES) + '-' + random.choice(_NOUNS) + '-' +                ''.join(random.choices(string.ascii_lowercase + string.digits, k=4))
    # Only mutate class= attributes (not href, src etc)
    def _replace_class(m):
        classes = m.group(1).split()
        new_classes = [_rand_cls() for _ in classes]
        return 'class="' + ' '.join(new_classes) + '"'
    return re.sub(r'class="([^"]+)"', _replace_class, html)


def inject_micro_noise(html: str, intensity: int = 1) -> str:
    """
    Inject invisible micro-elements: 0px divs, empty spans with random data-* attrs.
    These make every email unique to ML classifiers without affecting rendering.
    """
    if not html or '<' not in html: return html
    n_nodes = {1: 2, 2: 4, 3: 6}.get(intensity, 2)
    noise_parts = []
    for _ in range(n_nodes):
        rand_attr = ''.join(random.choices(string.ascii_lowercase, k=6))
        rand_val  = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        rand_id   = ''.join(random.choices(string.ascii_lowercase, k=5))
        noise_parts.append(
            f'<div id="{rand_id}" data-{rand_attr}="{rand_val}" '
            f'style="display:none;max-height:0;overflow:hidden;font-size:0;'
            f'height:0;width:0;opacity:0;position:absolute;left:-9999px"></div>'
        )
    noise = ''.join(noise_parts)
    if '</body>' in html.lower():
        return re.sub(r'(</body>)', noise + r'\1', html, flags=re.IGNORECASE, count=1)
    return html + noise


# ═══════════════════════════════════════════════════════════════════════════
# 11. HASH BUSTER  (attachment fingerprint variation)
# ═══════════════════════════════════════════════════════════════════════════

def hash_bust_html(html: str) -> str:
    """
    Vary the HTML enough to produce a different hash for each recipient
    while keeping it visually identical. Combines micro-noise, style variation,
    and a hidden timestamp comment.
    """
    if not html: return html
    import time as _t
    ts      = str(int(_t.time() * 1000))
    rand_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
    # Add a hidden timestamp span
    stamp = (
        f'<span id="hb-{rand_id}" style="display:none;font-size:0;'
        f'opacity:0;height:0;max-height:0">{ts}</span>'
    )
    html = inject_micro_noise(html, intensity=1)
    html = inject_style_variation(html)
    if '</body>' in html.lower():
        return re.sub(r'(</body>)', stamp + r'\1', html, flags=re.IGNORECASE, count=1)
    return html + stamp


# ═══════════════════════════════════════════════════════════════════════════
# MAIN ENTRY POINTS
# ═══════════════════════════════════════════════════════════════════════════

def apply_spam_filter(html, subject, enabled=True):
    """Basic filter — word replacement only. Backward-compatible."""
    if not enabled:
        return html, subject
    return replace_spam_words_html(html), replace_spam_words_text(subject)


def apply_full_bypass(
    html,
    subject,
    plain              = "",
    *,
    word_replace       = True,
    zero_font          = True,
    comments           = True,
    homoglyphs         = False,   # off by default — changes chars visually
    font_rand          = False,   # off by default — adds many spans
    innat              = True,
    noise_pixel        = True,
    style_variation    = True,
    shuffle            = True,
    homoglyph_rate     = 0.35,
    zero_intensity     = 2,
    comment_freq       = 4,
    font_freq          = 3,
    innat_freq         = 4,
    # new options
    mutate_classes     = False,   # randomise CSS class names
    micro_noise        = True,    # inject invisible micro-elements
    hash_bust          = False,   # full hash variation per email
    subject_encoding   = 0,       # 0-11, see ENC_* constants
):
    """
    Full multi-layer content bypass. Returns (html, subject, plain).
    """
    if shuffle:
        html    = resolve_shuffle_tags(html)
        subject = resolve_shuffle_tags(subject)
        if plain: plain = resolve_shuffle_tags(plain)

    if word_replace:
        html    = replace_spam_words_html(html)
        subject = replace_spam_words_text(subject)
        if plain: plain = replace_spam_words_text(plain)

    if homoglyphs:
        html = apply_homoglyph_html(html, rate=homoglyph_rate)

    if zero_font and html and '<' in html:
        html = inject_zero_font(html, intensity=zero_intensity)

    if comments and html and '<' in html:
        html = inject_html_comments(html, freq=comment_freq)

    if font_rand and html and '<' in html:
        html = apply_font_randomisation(html, freq=font_freq)

    if mutate_classes and html and '<' in html:
        html = mutate_html_classes(html)

    if micro_noise and html and '<' in html:
        html = inject_micro_noise(html, intensity=1)

    if style_variation and html and '<' in html:
        html = inject_style_variation(html)

    if noise_pixel and html and '<' in html:
        html = inject_noise_pixel(html)

    if hash_bust and html and '<' in html:
        html = hash_bust_html(html)

    # Subject encoding
    if subject_encoding and subject_encoding != ENC_NONE:
        subject = encode_subject(subject, method=subject_encoding)
    elif innat:
        subject = inject_invisible_chars(subject, freq=innat_freq)

    return html, subject, plain
