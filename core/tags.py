"""
core/tags.py — SynthTel Tag Engine
===================================
Single-pass tag resolution engine for email personalization.
Handles 100+ tags across 12 categories with full validation,
preview support, clash detection, and graceful error handling.

Usage:
    from core.tags import resolve_tags, extract_tags, validate_tags, build_context

    ctx = build_context(lead, sender, subject, counter, links_cfg)
    result = resolve_tags(html_body, ctx)
    issues = validate_tags(html_body, ctx)
"""

import re
import random
import string
import hashlib
import uuid as _uuid_mod
import base64
import urllib.parse
import calendar as _calendar
from datetime import datetime, timedelta
from typing import Any


# ── Date helper functions ──────────────────────────────────
def _fmt_date(d: datetime) -> str:
    return f"{MONTHS[d.month-1]} {d.day}, {d.year}"

def _fmt_date_short(d: datetime) -> str:
    return f"{d.month:02d}/{d.day:02d}/{d.year}"

def _fmt_date_iso(d: datetime) -> str:
    return d.strftime("%Y-%m-%d")

def _fmt_time12_offset(now: datetime, hours: int, minutes: int = 0) -> str:
    """Return 12h time adjusted by a fixed UTC offset (e.g. EST = -5)."""
    adjusted = now + timedelta(hours=hours, minutes=minutes)
    return adjusted.strftime("%I:%M %p").lstrip("0") or "12:00 AM"

def _fmt_time24_offset(now: datetime, hours: int, minutes: int = 0) -> str:
    """Return 24h time adjusted by a fixed UTC offset."""
    adjusted = now + timedelta(hours=hours, minutes=minutes)
    return adjusted.strftime("%H:%M:%S")

def _month_end(now: datetime) -> str:
    last_day = _calendar.monthrange(now.year, now.month)[1]
    return f"{MONTHS[now.month-1]} {last_day}, {now.year}"

def _quarter_start(now: datetime) -> str:
    q_start_month = ((now.month - 1) // 3) * 3 + 1
    return f"{MONTHS[q_start_month-1]} 1, {now.year}"

def _quarter_end(now: datetime) -> str:
    q_end_month = ((now.month - 1) // 3) * 3 + 3
    last_day = _calendar.monthrange(now.year, q_end_month)[1]
    return f"{MONTHS[q_end_month-1]} {last_day}, {now.year}"

def _next_month_start(now: datetime) -> str:
    if now.month == 12:
        return f"January 1, {now.year + 1}"
    return f"{MONTHS[now.month]} 1, {now.year}"

# ═══════════════════════════════════════════════════════════
# CONSTANTS — defined at module level, never re-created
# ═══════════════════════════════════════════════════════════

MONTHS = [
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December"
]

DAYS = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"]

COUNTRIES = [
    "United States", "United Kingdom", "Canada", "Australia", "Germany", "France",
    "Japan", "Brazil", "India", "Netherlands", "Spain", "Italy", "Sweden", "Norway",
    "Denmark", "Switzerland", "Singapore", "Ireland", "South Korea", "New Zealand",
    "Mexico", "Argentina", "Poland", "Czech Republic", "Austria", "Belgium",
    "Portugal", "Finland", "Hungary", "Romania", "Ukraine", "Greece", "Turkey",
    "Israel", "Saudi Arabia", "UAE", "South Africa", "Nigeria", "Kenya", "Egypt",
    "Thailand", "Vietnam", "Philippines", "Indonesia", "Malaysia", "Pakistan",
    "Bangladesh", "Sri Lanka", "Nepal", "Taiwan", "Hong Kong", "China",
]

CITIES = [
    "New York", "London", "Toronto", "Sydney", "Berlin", "Paris", "Tokyo",
    "Mumbai", "Amsterdam", "Madrid", "Milan", "Stockholm", "Oslo", "Copenhagen",
    "Zurich", "Singapore", "Dublin", "Seoul", "Auckland", "San Francisco",
    "Chicago", "Los Angeles", "Seattle", "Boston", "Houston", "Miami", "Denver",
    "Austin", "Portland", "Atlanta", "Dallas", "Phoenix", "San Diego", "Detroit",
    "Minneapolis", "Nashville", "Charlotte", "Las Vegas", "Philadelphia", "Tampa",
    "Vancouver", "Montreal", "Calgary", "Ottawa", "Melbourne", "Brisbane", "Perth",
    "Cape Town", "Johannesburg", "Lagos", "Cairo", "Dubai", "Abu Dhabi", "Riyadh",
    "Bangkok", "Jakarta", "Kuala Lumpur", "Manila", "Ho Chi Minh City", "Hanoi",
    "Warsaw", "Prague", "Vienna", "Brussels", "Lisbon", "Athens", "Budapest",
    "Helsinki", "Tallinn", "Riga", "Vilnius", "Bucharest", "Sofia", "Zagreb",
]

# Paired city+country for smart geo tags
CITY_COUNTRY_PAIRS = [
    ("New York", "United States"), ("Los Angeles", "United States"), ("Chicago", "United States"),
    ("San Francisco", "United States"), ("Seattle", "United States"), ("Boston", "United States"),
    ("Miami", "United States"), ("Austin", "United States"), ("Denver", "United States"),
    ("Atlanta", "United States"), ("Dallas", "United States"), ("Houston", "United States"),
    ("Phoenix", "United States"), ("Las Vegas", "United States"), ("Philadelphia", "United States"),
    ("Portland", "United States"), ("Nashville", "United States"), ("Minneapolis", "United States"),
    ("London", "United Kingdom"), ("Manchester", "United Kingdom"), ("Birmingham", "United Kingdom"),
    ("Edinburgh", "United Kingdom"), ("Glasgow", "United Kingdom"), ("Leeds", "United Kingdom"),
    ("Toronto", "Canada"), ("Vancouver", "Canada"), ("Montreal", "Canada"), ("Calgary", "Canada"),
    ("Ottawa", "Canada"), ("Edmonton", "Canada"),
    ("Sydney", "Australia"), ("Melbourne", "Australia"), ("Brisbane", "Australia"),
    ("Perth", "Australia"), ("Adelaide", "Australia"),
    ("Berlin", "Germany"), ("Munich", "Germany"), ("Hamburg", "Germany"),
    ("Frankfurt", "Germany"), ("Cologne", "Germany"), ("Stuttgart", "Germany"),
    ("Paris", "France"), ("Lyon", "France"), ("Marseille", "France"), ("Bordeaux", "France"),
    ("Tokyo", "Japan"), ("Osaka", "Japan"), ("Kyoto", "Japan"), ("Yokohama", "Japan"),
    ("Amsterdam", "Netherlands"), ("Rotterdam", "Netherlands"), ("The Hague", "Netherlands"),
    ("Madrid", "Spain"), ("Barcelona", "Spain"), ("Valencia", "Spain"), ("Seville", "Spain"),
    ("Milan", "Italy"), ("Rome", "Italy"), ("Naples", "Italy"), ("Florence", "Italy"),
    ("Stockholm", "Sweden"), ("Gothenburg", "Sweden"), ("Malmo", "Sweden"),
    ("Oslo", "Norway"), ("Bergen", "Norway"),
    ("Copenhagen", "Denmark"), ("Aarhus", "Denmark"),
    ("Zurich", "Switzerland"), ("Geneva", "Switzerland"), ("Basel", "Switzerland"),
    ("Singapore", "Singapore"),
    ("Dublin", "Ireland"), ("Cork", "Ireland"),
    ("Seoul", "South Korea"), ("Busan", "South Korea"),
    ("Auckland", "New Zealand"), ("Wellington", "New Zealand"),
    ("Vienna", "Austria"), ("Graz", "Austria"),
    ("Brussels", "Belgium"), ("Antwerp", "Belgium"),
    ("Lisbon", "Portugal"), ("Porto", "Portugal"),
    ("Warsaw", "Poland"), ("Krakow", "Poland"),
    ("Prague", "Czech Republic"), ("Brno", "Czech Republic"),
    ("Budapest", "Hungary"),
    ("Helsinki", "Finland"),
    ("Athens", "Greece"),
    ("Dubai", "UAE"), ("Abu Dhabi", "UAE"),
    ("Riyadh", "Saudi Arabia"),
    ("Cape Town", "South Africa"), ("Johannesburg", "South Africa"),
    ("Bangkok", "Thailand"),
    ("Kuala Lumpur", "Malaysia"),
    ("Jakarta", "Indonesia"),
    ("Manila", "Philippines"),
    ("Ho Chi Minh City", "Vietnam"), ("Hanoi", "Vietnam"),
    ("Mumbai", "India"), ("Delhi", "India"), ("Bangalore", "India"), ("Hyderabad", "India"),
    ("Mexico City", "Mexico"), ("Guadalajara", "Mexico"),
    ("São Paulo", "Brazil"), ("Rio de Janeiro", "Brazil"),
]

BROWSERS = [
    "Chrome 121", "Chrome 120", "Firefox 122", "Firefox 121", "Safari 17.3",
    "Safari 17.2", "Edge 121", "Edge 120", "Opera 106", "Brave 1.63",
    "Vivaldi 6.6", "Samsung Internet 23", "Chrome Mobile 121",
]

OS_LIST = [
    "Windows 11", "Windows 10", "Windows 10 Pro", "macOS Sonoma 14.3",
    "macOS Ventura 13.6", "macOS Monterey 12.7", "Ubuntu 24.04 LTS",
    "Ubuntu 22.04 LTS", "Debian 12", "Fedora 39", "iOS 17.3", "iOS 16.7",
    "Android 14", "Android 13", "Chrome OS 121",
]

COLOR_NAMES = [
    "Red", "Blue", "Green", "Yellow", "Purple", "Orange", "Pink", "Teal",
    "Cyan", "Indigo", "Violet", "Crimson", "Navy", "Emerald", "Gold", "Silver",
    "Coral", "Turquoise", "Magenta", "Lime", "Amber", "Rose", "Slate", "Zinc",
]

FAKE_COMPANIES = [
    "TechFlow Inc", "DataSphere", "NexaCore", "CloudVista", "SynapseAI",
    "QuantumLeap", "ByteForge", "CodeNova", "PixelMint", "VortexLabs",
    "Nextera Solutions", "Pinnacle Systems", "Horizon Labs", "Apex Dynamics",
    "Zenith Corp", "Atlas Technologies", "Summit Partners", "Nova Industries",
    "Vertex Global", "Prism Analytics", "Sterling Ventures", "Eclipse Software",
    "Meridian Group", "Cascade Digital", "Orbital Systems", "Luminary Tech",
    "Archway Solutions", "Cipher Labs", "Mosaic Partners", "Fulcrum Global",
]

FAKE_NAMES_FIRST = [
    "James", "John", "Robert", "Michael", "William", "David", "Richard", "Joseph",
    "Thomas", "Charles", "Mary", "Patricia", "Jennifer", "Linda", "Barbara",
    "Elizabeth", "Susan", "Jessica", "Sarah", "Karen", "Christopher", "Daniel",
    "Matthew", "Anthony", "Donald", "Emily", "Amanda", "Melissa", "Stephanie",
    "Ashley", "Emma", "Olivia", "Noah", "Liam", "Ava", "Isabella", "Sophia",
    "Lucas", "Mason", "Ethan", "Alexander", "Benjamin", "Logan", "Jackson",
]

FAKE_NAMES_LAST = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis",
    "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson",
    "Thomas", "Taylor", "Moore", "Jackson", "Martin", "Lee", "Perez", "Thompson",
    "White", "Harris", "Sanchez", "Clark", "Ramirez", "Lewis", "Robinson",
    "Walker", "Young", "Allen", "King", "Wright", "Scott", "Torres", "Nguyen",
    "Hill", "Flores", "Green", "Adams", "Nelson", "Baker", "Hall", "Rivera",
]

RANDOM_WORDS = [
    "synergy", "leverage", "optimize", "paradigm", "scalable", "robust",
    "streamline", "innovate", "transform", "empower", "strategic", "dynamic",
    "proactive", "efficient", "seamless", "agile", "premium", "cutting-edge",
    "next-generation", "disruptive", "visionary", "holistic", "sustainable",
]

STREET_NAMES = ["Oak", "Elm", "Pine", "Maple", "Cedar", "Main", "Park", "Lake",
                "River", "Hill", "Valley", "Forest", "Sunset", "Spring", "Willow"]
STREET_TYPES = ["St", "Ave", "Blvd", "Dr", "Ln", "Rd", "Way", "Pl", "Ct", "Terr"]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
]

LOREM_SHORT = "Lorem ipsum dolor sit amet, consectetur adipiscing elit."
LOREM_MEDIUM = (
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit. "
    "Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. "
    "Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris."
)
LOREM_LONG = (
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor "
    "incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud "
    "exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure "
    "dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. "
    "Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."
)

JOB_TITLES = [
    "CEO", "CTO", "CFO", "COO", "VP of Sales", "VP of Marketing", "VP of Engineering",
    "Director of Operations", "Director of Finance", "Senior Manager", "Project Manager",
    "Software Engineer", "Senior Developer", "Product Manager", "Marketing Manager",
    "Sales Manager", "Account Executive", "Business Analyst", "Data Scientist",
    "UX Designer", "DevOps Engineer", "Security Analyst", "Solutions Architect",
]

DEPARTMENTS = [
    "Engineering", "Marketing", "Sales", "Finance", "Operations", "HR",
    "Legal", "Product", "Design", "Customer Success", "IT", "Research",
    "Business Development", "Strategy", "Procurement", "Compliance",
]

INDUSTRIES = [
    "Technology", "Healthcare", "Finance", "Education", "Retail", "Manufacturing",
    "Real Estate", "Consulting", "Media", "Transportation", "Energy", "Telecom",
    "Insurance", "Government", "Non-profit", "Hospitality", "Legal", "Agriculture",
]

DOMAIN_EXTENSIONS = [".com", ".io", ".co", ".net", ".org", ".ai", ".app", ".dev"]

# Max characters allowed from a numeric/length argument in tags
MAX_TAG_ARG = 512


# ═══════════════════════════════════════════════════════════
# HELPER GENERATORS
# ═══════════════════════════════════════════════════════════

def _rand_digits(n: int) -> str:
    n = min(n, MAX_TAG_ARG)
    return ''.join(random.choices(string.digits, k=n))

def _rand_hex(n: int) -> str:
    n = min(n, MAX_TAG_ARG)
    return ''.join(random.choices('0123456789abcdef', k=n))

def _rand_alpha(n: int) -> str:
    n = min(n, MAX_TAG_ARG)
    return ''.join(random.choices(string.ascii_lowercase, k=n))

def _rand_alphanum(n: int) -> str:
    n = min(n, MAX_TAG_ARG)
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))

def _rand_alphanum_upper(n: int) -> str:
    n = min(n, MAX_TAG_ARG)
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=n))

def _rand_ipv4() -> str:
    return f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def _rand_ipv6() -> str:
    groups = [_rand_hex(4) for _ in range(8)]
    return ':'.join(groups)

def _rand_mac() -> str:
    return ':'.join([_rand_hex(2).upper() for _ in range(6)])

def _rand_amount(min_cents=125, max_cents=999999) -> str:
    return f"${random.randint(min_cents, max_cents) / 100:,.2f}"

def _rand_date_past(max_days=90) -> str:
    d = datetime.now() - timedelta(days=random.randint(1, max_days))
    return f"{MONTHS[d.month-1]} {d.day}, {d.year}"

def _rand_time12() -> str:
    h = random.randint(1, 12)
    m = random.randint(0, 59)
    ampm = random.choice(["AM", "PM"])
    return f"{h}:{m:02d} {ampm}"

def _rand_phone_us() -> str:
    return f"({_rand_digits(3)}) {_rand_digits(3)}-{_rand_digits(4)}"

def _rand_phone_intl() -> str:
    cc = random.choice(["+1", "+44", "+61", "+49", "+33", "+81", "+55", "+91"])
    return f"{cc} {_rand_digits(3)} {_rand_digits(3)} {_rand_digits(4)}"

def _rand_address() -> str:
    num = random.randint(100, 9999)
    street = random.choice(STREET_NAMES)
    stype = random.choice(STREET_TYPES)
    return f"{num} {street} {stype}"

def _rand_zip() -> str:
    return _rand_digits(5)

def _rand_domain() -> str:
    name = _rand_alpha(random.randint(5, 10))
    ext = random.choice(DOMAIN_EXTENSIONS)
    return f"{name}{ext}"

def _rand_url() -> str:
    domain = _rand_domain()
    path = _rand_alphanum(random.randint(4, 10))
    return f"https://{domain}/{path}"

def _rand_email_fake() -> str:
    first = random.choice(FAKE_NAMES_FIRST).lower()
    last = random.choice(FAKE_NAMES_LAST).lower()
    domain = _rand_domain()
    sep = random.choice([".", "_", ""])
    return f"{first}{sep}{last}@{domain}"

def _rand_cc_fake() -> str:
    """Fake credit card number (Luhn-valid pattern, not real)"""
    prefixes = ["4", "51", "52", "53", "54", "55", "37", "6011"]
    prefix = random.choice(prefixes)
    length = 15 if prefix == "37" else 16
    rest = _rand_digits(length - len(prefix) - 1)
    partial = prefix + rest
    # Luhn checksum
    total = 0
    reverse = partial[::-1]
    for i, d in enumerate(reverse):
        n = int(d)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    check = (10 - (total % 10)) % 10
    return partial + str(check)

def _rand_iban() -> str:
    cc = random.choice(["GB", "DE", "FR", "NL", "ES", "IT", "SE", "NO"])
    check = _rand_digits(2)
    bban = _rand_digits(18)
    return f"{cc}{check}{bban}"


# ═══════════════════════════════════════════════════════════
# CONTEXT BUILDER
# Builds a context dict ONCE per lead — all computed fields live here.
# Pass this ctx to resolve_tags() instead of computing inline.
# ═══════════════════════════════════════════════════════════

def build_context(lead: dict, sender: dict, subject: str, counter: int,
                  links_cfg: dict = None, now: datetime = None) -> dict:
    """
    Pre-compute all lead/sender derived values once per lead.
    This avoids recomputing the same splits/joins for every field
    (subject, html, plain, fromEmail, fromName, replyTo = 5+ calls).
    """
    if now is None:
        now = datetime.now()

    email = (lead.get("email") or "").strip().lower()
    at = email.find("@")
    email_user = email[:at] if at > -1 else email
    domain = email[at+1:] if at > -1 else ""
    domain_name = domain.split(".")[0] if domain else ""
    domain_tld = ".".join(domain.split(".")[1:]) if "." in domain else ""

    name = (lead.get("name") or "").strip()
    name_parts = name.split() if name else []
    first_name = name_parts[0] if name_parts else email_user
    last_name = name_parts[-1] if len(name_parts) > 1 else ""
    middle_name = name_parts[1] if len(name_parts) >= 3 else ""
    company = (lead.get("company") or domain_name.capitalize())

    from_email = (sender.get("fromEmail") or "").strip()
    from_at = from_email.find("@")
    from_domain = from_email[from_at+1:] if from_at > -1 else ""
    from_user = from_email[:from_at] if from_at > -1 else from_email
    from_name = (sender.get("fromName") or "").strip()
    reply_to = (sender.get("replyTo") or from_email).strip()

    # Lead custom fields (passed as extra keys in lead dict)
    custom = {k: str(v) for k, v in lead.items()
              if k not in ("email", "name", "company") and v}

    return {
        # Lead
        "email":         email,
        "email_user":    email_user,
        "domain":        domain,
        "domain_name":   domain_name,
        "domain_tld":    domain_tld,
        "name":          name,
        "first_name":    first_name,
        "last_name":     last_name,
        "middle_name":   middle_name,
        "company":       company,
        "lead":          lead,
        "custom":        custom,
        # Sender
        "from_email":    from_email,
        "from_domain":   from_domain,
        "from_user":     from_user,
        "from_name":     from_name,
        "reply_to":      reply_to,
        "sender":        sender,
        # Meta
        "subject":       subject or "",
        "counter":       counter,
        "links_cfg":     links_cfg or {},
        # Time (frozen at context build time for consistency across fields)
        "now":           now,
    }


# ═══════════════════════════════════════════════════════════
# TAG REGISTRY
# Maps each tag to a callable that takes (ctx) and returns str.
# Longer / more specific tags must come before shorter ones
# that share a prefix — the registry handles this via sort.
# ═══════════════════════════════════════════════════════════

def _make_registry(ctx: dict) -> list[tuple[str, Any]]:
    """
    Build the ordered list of (pattern, replacement) pairs.
    Returns list rather than dict to preserve order.
    All callables receive ctx and return str.
    """
    now: datetime = ctx["now"]
    email    = ctx["email"]
    name     = ctx["name"]
    first    = ctx["first_name"]
    last     = ctx["last_name"]
    middle   = ctx["middle_name"]
    company  = ctx["company"]
    domain   = ctx["domain"]
    dn       = ctx["domain_name"]
    dt       = ctx["domain_tld"]
    eu       = ctx["email_user"]
    fe       = ctx["from_email"]
    fd       = ctx["from_domain"]
    fn       = ctx["from_name"]
    rt       = ctx["reply_to"]
    subj     = ctx["subject"]
    counter  = ctx["counter"]

    # Static strings (computed once, returned as-is)
    # Listed longest-first within each category to avoid prefix collisions

    entries = [

        # ── RECIPIENT / LEAD ──────────────────────────────────────────
        ("#REALNAME",           name or eu),
        ("#FIRSTNAME",          first or eu),
        ("#LASTNAME",           last),
        ("#MIDDLENAME",         middle),
        ("#NAMEINITIALS",       "".join(p[0].upper() for p in (name or eu).split() if p)),
        ("#FULLNAME",           name or eu),
        ("#EMAIL_USER",         eu),
        ("#EMAILUSER",          eu),
        ("#EMAIL",              email),
        ("#DOMAIN_LOGO_URL",    f"https://logo.clearbit.com/{domain}"),
        ("#DOMAINNAME",         dn),
        ("#DOMAIN_TLD",         dt),
        ("#DOMAIN",             domain),
        ("#COMPANY_UPPER",      company.upper()),
        ("#COMPANY",            company),
        # Custom lead fields: #FIELD_phone, #FIELD_address, etc.
        *[(f"#FIELD_{k.upper()}", v) for k, v in ctx["custom"].items()],

        # ── SENDER ────────────────────────────────────────────────────
        ("#FROMNAME_UPPER",     fn.upper()),
        ("#FROMNAME",           fn),
        ("#FROMDOMAIN",         fd),
        ("#FROMUSER",           ctx["from_user"]),
        ("#FROMEMAIL",          fe),
        ("#REPLYTO",            rt),
        ("#SENDERDOMAIN",       fd),
        ("#SENDER",             fe),
        ("#SUBJECT_UPPER",      subj.upper()),
        ("#SUBJECT",            subj),

        # ── DATE / TIME ───────────────────────────────────────────────
        ("#DATESHORT",          _fmt_date_short(now)),
        ("#DATEISO",            _fmt_date_iso(now)),
        ("#DATE_RFC",           now.strftime("%a, %d %b %Y %H:%M:%S +0000")),
        ("#DATE_UNIX",          str(int(now.timestamp()))),
        # NOTE: #DATE_IN{N}/#DATE_PLUS{N} are resolved in Pass 0 of resolve_tags()
        # before this static registry runs, so bare #DATE here is safe.
        ("#DATE",               _fmt_date(now)),
        ("#DAYNAME_SHORT",      now.strftime("%a")),
        ("#DAYNAME",            now.strftime("%A")),
        ("#WEEKDAY",            now.strftime("%A")),
        # #DAYNUM before #DAY — prevents #DAY eating the prefix of #DAYNUM
        # #DAY = full day name (Monday, Tuesday…) — the intuitive meaning
        # #DAYNUM = day-of-month number (1–31) — for those who need it
        ("#DAYNUM",             str(now.day)),
        ("#DAY",                now.strftime("%A")),
        ("#MONTHNUM",           f"{now.month:02d}"),
        ("#MONTH_SHORT",        now.strftime("%b")),
        # ── Longer #MONTH_* tags BEFORE bare #MONTH to prevent prefix collision ──
        ("#MONTH_START",        f"{MONTHS[now.month-1]} 1, {now.year}"),
        ("#MONTH_END",          _month_end(now)),
        ("#MONTH",              MONTHS[now.month-1]),
        ("#YEAR_SHORT",         str(now.year)[-2:]),
        ("#YEAR_START",         f"January 1, {now.year}"),
        ("#YEAR_END",           f"December 31, {now.year}"),
        ("#YEAR",               str(now.year)),
        ("#HOUR24",             f"{now.hour:02d}"),
        ("#HOUR12",             now.strftime("%I").lstrip("0") or "12"),
        ("#MINUTE",             f"{now.minute:02d}"),
        ("#SECOND",             f"{now.second:02d}"),
        ("#AMPM",               now.strftime("%p")),
        ("#TIMESTAMP",          str(int(now.timestamp()))),
        ("#UNIXTIME",           str(int(now.timestamp()))),
        # Time tags — server always runs UTC, so these show UTC time.
        # Use #TIME12_EST / #TIME12_CST etc to get a specific zone offset.
        # Formula: UTC + offset. EST=-5, CST=-6, MST=-7, PST=-8
        ("#TIME12_EST",         _fmt_time12_offset(now, -5)),
        ("#TIME12_CST",         _fmt_time12_offset(now, -6)),
        ("#TIME12_MST",         _fmt_time12_offset(now, -7)),
        ("#TIME12_PST",         _fmt_time12_offset(now, -8)),
        ("#TIME12_GMT",         _fmt_time12_offset(now,  0)),
        ("#TIME12_CET",         _fmt_time12_offset(now, +1)),
        ("#TIME12_EET",         _fmt_time12_offset(now, +2)),
        ("#TIME12_IST",         _fmt_time12_offset(now, +5, 30)),
        ("#TIME12_JST",         _fmt_time12_offset(now, +9)),
        ("#TIME12_AEST",        _fmt_time12_offset(now, +10)),
        # #TIME12 = server local time (UTC on most VPS)
        ("#TIME12",             now.strftime("%I:%M %p").lstrip("0") or "12:00 AM"),
        ("#TIME_EST",           _fmt_time24_offset(now, -5)),
        ("#TIME_CST",           _fmt_time24_offset(now, -6)),
        ("#TIME_MST",           _fmt_time24_offset(now, -7)),
        ("#TIME_PST",           _fmt_time24_offset(now, -8)),
        ("#TIME_GMT",           _fmt_time24_offset(now,  0)),
        ("#TIME",               now.strftime("%H:%M:%S")),
        # ── QUARTER_START/END before bare #QUARTER ──
        ("#QUARTER_START",      _quarter_start(now)),
        ("#QUARTER_END",        _quarter_end(now)),
        ("#QUARTER",            f"Q{(now.month - 1) // 3 + 1}"),
        ("#WEEKNUM",            now.strftime("%V")),
        # ── Other relative date shortcuts ──
        ("#TOMORROW",           _fmt_date(now + timedelta(days=1))),
        ("#YESTERDAY",          _fmt_date(now - timedelta(days=1))),
        ("#NEXT_WEEK",          _fmt_date(now + timedelta(weeks=1))),
        ("#NEXT_MONTH",         _next_month_start(now)),
        ("#WEEK_START",         _fmt_date(now - timedelta(days=now.weekday()))),
        ("#WEEK_END",           _fmt_date(now + timedelta(days=6 - now.weekday()))),

        # ── RANDOM FIXED-LENGTH SHORTCUTS ─────────────────────────────
        # NOTE: ordering matters — more specific first, shorter last
        ("#RANDOMSTR",          lambda _: _rand_alphanum(8)),
        ("#RANDOM_SHA256",      lambda _: _rand_hex(64)),
        ("#RANDOM_MD5",         lambda _: _rand_hex(32)),
        ("#RANDOM_COLOR",       lambda _: f"#{_rand_hex(6).upper()}"),
        ("#RANDOM_WORD",        lambda _: random.choice(RANDOM_WORDS)),
        ("#SHORT_ID",           lambda _: _rand_alphanum(8)),
        ("#HEX8",               lambda _: _rand_hex(8)),
        ("#UUID4",              lambda _: str(_uuid_mod.uuid4())),
        ("#UUID",               lambda _: str(_uuid_mod.uuid4())),

        # ── ENCODING / HASHING ────────────────────────────────────────
        ("#B64EMAIL",           lambda _: base64.b64encode(email.encode()).decode()),
        ("#B64NAME",            lambda _: base64.b64encode((name or eu).encode()).decode()),
        ("#B64SUBJECT",         lambda _: base64.b64encode(subj.encode()).decode()),
        ("#URLENCODE_EMAIL",    lambda _: urllib.parse.quote(email)),
        ("#URLENCODE_NAME",     lambda _: urllib.parse.quote(name or eu)),
        ("#URLENCODE_SUBJECT",  lambda _: urllib.parse.quote(subj)),
        ("#MD5_EMAIL",          lambda _: hashlib.md5(email.encode()).hexdigest()),
        ("#SHA1_EMAIL",         lambda _: hashlib.sha1(email.encode()).hexdigest()),
        ("#SHA256_EMAIL",       lambda _: hashlib.sha256(email.encode()).hexdigest()),
        ("#MD5",                lambda _: hashlib.md5(email.encode()).hexdigest()[:12]),
        ("#SHA1",               lambda _: hashlib.sha1(email.encode()).hexdigest()[:16]),

        # ── RANDOM DATA ───────────────────────────────────────────────
        ("#RANDAMOUNT_SMALL",   lambda _: _rand_amount(100, 9999)),
        ("#RANDAMOUNT_LARGE",   lambda _: _rand_amount(10000, 9999999)),
        ("#RANDAMOUNT",         lambda _: _rand_amount()),
        ("#RANDPERCENT",        lambda _: f"{random.randint(1, 99)}%"),
        ("#RANDDATE_PAST30",    lambda _: _rand_date_past(30)),
        ("#RANDDATE_PAST365",   lambda _: _rand_date_past(365)),
        ("#RANDDATE",           lambda _: _rand_date_past(90)),
        ("#RANDTIME",           lambda _: _rand_time12()),
        ("#RANDCOUNTRY",        lambda _: random.choice(CITY_COUNTRY_PAIRS)[1]),
        ("#RANDCITY",           lambda _: random.choice(CITY_COUNTRY_PAIRS)[0]),
        ("#RAND_LOCATION_CITY_COUNTRY", lambda _: "{}, {}".format(*random.choice(CITY_COUNTRY_PAIRS))),
        ("#RAND_LOCATION_COUNTRY_CITY", lambda _: "{}, {}".format(random.choice(CITY_COUNTRY_PAIRS)[1], random.choice(CITY_COUNTRY_PAIRS)[0])),
        ("#RAND_LOCATION_COUNTRY", lambda _: random.choice(CITY_COUNTRY_PAIRS)[1]),
        ("#RAND_LOCATION_CITY",    lambda _: random.choice(CITY_COUNTRY_PAIRS)[0]),
        ("#RAND_LOCATION",      lambda _: "{}, {}".format(*random.choice(CITY_COUNTRY_PAIRS))),
        ("#RANDBROWSER",        lambda _: random.choice(BROWSERS)),
        ("#RANDOS",             lambda _: random.choice(OS_LIST)),
        ("#RANDCOLOR_NAME",     lambda _: random.choice(COLOR_NAMES)),
        ("#RANDCOLOR_HEX",      lambda _: f"#{_rand_hex(6).upper()}"),
        ("#RANDFIRSTNAME",      lambda _: random.choice(FAKE_NAMES_FIRST)),
        ("#RANDLASTNAME",       lambda _: random.choice(FAKE_NAMES_LAST)),
        ("#RANDFULLNAME",       lambda _: f"{random.choice(FAKE_NAMES_FIRST)} {random.choice(FAKE_NAMES_LAST)}"),
        ("#RANDJOBTITLE",       lambda _: random.choice(JOB_TITLES)),
        ("#RANDDEPARTMENT",     lambda _: random.choice(DEPARTMENTS)),
        ("#RANDINDUSTRY",       lambda _: random.choice(INDUSTRIES)),
        ("#RANDIPV6",           lambda _: _rand_ipv6()),
        ("#RANDIPV4",           lambda _: _rand_ipv4()),
        ("#IP_ADDRESS",         lambda _: _rand_ipv4()),
        ("#RANDMAC",            lambda _: _rand_mac()),
        ("#RANDZIP",            lambda _: _rand_zip()),
        ("#RANDDOMAIN",         lambda _: _rand_domain()),
        ("#RANDURL",            lambda _: _rand_url()),
        ("#RANDEMAIL_FAKE",     lambda _: _rand_email_fake()),
        ("#RANDPHONE_INTL",     lambda _: _rand_phone_intl()),
        ("#RANDPHONE",          lambda _: _rand_phone_us()),
        ("#RANDWORD",           lambda _: random.choice(RANDOM_WORDS)),

        # ── BUSINESS / TRANSACTIONS ───────────────────────────────────
        ("#INVOICE_NUM",        lambda _: f"INV-{_rand_digits(6)}"),
        ("#ORDER_NUM",          lambda _: f"ORD-{_rand_digits(7)}"),
        ("#TRANSACTION_ID",     lambda _: f"TXN-{_rand_alphanum_upper(8)}"),
        ("#TRACKING_NUM",       lambda _: f"TRK-{_rand_alphanum_upper(8)}"),
        ("#CONFIRMATION_CODE",  lambda _: _rand_hex(8).upper()),
        ("#VERIFICATION_CODE",  lambda _: _rand_digits(6)),
        ("#OTP_CODE",           lambda _: _rand_digits(6)),
        ("#PIN_CODE",           lambda _: _rand_digits(4)),
        ("#ACCOUNT_NUM",        lambda _: f"ACC-{_rand_digits(8)}"),
        ("#REFERENCE_NUM",      lambda _: f"REF-{_rand_alphanum_upper(8)}"),
        ("#TICKET_NUM",         lambda _: f"TKT-{_rand_digits(5)}"),
        ("#CASE_ID",            lambda _: f"CASE-{_rand_digits(7)}"),
        ("#POLICY_NUM",         lambda _: f"POL-{_rand_digits(8)}"),
        ("#CLAIM_NUM",          lambda _: f"CLM-{_rand_digits(7)}"),
        ("#QUOTE_ID",           lambda _: f"QUO-{_rand_alphanum_upper(6)}"),
        ("#CONTRACT_ID",        lambda _: f"CNT-{_rand_digits(8)}"),
        ("#SUBSCRIPTION_ID",    lambda _: f"SUB-{_rand_alphanum_upper(10)}"),
        ("#CUSTOMER_ID",        lambda _: f"CUS-{_rand_digits(7)}"),
        ("#MEMBERSHIP_ID",      lambda _: f"MEM-{_rand_alphanum_upper(8)}"),
        ("#BATCH_ID",           lambda _: f"BAT-{_rand_alphanum_upper(6)}"),
        ("#CC_FAKE",            lambda _: _rand_cc_fake()),
        ("#IBAN_FAKE",          lambda _: _rand_iban()),

        # ── TECHNICAL / SERVER ────────────────────────────────────────
        ("#SERVER_NAME",        lambda _: f"SRV-PROD-{_rand_digits(3)}"),
        ("#SERVER_ID",          lambda _: f"i-{_rand_hex(17)}"),
        ("#POD_NAME",           lambda _: f"pod-{_rand_alphanum(8)}-{_rand_alphanum(5)}"),
        ("#CONTAINER_ID",       lambda _: _rand_hex(12)),
        ("#API_KEY_FAKE",       lambda _: f"sk_live_{_rand_alphanum(24)}"),
        ("#API_KEY_TEST",       lambda _: f"sk_test_{_rand_alphanum(24)}"),
        ("#WEBHOOK_SECRET",     lambda _: f"whsec_{_rand_alphanum(32)}"),
        ("#JWT_FAKE",           lambda _: f"eyJ{_rand_alphanum(20)}.eyJ{_rand_alphanum(40)}.{_rand_alphanum(43)}"),
        ("#ERROR_CODE",         lambda _: f"ERR-{_rand_digits(4)}"),
        ("#STATUS_CODE",        lambda _: random.choice(["200", "201", "400", "401", "403", "404", "500", "503"])),
        ("#SESSION_ID",         lambda _: f"sess_{_rand_alphanum(20)}"),
        ("#REQUEST_ID",         lambda _: f"req-{_uuid_mod.uuid4()}"),
        ("#TRACE_ID",           lambda _: _rand_hex(32)),
        ("#BUILD_NUM",          lambda _: _rand_digits(4)),
        ("#VERSION_NUM",        lambda _: f"{random.randint(1,9)}.{random.randint(0,15)}.{random.randint(0,30)}"),
        ("#SEMVER",             lambda _: f"{random.randint(1,9)}.{random.randint(0,15)}.{random.randint(0,30)}"),
        ("#USER_AGENT",         lambda _: random.choice(USER_AGENTS)),
        ("#PORT_NUM",           lambda _: str(random.randint(1024, 65535))),

        # ── CONTENT / LOREM ───────────────────────────────────────────
        # Longer #FAKE_* tags BEFORE bare #FAKE_COMPANY to prevent prefix collision
        ("#FAKE_COMPANY_EMAIL",
         lambda _: (
             lambda fn, co: f"{fn.lower()}@{co.lower().replace(' ','').replace('.','').replace(',','')[:12]}.com"
         )(random.choice(FAKE_NAMES_FIRST), random.choice(FAKE_COMPANIES))
        ),
        ("#FAKE_FULLNAME_EMAIL",
         lambda _: (
             lambda fn, ln: f"{fn.lower()}{random.choice(['.','_',''])}{ln.lower()}@{_rand_domain()}"
         )(random.choice(FAKE_NAMES_FIRST), random.choice(FAKE_NAMES_LAST))
        ),
        ("#FAKE_PHONE_INTL",    lambda _: _rand_phone_intl()),
        ("#FAKE_COMPANY",       lambda _: random.choice(FAKE_COMPANIES)),
        ("#FAKE_ADDRESS",       lambda _: _rand_address()),
        ("#FAKE_PHONE",         lambda _: _rand_phone_us()),
        ("#FAKE_ZIP",           lambda _: _rand_zip()),
        ("#FAKE_CITY",          lambda _: random.choice(CITIES)),
        ("#FAKE_COUNTRY",       lambda _: random.choice(COUNTRIES)),
        ("#FAKE_JOBTITLE",      lambda _: random.choice(JOB_TITLES)),
        ("#RANDOM_PATH",        lambda _: f"/ref/{_rand_alphanum(4)}/{_rand_alphanum(8)}"),
        ("#RANDOM_LINK",        lambda _: f"https://{_rand_domain()}/ref/{_rand_alphanum(4)}/{_rand_alphanum(8)}"),
        ("#LOREM_LONG",         LOREM_LONG),
        ("#LOREM_PARAGRAPH",    LOREM_MEDIUM),
        ("#LOREM_SHORT",        LOREM_SHORT),
        ("#LOREM",              LOREM_SHORT),

        # ── META ──────────────────────────────────────────────────────
        ("#COUNTER",            str(counter)),
        ("#UNIQID",             lambda _: _rand_alphanum(8)),
    ]

    return entries


# ═══════════════════════════════════════════════════════════
# REGEX-BASED TAGS (variable length / functional)
# Applied AFTER static tags to avoid interfering with static values
# ═══════════════════════════════════════════════════════════

def _apply_regex_tags(s: str, ctx: dict) -> str:
    """Apply all regex-pattern tags with safe error handling."""
    lead = ctx["lead"]
    links_cfg = ctx["links_cfg"]
    counter = ctx["counter"]

    # ── Variable-length generators (capped at MAX_TAG_ARG) ──
    def _safe_int(m_group: str, default: int = 1) -> int:
        try:
            return min(int(m_group), MAX_TAG_ARG)
        except (ValueError, TypeError):
            return default

    # ── Range-based RAND: #RAND{min-max} or #RANDmin-max ──
    def _rand_range(m):
        try:
            lo, hi = int(m.group(1)), int(m.group(2))
            if lo > hi: lo, hi = hi, lo
            return str(random.randint(lo, hi))
        except Exception:
            return "0"
    s = re.sub(r'#RAND\{(\d+)-(\d+)\}', _rand_range, s)
    s = re.sub(r'#RAND(\d+)-(\d+)', _rand_range, s)

    # ── Smart geo combos ──
    def _rand_location(fmt):
        pair = random.choice(CITY_COUNTRY_PAIRS)
        city, country = pair
        if fmt == "city":        return city
        if fmt == "country":     return country
        if fmt == "city_country": return f"{city}, {country}"
        if fmt == "country_city": return f"{country}, {city}"
        return f"{city}, {country}"
    s = re.sub(r'#RAND_LOCATION_CITY_COUNTRY', lambda m: _rand_location("city_country"), s)
    s = re.sub(r'#RAND_LOCATION_COUNTRY_CITY', lambda m: _rand_location("country_city"), s)
    s = re.sub(r'#RAND_LOCATION_COUNTRY', lambda m: _rand_location("country"), s)
    s = re.sub(r'#RAND_LOCATION_CITY',    lambda m: _rand_location("city"), s)
    s = re.sub(r'#RAND_LOCATION',         lambda m: _rand_location("city_country"), s)
    # Also replace #RANDCITY and #RANDCOUNTRY with paired versions
    def _rand_city_paired(m):
        return random.choice(CITY_COUNTRY_PAIRS)[0]
    def _rand_country_paired(m):
        return random.choice(CITY_COUNTRY_PAIRS)[1]
    s = re.sub(r'#RANDCITY', _rand_city_paired, s)
    s = re.sub(r'#RANDCOUNTRY', _rand_country_paired, s)

    # ── #RAND1 / #RAND2 shortcuts (after range matching) ──
    s = s.replace('#RAND1', _rand_digits(5))
    s = s.replace('#RAND2', _rand_digits(7))

    # ── Bare #RAND not followed by letter/digit (e.g. #RAND@domain.com) ──
    s = re.sub(r'#RAND(?![A-Z0-9_a-z{])', lambda m: _rand_digits(6), s)

    # ── Bare #RANDOM not followed by _ ──
    s = re.sub(r'#RANDOM(?![_A-Z])', lambda m: _rand_digits(6), s)

    # ── Variable-length generators: brace {N} form FIRST, then plain digit form ──
    # Both #RANDNUM{3} and #RANDNUM3 are supported. Brace checked first to prevent
    # the plain-digit regex from eating the { and leaving a dangling }.
    s = re.sub(r'#RANDNUM\{(\d+)\}',
               lambda m: _rand_digits(_safe_int(m.group(1))), s)
    s = re.sub(r'#RANDNUM(\d+)',
               lambda m: _rand_digits(_safe_int(m.group(1))), s)
    s = re.sub(r'#RANDALPHANUM\{(\d+)\}',
               lambda m: _rand_alphanum(_safe_int(m.group(1))), s)
    s = re.sub(r'#RANDALPHANUM(\d+)',
               lambda m: _rand_alphanum(_safe_int(m.group(1))), s)
    s = re.sub(r'#RANDALPHA\{(\d+)\}',
               lambda m: _rand_alpha(_safe_int(m.group(1))), s)
    s = re.sub(r'#RANDALPHA(\d+)',
               lambda m: _rand_alpha(_safe_int(m.group(1))), s)
    s = re.sub(r'#RANDHEX\{(\d+)\}',
               lambda m: _rand_hex(_safe_int(m.group(1))), s)
    s = re.sub(r'#RANDHEX(\d+)',
               lambda m: _rand_hex(_safe_int(m.group(1))), s)
    s = re.sub(r'#RANDUPPERALPHA\{(\d+)\}',
               lambda m: _rand_alpha(_safe_int(m.group(1))).upper(), s)
    s = re.sub(r'#RANDUPPERALPHA(\d+)',
               lambda m: _rand_alpha(_safe_int(m.group(1))).upper(), s)
    s = re.sub(r'#RANDUPPERHEX\{(\d+)\}',
               lambda m: _rand_hex(_safe_int(m.group(1))).upper(), s)
    s = re.sub(r'#RANDUPPERHEX(\d+)',
               lambda m: _rand_hex(_safe_int(m.group(1))).upper(), s)
    s = re.sub(r'#RANDUPPERAL\{(\d+)\}',
               lambda m: _rand_alphanum(_safe_int(m.group(1))).upper(), s)
    s = re.sub(r'#RANDUPPERAL(\d+)',
               lambda m: _rand_alphanum(_safe_int(m.group(1))).upper(), s)

    # ── Functional tags (with brace args) ──

    def _shuf(m):
        try:
            opts = [x for x in m.group(1).split("|") if x.strip()]
            return random.choice(opts) if opts else ""
        except Exception:
            return ""

    def _ucfirst(m):
        try:
            t = m.group(1)
            return (t[0].upper() + t[1:]) if t else ""
        except Exception:
            return ""

    def _upper(m):
        try:
            return m.group(1).upper()
        except Exception:
            return ""

    def _lower(m):
        try:
            return m.group(1).lower()
        except Exception:
            return ""

    def _title(m):
        try:
            return m.group(1).title()
        except Exception:
            return ""

    def _repeat(m):
        try:
            text, n = m.group(1), min(int(m.group(2)), 50)
            return text * n
        except Exception:
            return ""

    def _if_name(m):
        try:
            return m.group(1) if lead.get("name") else ""
        except Exception:
            return ""

    def _if_noname(m):
        try:
            return m.group(1) if not lead.get("name") else ""
        except Exception:
            return ""

    def _if_company(m):
        try:
            return m.group(1) if lead.get("company") else ""
        except Exception:
            return ""

    def _if_nocompany(m):
        try:
            return m.group(1) if not lead.get("company") else ""
        except Exception:
            return ""

    def _if_field(m):
        """#IF_FIELD{fieldname}{content} — show if lead has that custom field"""
        try:
            field, content = m.group(1).lower(), m.group(2)
            return content if lead.get(field) else ""
        except Exception:
            return ""

    def _truncate(m):
        """#TRUNCATE{text}{N} — truncate text to N characters"""
        try:
            text, n = m.group(1), min(int(m.group(2)), MAX_TAG_ARG)
            return text[:n] + ("…" if len(text) > n else "")
        except Exception:
            return ""

    def _pad_left(m):
        """#PADLEFT{text}{N}{char} — pad text to N chars with char"""
        try:
            text, n, char = m.group(1), min(int(m.group(2)), 100), (m.group(3) or "0")[:1]
            return text.rjust(n, char)
        except Exception:
            return ""

    def _pad_right(m):
        try:
            text, n, char = m.group(1), min(int(m.group(2)), 100), (m.group(3) or " ")[:1]
            return text.ljust(n, char)
        except Exception:
            return ""

    s = re.sub(r'#SHUF\{([^}]*)\}',                                  _shuf,      s)
    s = re.sub(r'#UCFIRST\{([^}]*)\}',                               _ucfirst,   s)
    s = re.sub(r'#UPPER\{([^}]*)\}',                                  _upper,     s)
    s = re.sub(r'#LOWER\{([^}]*)\}',                                  _lower,     s)
    s = re.sub(r'#TITLE\{([^}]*)\}',                                  _title,     s)
    s = re.sub(r'#REPEAT\{([^}]*)\}\{(\d+)\}',                       _repeat,    s)
    s = re.sub(r'#TRUNCATE\{([^}]*)\}\{(\d+)\}',                     _truncate,  s)
    s = re.sub(r'#PADLEFT\{([^}]*)\}\{(\d+)\}\{([^}])\}',            _pad_left,  s)
    s = re.sub(r'#PADRIGHT\{([^}]*)\}\{(\d+)\}\{([^}])\}',           _pad_right, s)
    s = re.sub(r'#IF_FIELD\{([^}]+)\}\{([^}]*)\}',                   _if_field,  s)
    s = re.sub(r'#IF_NOCOMPANY\{([^}]*)\}',                          _if_nocompany, s)
    s = re.sub(r'#IF_COMPANY\{([^}]*)\}',                            _if_company, s)
    s = re.sub(r'#IF_NONAME\{([^}]*)\}',                             _if_noname, s)
    s = re.sub(r'#IF_NAME\{([^}]*)\}',                               _if_name,   s)

    # ── Link rotation ──
    if links_cfg and links_cfg.get("links"):
        valid = [l["url"] for l in links_cfg["links"] if l.get("url")]
        if valid:
            mode = links_cfg.get("mode", "random")
            def _link(m):
                if mode == "random":
                    return random.choice(valid)
                return valid[(counter - 1) % len(valid)]
            s = re.sub(r'#LINK', _link, s)

    return s


# ═══════════════════════════════════════════════════════════
# MAIN RESOLVER
# ═══════════════════════════════════════════════════════════

def resolve_tags(text: str, ctx: dict) -> str:
    """
    Resolve all #TAGs in text using the pre-built context dict.

    Pass 0: Date offset regex tags (#DATE_IN{N}, #DATE_PLUS{N}, etc.)
            Must run BEFORE Pass 1 — bare #DATE in the static registry
            would eat the prefix of #DATE_IN{7} → 'March 17, 2026_IN{7}'.
    Pass 1: Static registry tags (str.replace, longest-first ordered).
    Pass 2: All other regex/functional tags.
    """
    if not text:
        return text

    s = text
    _now = ctx["now"]

    # ── Pass 0: date offset tags (must precede #DATE static replacement) ──
    def _date_off(m):
        try: return _fmt_date(_now + timedelta(days=int(m.group(1))))
        except Exception: return ""
    def _dateshort_off(m):
        try: return _fmt_date_short(_now + timedelta(days=int(m.group(1))))
        except Exception: return ""
    def _dateiso_off(m):
        try: return _fmt_date_iso(_now + timedelta(days=int(m.group(1))))
        except Exception: return ""
    if '#DATE' in s:
        s = re.sub(r'#DATESHORT_IN\{(-?\d+)\}',  _dateshort_off, s)
        s = re.sub(r'#DATEISO_IN\{(-?\d+)\}',    _dateiso_off,   s)
        s = re.sub(r'#DATE_IN\{(-?\d+)\}',       _date_off,      s)
        s = re.sub(r'#DATE_PLUS\{(-?\d+)\}',     _date_off,      s)
        s = re.sub(r'#DATE_PLUS(-?\d+)',          _date_off,      s)

    # ── Pass 1: static registry tags ──
    registry = _make_registry(ctx)
    for tag, value in registry:
        if tag not in s:
            continue
        if callable(value):
            try:
                s = s.replace(tag, value(ctx))
            except Exception:
                pass
        else:
            s = s.replace(tag, str(value))

    # ── Pass 2: regex-based and functional tags ──
    s = _apply_regex_tags(s, ctx)

    return s


# ═══════════════════════════════════════════════════════════
# TAG EXTRACTION — find all #TAGS used in a template
# ═══════════════════════════════════════════════════════════

# Pattern matches any #UPPERCASE_TAG optionally followed by {content} or N
_TAG_EXTRACT_PATTERN = re.compile(
    r'#[A-Z][A-Z0-9_]*'          # #TAGNAME
    r'(?:\d+)?'                   # optional numeric suffix (#RANDNUM5)
    r'(?:\{[^}]*\})*'            # optional brace args (#SHUF{a|b|c}, #IF_NAME{...})
)

def extract_tags(text: str) -> list[str]:
    """
    Extract all unique #TAGS found in a template string.
    Returns sorted list of unique tag strings found.
    """
    if not text:
        return []
    found = _TAG_EXTRACT_PATTERN.findall(text)
    return sorted(set(found))


# ═══════════════════════════════════════════════════════════
# TAG VALIDATION — detect issues before sending
# ═══════════════════════════════════════════════════════════

# All known static tags (built once at module load)
_STATIC_TAGS = None

def _get_all_known_tags() -> set[str]:
    global _STATIC_TAGS
    if _STATIC_TAGS is None:
        # Build with a dummy context to get the full tag list
        dummy_ctx = build_context(
            lead={"email": "test@example.com", "name": "Test User"},
            sender={"fromEmail": "from@example.com", "fromName": "Sender"},
            subject="Test Subject",
            counter=1,
        )
        registry = _make_registry(dummy_ctx)
        _STATIC_TAGS = {tag for tag, _ in registry}
        # Add regex-based patterns as known
        _STATIC_TAGS.update({
            "#RANDNUM", "#RANDALPHANUM", "#RANDALPHA", "#RANDHEX",
            "#RANDUPPERALPHA", "#RANDUPPERHEX", "#RANDUPPERAL",
            "#SHUF", "#UCFIRST", "#UPPER", "#LOWER", "#TITLE",
            "#REPEAT", "#TRUNCATE", "#PADLEFT", "#PADRIGHT",
            "#IF_NAME", "#IF_NONAME", "#IF_COMPANY", "#IF_NOCOMPANY",
            "#IF_FIELD", "#LINK",
            # Date offset
            "#DATE_IN", "#DATE_PLUS", "#DATESHORT_IN", "#DATEISO_IN",
            # New static tags
            "#SENDER", "#SENDERDOMAIN", "#UNIQID", "#UNIXTIME", "#WEEKDAY",
            "#DAYNUM",
            "#TOMORROW", "#YESTERDAY", "#NEXT_WEEK", "#NEXT_MONTH",
            "#WEEK_START", "#WEEK_END", "#MONTH_START", "#MONTH_END",
            "#QUARTER_START", "#QUARTER_END", "#YEAR_START", "#YEAR_END",
            "#FAKE_COMPANY_EMAIL", "#FAKE_FULLNAME_EMAIL",
            "#RANDOM_PATH", "#RANDOM_LINK",
            "#TIME12_EST", "#TIME12_CST", "#TIME12_MST", "#TIME12_PST",
            "#TIME12_GMT", "#TIME12_CET", "#TIME12_EET", "#TIME12_IST",
            "#TIME12_JST", "#TIME12_AEST",
            "#TIME_EST", "#TIME_CST", "#TIME_MST", "#TIME_PST", "#TIME_GMT",
        })
    return _STATIC_TAGS

# Tags that require lead data to be meaningful
_LEAD_DEPENDENT_TAGS = {
    "#REALNAME", "#FIRSTNAME", "#LASTNAME", "#MIDDLENAME", "#FULLNAME",
    "#NAMEINITIALS", "#EMAIL", "#EMAILUSER", "#EMAIL_USER",
    "#DOMAIN", "#DOMAINNAME", "#DOMAIN_TLD", "#DOMAIN_LOGO_URL",
    "#COMPANY", "#COMPANY_UPPER", "#B64EMAIL", "#B64NAME",
    "#URLENCODE_EMAIL", "#URLENCODE_NAME", "#MD5", "#SHA1",
    "#MD5_EMAIL", "#SHA1_EMAIL", "#SHA256_EMAIL",
    "#IF_NAME", "#IF_NONAME", "#IF_COMPANY", "#IF_NOCOMPANY",
}

# Tags that produce different values every send (can't be "previewed" accurately)
_RANDOM_TAGS = {
    "#UUID", "#UUID4", "#RAND1", "#RAND2", "#SHORT_ID", "#HEX8",
    "#RANDNUM", "#RANDALPHA", "#RANDALPHANUM", "#RANDHEX",
    "#RANDAMOUNT", "#RANDPERCENT", "#RANDDATE", "#RANDTIME",
    "#RANDCOUNTRY", "#RANDCITY", "#RANDBROWSER", "#RANDOS",
    "#RANDCOLOR_NAME", "#RANDCOLOR_HEX", "#RANDOM_COLOR",
    "#RANDFIRSTNAME", "#RANDLASTNAME", "#RANDFULLNAME",
    "#RANDJOBTITLE", "#RANDDEPARTMENT", "#RANDINDUSTRY",
    "#RANDIPV4", "#RANDIPV6", "#RANDMAC", "#RANDZIP",
    "#RANDDOMAIN", "#RANDURL", "#RANDEMAIL_FAKE",
    "#RANDPHONE", "#RANDPHONE_INTL", "#RANDWORD", "#RANDOM_WORD",
    "#INVOICE_NUM", "#ORDER_NUM", "#TRANSACTION_ID", "#TRACKING_NUM",
    "#CONFIRMATION_CODE", "#VERIFICATION_CODE", "#OTP_CODE", "#PIN_CODE",
    "#ACCOUNT_NUM", "#REFERENCE_NUM", "#TICKET_NUM", "#CASE_ID",
    "#POLICY_NUM", "#CLAIM_NUM", "#QUOTE_ID", "#CONTRACT_ID",
    "#SUBSCRIPTION_ID", "#CUSTOMER_ID", "#MEMBERSHIP_ID", "#BATCH_ID",
    "#SERVER_NAME", "#SERVER_ID", "#POD_NAME", "#CONTAINER_ID",
    "#API_KEY_FAKE", "#API_KEY_TEST", "#WEBHOOK_SECRET", "#JWT_FAKE",
    "#ERROR_CODE", "#STATUS_CODE", "#SESSION_ID", "#REQUEST_ID",
    "#TRACE_ID", "#BUILD_NUM", "#VERSION_NUM", "#SEMVER",
    "#IP_ADDRESS", "#USER_AGENT", "#PORT_NUM",
    "#FAKE_COMPANY", "#FAKE_ADDRESS", "#FAKE_PHONE", "#FAKE_PHONE_INTL",
    "#FAKE_ZIP", "#FAKE_CITY", "#FAKE_COUNTRY", "#FAKE_JOBTITLE",
    "#RANDOM_SHA256", "#RANDOM_MD5", "#SHUF", "#CC_FAKE", "#IBAN_FAKE",
}

def validate_tags(
    *texts: str,
    ctx: dict = None,
    lead: dict = None,
) -> dict:
    """
    Validate all tags used across one or more template strings.
    Pass multiple texts (subject, html, plain) in one call.
    
    Returns:
        {
            "errors":   [...],   # Must fix — will break send
            "warnings": [...],   # Should review
            "info":     [...],   # FYI
            "used_tags": [...],  # All tags found
            "unknown_tags": [...],
            "lead_tags": [...],  # Tags needing lead data
            "random_tags": [...],# Tags that vary per send
            "clashes": [...],    # Tags where one is prefix of another and both appear
        }
    """
    all_known = _get_all_known_tags()
    errors, warnings, info = [], [], []

    # Collect all tags from all texts
    all_tags = []
    for text in texts:
        all_tags.extend(extract_tags(text or ""))
    used_tags = sorted(set(all_tags))

    # ── Normalize tag bases (strip numeric suffix and brace content for lookup) ──
    def _base(tag: str) -> str:
        # Strip trailing digits: #RANDNUM5 → #RANDNUM
        t = re.sub(r'\d+$', '', tag)
        # Strip brace content: #SHUF{a|b} → #SHUF
        t = re.sub(r'\{[^}]*\}', '', t)
        return t

    # Classify each found tag
    unknown_tags = []
    lead_tags = []
    random_tags = []
    clash_candidates = []

    for tag in used_tags:
        base = _base(tag)
        if base not in all_known and tag not in all_known:
            unknown_tags.append(tag)
        if base in _LEAD_DEPENDENT_TAGS or tag in _LEAD_DEPENDENT_TAGS:
            lead_tags.append(tag)
        if base in _RANDOM_TAGS or tag in _RANDOM_TAGS:
            random_tags.append(tag)

    # ── Clash detection — check if a shorter tag is a prefix of a longer used tag ──
    # e.g. #DATE and #DATESHORT both present — if #DATE is resolved before #DATESHORT
    # in some implementations, #DATESHORT would get its #DATE prefix resolved first.
    # Our registry handles this correctly, but we warn anyway so the user knows.
    sorted_used = sorted(used_tags, key=len, reverse=True)
    for i, longer in enumerate(sorted_used):
        for shorter in sorted_used[i+1:]:
            base_longer = _base(longer)
            base_shorter = _base(shorter)
            if base_longer.startswith(base_shorter) and base_shorter != base_longer:
                clash_candidates.append((shorter, longer))

    clashes = clash_candidates

    # ── Validate lead data ──
    if ctx and lead_tags:
        email = ctx.get("email", "")
        name = ctx.get("name", "")
        company = ctx.get("company", "")

        if not email:
            errors.append("Lead is missing an email address — all #EMAIL/* tags will be empty")
        if not name and any(t in lead_tags for t in ["#REALNAME", "#FIRSTNAME", "#LASTNAME", "#IF_NAME"]):
            warnings.append("Lead has no name — #REALNAME, #FIRSTNAME will fall back to email username")
        if not company and "#COMPANY" in lead_tags:
            info.append("#COMPANY will use domain name as fallback (no company field in lead)")

    # ── Malformed tag detection ──
    for text in texts:
        if not text:
            continue
        # Unclosed braces: #SHUF{a|b without closing }
        open_braces = re.findall(r'#[A-Z][A-Z0-9_]*\{[^}]*$', text, re.MULTILINE)
        for tag in open_braces:
            errors.append(f"Unclosed brace in tag: {tag[:50]}... — closing '}}' is missing")

        # Empty SHUF options: #SHUF{} or #SHUF{|}
        empty_shuf = re.findall(r'#SHUF\{([^}]*)\}', text)
        for opts in empty_shuf:
            parts = [p for p in opts.split("|") if p.strip()]
            if len(parts) == 0:
                errors.append(f"#SHUF{{}} has no options — provide at least one: #SHUF{{option1|option2}}")
            elif len(parts) == 1:
                warnings.append(f"#SHUF{{{opts}}} has only one option — shuffle has nothing to randomize")

        # REPEAT/TRUNCATE with huge numbers
        big_repeats = re.findall(r'#REPEAT\{[^}]*\}\{(\d+)\}', text)
        for n in big_repeats:
            if int(n) > 50:
                warnings.append(f"#REPEAT{{...}}{{{n}}} — repeat count {n} is very high, may bloat email size")

        # Oversized RANDNUM/RANDALPHA etc
        big_gens = re.findall(r'#RAND(?:NUM|ALPHA|HEX|ALPHANUM)(\d+)', text)
        for n in big_gens:
            if int(n) > 100:
                warnings.append(f"#RAND...{n} — generating {n} characters; values >100 chars may look suspicious")

    # ── Unknown tag warnings ──
    for tag in unknown_tags:
        # Could be a typo or intentional custom placeholder
        warnings.append(f"Unknown tag: {tag} — will be left as literal text in the email")

    # ── Clash warnings ──
    for shorter, longer in clashes:
        info.append(
            f"Tag prefix overlap: {shorter} is a prefix of {longer} — "
            f"both are in your template. The tag engine handles this correctly "
            f"(longer tags resolved first), but double-check the output looks right."
        )

    # ── Sender field missing ──
    if ctx:
        if not ctx.get("from_email") and "#FROMEMAIL" in used_tags:
            errors.append("#FROMEMAIL tag used but no sender From Email is configured")
        if not ctx.get("from_name") and "#FROMNAME" in used_tags:
            warnings.append("#FROMNAME tag used but sender has no From Name — will be empty")

    return {
        "errors":       errors,
        "warnings":     warnings,
        "info":         info,
        "used_tags":    used_tags,
        "unknown_tags": unknown_tags,
        "lead_tags":    lead_tags,
        "random_tags":  random_tags,
        "clashes":      [f"{s} / {l}" for s, l in clashes],
    }


# ═══════════════════════════════════════════════════════════
# PREVIEW RENDERER
# Resolves tags for display in the UI preview panel
# ═══════════════════════════════════════════════════════════

_PREVIEW_LEAD = {
    "email":   "john.smith@acme.com",
    "name":    "John Smith",
    "company": "Acme Corp",
}

_PREVIEW_SENDER = {
    "fromEmail": "hello@yourcompany.com",
    "fromName":  "Your Company",
    "replyTo":   "hello@yourcompany.com",
}

def preview_resolve(text: str, subject: str = "Preview Subject",
                    lead: dict = None, sender: dict = None,
                    counter: int = 1) -> str:
    """
    Resolve tags using preview/dummy data for UI display.
    Uses a realistic sample lead/sender if none provided.
    """
    ctx = build_context(
        lead=lead or _PREVIEW_LEAD,
        sender=sender or _PREVIEW_SENDER,
        subject=subject,
        counter=counter,
    )
    return resolve_tags(text, ctx)


def preview_with_highlights(text: str, subject: str = "Preview Subject",
                             lead: dict = None, sender: dict = None,
                             counter: int = 1) -> dict:
    """
    Resolve tags AND return metadata about what was resolved,
    for use in the frontend preview panel.
    
    Returns:
        {
            "resolved": str,          # fully resolved text
            "validation": dict,       # from validate_tags()
            "tag_map": {              # what each tag resolved to
                "#FIRSTNAME": "John",
                "#EMAIL": "john.smith@acme.com",
                ...
            }
        }
    """
    _lead   = lead   or _PREVIEW_LEAD
    _sender = sender or _PREVIEW_SENDER
    ctx = build_context(
        lead=_lead, sender=_sender,
        subject=subject, counter=counter,
    )
    resolved = resolve_tags(text, ctx)
    validation = validate_tags(text, ctx=ctx, lead=_lead)

    # Build a tag_map: resolve each found tag individually for the info panel
    tag_map = {}
    for tag in validation["used_tags"]:
        try:
            sample = resolve_tags(tag, ctx)
            if sample != tag:  # only include if it was actually resolved
                tag_map[tag] = sample
        except Exception:
            pass

    return {
        "resolved":   resolved,
        "validation": validation,
        "tag_map":    tag_map,
    }


# ═══════════════════════════════════════════════════════════
# TAG CATALOG — machine-readable list for frontend TAG_CATEGORIES
# ═══════════════════════════════════════════════════════════

TAG_CATALOG = [
    {
        "name": "Recipient / Lead",
        "tags": [
            {"tag": "#REALNAME",        "desc": "Full name, or email username if no name"},
            {"tag": "#FIRSTNAME",        "desc": "First name (first word of name)"},
            {"tag": "#LASTNAME",         "desc": "Last name (last word if multiple words)"},
            {"tag": "#MIDDLENAME",       "desc": "Middle name (middle word if 3+ words)"},
            {"tag": "#FULLNAME",         "desc": "Same as #REALNAME"},
            {"tag": "#NAMEINITIALS",     "desc": "Initials of full name (e.g. JS)"},
            {"tag": "#EMAIL",            "desc": "Full recipient email address"},
            {"tag": "#EMAILUSER",        "desc": "Part before @ in email"},
            {"tag": "#DOMAIN",           "desc": "Domain (e.g. gmail.com)"},
            {"tag": "#DOMAINNAME",       "desc": "Domain without TLD (e.g. gmail)"},
            {"tag": "#DOMAIN_TLD",       "desc": "TLD only (e.g. com)"},
            {"tag": "#COMPANY",          "desc": "Company from lead list, or capitalized domain"},
            {"tag": "#COMPANY_UPPER",    "desc": "Company in UPPERCASE"},
            {"tag": "#DOMAIN_LOGO_URL",  "desc": "Clearbit logo image URL for recipient domain"},
            {"tag": "#FIELD_{KEY}",      "desc": "Any custom lead column, e.g. #FIELD_PHONE"},
        ]
    },
    {
        "name": "Sender",
        "tags": [
            {"tag": "#FROMNAME",         "desc": "Sender's From Name"},
            {"tag": "#FROMNAME_UPPER",   "desc": "Sender's From Name in UPPERCASE"},
            {"tag": "#FROMEMAIL",        "desc": "Sender's From Email"},
            {"tag": "#FROMDOMAIN",       "desc": "Domain of sender email"},
            {"tag": "#FROMUSER",         "desc": "Username part of sender email"},
            {"tag": "#REPLYTO",          "desc": "Reply-To address"},
            {"tag": "#SENDER",           "desc": "Sender email (alias for #FROMEMAIL)"},
            {"tag": "#SENDERDOMAIN",     "desc": "Sender domain (alias for #FROMDOMAIN)"},
            {"tag": "#SUBJECT",          "desc": "Current subject line"},
            {"tag": "#SUBJECT_UPPER",    "desc": "Subject in UPPERCASE"},
            {"tag": "#UNIQID",           "desc": "Unique 8-char alphanumeric ID per email"},
        ]
    },
    {
        "name": "Date & Time",
        "tags": [
            {"tag": "#DATE",             "desc": "Full date (February 28, 2026)"},
            {"tag": "#DATESHORT",        "desc": "Short date (02/28/2026)"},
            {"tag": "#DATEISO",          "desc": "ISO date (2026-02-28)"},
            {"tag": "#DATE_RFC",         "desc": "RFC 2822 date for email headers"},
            {"tag": "#DATE_UNIX",        "desc": "Unix timestamp of today"},
            {"tag": "#DAYNAME",          "desc": "Day name (Monday, Tuesday…)"},
            {"tag": "#DAYNAME_SHORT",    "desc": "Short day name (Mon, Tue…)"},
            {"tag": "#WEEKDAY",          "desc": "Day name alias (Monday, Tuesday…)"},
            {"tag": "#DAY",              "desc": "Day name — Monday, Tuesday… (same as #DAYNAME)"},
            {"tag": "#DAYNUM",           "desc": "Day of month number — 1–31"},
            {"tag": "#MONTHNUM",         "desc": "Month number (03)"},
            {"tag": "#MONTH_SHORT",      "desc": "Short month name (Mar)"},
            {"tag": "#MONTH",            "desc": "Month name (March)"},
            {"tag": "#YEAR_SHORT",       "desc": "2-digit year (26)"},
            {"tag": "#YEAR",             "desc": "4-digit year (2026)"},
            {"tag": "#HOUR24",           "desc": "Hour in 24h (14)"},
            {"tag": "#HOUR12",           "desc": "Hour in 12h (2)"},
            {"tag": "#MINUTE",           "desc": "Minute (30)"},
            {"tag": "#SECOND",           "desc": "Second (00)"},
            {"tag": "#AMPM",             "desc": "AM or PM"},
            {"tag": "#TIME12",           "desc": "12h time in server timezone (UTC on most VPS)"},
            {"tag": "#TIME12_EST",       "desc": "12h time — Eastern (UTC-5)"},
            {"tag": "#TIME12_CST",       "desc": "12h time — Central (UTC-6)"},
            {"tag": "#TIME12_MST",       "desc": "12h time — Mountain (UTC-7)"},
            {"tag": "#TIME12_PST",       "desc": "12h time — Pacific (UTC-8)"},
            {"tag": "#TIME12_GMT",       "desc": "12h time — GMT/UTC"},
            {"tag": "#TIME12_CET",       "desc": "12h time — Central European (UTC+1)"},
            {"tag": "#TIME12_EET",       "desc": "12h time — Eastern European (UTC+2)"},
            {"tag": "#TIME12_IST",       "desc": "12h time — India (UTC+5:30)"},
            {"tag": "#TIME12_JST",       "desc": "12h time — Japan (UTC+9)"},
            {"tag": "#TIME12_AEST",      "desc": "12h time — Australia Eastern (UTC+10)"},
            {"tag": "#TIME",             "desc": "24h time in server timezone"},
            {"tag": "#TIME_EST",         "desc": "24h time — Eastern (UTC-5)"},
            {"tag": "#TIME_CST",         "desc": "24h time — Central (UTC-6)"},
            {"tag": "#TIME_MST",         "desc": "24h time — Mountain (UTC-7)"},
            {"tag": "#TIME_PST",         "desc": "24h time — Pacific (UTC-8)"},
            {"tag": "#TIME_GMT",         "desc": "24h time — GMT/UTC"},
            {"tag": "#TIMESTAMP",        "desc": "Unix timestamp"},
            {"tag": "#UNIXTIME",         "desc": "Unix timestamp (alias)"},
            {"tag": "#WEEKDAY",          "desc": "Day name alias (e.g. Tuesday)"},
            {"tag": "#TOMORROW",         "desc": "Tomorrow's full date"},
            {"tag": "#YESTERDAY",        "desc": "Yesterday's full date"},
            {"tag": "#NEXT_WEEK",        "desc": "Date exactly 7 days from now"},
            {"tag": "#NEXT_MONTH",       "desc": "First day of next month"},
            {"tag": "#WEEK_START",       "desc": "Monday of current week"},
            {"tag": "#WEEK_END",         "desc": "Sunday of current week"},
            {"tag": "#MONTH_START",      "desc": "First day of current month"},
            {"tag": "#MONTH_END",        "desc": "Last day of current month"},
            {"tag": "#QUARTER_START",    "desc": "First day of current quarter"},
            {"tag": "#QUARTER_END",      "desc": "Last day of current quarter"},
            {"tag": "#YEAR_START",       "desc": "January 1 of current year"},
            {"tag": "#YEAR_END",         "desc": "December 31 of current year"},
            {"tag": "#DATE_IN{N}",       "desc": "Full date N days from now — e.g. #DATE_IN{7}, #DATE_IN{-3}"},
            {"tag": "#DATE_PLUS{N}",     "desc": "Full date N days from now (alias for DATE_IN)"},
            {"tag": "#DATESHORT_IN{N}",  "desc": "Short date N days from now — MM/DD/YYYY"},
            {"tag": "#DATEISO_IN{N}",    "desc": "ISO date N days from now — YYYY-MM-DD"},
        ]
    },
    {
        "name": "Random Generators",
        "tags": [
            {"tag": "#RANDNUM{N}",       "desc": "N random digits e.g. #RANDNUM6"},
            {"tag": "#RANDALPHA{N}",     "desc": "N random lowercase letters"},
            {"tag": "#RANDUPPERALPHA{N}","desc": "N random UPPERCASE letters"},
            {"tag": "#RANDALPHANUM{N}",  "desc": "N random alphanumeric chars"},
            {"tag": "#RANDUPPERAL{N}",   "desc": "N random UPPERCASE alphanumeric"},
            {"tag": "#RANDHEX{N}",       "desc": "N random hex chars (lowercase)"},
            {"tag": "#RANDUPPERHEX{N}",  "desc": "N random HEX chars (uppercase)"},
            {"tag": "#RAND1",            "desc": "5-digit random number"},
            {"tag": "#RAND2",            "desc": "7-digit random number"},
            {"tag": "#SHORT_ID",         "desc": "8-char alphanumeric ID"},
            {"tag": "#HEX8",             "desc": "8-char hex string"},
            {"tag": "#UUID",             "desc": "Random UUID v4"},
        ]
    },
    {
        "name": "Encoding & Hashing",
        "tags": [
            {"tag": "#B64EMAIL",         "desc": "Base64-encoded recipient email"},
            {"tag": "#B64NAME",          "desc": "Base64-encoded recipient name"},
            {"tag": "#B64SUBJECT",       "desc": "Base64-encoded subject"},
            {"tag": "#URLENCODE_EMAIL",  "desc": "URL-encoded recipient email"},
            {"tag": "#URLENCODE_NAME",   "desc": "URL-encoded recipient name"},
            {"tag": "#URLENCODE_SUBJECT","desc": "URL-encoded subject"},
            {"tag": "#MD5",              "desc": "12-char MD5 of email"},
            {"tag": "#MD5_EMAIL",        "desc": "Full MD5 hash of email"},
            {"tag": "#SHA1",             "desc": "16-char SHA1 of email"},
            {"tag": "#SHA1_EMAIL",       "desc": "Full SHA1 hash of email"},
            {"tag": "#SHA256_EMAIL",     "desc": "Full SHA256 hash of email"},
            {"tag": "#RANDOM_MD5",       "desc": "Random 32-char hex (MD5-shaped)"},
            {"tag": "#RANDOM_SHA256",    "desc": "Random 64-char hex (SHA256-shaped)"},
        ]
    },
    {
        "name": "Random Data",
        "tags": [
            {"tag": "#RANDAMOUNT",       "desc": "Random dollar amount ($12.50–$9,999.99)"},
            {"tag": "#RANDAMOUNT_SMALL", "desc": "Small amount ($1.00–$99.99)"},
            {"tag": "#RANDAMOUNT_LARGE", "desc": "Large amount ($100.00–$99,999.99)"},
            {"tag": "#RANDPERCENT",      "desc": "Random percentage (1%–99%)"},
            {"tag": "#RANDDATE",         "desc": "Random date in past 90 days"},
            {"tag": "#RANDDATE_PAST30",  "desc": "Random date in past 30 days"},
            {"tag": "#RANDDATE_PAST365", "desc": "Random date in past year"},
            {"tag": "#RANDTIME",         "desc": "Random 12h time"},
            {"tag": "#RANDCOUNTRY",      "desc": "Random country name"},
            {"tag": "#RANDCITY",         "desc": "Random city name"},
            {"tag": "#RANDBROWSER",      "desc": "Random browser + version"},
            {"tag": "#RANDOS",           "desc": "Random OS name + version"},
            {"tag": "#RANDCOLOR_NAME",   "desc": "Random color name (Red, Blue…)"},
            {"tag": "#RANDCOLOR_HEX",    "desc": "Random hex color (#A1B2C3)"},
            {"tag": "#RANDFIRSTNAME",    "desc": "Random first name"},
            {"tag": "#RANDLASTNAME",     "desc": "Random last name"},
            {"tag": "#RANDFULLNAME",     "desc": "Random full name"},
            {"tag": "#RANDJOBTITLE",     "desc": "Random job title"},
            {"tag": "#RANDDEPARTMENT",   "desc": "Random department name"},
            {"tag": "#RANDINDUSTRY",     "desc": "Random industry"},
            {"tag": "#RANDIPV4",         "desc": "Random IPv4 address"},
            {"tag": "#RANDIPV6",         "desc": "Random IPv6 address"},
            {"tag": "#RANDMAC",          "desc": "Random MAC address"},
            {"tag": "#RANDZIP",          "desc": "Random 5-digit ZIP code"},
            {"tag": "#RANDDOMAIN",       "desc": "Random domain name"},
            {"tag": "#RANDURL",          "desc": "Random HTTPS URL"},
            {"tag": "#RANDEMAIL_FAKE",   "desc": "Random fake email address"},
            {"tag": "#RANDPHONE",        "desc": "Random US phone (555) 123-4567"},
            {"tag": "#RANDPHONE_INTL",   "desc": "Random international phone +44 123 456 7890"},
            {"tag": "#RANDWORD",         "desc": "Random business buzzword"},
        ]
    },
    {
        "name": "Business / Transactions",
        "tags": [
            {"tag": "#INVOICE_NUM",      "desc": "Invoice number (INV-123456)"},
            {"tag": "#ORDER_NUM",        "desc": "Order number (ORD-1234567)"},
            {"tag": "#TRANSACTION_ID",   "desc": "Transaction ID (TXN-ABC12345)"},
            {"tag": "#TRACKING_NUM",     "desc": "Tracking number (TRK-ABCD1234)"},
            {"tag": "#CONFIRMATION_CODE","desc": "8-char uppercase hex code"},
            {"tag": "#VERIFICATION_CODE","desc": "6-digit verification code"},
            {"tag": "#OTP_CODE",         "desc": "6-digit OTP"},
            {"tag": "#PIN_CODE",         "desc": "4-digit PIN"},
            {"tag": "#ACCOUNT_NUM",      "desc": "Account number (ACC-12345678)"},
            {"tag": "#REFERENCE_NUM",    "desc": "Reference (REF-ABC12345)"},
            {"tag": "#TICKET_NUM",       "desc": "Support ticket (TKT-12345)"},
            {"tag": "#CASE_ID",          "desc": "Case ID (CASE-1234567)"},
            {"tag": "#POLICY_NUM",       "desc": "Policy number (POL-12345678)"},
            {"tag": "#CLAIM_NUM",        "desc": "Claim number (CLM-1234567)"},
            {"tag": "#QUOTE_ID",         "desc": "Quote ID (QUO-ABC123)"},
            {"tag": "#CONTRACT_ID",      "desc": "Contract (CNT-12345678)"},
            {"tag": "#SUBSCRIPTION_ID",  "desc": "Subscription (SUB-ABC1234567)"},
            {"tag": "#CUSTOMER_ID",      "desc": "Customer ID (CUS-1234567)"},
            {"tag": "#MEMBERSHIP_ID",    "desc": "Membership (MEM-ABC12345)"},
            {"tag": "#CC_FAKE",          "desc": "Fake Luhn-valid credit card number"},
            {"tag": "#IBAN_FAKE",        "desc": "Fake IBAN bank account"},
        ]
    },
    {
        "name": "Technical / Server",
        "tags": [
            {"tag": "#SERVER_NAME",      "desc": "Server name (SRV-PROD-123)"},
            {"tag": "#SERVER_ID",        "desc": "AWS-style instance ID"},
            {"tag": "#POD_NAME",         "desc": "Kubernetes pod name"},
            {"tag": "#CONTAINER_ID",     "desc": "12-char container ID"},
            {"tag": "#API_KEY_FAKE",     "desc": "Fake live API key (sk_live_...)"},
            {"tag": "#API_KEY_TEST",     "desc": "Fake test API key (sk_test_...)"},
            {"tag": "#WEBHOOK_SECRET",   "desc": "Fake webhook secret"},
            {"tag": "#JWT_FAKE",         "desc": "Fake JWT token format"},
            {"tag": "#ERROR_CODE",       "desc": "Error code (ERR-1234)"},
            {"tag": "#STATUS_CODE",      "desc": "HTTP status code"},
            {"tag": "#SESSION_ID",       "desc": "Session ID (sess_...)"},
            {"tag": "#REQUEST_ID",       "desc": "Request ID (req-uuid)"},
            {"tag": "#TRACE_ID",         "desc": "Distributed trace ID"},
            {"tag": "#BUILD_NUM",        "desc": "4-digit build number"},
            {"tag": "#VERSION_NUM",      "desc": "Semantic version (1.2.3)"},
            {"tag": "#SEMVER",           "desc": "Same as #VERSION_NUM"},
            {"tag": "#USER_AGENT",       "desc": "Full browser user agent string"},
            {"tag": "#PORT_NUM",         "desc": "Random port number (1024-65535)"},
            {"tag": "#IP_ADDRESS",       "desc": "Random IPv4 address"},
        ]
    },
    {
        "name": "Content / Fake Data",
        "tags": [
            {"tag": "#FAKE_COMPANY",     "desc": "Random company name"},
            {"tag": "#FAKE_ADDRESS",     "desc": "Random street address"},
            {"tag": "#FAKE_PHONE",       "desc": "Random US phone number"},
            {"tag": "#FAKE_PHONE_INTL",  "desc": "Random international phone"},
            {"tag": "#FAKE_ZIP",         "desc": "Random ZIP code"},
            {"tag": "#FAKE_CITY",        "desc": "Random city"},
            {"tag": "#FAKE_COUNTRY",     "desc": "Random country"},
            {"tag": "#FAKE_JOBTITLE",        "desc": "Random job title"},
            {"tag": "#FAKE_COMPANY_EMAIL",   "desc": "Fake company email — name@company.com"},
            {"tag": "#FAKE_FULLNAME_EMAIL",  "desc": "Fake person email — john.smith@domain.com"},
            {"tag": "#RANDOM_PATH",          "desc": "Random URL path — /ref/ab3c/x9k2mn7p"},
            {"tag": "#RANDOM_LINK",          "desc": "Random full HTTPS URL with path"},
            {"tag": "#LOREM_SHORT",          "desc": "One sentence of lorem ipsum"},
            {"tag": "#LOREM_PARAGRAPH",  "desc": "One paragraph of lorem ipsum"},
            {"tag": "#LOREM_LONG",       "desc": "Full lorem ipsum paragraph"},
        ]
    },
    {
        "name": "Functional / Smart",
        "tags": [
            {"tag": "#SHUF{A|B|C}",          "desc": "Pick random option from pipe-separated list"},
            {"tag": "#IF_NAME{text}",         "desc": "Show text only if lead has a name"},
            {"tag": "#IF_NONAME{text}",       "desc": "Show text only if lead has NO name"},
            {"tag": "#IF_COMPANY{text}",      "desc": "Show text only if lead has a company"},
            {"tag": "#IF_NOCOMPANY{text}",    "desc": "Show text only if lead has NO company"},
            {"tag": "#IF_FIELD{key}{text}",   "desc": "Show text if lead has custom field 'key'"},
            {"tag": "#UPPER{text}",           "desc": "Uppercase the text"},
            {"tag": "#LOWER{text}",           "desc": "Lowercase the text"},
            {"tag": "#UCFIRST{text}",         "desc": "Capitalize first letter"},
            {"tag": "#TITLE{text}",           "desc": "Title Case the text"},
            {"tag": "#TRUNCATE{text}{N}",     "desc": "Truncate text to N characters"},
            {"tag": "#REPEAT{text}{N}",       "desc": "Repeat text N times (max 50)"},
            {"tag": "#PADLEFT{text}{N}{c}",   "desc": "Left-pad text to N chars with char c"},
            {"tag": "#PADRIGHT{text}{N}{c}",  "desc": "Right-pad text to N chars with char c"},
            {"tag": "#LINK",                  "desc": "Rotates through your link list"},
            {"tag": "#COUNTER",               "desc": "Incrementing counter per email"},
        ]
    },
]
