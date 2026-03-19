"""
core/email_sorter.py — SynthTel Email Sorter
=============================================
Classifies email addresses by mail provider using domain map (instant)
then MX record lookup (for unknown domains).

Providers covered
-----------------
Consumer webmail:
  gmail       — Gmail / Google Workspace
  outlook     — Outlook.com / Hotmail / Live / MSN (personal Microsoft)
  o365        — Microsoft Office 365 (corporate, protection.outlook.com MX)
  yahoo       — Yahoo Mail (all country variants)
  icloud      — Apple iCloud / me.com / mac.com
  aol         — AOL Mail / AIM / Netscape / CompuServe
  gmx         — GMX / Mail.com / WEB.DE / T-Online
  protonmail  — ProtonMail / Proton.me
  fastmail    — Fastmail
  zoho        — Zoho Mail
  tutanota    — Tutanota / Tuta
  yandex      — Yandex Mail
  rambler     — Rambler Mail (Russia)
  mail_ru     — Mail.ru / Inbox.ru / Bk.ru / List.ru
  qq          — QQ Mail (China)
  netease     — 163.com / 126.com / yeah.net (China NetEase)
  sina        — Sina Mail (China)
  posteo      — Posteo (Germany, privacy)
  laposte     — La Poste (France)
  bluewin     — Bluewin / Sunrise (Switzerland)
  pobox       — Pobox (email forwarding)
  gandi       — Gandi.net hosting email
  one_com     — One.com hosting email
  ovh         — OVH hosting email
  strato      — Strato (Germany hosting)
  freenet_de  — Freenet.de (Germany ISP)
  arcor       — Arcor / Vodafone Germany
  vodafone_de — Vodafone Germany
  alice_de    — Alice / O2 Germany
  seznam      — Seznam.cz (Czech Republic)
  wp_pl       — WP.pl / o2.pl / Onet.pl (Poland)
  proximus    — Proximus / Belgacom / Skynet (Belgium)
  telenet_be  — Telenet (Belgium)
  ziggo       — Ziggo / XS4ALL (Netherlands)
  bigpond     — Bigpond / Telstra (Australia)
  xtra        — Xtra (New Zealand)
  telenor_dk  — Telenor Denmark (many alias domains)

Canadian ISPs:
  shaw        — Shaw Communications (shaw.ca, shawcable.net)
  rogers      — Rogers Communications (rogers.com, rogersmail.net)
  bell        — Bell Canada (bell.net, bellnet.ca, sympatico.ca)
  telus       — TELUS (telus.net, telusplanet.net)
  eastlink    — Eastlink (eastlink.ca)
  videotron   — Videotron (videotron.ca, videotron.net)
  cogeco      — Cogeco (cogeco.ca, cogeco.net)
  sasktel     — SaskTel (sasktel.net)
  mts         — MTS / Bell MTS (mts.net)
  tbaytel     — TBayTel (tbaytel.net)
  xplornet    — Xplornet (xplornet.com, xplornet.ca)

US ISPs:
  comcast     — Comcast / Xfinity (comcast.net, xfinity.com)
  att         — AT&T (att.net, sbcglobal.net, bellsouth.net, ameritech.net)
  verizon     — Verizon (verizon.net, verizon.com)
  cox         — Cox Communications (cox.net, cox.com)
  charter     — Charter / Spectrum (charter.net, spectrum.net, rr.com, twc.com)
  earthlink   — EarthLink (earthlink.net, mindspring.com)
  netzero     — NetZero (netzero.net)

UK ISPs:
  bt          — BT / British Telecom (btinternet.com, btopenworld.com)
  sky         — Sky UK (sky.com, bskyb.com, skybroadband.com)
  talktalk    — TalkTalk (talktalk.net, talktalk.co.uk)
  virginmedia — Virgin Media (virginmedia.com, ntlworld.com, blueyonder.co.uk)
  plusnet     — Plusnet (plusnet.com)
  ee          — EE / Orange UK (ee.co.uk, orange.net)
  o2          — O2 UK (o2.co.uk)
  tiscali     — Tiscali UK (tiscali.co.uk)

European ISPs / webmail:
  orange      — Orange France (orange.fr, wanadoo.fr, laposte.net)
  sfr         — SFR / Neuf (sfr.fr, neuf.fr, club-internet.fr)
  free        — Free.fr / Iliad (free.fr, aliceadsl.fr)
  web_de      — WEB.DE (web.de)
  t_online    — T-Online Germany (t-online.de)
  libero      — Libero Italy (libero.it, inwind.it)
  tiscali_it  — Tiscali Italy (tiscali.it)
  telefonica  — Telefónica / Movistar Spain (telefonica.net, movistar.es)
  terra       — Terra Networks (terra.es, terra.com.br)
  oi          — Oi Brazil (oi.com.br, oi.net.br)
  uol         — UOL Brazil (uol.com.br)

Hosting / business email:
  godaddy     — GoDaddy Workspace Email (secureserver.net MX)
  namecheap   — Namecheap Private Email (privateemail.com MX)
  bluehost    — Bluehost / Endurance (bluehost.com)
  hostgator   — HostGator (hostgator.com)
  siteground  — SiteGround (siteground.net)
  ionos       — IONOS / 1&1 (ionos.com, 1and1.com)
  rackspace   — Rackspace Email (emailsrvr.com MX)
  google_ws   — Google Workspace legacy (googlehosted.com MX)

Enterprise security / filtering:
  mimecast    — Mimecast (mimecast.com MX)
  proofpoint  — Proofpoint (pphosted.com MX)
  barracuda   — Barracuda Networks
  ironport    — Cisco IronPort / ESA
  forcepoint  — Forcepoint (forcepoint.com)
  messagelabs — Symantec / MessageLabs (messagelabs.com MX)
  sophos      — Sophos (hydra.sophos.com MX)
  spamhero    — SpamHero (spamhero.com MX)
  mailhop     — Mailhop / Duocircle
  exclaimer   — Exclaimer Cloud (exclaimer.net MX)

  generic     — Unknown / catch-all
"""

import re
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed


# ═══════════════════════════════════════════════════════════════
# DOMAIN → PROVIDER MAP  (instant lookup, no DNS)
# ═══════════════════════════════════════════════════════════════

_DOMAIN_MAP = {

    # ── Gmail ──────────────────────────────────────────────────
    "gmail.com":        "gmail",
    "googlemail.com":   "gmail",
    "google.com":       "gmail",
    "mozilla.com":      "gmail",   # Mozilla uses Google Workspace
    "mozillafoundation.org": "gmail",

    # ── Microsoft personal (Outlook/Hotmail/Live) ───────────────
    "outlook.com":      "outlook",
    "outlook.ca":       "outlook",
    "outlook.co.uk":    "outlook",
    "outlook.com.au":   "outlook",
    "outlook.de":       "outlook",
    "outlook.fr":       "outlook",
    "outlook.it":       "outlook",
    "outlook.es":       "outlook",
    "outlook.jp":       "outlook",
    "outlook.at":       "outlook",
    "outlook.be":       "outlook",
    "outlook.cl":       "outlook",
    "outlook.co.id":    "outlook",
    "outlook.co.il":    "outlook",
    "outlook.co.th":    "outlook",
    "outlook.com.ar":   "outlook",
    "outlook.com.gr":   "outlook",
    "outlook.com.tr":   "outlook",
    "outlook.com.vn":   "outlook",
    "outlook.cz":       "outlook",
    "outlook.dk":       "outlook",
    "outlook.hu":       "outlook",
    "outlook.ie":       "outlook",
    "outlook.in":       "outlook",
    "outlook.kr":       "outlook",
    "outlook.lv":       "outlook",
    "outlook.my":       "outlook",
    "outlook.ph":       "outlook",
    "outlook.pt":       "outlook",
    "outlook.sa":       "outlook",
    "outlook.sg":       "outlook",
    "outlook.sk":       "outlook",
    "hotmail.com":      "outlook",
    "hotmail.ca":       "outlook",
    "hotmail.co.uk":    "outlook",
    "hotmail.co.nz":    "outlook",
    "hotmail.co.za":    "outlook",
    "hotmail.fr":       "outlook",
    "hotmail.de":       "outlook",
    "hotmail.es":       "outlook",
    "hotmail.it":       "outlook",
    "hotmail.nl":       "outlook",
    "hotmail.be":       "outlook",
    "hotmail.se":       "outlook",
    "hotmail.no":       "outlook",
    "hotmail.dk":       "outlook",
    "hotmail.fi":       "outlook",
    "hotmail.pt":       "outlook",
    "hotmail.gr":       "outlook",
    "hotmail.co.jp":    "outlook",
    "hotmail.co.id":    "outlook",
    "hotmail.co.il":    "outlook",
    "hotmail.co.in":    "outlook",
    "hotmail.co.kr":    "outlook",
    "hotmail.co.th":    "outlook",
    "hotmail.com.ar":   "outlook",
    "hotmail.com.au":   "outlook",
    "hotmail.com.br":   "outlook",
    "hotmail.com.hk":   "outlook",
    "hotmail.com.tr":   "outlook",
    "hotmail.com.tw":   "outlook",
    "hotmail.com.vn":   "outlook",
    "hotmail.cl":       "outlook",
    "hotmail.cz":       "outlook",
    "hotmail.hu":       "outlook",
    "hotmail.lt":       "outlook",
    "hotmail.lv":       "outlook",
    "hotmail.my":       "outlook",
    "hotmail.ph":       "outlook",
    "hotmail.rs":       "outlook",
    "hotmail.sg":       "outlook",
    "hotmail.sk":       "outlook",
    "live.com":         "outlook",
    "live.ca":          "outlook",
    "live.co.uk":       "outlook",
    "live.com.au":      "outlook",
    "live.fr":          "outlook",
    "live.de":          "outlook",
    "live.it":          "outlook",
    "live.es":          "outlook",
    "live.nl":          "outlook",
    "live.be":          "outlook",
    "live.se":          "outlook",
    "live.no":          "outlook",
    "live.dk":          "outlook",
    "live.fi":          "outlook",
    "live.jp":          "outlook",
    "live.cn":          "outlook",
    "live.com.mx":      "outlook",
    "live.com.ar":      "outlook",
    "live.com.br":      "outlook",
    "live.co.za":       "outlook",
    "live.at":          "outlook",
    "live.cl":          "outlook",
    "live.co.jp":       "outlook",
    "live.co.kr":       "outlook",
    "live.com.my":      "outlook",
    "live.com.ph":      "outlook",
    "live.com.pt":      "outlook",
    "live.com.sg":      "outlook",
    "live.hk":          "outlook",
    "live.ie":          "outlook",
    "live.in":          "outlook",
    "live.ru":          "outlook",
    "livemail.tw":      "outlook",
    "msn.com":          "outlook",
    "passport.com":     "outlook",
    "windowslive.com":  "outlook",
    "onmicrosoft.com":  "outlook",

    # ── Yahoo ───────────────────────────────────────────────────
    "yahoo.com":        "yahoo",
    "yahoo.ca":         "yahoo",
    "yahoo.co.uk":      "yahoo",
    "yahoo.co.in":      "yahoo",
    "yahoo.co.nz":      "yahoo",
    "yahoo.co.za":      "yahoo",
    "yahoo.co.jp":      "yahoo",
    "yahoo.com.au":     "yahoo",
    "yahoo.com.ar":     "yahoo",
    "yahoo.com.br":     "yahoo",
    "yahoo.com.mx":     "yahoo",
    "yahoo.com.ph":     "yahoo",
    "yahoo.com.sg":     "yahoo",
    "yahoo.fr":         "yahoo",
    "yahoo.de":         "yahoo",
    "yahoo.it":         "yahoo",
    "yahoo.es":         "yahoo",
    "yahoo.nl":         "yahoo",
    "yahoo.se":         "yahoo",
    "yahoo.no":         "yahoo",
    "yahoo.dk":         "yahoo",
    "yahoo.fi":         "yahoo",
    "yahoo.gr":         "yahoo",
    "yahoo.ro":         "yahoo",
    "yahoo.hu":         "yahoo",
    "ymail.com":        "yahoo",
    "rocketmail.com":   "yahoo",
    "yahoodns.net":     "yahoo",
    "ybb.ne.jp":        "yahoo",   # Yahoo Japan BB

    # ── Apple iCloud ────────────────────────────────────────────
    "icloud.com":                "icloud",
    "me.com":                    "icloud",
    "mac.com":                   "icloud",
    "privaterelay.appleid.com":  "icloud",

    # ── AOL / AIM / legacy Verizon webmail ──────────────────────
    "aol.com":          "aol",
    "aol.co.uk":        "aol",
    "aol.ca":           "aol",
    "aol.fr":           "aol",
    "aol.de":           "aol",
    "aol.it":           "aol",
    "aol.es":           "aol",
    "aol.se":           "aol",
    "aol.co.nz":        "aol",
    "aol.com.au":       "aol",
    "aol.com.ar":       "aol",
    "aol.com.br":       "aol",
    "aol.com.mx":       "aol",
    "aim.com":          "aol",
    "netscape.net":     "aol",
    "netscape.com":     "aol",
    "compuserve.com":   "aol",
    "cs.com":           "aol",
    "wmconnect.com":    "aol",

    # ── GMX / Mail.com / WEB.DE / T-Online ──────────────────────
    "gmx.com":          "gmx",
    "gmx.net":          "gmx",
    "gmx.de":           "gmx",
    "gmx.at":           "gmx",
    "gmx.ch":           "gmx",
    "gmx.co.uk":        "gmx",
    "gmx.fr":           "gmx",
    "gmx.es":           "gmx",
    "gmx.it":           "gmx",
    "gmx.nl":           "gmx",
    "gmx.us":           "gmx",
    "gmx.biz":          "gmx",
    "gmx.ca":           "gmx",
    "gmx.cn":           "gmx",
    "gmx.co.in":        "gmx",
    "gmx.com.br":       "gmx",
    "gmx.com.my":       "gmx",
    "gmx.com.tr":       "gmx",
    "gmx.eu":           "gmx",
    "gmx.hk":           "gmx",
    "gmx.ie":           "gmx",
    "gmx.info":         "gmx",
    "gmx.li":           "gmx",
    "gmx.org":          "gmx",
    "gmx.ph":           "gmx",
    "gmx.pt":           "gmx",
    "gmx.ru":           "gmx",
    "gmx.se":           "gmx",
    "gmx.sg":           "gmx",
    "gmx.tm":           "gmx",
    "gmx.tw":           "gmx",
    "mail.com":         "gmx",
    "usa.com":          "gmx",
    "email.com":        "gmx",
    "cheerful.com":     "gmx",
    "myself.com":       "gmx",
    "consultant.com":   "gmx",
    "mail.org":         "gmx",
    "iname.com":        "gmx",
    "oath.com":         "gmx",
    # mail.com vanity domains
    "accountant.com":   "gmx",
    "activist.com":     "gmx",
    "adexec.com":       "gmx",
    "africamail.com":   "gmx",
    "aircraftmail.com": "gmx",
    "allergist.com":    "gmx",
    "alumni.com":       "gmx",
    "alumnidirector.com": "gmx",
    "americamail.com":  "gmx",
    "angelic.com":      "gmx",
    "archaeologist.com":"gmx",
    "artlover.com":     "gmx",
    "asia-mail.com":    "gmx",
    "atheist.com":      "gmx",
    "australiamail.com":"gmx",
    "bartender.net":    "gmx",
    "berlin.com":       "gmx",
    "bigger.com":       "gmx",
    "bikerider.com":    "gmx",
    "birdlover.com":    "gmx",
    "blader.com":       "gmx",
    "boardermail.com":  "gmx",
    "brazilmail.com":   "gmx",
    "brew-master.com":  "gmx",
    "california.usa.com": "gmx",
    "californiamail.com": "gmx",
    "caress.com":       "gmx",
    "catlover.com":     "gmx",
    "chef.net":         "gmx",
    "chemist.com":      "gmx",
    "chinamail.com":    "gmx",
    "clerk.com":        "gmx",
    "cliffhanger.com":  "gmx",
    "collector.org":    "gmx",
    "columnist.com":    "gmx",
    "comic.com":        "gmx",
    "computer4u.com":   "gmx",
    "contractor.net":   "gmx",
    "coolsite.net":     "gmx",
    "counsellor.com":   "gmx",
    "count.com":        "gmx",
    "couple.com":       "gmx",
    "cutey.com":        "gmx",
    "cyber-wizard.com": "gmx",
    "cyberdude.com":    "gmx",
    "cybergal.com":     "gmx",
    "dallasmail.com":   "gmx",
    "dbzmail.com":      "gmx",
    "deliveryman.com":  "gmx",
    "diplomats.com":    "gmx",
    "disciples.com":    "gmx",
    "doctor.com":       "gmx",
    "doglover.com":     "gmx",
    "doramail.com":     "gmx",
    "dr.com":           "gmx",
    "dublin.com":       "gmx",
    "earthling.net":    "gmx",
    "elvisfan.com":     "gmx",
    "engineer.com":     "gmx",
    "englandmail.com":  "gmx",
    "europe.com":       "gmx",
    "europemail.com":   "gmx",
    "execs.com":        "gmx",
    "fan.com":          "gmx",
    "feelings.com":     "gmx",
    "financier.com":    "gmx",
    "fireman.net":      "gmx",
    "florida.usa.com":  "gmx",
    "footballer.com":   "gmx",
    "gardener.com":     "gmx",
    "geologist.com":    "gmx",
    "germanymail.com":  "gmx",
    "graduate.org":     "gmx",
    "graphic-designer.com": "gmx",
    "hackermail.com":   "gmx",
    "hairdresser.net":  "gmx",
    "hilarious.com":    "gmx",
    "hockeymail.com":   "gmx",
    "homemail.com":     "gmx",
    "hot-shot.com":     "gmx",
    "hour.com":         "gmx",
    "humanoid.net":     "gmx",
    "illinois.usa.com": "gmx",
    "innocent.com":     "gmx",
    "inorbit.com":      "gmx",
    "instruction.com":  "gmx",
    "instructor.net":   "gmx",
    "insurer.com":      "gmx",
    "irelandmail.com":  "gmx",
    "italymail.com":    "gmx",
    "japan.com":        "gmx",
    "journalist.com":   "gmx",
    "keromail.com":     "gmx",
    "kittymail.com":    "gmx",
    "koreamail.com":    "gmx",
    "lawyer.com":       "gmx",
    "legislator.com":   "gmx",
    "linuxmail.org":    "gmx",
    "london.com":       "gmx",
    "loveable.com":     "gmx",
    "lovecat.com":      "gmx",
    "mad.scientist.com":"gmx",
    "madonnafan.com":   "gmx",
    "madrid.com":       "gmx",
    "marchmail.com":    "gmx",
    "mexicomail.com":   "gmx",
    "mindless.com":     "gmx",
    "minister.com":     "gmx",
    "mobsters.com":     "gmx",
    "monarchy.com":     "gmx",
    "moscowmail.com":   "gmx",
    "munich.com":       "gmx",
    "musician.org":     "gmx",
    "muslim.com":       "gmx",
    "newyork.usa.com":  "gmx",
    "null.net":         "gmx",
    "nycmail.com":      "gmx",
    "optician.com":     "gmx",
    "pacificwest.com":  "gmx",
    "petlover.com":     "gmx",
    "photographer.net": "gmx",
    "playful.com":      "gmx",
    "poetic.com":       "gmx",
    "politician.com":   "gmx",
    "popstar.com":      "gmx",
    "post.com":         "gmx",
    "presidency.com":   "gmx",
    "priest.com":       "gmx",
    "programmer.net":   "gmx",
    "publicist.com":    "gmx",
    "realtyagent.com":  "gmx",
    "reborn.com":       "gmx",
    "reggaefan.com":    "gmx",
    "religious.com":    "gmx",
    "repairman.com":    "gmx",
    "representative.com": "gmx",
    "rescueteam.com":   "gmx",
    "revenue.com":      "gmx",
    "rocketship.com":   "gmx",
    "rockfan.com":      "gmx",
    "rome.com":         "gmx",
    "royal.net":        "gmx",
    "saintly.com":      "gmx",
    "salesperson.net":  "gmx",
    "sanfranmail.com":  "gmx",
    "scientist.com":    "gmx",
    "scotlandmail.com": "gmx",
    "secretary.net":    "gmx",
    "seductive.com":    "gmx",
    "singapore.com":    "gmx",
    "snakebite.com":    "gmx",
    "songwriter.net":   "gmx",
    "soon.com":         "gmx",
    "spainmail.com":    "gmx",
    "teachers.org":     "gmx",
    "techie.com":       "gmx",
    "technologist.com": "gmx",
    "texas.usa.com":    "gmx",
    "thegame.com":      "gmx",
    "therapist.net":    "gmx",
    "toke.com":         "gmx",
    "tokyo.com":        "gmx",
    "toothfairy.com":   "gmx",
    "tvstar.com":       "gmx",
    "umpire.com":       "gmx",
    "uymail.com":       "gmx",
    "wallet.com":       "gmx",
    "webname.com":      "gmx",
    "weirdness.com":    "gmx",
    "who.net":          "gmx",
    "whoever.com":      "gmx",
    "winning.com":      "gmx",
    "witty.com":        "gmx",
    "worker.com":       "gmx",
    "workmail.com":     "gmx",
    "writeme.com":      "gmx",
    "yours.com":        "gmx",
    "web.de":           "web_de",
    "t-online.de":      "t_online",
    "magenta.de":       "t_online",  # T-Online rebranded

    # ── ProtonMail ──────────────────────────────────────────────
    "protonmail.com":   "protonmail",
    "protonmail.ch":    "protonmail",
    "proton.me":        "protonmail",
    "pm.me":            "protonmail",

    # ── Tutanota ────────────────────────────────────────────────
    "tutanota.com":     "tutanota",
    "tutanota.de":      "tutanota",
    "tutamail.com":     "tutanota",
    "tuta.io":          "tutanota",
    "tuta.com":         "tutanota",
    "keemail.me":       "tutanota",

    # ── Yandex ──────────────────────────────────────────────────
    "yandex.com":       "yandex",
    "yandex.ru":        "yandex",
    "yandex.ua":        "yandex",
    "yandex.kz":        "yandex",
    "yandex.by":        "yandex",
    "yandex.net":       "yandex",
    "ya.ru":            "yandex",
    "narod.ru":         "yandex",

    # ── Mail.ru group ───────────────────────────────────────────
    "mail.ru":          "mail_ru",
    "inbox.ru":         "mail_ru",
    "bk.ru":            "mail_ru",
    "list.ru":          "mail_ru",
    "corp.mail.ru":     "mail_ru",

    # ── Rambler ─────────────────────────────────────────────────
    "rambler.ru":       "rambler",
    "lenta.ru":         "rambler",
    "autorambler.ru":   "rambler",
    "myrambler.ru":     "rambler",
    "ro.ru":            "rambler",

    # ── Fastmail ────────────────────────────────────────────────
    "fastmail.com":     "fastmail",
    "fastmail.fm":      "fastmail",
    "fastmail.to":      "fastmail",
    "fastmail.net":     "fastmail",
    "fastmail.org":     "fastmail",
    "fastmail.cn":      "fastmail",
    "fastmail.in":      "fastmail",
    "fastmail.jp":      "fastmail",
    "fastmail.es":      "fastmail",
    "fastmail.de":      "fastmail",
    "fastmail.us":      "fastmail",
    "messagingengine.com": "fastmail",

    # ── Zoho ────────────────────────────────────────────────────
    "zoho.com":         "zoho",
    "zohomail.com":     "zoho",

    # ── Posteo (Germany, privacy-focused) ───────────────────────
    "posteo.de":        "posteo",
    "posteo.at":        "posteo",
    "posteo.ch":        "posteo",
    "posteo.eu":        "posteo",
    "posteo.org":       "posteo",

    # ── QQ Mail (China) ─────────────────────────────────────────
    "qq.com":           "qq",

    # ── NetEase (China) ─────────────────────────────────────────
    "163.com":          "netease",
    "126.com":          "netease",
    "yeah.net":         "netease",

    # ── Sina (China) ────────────────────────────────────────────
    "sina.com":         "sina",
    "sina.cn":          "sina",

    # ── La Poste (France) ───────────────────────────────────────
    "laposte.net":      "laposte",

    # ── Bluewin / Sunrise (Switzerland) ─────────────────────────
    "bluewin.ch":       "bluewin",
    "bluemail.ch":      "bluewin",
    "freesurf.ch":      "bluewin",
    "swissonline.ch":   "bluewin",
    "sunrise.ch":       "bluewin",
    "hispeed.ch":       "bluewin",

    # ── Pobox ───────────────────────────────────────────────────
    "pobox.com":        "pobox",

    # ── Gandi.net ───────────────────────────────────────────────
    "gandi.net":        "gandi",

    # ── One.com ─────────────────────────────────────────────────
    "one.com":          "one_com",

    # ── OVH ─────────────────────────────────────────────────────
    "ovh.net":          "ovh",

    # ── Strato (Germany hosting) ─────────────────────────────────
    "strato.de":        "strato",
    "rzone.de":         "strato",

    # ── Freenet.de (Germany ISP) ────────────────────────────────
    "freenet.de":       "freenet_de",

    # ── Arcor / O2 Germany ──────────────────────────────────────
    "arcor.de":         "arcor",
    "arcormail.de":     "arcor",
    "alice.de":         "arcor",
    "alice-dsl.de":     "arcor",
    "alice-dsl.net":    "arcor",
    "o2mail.de":        "arcor",
    "o2online.de":      "arcor",
    "genion.de":        "arcor",
    "hanse.net":        "arcor",
    "loop.de":          "arcor",

    # ── Vodafone Germany ────────────────────────────────────────
    "vodafone.de":      "vodafone_de",
    "vodafone.net":     "vodafone_de",

    # ── Seznam (Czech Republic) ──────────────────────────────────
    "seznam.cz":        "seznam",
    "email.cz":         "seznam",
    "post.cz":          "seznam",
    "spoluzaci.cz":     "seznam",

    # ── Polish providers ─────────────────────────────────────────
    "wp.pl":            "wp_pl",
    "o2.pl":            "wp_pl",
    "onet.pl":          "wp_pl",
    "op.pl":            "wp_pl",
    "go2.pl":           "wp_pl",
    "go.pl":            "wp_pl",
    "vp.pl":            "wp_pl",
    "tlen.pl":          "wp_pl",
    "prokonto.pl":      "wp_pl",
    "republika.pl":     "wp_pl",
    "amorki.pl":        "wp_pl",
    "autograf.pl":      "wp_pl",
    "buziaczek.pl":     "wp_pl",
    "poczta.onet.pl":   "wp_pl",
    "onet.eu":          "wp_pl",
    "poczta.onet.eu":   "wp_pl",

    # ── Proximus / Belgacom / Skynet (Belgium) ───────────────────
    "proximus.be":      "proximus",
    "belgacom.net":     "proximus",
    "skynet.be":        "proximus",
    "kidcity.be":       "proximus",

    # ── Telenet (Belgium) ────────────────────────────────────────
    "telenet.be":       "telenet_be",

    # ── Ziggo / XS4ALL (Netherlands) ────────────────────────────
    "ziggo.nl":         "ziggo",
    "ziggomail.com":    "ziggo",
    "xs4all.nl":        "ziggo",
    "home.nl":          "ziggo",
    "casema.nl":        "ziggo",
    "multiweb.nl":      "ziggo",
    "hahah.nl":         "ziggo",
    "upcmail.nl":       "ziggo",
    "zeelandnet.nl":    "ziggo",
    "razcall.com":      "ziggo",
    "razcall.nl":       "ziggo",
    "quicknet.nl":      "ziggo",
    "zinders.nl":       "ziggo",
    "zeggis.nl":        "ziggo",
    "zeggis.com":       "ziggo",

    # ── Bigpond / Telstra (Australia) ───────────────────────────
    "bigpond.com":      "bigpond",
    "bigpond.net.au":   "bigpond",
    "bigpond.net":      "bigpond",
    "telstra.com":      "bigpond",

    # ── Xtra (New Zealand) ───────────────────────────────────────
    "xtra.co.nz":       "xtra",

    # ── Telenor Denmark (massive alias cluster) ──────────────────
    "mail.telenor.dk":  "telenor_dk",
    "anarki.dk":        "telenor_dk",
    "anderledes.dk":    "telenor_dk",
    "begavet.dk":       "telenor_dk",
    "bitnisse.dk":      "telenor_dk",
    "city.dk":          "telenor_dk",
    "cool.dk":          "telenor_dk",
    "cyberdude.dk":     "telenor_dk",
    "cyberjunkie.dk":   "telenor_dk",
    "dk-online.dk":     "telenor_dk",
    "dk2net.dk":        "telenor_dk",
    "elinstallatoer.dk":"telenor_dk",
    "elsker.dk":        "telenor_dk",
    "elvis.dk":         "telenor_dk",
    "email.dk":         "telenor_dk",
    "fald.dk":          "telenor_dk",
    "fedt.dk":          "telenor_dk",
    "feminin.dk":       "telenor_dk",
    "film.dk":          "telenor_dk",
    "forening.dk":      "telenor_dk",
    "gadefejer.dk":     "telenor_dk",
    "gason.dk":         "telenor_dk",
    "grin.dk":          "telenor_dk",
    "grov.dk":          "telenor_dk",
    "hardworking.dk":   "telenor_dk",
    "heaven.dk":        "telenor_dk",
    "hemmelig.dk":      "telenor_dk",
    "huleboer.dk":      "telenor_dk",
    "image.dk":         "telenor_dk",
    "inbound.dk":       "telenor_dk",
    "indbakke.dk":      "telenor_dk",
    "infile.dk":        "telenor_dk",
    "info.dk":          "telenor_dk",
    "io.dk":            "telenor_dk",
    "it.dk":            "telenor_dk",
    "jyde.dk":          "telenor_dk",
    "klog.dk":          "telenor_dk",
    "knus.dk":          "telenor_dk",
    "krudt.dk":         "telenor_dk",
    "kulturel.dk":      "telenor_dk",
    "larsen.dk":        "telenor_dk",
    "lazy.dk":          "telenor_dk",
    "lystig.dk":        "telenor_dk",
    "mail.dia.dk":      "telenor_dk",
    "maskulin.dk":      "telenor_dk",
    "min-postkasse.dk": "telenor_dk",
    "mobil.dk":         "telenor_dk",
    "musling.dk":       "telenor_dk",
    "natteliv.dk":      "telenor_dk",
    "netbruger.dk":     "telenor_dk",
    "pedal.dk":         "telenor_dk",
    "pengemand.dk":     "telenor_dk",
    "pokerface.dk":     "telenor_dk",
    "post.cybercity.dk":"telenor_dk",
    "post.dia.dk":      "telenor_dk",
    "postman.dk":       "telenor_dk",
    "privat.dia.dk":    "telenor_dk",
    "privatmail.dk":    "telenor_dk",
    "quake.dk":         "telenor_dk",
    "ready.dk":         "telenor_dk",
    "secret.dk":        "telenor_dk",
    "sleepy.dk":        "telenor_dk",
    "sporty.dk":        "telenor_dk",
    "superbruger.dk":   "telenor_dk",
    "talent.dk":        "telenor_dk",
    "tanke.dk":         "telenor_dk",
    "taxidriver.dk":    "telenor_dk",
    "teens.dk":         "telenor_dk",
    "teknik.dk":        "telenor_dk",
    "tjekket.dk":       "telenor_dk",
    "traceroute.dk":    "telenor_dk",
    "tv.dk":            "telenor_dk",
    "ugenstilbud.dk":   "telenor_dk",
    "ungdom.dk":        "telenor_dk",
    "video.dk":         "telenor_dk",
    "vip.cybercity.dk": "telenor_dk",
    "vittig.dk":        "telenor_dk",
    "wol.dk":           "telenor_dk",
    "worldonline.dk":   "telenor_dk",

    # ── IONOS / 1&1 ─────────────────────────────────────────────
    "ionos.com":        "ionos",
    "ionos.de":         "ionos",
    "ionos.co.uk":      "ionos",
    "ionos.fr":         "ionos",
    "ionos.es":         "ionos",
    "1and1.com":        "ionos",
    "1and1.co.uk":      "ionos",
    "1and1.de":         "ionos",
    "1and1.es":         "ionos",
    "1and1.fr":         "ionos",
    "1und1.de":         "ionos",
    "online.de":        "ionos",
    "onlinehome.de":    "ionos",
    "sofort-start.de":  "ionos",
    "sofort-surf.de":   "ionos",
    "sofortstart.de":   "ionos",
    "sofortsurf.de":    "ionos",
    "go4more.de":       "ionos",
    "kundenserver.de":  "ionos",
    "schlund.de":       "ionos",

    # ══ CANADIAN ISPs ══════════════════════════════════════════

    # Shaw Communications
    "shaw.ca":          "shaw",
    "shawcable.net":    "shaw",
    "shawbiz.ca":       "shaw",

    # Rogers Communications
    "rogers.com":       "rogers",
    "rogersmail.net":   "rogers",
    "infointeractive.com": "rogers",

    # Bell Canada
    "bell.net":         "bell",
    "bellnet.ca":       "bell",
    "sympatico.ca":     "bell",
    "bellaliant.net":   "bell",
    "belldsl.net":      "bell",
    "nb.sympatico.ca":  "bell",
    "ns.sympatico.ca":  "bell",
    "on.bell.ca":       "bell",

    # TELUS
    "telus.net":        "telus",
    "telusplanet.net":  "telus",
    "bctel.net":        "telus",
    "telus.com":        "telus",

    # Eastlink
    "eastlink.ca":      "eastlink",
    "eastlinkmail.com": "eastlink",

    # Videotron
    "videotron.ca":     "videotron",
    "videotron.net":    "videotron",
    "cableamos.com":    "videotron",
    "cgocable.net":     "videotron",

    # Cogeco
    "cogeco.ca":        "cogeco",
    "cogeco.net":       "cogeco",
    "cogecable.com":    "cogeco",
    "cableaxion.ca":    "cogeco",
    "execulink.com":    "cogeco",

    # SaskTel
    "sasktel.net":      "sasktel",

    # MTS / Bell MTS
    "mts.net":          "mts",

    # TBayTel
    "tbaytel.net":      "tbaytel",

    # Xplornet
    "xplornet.com":     "xplornet",
    "xplornet.ca":      "xplornet",

    # ══ US ISPs ═════════════════════════════════════════════════

    # Comcast / Xfinity
    "comcast.net":      "comcast",
    "xfinity.com":      "comcast",

    # AT&T
    "att.net":          "att",
    "sbcglobal.net":    "att",
    "bellsouth.net":    "att",
    "ameritech.net":    "att",
    "swbell.net":       "att",
    "flash.net":        "att",
    "prodigy.net":      "att",
    "nvbell.net":       "att",
    "pacbell.net":      "att",
    "snet.net":         "att",
    "wans.net":         "att",

    # Verizon
    "verizon.net":      "verizon",

    # Cox
    "cox.net":          "cox",
    "cox.com":          "cox",
    "coxmail.com":      "cox",

    # Charter / Spectrum / Time Warner
    "charter.net":      "charter",
    "charter.com":      "charter",
    "spectrum.net":     "charter",
    "rr.com":           "charter",
    "twc.com":          "charter",
    "roadrunner.com":   "charter",
    "cfl.rr.com":       "charter",
    "nc.rr.com":        "charter",
    "wi.rr.com":        "charter",
    "tx.rr.com":        "charter",
    "nycap.rr.com":     "charter",
    "rochester.rr.com": "charter",

    # EarthLink / MindSpring
    "earthlink.net":    "earthlink",
    "mindspring.com":   "earthlink",
    "peoplepc.com":     "earthlink",
    "ix.netcom.com":    "earthlink",

    # NetZero
    "netzero.net":      "netzero",
    "netzero.com":      "netzero",

    # ══ UK ISPs ══════════════════════════════════════════════════

    # BT / British Telecom
    "btinternet.com":   "bt",
    "btopenworld.com":  "bt",
    "bt.com":           "bt",
    "talk21.com":       "bt",

    # Sky UK
    "sky.com":          "sky",
    "bskyb.com":        "sky",
    "skybroadband.com": "sky",

    # TalkTalk
    "talktalk.net":     "talktalk",
    "talktalk.co.uk":   "talktalk",

    # Virgin Media
    "virginmedia.com":  "virginmedia",
    "ntlworld.com":     "virginmedia",
    "blueyonder.co.uk": "virginmedia",
    "telewest.net":     "virginmedia",
    "virgin.net":       "virginmedia",

    # Plusnet
    "plusnet.com":      "plusnet",
    "plus.net":         "plusnet",

    # EE / Orange UK
    "ee.co.uk":         "ee",
    "orange.net":       "ee",
    "wanadoo.co.uk":    "ee",
    "t-mobile.uk.net":  "ee",

    # O2 UK
    "o2.co.uk":         "o2",

    # Tiscali UK
    "tiscali.co.uk":    "tiscali",
    "tiscali.net":      "tiscali",

    # ══ EUROPEAN ════════════════════════════════════════════════

    # Orange France / Wanadoo
    "orange.fr":        "orange",
    "wanadoo.fr":       "orange",
    "wanadoo.net":      "orange",

    # SFR France
    "sfr.fr":           "sfr",
    "neuf.fr":          "sfr",
    "club-internet.fr": "sfr",
    "cegetel.net":      "sfr",

    # Free / Iliad France
    "free.fr":          "free",
    "libertysurf.fr":   "free",
    "aliceadsl.fr":     "free",

    # Libero Italy
    "libero.it":        "libero",
    "inwind.it":        "libero",
    "iol.it":           "libero",
    "blu.it":           "libero",
    "giallo.it":        "libero",

    # Tiscali Italy
    "tiscali.it":       "tiscali_it",

    # Telefonica Spain
    "telefonica.net":   "telefonica",
    "telefonica.es":    "telefonica",
    "movistar.es":      "telefonica",
    "terra.es":         "terra",
    "jazztel.es":       "gmail",  # Jazztel uses Google Workspace

    # UOL / Terra Brazil
    "uol.com.br":       "uol",
    "terra.com.br":     "terra",
    "oi.com.br":        "oi",
    "oi.net.br":        "oi",
    "globo.com":        "generic",
    "ig.com.br":        "generic",
    "bol.com.br":       "generic",
}


# ═══════════════════════════════════════════════════════════════
# MX HOSTNAME → PROVIDER  (for business/unknown domains via DNS)
# ═══════════════════════════════════════════════════════════════

_MX_PATTERNS = [

    # ── Google / Gmail / Google Workspace ──────────────────────
    (r"aspmx\.l\.google\.com$",         "gmail"),
    (r"alt\d*\.aspmx\.l\.google\.com$", "gmail"),
    (r"smtp\.google\.com$",             "gmail"),
    (r"googlemail\.com$",               "gmail"),
    (r"\.google\.com$",                 "gmail"),
    (r"googlehosted\.com$",             "gmail"),  # legacy Google Apps
    (r"google\.com$",                   "gmail"),

    # ── Microsoft Office 365 (corporate) ───────────────────────
    (r"\.protection\.outlook\.com$",    "o365"),
    (r"mail\.protection\.outlook\.com$","o365"),
    (r"\.onmicrosoft\.com$",            "o365"),
    (r"\.mail\.microsoft$",             "o365"),

    # ── Outlook personal ────────────────────────────────────────
    (r"^mx\d*\.hotmail\.com$",          "outlook"),
    (r"^mx\d*\.live\.com$",             "outlook"),
    (r"hotmail\.com$",                  "outlook"),
    (r"outlook\.com$",                  "outlook"),

    # ── Yahoo ───────────────────────────────────────────────────
    (r"yahoodns\.net$",                 "yahoo"),
    (r"mx\.yahoo\.com$",               "yahoo"),
    (r"yahoo\.com$",                    "yahoo"),
    (r"mta5\.am0\.yahoodns\.net$",      "yahoo"),

    # ── Apple iCloud ────────────────────────────────────────────
    (r"icloud\.com$",                   "icloud"),
    (r"me\.com$",                       "icloud"),
    (r"apple\.com$",                    "icloud"),

    # ── AOL / Verizon ───────────────────────────────────────────
    (r"aol\.com$",                      "aol"),
    (r"mx\.aol\.com$",                  "aol"),

    # ── GMX / Mail.com ──────────────────────────────────────────
    (r"gmx\.net$",                      "gmx"),
    (r"gmx\.com$",                      "gmx"),
    (r"mx\.mail\.com$",                 "gmx"),

    # ── WEB.DE ──────────────────────────────────────────────────
    (r"mx\d*\.web\.de$",               "web_de"),

    # ── T-Online ────────────────────────────────────────────────
    (r"t-online\.de$",                  "t_online"),
    (r"mx\d*\.t-online\.de$",          "t_online"),

    # ── ProtonMail ──────────────────────────────────────────────
    (r"protonmail\.ch$",               "protonmail"),
    (r"mail\.protonmail\.ch$",         "protonmail"),

    # ── Tutanota ────────────────────────────────────────────────
    (r"tutanota\.de$",                  "tutanota"),
    (r"tutanota\.com$",                 "tutanota"),

    # ── Yandex ──────────────────────────────────────────────────
    (r"yandex\.ru$",                    "yandex"),
    (r"yandex\.net$",                   "yandex"),

    # ── Mail.ru ─────────────────────────────────────────────────
    (r"mail\.ru$",                      "mail_ru"),
    (r"smtp\.mail\.ru$",               "mail_ru"),

    # ── Fastmail ────────────────────────────────────────────────
    (r"fastmail\.com$",                 "fastmail"),
    (r"fastmailbox\.net$",              "fastmail"),
    (r"messagingengine\.com$",          "fastmail"),

    # ── Zoho ────────────────────────────────────────────────────
    (r"zoho\.com$",                     "zoho"),
    (r"zohomail\.com$",                 "zoho"),
    (r"mx\.zoho\.com$",                "zoho"),

    # ── QQ ──────────────────────────────────────────────────────
    (r"qq\.com$",                       "qq"),
    (r"mx\.qq\.com$",                   "qq"),

    # ── NetEase ─────────────────────────────────────────────────
    (r"163\.com$",                      "netease"),
    (r"126\.com$",                      "netease"),

    # ── Posteo ──────────────────────────────────────────────────
    (r"posteo\.de$",                    "posteo"),

    # ── Bluewin / Sunrise ───────────────────────────────────────
    (r"bluewin\.ch$",                   "bluewin"),
    (r"sunrise\.ch$",                   "bluewin"),

    # ── Seznam ──────────────────────────────────────────────────
    (r"seznam\.cz$",                    "seznam"),

    # ── Polish ──────────────────────────────────────────────────
    (r"wp\.pl$",                        "wp_pl"),
    (r"poczta\.onet\.pl$",              "wp_pl"),
    (r"poczta\.o2\.pl$",                "wp_pl"),

    # ── Proximus / Belgacom ──────────────────────────────────────
    (r"proximus\.be$",                  "proximus"),
    (r"belgacom\.net$",                 "proximus"),

    # ── Telenet Belgium ─────────────────────────────────────────
    (r"telenet\.be$",                   "telenet_be"),

    # ── Ziggo / Netherlands ──────────────────────────────────────
    (r"ziggo\.nl$",                     "ziggo"),

    # ── Bigpond / Telstra ────────────────────────────────────────
    (r"bigpond\.com$",                  "bigpond"),
    (r"telstra\.com$",                  "bigpond"),

    # ── Strato ──────────────────────────────────────────────────
    (r"strato\.de$",                    "strato"),

    # ── Freenet.de ──────────────────────────────────────────────
    (r"freenet\.de$",                   "freenet_de"),
    (r"mx\.freenet\.de$",               "freenet_de"),

    # ── Arcor / O2 Germany ──────────────────────────────────────
    (r"arcor\.de$",                     "arcor"),
    (r"o2mail\.de$",                    "arcor"),

    # ── Vodafone Germany ────────────────────────────────────────
    (r"vodafone\.de$",                  "vodafone_de"),

    # ── Telenor Denmark ─────────────────────────────────────────
    (r"mail\.telenor\.dk$",             "telenor_dk"),

    # ── GoDaddy / Workspace Email ────────────────────────────────
    (r"secureserver\.net$",             "godaddy"),
    (r"gdmail\.net$",                   "godaddy"),
    (r"gomo\.com$",                     "godaddy"),
    (r"workspace\.mail$",               "godaddy"),

    # ── Namecheap Private Email ──────────────────────────────────
    (r"privateemail\.com$",             "namecheap"),

    # ── Rackspace Email ─────────────────────────────────────────
    (r"emailsrvr\.com$",                "rackspace"),

    # ── IONOS / 1&1 ─────────────────────────────────────────────
    (r"1and1\.com$",                    "ionos"),
    (r"ionos\.com$",                    "ionos"),
    (r"perfora\.net$",                  "ionos"),
    (r"ui-mx\.com$",                    "ionos"),
    (r"mx00\.ionos\.com$",              "ionos"),
    (r"mx01\.ionos\.co\.uk$",           "ionos"),
    (r"1und1\.de$",                     "ionos"),

    # ── Bluehost / Endurance ────────────────────────────────────
    (r"bluehost\.com$",                 "bluehost"),
    (r"hostmonster\.com$",              "bluehost"),

    # ── HostGator ───────────────────────────────────────────────
    (r"hostgator\.com$",               "hostgator"),
    (r"gator\d+\.hostgator\.com$",     "hostgator"),

    # ── SiteGround ──────────────────────────────────────────────
    (r"siteground\.net$",               "siteground"),
    (r"siteground\.biz$",               "siteground"),

    # ── Canadian ISPs ───────────────────────────────────────────
    (r"shaw\.ca$",                      "shaw"),
    (r"shawcable\.net$",               "shaw"),
    (r"rogers\.com$",                   "rogers"),
    (r"bell\.net$",                     "bell"),
    (r"bellnet\.ca$",                   "bell"),
    (r"sympatico\.ca$",                 "bell"),
    (r"telus\.net$",                    "telus"),
    (r"telusplanet\.net$",              "telus"),
    (r"eastlink\.ca$",                  "eastlink"),
    (r"videotron\.ca$",                 "videotron"),
    (r"videotron\.net$",               "videotron"),
    (r"cogeco\.ca$",                    "cogeco"),
    (r"cogeco\.net$",                   "cogeco"),
    (r"sasktel\.net$",                  "sasktel"),
    (r"mts\.net$",                      "mts"),
    (r"tbaytel\.net$",                  "tbaytel"),
    (r"xplornet\.com$",                 "xplornet"),

    # ── US ISPs ─────────────────────────────────────────────────
    (r"comcast\.net$",                  "comcast"),
    (r"attmail\.com$",                  "att"),
    (r"att\.net$",                      "att"),
    (r"sbcglobal\.net$",               "att"),
    (r"bellsouth\.net$",               "att"),
    (r"cox\.net$",                      "cox"),
    (r"charter\.net$",                  "charter"),
    (r"spectrum\.net$",                 "charter"),
    (r"rr\.com$",                       "charter"),
    (r"earthlink\.net$",               "earthlink"),
    (r"verizon\.net$",                  "verizon"),

    # ── UK ISPs ─────────────────────────────────────────────────
    (r"btinternet\.com$",               "bt"),
    (r"btopenworld\.com$",              "bt"),
    (r"bt\.com$",                       "bt"),
    (r"sky\.com$",                      "sky"),
    (r"bskyb\.com$",                    "sky"),
    (r"talktalk\.net$",                 "talktalk"),
    (r"virginmedia\.com$",              "virginmedia"),
    (r"ntlworld\.com$",                 "virginmedia"),
    (r"blueyonder\.co\.uk$",           "virginmedia"),
    (r"plus\.net$",                     "plusnet"),

    # ── Orange France ───────────────────────────────────────────
    (r"orange\.fr$",                    "orange"),
    (r"wanadoo\.fr$",                   "orange"),

    # ── SFR France ──────────────────────────────────────────────
    (r"sfr\.fr$",                       "sfr"),
    (r"neuf\.fr$",                      "sfr"),

    # ── Free France ─────────────────────────────────────────────
    (r"free\.fr$",                      "free"),

    # ── Libero Italy ────────────────────────────────────────────
    (r"libero\.it$",                    "libero"),
    (r"imapmail\.libero\.it$",          "libero"),

    # ── Tiscali Italy ───────────────────────────────────────────
    (r"tiscali\.it$",                   "tiscali_it"),

    # ── Enterprise filtering (must be LAST — catch corporate domains) ──
    (r"mimecast\.com$",                 "mimecast"),
    (r"pphosted\.com$",                 "proofpoint"),
    (r"proofpoint\.com$",               "proofpoint"),
    (r"barracudanetworks\.com$",        "barracuda"),
    (r"cudamail\.com$",                 "barracuda"),
    (r"messagelabs\.com$",              "messagelabs"),
    (r"symanteccloud\.com$",            "messagelabs"),
    (r"hydra\.sophos\.com$",            "sophos"),
    (r"spamhero\.com$",                 "spamhero"),
    (r"ppe-hosted\.com$",               "proofpoint"),
    (r"forcepoint\.net$",               "forcepoint"),
    (r"ironport\.com$",                 "ironport"),
    (r"cisco\.com$",                    "ironport"),
    (r"exclaimer\.net$",                "exclaimer"),
    (r"duocircle\.com$",               "mailhop"),
]

_MX_RE = [(re.compile(pat, re.IGNORECASE), prov) for pat, prov in _MX_PATTERNS]
_DNS_TIMEOUT = 5
_dns_cache: dict = {}
_dns_lock = threading.Lock()


# ═══════════════════════════════════════════════════════════════
# PROVIDER METADATA
# ═══════════════════════════════════════════════════════════════

PROVIDER_META = {
    # Consumer webmail
    "gmail":        {"name": "Gmail / Google Workspace",      "smtp_delay": 3.0, "max_per_hr": 500},
    "o365":         {"name": "Office 365 (Corporate)",         "smtp_delay": 5.0, "max_per_hr": 200},
    "outlook":      {"name": "Outlook.com / Hotmail / Live",   "smtp_delay": 4.0, "max_per_hr": 300},
    "yahoo":        {"name": "Yahoo Mail",                     "smtp_delay": 3.0, "max_per_hr": 400},
    "icloud":       {"name": "Apple iCloud Mail",              "smtp_delay": 3.0, "max_per_hr": 300},
    "aol":          {"name": "AOL Mail",                       "smtp_delay": 2.5, "max_per_hr": 400},
    "gmx":          {"name": "GMX / Mail.com",                 "smtp_delay": 2.0, "max_per_hr": 500},
    "web_de":       {"name": "WEB.DE",                         "smtp_delay": 2.0, "max_per_hr": 500},
    "t_online":     {"name": "T-Online (Germany)",             "smtp_delay": 2.0, "max_per_hr": 500},
    "protonmail":   {"name": "ProtonMail / Proton.me",         "smtp_delay": 2.0, "max_per_hr": 500},
    "tutanota":     {"name": "Tutanota",                       "smtp_delay": 2.0, "max_per_hr": 500},
    "yandex":       {"name": "Yandex Mail",                    "smtp_delay": 2.0, "max_per_hr": 500},
    "mail_ru":      {"name": "Mail.ru",                        "smtp_delay": 2.0, "max_per_hr": 500},
    "rambler":      {"name": "Rambler Mail",                   "smtp_delay": 2.0, "max_per_hr": 500},
    "fastmail":     {"name": "Fastmail",                       "smtp_delay": 2.0, "max_per_hr": 500},
    "zoho":         {"name": "Zoho Mail",                      "smtp_delay": 2.0, "max_per_hr": 500},
    "qq":           {"name": "QQ Mail (China)",                "smtp_delay": 3.0, "max_per_hr": 300},
    "netease":      {"name": "NetEase (163/126) China",        "smtp_delay": 3.0, "max_per_hr": 300},
    "sina":         {"name": "Sina Mail (China)",              "smtp_delay": 3.0, "max_per_hr": 300},
    "posteo":       {"name": "Posteo (Germany)",               "smtp_delay": 2.0, "max_per_hr": 500},
    "laposte":      {"name": "La Poste (France)",              "smtp_delay": 2.5, "max_per_hr": 400},
    "bluewin":      {"name": "Bluewin / Sunrise (CH)",         "smtp_delay": 2.5, "max_per_hr": 400},
    "pobox":        {"name": "Pobox",                          "smtp_delay": 2.0, "max_per_hr": 500},
    "gandi":        {"name": "Gandi.net",                      "smtp_delay": 2.0, "max_per_hr": 500},
    "one_com":      {"name": "One.com",                        "smtp_delay": 2.0, "max_per_hr": 500},
    "ovh":          {"name": "OVH",                            "smtp_delay": 2.0, "max_per_hr": 500},
    "strato":       {"name": "Strato (Germany)",               "smtp_delay": 2.0, "max_per_hr": 500},
    "freenet_de":   {"name": "Freenet.de (Germany)",           "smtp_delay": 2.5, "max_per_hr": 400},
    "arcor":        {"name": "Arcor / O2 (Germany)",           "smtp_delay": 2.5, "max_per_hr": 400},
    "vodafone_de":  {"name": "Vodafone Germany",               "smtp_delay": 2.5, "max_per_hr": 400},
    "seznam":       {"name": "Seznam.cz (Czech Republic)",     "smtp_delay": 2.5, "max_per_hr": 400},
    "wp_pl":        {"name": "WP.pl / Onet / O2 (Poland)",     "smtp_delay": 2.5, "max_per_hr": 400},
    "proximus":     {"name": "Proximus / Belgacom (Belgium)",  "smtp_delay": 2.5, "max_per_hr": 400},
    "telenet_be":   {"name": "Telenet (Belgium)",              "smtp_delay": 2.5, "max_per_hr": 400},
    "ziggo":        {"name": "Ziggo / XS4ALL (Netherlands)",   "smtp_delay": 2.5, "max_per_hr": 400},
    "bigpond":      {"name": "Bigpond / Telstra (Australia)",  "smtp_delay": 2.5, "max_per_hr": 400},
    "xtra":         {"name": "Xtra (New Zealand)",             "smtp_delay": 2.5, "max_per_hr": 400},
    "telenor_dk":   {"name": "Telenor Denmark",                "smtp_delay": 2.0, "max_per_hr": 500},
    # French ISPs
    "orange":       {"name": "Orange / Wanadoo (France)",      "smtp_delay": 2.5, "max_per_hr": 400},
    "sfr":          {"name": "SFR / Neuf (France)",            "smtp_delay": 2.5, "max_per_hr": 400},
    "free":         {"name": "Free.fr (France)",               "smtp_delay": 2.5, "max_per_hr": 400},
    # Italian
    "libero":       {"name": "Libero (Italy)",                 "smtp_delay": 2.5, "max_per_hr": 400},
    "tiscali_it":   {"name": "Tiscali (Italy)",                "smtp_delay": 2.5, "max_per_hr": 400},
    # Spanish
    "telefonica":   {"name": "Telefónica / Movistar",          "smtp_delay": 2.5, "max_per_hr": 400},
    "terra":        {"name": "Terra Networks",                  "smtp_delay": 2.5, "max_per_hr": 400},
    # Brazil
    "uol":          {"name": "UOL (Brazil)",                   "smtp_delay": 2.5, "max_per_hr": 400},
    "oi":           {"name": "Oi (Brazil)",                    "smtp_delay": 2.5, "max_per_hr": 400},
    # Canadian ISPs
    "shaw":         {"name": "Shaw Communications (CA)",       "smtp_delay": 2.0, "max_per_hr": 500},
    "rogers":       {"name": "Rogers Communications (CA)",     "smtp_delay": 2.0, "max_per_hr": 500},
    "bell":         {"name": "Bell Canada",                    "smtp_delay": 2.0, "max_per_hr": 500},
    "telus":        {"name": "TELUS (CA)",                     "smtp_delay": 2.0, "max_per_hr": 500},
    "eastlink":     {"name": "Eastlink (CA)",                  "smtp_delay": 2.0, "max_per_hr": 500},
    "videotron":    {"name": "Videotron (CA)",                 "smtp_delay": 2.0, "max_per_hr": 500},
    "cogeco":       {"name": "Cogeco (CA)",                    "smtp_delay": 2.0, "max_per_hr": 500},
    "sasktel":      {"name": "SaskTel (CA)",                   "smtp_delay": 2.0, "max_per_hr": 500},
    "mts":          {"name": "Bell MTS (CA)",                  "smtp_delay": 2.0, "max_per_hr": 500},
    "tbaytel":      {"name": "TBayTel (CA)",                   "smtp_delay": 2.0, "max_per_hr": 500},
    "xplornet":     {"name": "Xplornet (CA)",                  "smtp_delay": 2.0, "max_per_hr": 500},
    # US ISPs
    "comcast":      {"name": "Comcast / Xfinity (US)",         "smtp_delay": 2.5, "max_per_hr": 400},
    "att":          {"name": "AT&T / SBC / BellSouth (US)",    "smtp_delay": 2.5, "max_per_hr": 400},
    "verizon":      {"name": "Verizon (US)",                   "smtp_delay": 2.5, "max_per_hr": 400},
    "cox":          {"name": "Cox Communications (US)",        "smtp_delay": 2.5, "max_per_hr": 400},
    "charter":      {"name": "Charter / Spectrum / TWC (US)",  "smtp_delay": 2.5, "max_per_hr": 400},
    "earthlink":    {"name": "EarthLink (US)",                 "smtp_delay": 2.5, "max_per_hr": 400},
    "netzero":      {"name": "NetZero (US)",                   "smtp_delay": 2.5, "max_per_hr": 400},
    # UK ISPs
    "bt":           {"name": "BT / British Telecom (UK)",      "smtp_delay": 2.5, "max_per_hr": 400},
    "sky":          {"name": "Sky UK",                         "smtp_delay": 2.5, "max_per_hr": 400},
    "talktalk":     {"name": "TalkTalk (UK)",                  "smtp_delay": 2.5, "max_per_hr": 400},
    "virginmedia":  {"name": "Virgin Media / NTL (UK)",        "smtp_delay": 2.5, "max_per_hr": 400},
    "plusnet":      {"name": "Plusnet (UK)",                   "smtp_delay": 2.5, "max_per_hr": 400},
    "ee":           {"name": "EE / Orange UK",                 "smtp_delay": 2.5, "max_per_hr": 400},
    "o2":           {"name": "O2 (UK)",                        "smtp_delay": 2.5, "max_per_hr": 400},
    "tiscali":      {"name": "Tiscali (UK)",                   "smtp_delay": 2.5, "max_per_hr": 400},
    # Hosting
    "godaddy":      {"name": "GoDaddy Workspace",              "smtp_delay": 2.0, "max_per_hr": 600},
    "namecheap":    {"name": "Namecheap Private Email",        "smtp_delay": 2.0, "max_per_hr": 600},
    "rackspace":    {"name": "Rackspace Email",                "smtp_delay": 2.0, "max_per_hr": 600},
    "ionos":        {"name": "IONOS / 1&1",                    "smtp_delay": 2.0, "max_per_hr": 600},
    "bluehost":     {"name": "Bluehost",                       "smtp_delay": 2.0, "max_per_hr": 600},
    "hostgator":    {"name": "HostGator",                      "smtp_delay": 2.0, "max_per_hr": 600},
    "siteground":   {"name": "SiteGround",                     "smtp_delay": 2.0, "max_per_hr": 600},
    # Enterprise filtering
    "mimecast":     {"name": "Mimecast (Enterprise Filter)",   "smtp_delay": 6.0, "max_per_hr": 150},
    "proofpoint":   {"name": "Proofpoint (Enterprise Filter)", "smtp_delay": 6.0, "max_per_hr": 150},
    "barracuda":    {"name": "Barracuda Networks",             "smtp_delay": 4.0, "max_per_hr": 200},
    "messagelabs":  {"name": "Symantec / MessageLabs",         "smtp_delay": 5.0, "max_per_hr": 150},
    "sophos":       {"name": "Sophos Email",                   "smtp_delay": 5.0, "max_per_hr": 150},
    "ironport":     {"name": "Cisco IronPort",                 "smtp_delay": 5.0, "max_per_hr": 150},
    "forcepoint":   {"name": "Forcepoint Email Security",      "smtp_delay": 5.0, "max_per_hr": 150},
    "spamhero":     {"name": "SpamHero",                       "smtp_delay": 4.0, "max_per_hr": 200},
    "mailhop":      {"name": "Mailhop / Duocircle",            "smtp_delay": 4.0, "max_per_hr": 200},
    "exclaimer":    {"name": "Exclaimer Cloud",                "smtp_delay": 4.0, "max_per_hr": 200},
    "generic":      {"name": "Generic / Unknown",              "smtp_delay": 2.0, "max_per_hr": 600},
}


# ═══════════════════════════════════════════════════════════════
# DNS MX LOOKUP
# ═══════════════════════════════════════════════════════════════

def _resolve_mx(domain: str) -> list:
    try:
        import dns.resolver as _r
        answers = _r.resolve(domain, "MX")
        return sorted((int(r.preference), str(r.exchange).rstrip(".")) for r in answers)
    except ImportError:
        pass
    except Exception:
        pass
    try:
        from urllib.request import Request, urlopen
        import json
        url  = f"https://cloudflare-dns.com/dns-query?name={domain}&type=MX"
        req  = Request(url, headers={"Accept": "application/dns-json"})
        resp = urlopen(req, timeout=_DNS_TIMEOUT)
        data = json.loads(resp.read().decode())
        recs = []
        for a in (data.get("Answer") or []):
            if a.get("type") == 15:
                parts = (a.get("data") or "").split()
                if len(parts) >= 2:
                    try:
                        recs.append((int(parts[0]), parts[1].rstrip(".")))
                    except Exception:
                        pass
        return sorted(recs)
    except Exception:
        pass
    return []


def _mx_to_provider(mx_hostnames: list) -> str:
    for _, mx in mx_hostnames:
        mx_lower = mx.lower()
        for pattern, provider in _MX_RE:
            if pattern.search(mx_lower):
                return provider
    return "generic"


def _classify_domain_cached(domain: str) -> str:
    domain = domain.lower().strip()
    if domain in _DOMAIN_MAP:
        return _DOMAIN_MAP[domain]
    with _dns_lock:
        if domain in _dns_cache:
            return _dns_cache[domain]
    try:
        mx_records = _resolve_mx(domain)
        provider   = _mx_to_provider(mx_records) if mx_records else "generic"
    except Exception:
        provider = "generic"
    with _dns_lock:
        _dns_cache[domain] = provider
    return provider


# ═══════════════════════════════════════════════════════════════
# PUBLIC API
# ═══════════════════════════════════════════════════════════════

def classify_email(email: str) -> str:
    if "@" not in email:
        return "generic"
    domain = email.strip().split("@")[-1].lower()
    return _classify_domain_cached(domain)


def sort_emails(emails: list, workers: int = 20, timeout: int = 30) -> dict:
    if not emails:
        return {}
    domain_set = set()
    for e in emails:
        if "@" in e:
            domain_set.add(e.strip().split("@")[-1].lower())
    unknown = [d for d in domain_set if d not in _DOMAIN_MAP and d not in _dns_cache]
    if unknown:
        def _resolve_one(domain):
            return domain, _classify_domain_cached(domain)
        with ThreadPoolExecutor(max_workers=min(workers, len(unknown))) as ex:
            futs = {ex.submit(_resolve_one, d): d for d in unknown}
            for fut in as_completed(futs, timeout=timeout):
                try:
                    dom, prov = fut.result(timeout=0)
                    with _dns_lock:
                        _dns_cache[dom] = prov
                except Exception:
                    pass
    buckets: dict = {}
    for email in emails:
        email = email.strip()
        if not email:
            continue
        provider = classify_email(email)
        buckets.setdefault(provider, []).append(email)
    return buckets


def sort_leads(leads: list, workers: int = 20, timeout: int = 30) -> dict:
    if not leads:
        return {}
    emails = [l.get("email", "") for l in leads if isinstance(l, dict)]
    email_buckets = sort_emails(emails, workers=workers, timeout=timeout)
    email_to_provider = {}
    for provider, bucket_emails in email_buckets.items():
        for e in bucket_emails:
            email_to_provider[e.lower()] = provider
    lead_buckets: dict = {}
    for lead in leads:
        if not isinstance(lead, dict):
            continue
        email    = (lead.get("email") or "").strip()
        provider = email_to_provider.get(email.lower(), "generic")
        lead_buckets.setdefault(provider, []).append(lead)
    return lead_buckets


def get_provider_delay(provider: str) -> float:
    return PROVIDER_META.get(provider, PROVIDER_META["generic"])["smtp_delay"]


def get_provider_name(provider: str) -> str:
    return PROVIDER_META.get(provider, PROVIDER_META["generic"])["name"]


def bucket_summary(buckets: dict) -> dict:
    return {k: len(v) for k, v in buckets.items()}


def clear_dns_cache():
    with _dns_lock:
        _dns_cache.clear()
