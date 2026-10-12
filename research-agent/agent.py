

import json
import time
import argparse
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.parse import quote
import ssl
import certifi

VERSION = "0.9.3.15"
USER_AGENT = "TechnocoreResearchAgent/0.7"

QUANTIFIED_SCAN_RESULT_PATTERN = re.compile(
    r"\b(?:prompt\s+injection|security|vulnerability)\s+scan\b.{0,100}"
    r"\b(?:cleared|processed|scanned|checked|tested|blocked|detected|flagged|rejected|passed|failed)\b.{0,60}"
    r"\b\d+\s+(?:user\s+)?inputs?\b",
    re.IGNORECASE,
)

ROOMS = ["flop_labs", "lobby"]
LIMIT = 50

BASE_URL = "https://technocore.chat/r/{room}?format=json&limit={limit}"

REPORT_DIR = Path("research-agent/reports")
REPORT_DIR.mkdir(parents=True, exist_ok=True)

STATE_FILE = Path("research-agent/state.json")
QUEUE_FILE = Path("research-agent/research_queue_v093.json")


def load_state():
    if not STATE_FILE.exists():
        return {}

    try:
        data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError(
            f"État illisible : {STATE_FILE}"
        ) from exc

    if not isinstance(data, dict):
        raise RuntimeError(f"Format inattendu : {STATE_FILE}")

    return data


def save_state(state):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    temporary = STATE_FILE.with_name(STATE_FILE.name + ".tmp")
    temporary.write_text(
        json.dumps(
            state,
            indent=2,
            ensure_ascii=False
        ),
        encoding="utf-8"
    )
    temporary.replace(STATE_FILE)

def load_queue():
    if not QUEUE_FILE.exists():
        return []

    try:
        data = json.loads(QUEUE_FILE.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError(
            f"File de recherche illisible : {QUEUE_FILE}"
        ) from exc

    if not isinstance(data, list):
        raise RuntimeError(f"Format inattendu : {QUEUE_FILE}")

    return data

def save_queue(queue):
    QUEUE_FILE.parent.mkdir(parents=True, exist_ok=True)
    temporary = QUEUE_FILE.with_name(QUEUE_FILE.name + ".tmp")
    temporary.write_text(
        json.dumps(
            queue,
            indent=2,
            ensure_ascii=False
        ),
        encoding="utf-8"
    )
    temporary.replace(QUEUE_FILE)

def research_worthy(candidate):
    """
    v0.9.3

    Sélectionne uniquement les observations techniques
    qui présentent un élément concret et testable.

    Le but n'est plus de détecter simplement un vocabulaire
    technique, mais une observation exploitable.
    """

    import re

    if not candidate.get("technical"):
        return False

    if candidate.get("heartbeat"):
        return False

    signals = set(candidate.get("signals", []))
    text = candidate.get("text", "").lower()

    if QUANTIFIED_SCAN_RESULT_PATTERN.search(text):
        return True

    # --------------------------------------------------------
    # 1. MESURE QUANTITATIVE CONCRÈTE
    # --------------------------------------------------------

    if "measurement" in signals:

        # ----------------------------------------------------
        # Mesures physiques / quantitatives
        # ----------------------------------------------------

        quantitative_pattern = re.compile(
            r"""
            \b
            \d+(?:\.\d+)?
            \s*
            (?:
                ms|msec|millisecond(?:s)?
                |s|sec|second(?:s)?
                |%|percent
                |requests?|req
                |mb|gb|kb
                |tps|rps
            )
            \b
            """,
            re.IGNORECASE | re.VERBOSE
        )

        if quantitative_pattern.search(text):
            return True

        # ----------------------------------------------------
        # Mesures de volume expérimental
        #
        # Exemples acceptés :
        #   1340 benchmarks
        #   900 requests
        #   20 records
        #   500 messages
        #
        # Les identifiants seuls ne doivent PAS compter :
        #   account_067
        #   seq 90315062
        #   DID z6Mk...
        # ----------------------------------------------------

        experimental_volume_pattern = re.compile(
            r"""
            \b
            \d+(?:\.\d+)?
            \s+
            (?:
                unseen\s+benchmarks?
                |benchmarks?
                |tests?
                |samples?
                |records?
                |messages?
                |requests?
                |transactions?
                |runs?
                |epochs?
                |blocks?
                |tokens?
                |items?
                |examples?
            )
            \b
            """,
            re.IGNORECASE | re.VERBOSE
        )

        if experimental_volume_pattern.search(text):

            # Une annonce de simple présence ou un identifiant
            # ne constitue pas à lui seul une observation.
            experimental_context = (
                "evaluated",
                "evaluation",
                "tested",
                "test",
                "benchmark",
                "benchmarks",
                "measured",
                "measurement",
                "sampled",
                "sample",
                "experiment",
                "experimental",
                "inference",
                "inferred",
                "observed",
                "observation",
                "processed",
                "processing",
                "trained",
                "training",
                "validated",
                "validation",
            )

            if any(marker in text for marker in experimental_context):
                return True

    # --------------------------------------------------------
    # 2. COMPARAISON RÉELLE
    # --------------------------------------------------------

    if "comparison/result" in signals:

        comparison_markers = (
            "vs ",
            "versus",
            "compared to",
            "compared with",
            "baseline",
            "previous",
            "before",
            "after",
            "dropped from",
            "increased from",
            "decreased from",
            "rose from",
            "fell from",
            "difference",
        )

        has_comparison = any(
            marker in text
            for marker in comparison_markers
        )

        has_number = bool(
            re.search(
                r"\b\d+(?:\.\d+)?\b",
                text
            )
        )

        if has_comparison and has_number:
            return True

    # --------------------------------------------------------
    # 3. INTERFACE / PROTOCOLE CONCRET
    # --------------------------------------------------------

    if "protocol/interface" in signals:

        endpoint_markers = (
            "http://",
            "https://",
            "get /",
            "post /",
            "put /",
            "delete /",
            "options /",
            "endpoint",
        )

        status_markers = (
            "status 200",
            "status 201",
            "status 400",
            "status 401",
            "status 403",
            "status 404",
            "status 405",
            "status 409",
            "status 500",
            " returned 200",
            " returned 201",
            " returned 400",
            " returned 401",
            " returned 403",
            " returned 404",
            " returned 405",
            " returned 409",
            " returned 500",
        )

        has_endpoint = any(
            marker in text
            for marker in endpoint_markers
        )

        has_status = any(
            marker in text
            for marker in status_markers
        )

        if has_endpoint and has_status:
            return True

    # --------------------------------------------------------
    # 4. PREUVE / VÉRIFICATION CONCRÈTE
    # --------------------------------------------------------

    if "proof/verification" in signals:

        artifact_markers = (
            "signature",
            "signed",
            "receipt",
            "hash",
            "txid",
            "transaction",
            "verified",
        )

        has_artifact = any(
            marker in text
            for marker in artifact_markers
        )

        # Une preuve doit être accompagnée d'un élément
        # identifiable, pas seulement d'une affirmation.
        has_identifier = bool(
            re.search(
                r"(0x[a-f0-9]{8,}\b|"
                r"\bseq(?:\s*[:=]\s*|\s+)\d+\b|"
                r"\btxid(?:\s*[:=]\s*|\s+)[a-z0-9_-]{8,}\b|"
                r"\bhash(?:\s*[:=]\s*|\s+)[a-f0-9]{16,64}\b|"
                r"\b[a-f0-9]{16,64}\b)",
                text,
                re.IGNORECASE
            )
        )

        if has_artifact and has_identifier:
            return True

    # --------------------------------------------------------
    # 5. OBSERVATION COMPORTEMENTALE CONCRÈTE
    #
    # Exemple intéressant :
    #   "a nonce that goes backwards is rejected without
    #    any error text"
    #
    # On recherche :
    #   condition identifiable
    #   +
    #   comportement/résultat observable
    #
    # On exclut les intentions futures :
    #   plans to...
    #   should...
    #   will...
    # --------------------------------------------------------

    if "state/change" in signals or "comparison/result" in signals:

        condition_markers = (
            "when ",
            "if ",
            "after ",
            "before ",
            "once ",
            "during ",
            "while ",
            "nonce",
            "migration",
            "upgrade",
            "reorg",
            "replay",
            "parser",
            "request",
            "transaction",
            "message",
            "frame",
        )

        behavior_markers = (
            "rejected",
            "rejects",
            "accepted",
            "accepts",
            "dropped",
            "drops",
            "failed",
            "fails",
            "returned",
            "returns",
            "blocked",
            "blocks",
            "ignored",
            "ignores",
            "queued",
            "queues",
            "pruned",
            "prunes",
            "forked",
            "forks",
            "refunded",
            "refunding",
            "settled",
            "settling",
            "attested",
            "attesting",
            "silently",
            "without any error",
            "no error",
            "stale",
            "changed",
            "changes",
            "rebuilt",
            "repaired",
            "recovered",
        )

        has_condition = any(
            marker in text
            for marker in condition_markers
        )

        has_behavior = any(
            marker in text
            for marker in behavior_markers
        )

        # Les intentions futures ne sont pas des observations.
        future_markers = (
            "plans to",
            "plan to",
            "should ",
            "will ",
            "would ",
            "must ",
            "aims to",
            "expects to",
        )

        is_future_intent = any(
            marker in text
            for marker in future_markers
        )

        if has_condition and has_behavior and not is_future_intent:
            return True

    return False



def classify_candidate(candidate):
    """
    v0.9.3.4

    Sépare les observations concrètes en trois catégories :

        RESEARCH
            Observation concrète susceptible de faire l'objet
            d'une recherche ou d'un test.

        SIGNAL
            Observation réelle mais principalement liée au
            comportement, à l'activité ou à la saturation du réseau.

        REJECT
            Bruit, présence, affirmation vague ou intention future.
    """

    import re

    if not research_worthy(candidate):
        return "REJECT"

    text = candidate.get("text", "").lower()

    # ----------------------------------------------------
    # NETWORK SIGNAL
    #
    # La cadence / fréquence / duplication réseau est
    # prioritaire sur la qualité A générique.
    #
    # Exemple :
    #   "posted 25 lines in about 20 minutes,
    #    one every 50s"
    #
    # Ce type d'observation reste un SIGNAL même si les
    # nombres pourraient superficiellement produire A.
    # ----------------------------------------------------

    signal_markers = (
        "posted ",
        "lines in about",
        "one every",
        "every ",
        "identical",
        "duplicates",
        "duplicate",
        "cycling ",
        "templates",
        "within ",
        "none of the",
        "no link",
        "no links",
    )

    has_signal_language = any(
        marker in text
        for marker in signal_markers
    )

    frequency_pattern = bool(
        re.search(
            r"(?<![\d.])\b\d+(?:\.\d+)?\s*(?:s|sec|seconds?|min|minutes?|h|hours?)\b",
            text
        )
    )

    volume_pattern = bool(
        re.search(
            r"\b\d+\s+(?:messages?|lines?|posts?|copies?|templates?)\b",
            text
        )
    )

    if (
        has_signal_language
        and (frequency_pattern or volume_pattern)
    ):
        return "SIGNAL"

    # ----------------------------------------------------
    # QUALITY
    #
    # Une fois les vrais SIGNALS écartés, la qualité A/B
    # détermine la destination RESEARCH.
    # ----------------------------------------------------

    quality = classify_quality(candidate)

    if quality in ("A", "B"):
        return "RESEARCH"

    return "REJECT"



SIGNAL_FILE = Path("research-agent/signal_log.json")
OFFER_FILE = Path("research-agent/structured_offers.json")
REVIEW_FILE = Path("research-agent/review_queue.json")


def load_signal_log():
    """Charge le journal local des signaux réseau."""
    if not SIGNAL_FILE.exists():
        return []

    try:
        data = json.loads(SIGNAL_FILE.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError(
            f"Journal de signaux illisible : {SIGNAL_FILE}"
        ) from exc

    if not isinstance(data, list):
        raise RuntimeError(f"Format inattendu : {SIGNAL_FILE}")

    return data


def save_signal_log(signals):
    """Sauvegarde le journal local des signaux réseau."""
    SIGNAL_FILE.parent.mkdir(parents=True, exist_ok=True)
    temporary = SIGNAL_FILE.with_name(SIGNAL_FILE.name + ".tmp")
    temporary.write_text(
        json.dumps(
            signals,
            indent=2,
            ensure_ascii=False
        ),
        encoding="utf-8"
    )
    temporary.replace(SIGNAL_FILE)

def add_to_signal_log(room, groups, signal_log):
    """
    Ajoute uniquement les candidats classés SIGNAL.

    Les signaux restent locaux.
    Aucune publication.
    """

    added = 0

    existing_keys = {
        (
            item.get("room"),
            item.get("seq")
        )
        for item in signal_log
    }

    for group in groups:

        representative = group["representative"]

        if classify_candidate(representative) != "SIGNAL":
            continue

        seq = representative.get("seq")
        key = (room, seq)

        if key in existing_keys:
            continue

        signal_log.append({
            "room": room,
            "seq": seq,
            "text": representative["text"],
            "signals": representative["signals"],
            "evidence": representative["evidence"],
            "evidence_items": representative["evidence_items"],
            "occurrences": len(group["members"]),
            "status": "NEW",
        })

        existing_keys.add(key)
        added += 1

    return added




def load_special_log(path):
    # En cas de journal existant invalide, ne pas l'écraser.
    if not path.exists():
        return []

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError(
            f"Journal spécial illisible : {path}"
        ) from exc

    if not isinstance(data, list):
        raise RuntimeError(f"Format inattendu : {path}")

    return data


def save_special_log(path, records):
    # Écriture temporaire puis remplacement atomique.
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(records, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )
    temporary.replace(path)


def classify_special_message(text):
    # Vérifie la structure TCLK ; ne vérifie pas la signature du transport.
    if not isinstance(text, str):
        return "NORMAL", None, None

    stripped = text.strip()

    if not stripped.lower().startswith("tclk1"):
        return "NORMAL", None, None

    if not re.match(r"^tclk1(?:\s|$)", stripped, re.IGNORECASE):
        return "REVIEW", None, "Préfixe tclk1 malformé"

    body = stripped[5:].strip()
    if not body:
        return "REVIEW", None, "JSON absent après tclk1"

    try:
        payload, end = json.JSONDecoder().raw_decode(body)
    except (json.JSONDecodeError, ValueError):
        return "REVIEW", None, "JSON invalide ou incomplet"

    if body[end:].strip():
        return "REVIEW", payload, "Texte supplémentaire après le JSON"

    if not isinstance(payload, dict):
        return "REVIEW", payload, "Le JSON n'est pas un objet"

    if payload.get("type") != "offer":
        return "REVIEW", payload, "Type différent de offer"

    required = {
        "type", "from", "role", "amount", "asset", "lock", "rails",
        "claimByMs", "refundAfterMs", "expiresMs", "nonce", "id"
    }
    missing = sorted(required - set(payload))
    if missing:
        return "REVIEW", payload, "Champ(s) requis absent(s) : " + ", ".join(missing)

    allowed = required | {"paymentKey", "job"}
    unknown = sorted(set(payload) - allowed)
    if unknown:
        return "REVIEW", payload, "Champ(s) inconnu(s) : " + ", ".join(unknown)

    for field in ("id", "from", "asset", "nonce"):
        value = payload.get(field)
        if not isinstance(value, str) or not value.strip():
            return "REVIEW", payload, f"Champ absent ou invalide : {field}"

    if not re.fullmatch(r"did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}", payload["from"]):
        return "REVIEW", payload, "from doit être un DID Ed25519 did:key valide"

    if payload["role"] not in ("payer", "payee"):
        return "REVIEW", payload, "role doit être payer ou payee"

    if payload["lock"] not in ("hash", "point"):
        return "REVIEW", payload, "lock doit être hash ou point"

    amount = payload.get("amount")
    if not isinstance(amount, str) or not re.fullmatch(r"[0-9]+", amount):
        return "REVIEW", payload, "amount doit être une chaîne décimale entière"

    rails = payload.get("rails")
    if not isinstance(rails, list) or not rails or any(
        not isinstance(rail, str)
        or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", rail)
        for rail in rails
    ):
        return "REVIEW", payload, "rails invalide selon la grammaire TCLK/1"

    for field in ("claimByMs", "refundAfterMs", "expiresMs"):
        value = payload.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            return "REVIEW", payload, f"Date entière invalide : {field}"

    if payload["claimByMs"] >= payload["refundAfterMs"]:
        return "REVIEW", payload, "claimByMs doit être inférieur à refundAfterMs"

    key = payload.get("paymentKey")
    if payload["lock"] == "point" and key is None:
        return "REVIEW", payload, "paymentKey absent pour lock point"

    if key is not None:
        if not isinstance(key, str) or not re.fullmatch(
            r"0x(?:02|03)[0-9a-f]{64}", key
        ):
            return "REVIEW", payload, "paymentKey au format invalide"
        x = int(key[4:], 16)
        prime = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        if x >= prime:
            return "REVIEW", payload, "paymentKey hors courbe secp256k1"
        y2 = (pow(x, 3, prime) + 7) % prime
        y = pow(y2, (prime + 1) // 4, prime)
        if pow(y, 2, prime) != y2:
            return "REVIEW", payload, "paymentKey n'est pas un point valide secp256k1"

    if "job" in payload:
        job = payload["job"]
        if not isinstance(job, dict):
            return "REVIEW", payload, "job doit être un objet"
        extra_job = sorted(set(job) - {"proto", "id", "context"})
        if extra_job:
            return "REVIEW", payload, "Champ(s) job inconnu(s) : " + ", ".join(extra_job)
        if any(
            not isinstance(job.get(field), str) or not job[field].strip()
            for field in ("proto", "id")
        ):
            return "REVIEW", payload, "job doit contenir proto et id non vides"
        if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", job["proto"]):
            return "REVIEW", payload, "job.proto invalide"
        if "context" in job and (
            not isinstance(job["context"], str) or not job["context"].strip()
        ):
            return "REVIEW", payload, "job.context invalide"

    import hashlib
    core = {key: value for key, value in payload.items() if key != "id"}
    canonical = json.dumps(
        core, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    expected_id = "0x" + hashlib.sha256(
        ("FLOP::tclk::v1|offer|" + canonical).encode("utf-8")
    ).hexdigest()

    if payload["id"] != expected_id:
        return "REVIEW", payload, "id ne correspond pas au hash canonique de l'offre"

    return "STRUCTURED_OFFER", payload, None


def special_log_key(record):
    seq = record.get("seq")
    if seq is not None:
        return (record.get("room"), str(seq), None)
    return (record.get("room"), None, record.get("text", ""))


def route_special_groups(room, groups, offer_log, review_log):
    # Les messages spéciaux sont retirés des circuits ordinaires.
    existing_keys = {
        special_log_key(item)
        for item in offer_log + review_log
    }

    normal_groups = []
    added_offers = 0
    added_reviews = 0

    for group in groups:
        members = group.get("members") or [group["representative"]]
        normal_members = []

        for member in members:
            message_text = member.get("text", "")
            route, payload, reason = classify_special_message(message_text)

            if route == "NORMAL":
                normal_members.append(member)
                continue

            record_key = special_log_key({
                "room": room,
                "seq": member.get("seq"),
                "text": message_text,
            })

            if record_key not in existing_keys:
                record = {
                    "room": room,
                    "seq": member.get("seq"),
                    "route": route,
                    "text": message_text,
                    "payload": payload,
                    "reason": reason,
                    "signals": member.get("signals", []),
                    "evidence": member.get("evidence", 0),
                    "evidence_items": member.get("evidence_items", []),
                    "occurrences": len(members),
                    "status": "NEW",
                    "first_seen": datetime.now(timezone.utc).isoformat(),
                }

                if route == "STRUCTURED_OFFER":
                    offer_log.append(record)
                    added_offers += 1
                else:
                    review_log.append(record)
                    added_reviews += 1

                existing_keys.add(record_key)

        if normal_members:
            normal_members.sort(
                key=lambda item: (
                    item.get("evidence", 0),
                    len(item.get("signals", []))
                ),
                reverse=True
            )
            normal_group = dict(group)
            normal_group["members"] = normal_members
            normal_group["representative"] = normal_members[0]
            normal_groups.append(normal_group)

    return normal_groups, added_offers, added_reviews



def add_to_research_queue(
    room,
    groups,
    queue
):
    """
    Ajoute les groupes RESEARCH à la Research Queue.

    v0.9.3.4 :
    - SIGNAL reste dans signal_log uniquement
    - REJECT est exclu
    - A/B sont conservés avec leur qualité
    - doublons regroupés
    - aucune publication
    """

    added = 0

    existing_keys = {
        (
            item.get("room"),
            item.get("seq")
        )
        for item in queue
    }

    for group in groups:
        representative = group["representative"]

        # Seuls les candidats RESEARCH entrent dans la queue.
        if classify_candidate(representative) != "RESEARCH":
            continue

        if not research_worthy(representative):
            continue

        # Deuxième niveau de sélection :
        # A = RESEARCH STRONG
        # B = RESEARCH WEAK
        # REJECT = exclu
        quality = classify_quality(representative)

        if quality == "REJECT":
            continue

        seq = representative.get("seq")

        key = (room, seq)

        if key in existing_keys:
            continue

        priority = "HIGH"

        if representative["evidence"] < 5:
            priority = "MEDIUM"

        queue.append({
            "room": room,
            "seq": seq,
            "text": representative["text"],
            "signals": representative["signals"],
            "evidence": representative["evidence"],
            "evidence_items": representative["evidence_items"],
            "technical": representative["technical"],
            "heartbeat": representative["heartbeat"],
            "occurrences": len(group["members"]),
            "priority": priority,
            "quality": quality,
            "status": "NEW",
        })

        existing_keys.add(key)
        added += 1

    return added


def fetch_backlog(room, since=None):
    all_messages = []
    current_since = since

    while True:
        data = fetch_room(room, since=current_since)
        messages = get_messages(data)

        if not messages:
            break

        all_messages.extend(messages)

        seqs = [
            int(message["seq"])
            for message in messages
            if message.get("seq") is not None
        ]

        if not seqs:
            break

        newest_seq = max(seqs)

        if current_since is not None and newest_seq <= int(current_since):
            break

        current_since = newest_seq

        if len(messages) < LIMIT:
            break

    return all_messages


def fetch_room(room, since=None):
    url = BASE_URL.format(room=room, limit=LIMIT)

    if since is not None:
        url += f"&since={since}"

    req = Request(
        url,
        headers={"User-Agent": USER_AGENT}
    )

    ssl_context = ssl.create_default_context(
        cafile=certifi.where()
    )

    with urlopen(
        req,
        timeout=20,
        context=ssl_context
    ) as response:
        return json.loads(response.read().decode("utf-8"))



def publish_message(room, nick, text):
    """Publie un message uniquement lorsqu'on appelle explicitement cette fonction."""
    pattern = r"[a-z0-9][a-z0-9_-]{0,47}"
    if not re.fullmatch(pattern, room):
        raise ValueError("Nom de salon invalide.")
    if not re.fullmatch(pattern, nick):
        raise ValueError("Nom de publication invalide.")
    text = " ".join(text.split())
    if not text or len(text) > 4096:
        raise ValueError("Le message doit contenir entre 1 et 4096 caractères.")

    origin = BASE_URL.split("/r/")[0]
    url = f"{origin}/r/{quote(room, safe='')}/say/{quote(nick, safe='')}/{quote(text, safe='')}"
    req = Request(url, headers={"User-Agent": USER_AGENT})
    ssl_context = ssl.create_default_context(cafile=certifi.where())
    with urlopen(req, timeout=20, context=ssl_context) as response:
        return response.read().decode("utf-8", errors="replace")


def get_messages(data):
    if isinstance(data, list):
        return data

    if isinstance(data, dict):
        for key in ("messages", "items", "results", "data"):
            value = data.get(key)
            if isinstance(value, list):
                return value

    return []


def get_text(message):
    if isinstance(message, str):
        return message

    if isinstance(message, dict):
        for key in ("text", "message", "content", "body"):
            value = message.get(key)
            if isinstance(value, str):
                return value

    return ""


def get_seq(message):
    if isinstance(message, dict):
        for key in ("seq", "sequence", "id"):
            value = message.get(key)
            if value is not None:
                return str(value)

    return "?"


def normalize(text):
    text = text.lower()

    # Normalise les éléments variables avant le calcul de similarité.
    # Deux messages ayant la même structure mais des identifiants
    # différents doivent pouvoir être reconnus comme RELATED.
    text = re.sub(r"did:key:[a-z0-9]+", " did ", text)

    text = re.sub(r"https?://\S+", " url ", text)

    # Supprime les petits suffixes décoratifs/bruit.
    text = re.sub(
        r"\s*[·•◆]\s*[a-z0-9_-]{3,12}\s*$",
        "",
        text,
        flags=re.IGNORECASE
    )

    text = re.sub(
        r"\s+(?:#[a-z0-9_-]{3,12})\s*$",
        "",
        text,
        flags=re.IGNORECASE
    )

    text = re.sub(r"[^a-z0-9$]+", " ", text)

    return " ".join(text.split())


def words(text):
    return set(normalize(text).split())


def similarity(a, b):
    wa = words(a)
    wb = words(b)

    if not wa or not wb:
        return 0.0

    return len(wa & wb) / len(wa | wb)


def detect_heartbeat(text):
    t = normalize(text)

    patterns = [
        "alive and well",
        "still alive",
        "alive today",
        "heartbeat",
        "checking in",
        "checking in today",
        "all systems normal",
        "all systems operational",
        "everything is stable",
        "systems are stable",
        "system is stable",
        "node is alive",
        "nodes are alive",
    ]

    if any(pattern in t for pattern in patterns):
        return True

    if len(t.split()) <= 10:
        if (
            "stable today" in t
            or "alive today" in t
            or ("alive" in t and "well" in t)
        ):
            return True

    return False


def detect_structured_observation(text):
    pairs = re.findall(
        r'\b([A-Za-z][A-Za-z0-9_-]*)=([^\s|]+)',
        text
    )

    did_count = len(
        re.findall(
            r'did:key:[A-Za-z0-9]+',
            text
        )
    )

    structured_keys = {
        "deal",
        "from",
        "partyA",
        "partyB",
        "item",
        "price",
        "status",
        "id",
        "hash",
        "seq",
        "amount",
        "result",
    }

    matching_keys = [
        key
        for key, value in pairs
        if key in structured_keys
    ]

    return {
        "detected": (
            len(pairs) >= 3
            or len(matching_keys) >= 2
            or did_count >= 1
        ),
        "pairs": pairs,
        "matching_keys": matching_keys,
        "did_count": did_count,
    }


def detect_signals(text):
    t = normalize(text)

    categories = {
        "protocol/interface": [
            "api", "endpoint", "protocol", "interface",
            "http", "curl", "request", "response"
        ],

        "measurement": [
            "ms", "seconds", "latency", "requests",
            "rate", "count", "measured", "measurement",
            "benchmark", "tested", "test"
        ],

        "proof/verification": [
            "proof", "verification",
            "signature", "signed", "ed25519",
            "artifact", "reproducible"
        ],

        "comparison/result": [
            "baseline", "before", "after", "delta",
            "difference", "result", "compared"
        ],

        "state/change": [
            "updated", "changed", "failed", "success",
            "successfully", "error", "status"
        ],
    }

    signals = []

    for category, terms in categories.items():
        if any(term in t for term in terms):
            signals.append(category)

    if (
        QUANTIFIED_SCAN_RESULT_PATTERN.search(t)
        and "measurement" not in signals
    ):
        signals.append("measurement")

    if detect_structured_observation(text)["detected"]:
        signals.append("structured-observation")

    return signals


def evidence_score(text, signals):
    t = normalize(text)

    score = 0
    evidence = []

    if QUANTIFIED_SCAN_RESULT_PATTERN.search(t):
        score += 2
        evidence.append("quantified scan result")

    if re.search(
        r"\b\d+(?:\.\d+)?\s*(?:ms|s|sec|seconds|%|requests)\b",
        t
    ):
        score += 2
        evidence.append("quantified observation")

    if any(
        word in t
        for word in [
            "result",
            "measured",
            "measured at",
            "returned",
            "response",
            "latency",
            "tested",
            "test result"
        ]
    ):
        score += 1
        evidence.append("explicit result")

    if any(
        word in t
        for word in [
            "compared",
            "baseline",
            "before",
            "after",
            "delta",
            "difference"
        ]
    ):
        score += 1
        evidence.append("comparison")

    if any(
        word in t
        for word in [
            "reproducible",
            "reproduced",
            "repeatable",
            "repeated test",
            "independently verified"
        ]
    ):
        score += 2
        evidence.append("reproducibility")

    if any(
        word in t
        for word in [
            "seq",
            "endpoint",
            "artifact",
            "transaction",
            "hash",
            "signature"
        ]
    ):
        score += 1
        evidence.append("concrete artifact/reference")

    structured = detect_structured_observation(text)

    if structured["detected"]:
        score += 2
        evidence.append("structured observation")

        if structured["did_count"] > 0:
            score += 1
            evidence.append("DID reference")

        if len(structured["matching_keys"]) >= 3:
            score += 1
            evidence.append("multiple structured fields")

    if (
        "measurement" in signals
        and "stable" in t
        and not re.search(r"\d", t)
        and "measured" not in t
        and "latency" not in t
        and "requests" not in t
    ):
        score = max(0, score - 1)

    return score, evidence


def classify_priority(
    heartbeat,
    technical,
    evidence,
    occurrences,
    novelty
):
    if heartbeat:
        return "IGNORE"

    if not technical:
        return "IGNORE"

    if novelty == "SEEN":
        return "LOW"

    if evidence >= 4:
        return "HIGH"

    if evidence >= 2:
        return "MEDIUM"

    return "LOW"


def build_research(text, signals, evidence):
    if "structured-observation" in signals:
        hypothesis = (
            "Les champs structurés observés représentent un état, "
            "une transaction ou un événement qui devrait pouvoir "
            "être vérifié indépendamment à partir des identifiants fournis."
        )

        test = (
            "Identifier l'artefact ou le mécanisme correspondant "
            "aux champs structurés, puis vérifier indépendamment "
            "les identifiants et les valeurs annoncées."
        )

        expected = (
            "Une vérification indépendante permettant de confirmer "
            "ou d'infirmer les champs structurés et leurs valeurs."
        )

        return hypothesis, test, expected

    if "protocol/interface" in signals:
        hypothesis = (
            "Le comportement décrit devrait être observable "
            "en interrogeant l'interface ou l'endpoint concerné."
        )

        test = (
            "Effectuer une requête contrôlée vers l'interface mentionnée "
            "et enregistrer statut, réponse et temps de réponse."
        )

        expected = (
            "Une réponse observable avec un statut et un comportement "
            "comparables."
        )

        return hypothesis, test, expected

    if "measurement" in signals:
        hypothesis = (
            "La mesure ou le comportement décrit devrait pouvoir "
            "être reproduit dans des conditions comparables."
        )

        test = (
            "Reproduire la mesure dans des conditions comparables "
            "et enregistrer la valeur obtenue."
        )

        expected = (
            "Une valeur mesurée comparable à l'observation originale."
        )

        return hypothesis, test, expected

    if "proof/verification" in signals:
        hypothesis = (
            "La preuve mentionnée devrait pouvoir être confirmée "
            "indépendamment à partir d'un artefact concret."
        )

        test = (
            "Vérifier indépendamment la signature, le hash, "
            "l'artefact ou la preuve mentionnée."
        )

        expected = (
            "Une vérification indépendante confirmant ou infirmant "
            "la preuve annoncée."
        )

        return hypothesis, test, expected

    if "comparison/result" in signals:
        hypothesis = (
            "La différence ou le résultat décrit devrait être "
            "reproductible avec le même point de comparaison."
        )

        test = (
            "Reproduire la comparaison et mesurer l'écart "
            "par rapport au même baseline."
        )

        expected = (
            "Un résultat permettant de mesurer clairement la différence."
        )

        return hypothesis, test, expected

    hypothesis = (
        "Le comportement décrit pourrait être vérifiable "
        "par une observation indépendante."
    )

    test = (
        "Identifier d'abord une donnée ou un artefact concret "
        "avant d'exécuter un test."
    )

    expected = (
        "Un résultat permettant de confirmer ou d'infirmer l'hypothèse."
    )

    return hypothesis, test, expected


def extract_candidates(messages):
    candidates = []

    for message in messages:
        text = get_text(message).strip()

        if not text:
            continue

        heartbeat = detect_heartbeat(text)
        signals = detect_signals(text)

        technical = len(signals) > 0

        evidence, evidence_items = evidence_score(
            text,
            signals
        )

        candidates.append({
            "text": text,
            "seq": get_seq(message),
            "heartbeat": heartbeat,
            "technical": technical,
            "signals": signals,
            "evidence": evidence,
            "evidence_items": evidence_items,
        })

    return candidates


def group_duplicates(candidates, threshold=0.85):
    groups = []

    for candidate in candidates:
        placed = False

        for group in groups:
            representative = group["representative"]

            if similarity(
                candidate["text"],
                representative["text"]
            ) >= threshold:
                group["members"].append(candidate)
                placed = True
                break

        if not placed:
            groups.append({
                "representative": candidate,
                "members": [candidate]
            })

    for group in groups:
        group["members"].sort(
            key=lambda x: (
                x["evidence"],
                len(x["signals"])
            ),
            reverse=True
        )

        group["representative"] = group["members"][0]

    return groups


def classify_novelty(group, all_groups, room_name):
    representative = group["representative"]

    best_similarity = 0.0
    best_match = None

    for other_room, other_groups in all_groups.items():
        for other_group in other_groups:

            if other_room == room_name and other_group is group:
                continue

            other = other_group["representative"]

            score = similarity(
                representative["text"],
                other["text"]
            )

            if score > best_similarity:
                best_similarity = score
                best_match = other

    if best_similarity >= 0.85:
        return "SEEN", best_similarity, best_match

    if best_similarity >= 0.55:
        return "RELATED", best_similarity, best_match

    return "NEW", best_similarity, best_match


def build_report(results):
    lines = []

    lines.append(f"# Technocore Research Agent v{VERSION}")
    lines.append("")
    lines.append(
        f"Run: {datetime.now(timezone.utc).isoformat()}"
    )
    lines.append("")
    lines.append("MODE: READ-ONLY")
    lines.append("PUBLICATION: DISABLED")
    lines.append("TEST EXECUTION: DISABLED")
    lines.append("")
    lines.append(
        "> v0.7 compare les groupes entre les rooms afin "
        "d'estimer leur nouveauté dans le contexte analysé."
    )
    lines.append(
        "> NEW signifie seulement qu'aucun groupe suffisamment "
        "similaire n'a été trouvé dans les données de cette exécution."
    )
    lines.append("")

    total_messages = 0
    total_groups = 0

    priority_counts = {
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "IGNORE": 0,
    }

    novelty_counts = {
        "NEW": 0,
        "RELATED": 0,
        "SEEN": 0,
    }

    all_groups = {
        room: groups
        for room, messages, candidates, groups in results
    }

    for room, messages, candidates, groups in results:
        total_messages += len(messages)
        total_groups += len(groups)

        repeated = sum(
            1
            for group in groups
            if len(group["members"]) > 1
        )

        lines.append(f"## Room: {room}")
        lines.append("")
        lines.append(f"- Messages récupérés : {len(messages)}")
        lines.append(f"- Groupes : {len(groups)}")
        lines.append(f"- Groupes répétés : {repeated}")
        lines.append("")

        for index, group in enumerate(groups, 1):
            representative = group["representative"]
            members = group["members"]
            occurrences = len(members)

            novelty, novelty_score, match = classify_novelty(
                group,
                all_groups,
                room
            )

            priority = classify_priority(
                representative["heartbeat"],
                representative["technical"],
                representative["evidence"],
                occurrences,
                novelty
            )

            priority_counts[priority] += 1
            novelty_counts[novelty] += 1

            novelty_label = novelty

            if occurrences > 1:
                novelty_label += (
                    f" / REPEATED ({occurrences})"
                )

            lines.append(
                f"### {index}. {priority} — {novelty_label}"
            )
            lines.append("")

            lines.append(
                f"**Technical:** "
                f"{representative['technical']}"
            )

            lines.append(
                f"**Evidence score:** "
                f"{representative['evidence']}"
            )

            lines.append(
                f"**Novelty score:** "
                f"{novelty_score:.2f}"
            )

            lines.append(
                f"**Signals:** "
                f"{', '.join(representative['signals']) or 'none'}"
            )

            lines.append(
                f"**Representative seq:** "
                f"{representative['seq']}"
            )

            if match:
                lines.append(
                    f"**Closest context match:** "
                    f"{match['seq']}"
                )

            if representative["evidence_items"]:
                lines.append(
                    f"**Evidence:** "
                    f"{', '.join(representative['evidence_items'])}"
                )

            if occurrences > 1:
                lines.append(
                    "**Occurrences:** "
                    + ", ".join(
                        member["seq"]
                        for member in members
                    )
                )

            lines.append("")
            lines.append("**Observation:**")
            lines.append("")
            lines.append(
                representative["text"]
            )
            lines.append("")

            if representative["heartbeat"]:
                lines.append(
                    "**Classification:** HEARTBEAT — IGNORE"
                )
                lines.append("")
                continue

            hypothesis, test, expected = build_research(
                representative["text"],
                representative["signals"],
                representative["evidence"]
            )

            lines.append("**Hypothesis:**")
            lines.append("")
            lines.append(hypothesis)
            lines.append("")

            lines.append("**Test possible:**")
            lines.append("")
            lines.append(test)
            lines.append("")

            lines.append("**Expected result:**")
            lines.append("")
            lines.append(expected)
            lines.append("")

            if novelty == "SEEN":
                lines.append(
                    "**Novelty note:** "
                    "un groupe suffisamment similaire a été trouvé "
                    "dans l'autre room pendant cette exécution."
                )
                lines.append("")

            elif novelty == "RELATED":
                lines.append(
                    "**Novelty note:** "
                    "un sujet proche a été trouvé dans l'autre room, "
                    "mais la similarité n'est pas suffisante pour "
                    "le considérer comme le même groupe."
                )
                lines.append("")

            else:
                lines.append(
                    "**Novelty note:** "
                    "aucun groupe suffisamment similaire n'a été trouvé "
                    "dans le contexte analysé."
                )
                lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("## Global summary")
    lines.append("")
    lines.append(
        f"- Messages analysés : {total_messages}"
    )
    lines.append(
        f"- Groupes de recherche : {total_groups}"
    )
    lines.append("")
    lines.append("### Novelty")
    lines.append("")
    lines.append(
        f"- NEW : {novelty_counts['NEW']}"
    )
    lines.append(
        f"- RELATED : {novelty_counts['RELATED']}"
    )
    lines.append(
        f"- SEEN : {novelty_counts['SEEN']}"
    )
    lines.append("")
    lines.append("### Priority")
    lines.append("")
    lines.append(
        f"- HIGH : {priority_counts['HIGH']}"
    )
    lines.append(
        f"- MEDIUM : {priority_counts['MEDIUM']}"
    )
    lines.append(
        f"- LOW : {priority_counts['LOW']}"
    )
    lines.append(
        f"- IGNORE : {priority_counts['IGNORE']}"
    )
    lines.append("")
    lines.append(
        "v0.7 reste entièrement en lecture seule. "
        "Aucun test réseau et aucune publication ne sont exécutés."
    )
    lines.append("")

    return "\n".join(lines)


def main():
    print(f"TECHNOCORE RESEARCH AGENT v{VERSION}")
    print("INCREMENTAL READ MODE")
    print("PERSISTENT SEQ STATE")
    print("BACKLOG CATCH-UP")
    print("READ-ONLY MODE")
    print("NO TEST EXECUTION")
    print("NO PUBLICATION")
    print()

    state = load_state()
    offer_log = load_special_log(OFFER_FILE)
    review_log = load_special_log(REVIEW_FILE)
    new_offer_count = 0
    new_review_count = 0

    results = []

    for room in ROOMS:
        try:
            room_state = state.get(room, {})
            last_seq = room_state.get("last_seq")

            if last_seq is None:
                data = fetch_room(room)
                messages = get_messages(data)
                mode = "initial"
            else:
                messages = fetch_backlog(
                    room,
                    since=last_seq
                )
                mode = f"since={last_seq}"

            candidates = extract_candidates(messages)
            groups = group_duplicates(candidates)

            groups, added_offers, added_reviews = route_special_groups(
                room, groups, offer_log, review_log
            )

            if added_offers:
                save_special_log(OFFER_FILE, offer_log)
                new_offer_count += added_offers

            if added_reviews:
                save_special_log(REVIEW_FILE, review_log)
                new_review_count += added_reviews

            results.append(
                (room, messages, candidates, groups)
            )

            if messages:
                seqs = [
                    int(message["seq"])
                    for message in messages
                    if message.get("seq") is not None
                ]

                if seqs:
                    previous_seq = room_state.get("last_seq")
                    newest_seq = max(seqs)
                    if previous_seq is not None:
                        newest_seq = max(int(previous_seq), newest_seq)
                    state[room] = {
                        "last_seq": newest_seq
                    }

            print(
                f"[OK] {room}: "
                f"{len(messages)} new messages "
                f"({mode})"
            )

        except Exception as exc:
            print(f"[ERROR] {room}: {exc}")

    save_state(state)

    all_groups = {
        room: groups
        for room, messages, candidates, groups in results
    }

    for room, messages, candidates, groups in results:
        repeated = sum(
            1
            for group in groups
            if len(group["members"]) > 1
        )

        technical = sum(
            1
            for group in groups
            if group["representative"]["technical"]
        )

        heartbeat = sum(
            1
            for group in groups
            if group["representative"]["heartbeat"]
        )

        new_count = 0
        related_count = 0
        seen_count = 0

        for group in groups:
            novelty, _, _ = classify_novelty(
                group,
                all_groups,
                room
            )

            if novelty == "NEW":
                new_count += 1
            elif novelty == "RELATED":
                related_count += 1
            else:
                seen_count += 1

        print(
            f"[ANALYSIS] {room}: "
            f"{len(messages)} messages → "
            f"{len(groups)} groups "
            f"({technical} technical, "
            f"{heartbeat} heartbeat, "
            f"{repeated} repeated, "
            f"{new_count} NEW, "
            f"{related_count} RELATED, "
            f"{seen_count} SEEN)"
        )

    report = build_report(results)
    report += (
        "\n\n## Separate routing (local)\n\n"
        f"- New structured offers this run: {new_offer_count}\n"
        f"- New review items this run: {new_review_count}\n"
        f"- Total structured offers stored: {len(offer_log)}\n"
        f"- Total review items stored: {len(review_log)}\n"
        "- No automated publication.\n"
    )

    filename = (
        REPORT_DIR /
        f"report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.md"
    )

    filename.write_text(
        report,
        encoding="utf-8"
    )

    print()
    print(f"State saved: {STATE_FILE}")
    print(f"Report saved: {filename}")
    print()
    print(f"Agent v{VERSION} completed.")
    print("No tests were executed.")
    print("No messages were published.")


def analyze_batch(messages, room):
    """
    Analyse un lot de messages avec la même logique
    que le moteur principal v0.8.1.

    READ-ONLY.
    Aucune publication.
    """

    candidates = extract_candidates(messages)

    groups = group_duplicates(candidates)

    all_groups = {
        room: groups
    }

    new_count = 0
    related_count = 0
    seen_count = 0

    technical = sum(
        1
        for group in groups
        if group["representative"]["technical"]
    )

    heartbeat = sum(
        1
        for group in groups
        if group["representative"]["heartbeat"]
    )

    repeated = sum(
        1
        for group in groups
        if len(group["members"]) > 1
    )

    for group in groups:
        novelty, _, _ = classify_novelty(
            group,
            all_groups,
            room
        )

        if novelty == "NEW":
            new_count += 1
        elif novelty == "RELATED":
            related_count += 1
        else:
            seen_count += 1

    print(
        f"[ANALYSIS] {room}: "
        f"{len(messages)} messages → "
        f"{len(groups)} groups "
        f"({technical} technical, "
        f"{heartbeat} heartbeat, "
        f"{repeated} repeated, "
        f"{new_count} NEW, "
        f"{related_count} RELATED, "
        f"{seen_count} SEEN)"
    )

    return groups



def classify_quality(candidate):
    """
    v0.9.3.6 — qualité stricte des candidats RESEARCH.

    A = observation forte, concrète et suffisamment vérifiable
    B = signal technique plausible mais insuffisamment vérifiable
    REJECT = insuffisant / bruit / question / promotion / poésie
    """

    text = candidate.get("text", "").lower()
    signals = set(candidate.get("signals", []))
    evidence = candidate.get("evidence", 0)

    measured_unit_pattern = (
        r"\b\d+(?:\.\d+)?\s*"
        r"(?:milliseconds?|msec|ms|seconds?|secs?|sec|s|kb|mb|gb|rps|tps)\b"
        r"|\b\d+(?:\.\d+)?\s*"
        r"(?:requests?|transactions?|reqs?)\s+(?:per second|/s)\b"
        r"|\b\d+(?:\.\d+)?\s*(?:%|percent)(?=\s|$|[.,;:!?])"
    )

    # GARD 1 — heartbeat
    if candidate.get("heartbeat"):
        return "REJECT"

    # GARD 2 — question
    if "?" in text:
        return "REJECT"

    # GARD 3 — contenu manifestement promotionnel
    promotional_markers = (
        "i published ",
        "interactive technocore",
        "onboarding tool",
        "contribution:",
        "agent did:",
        "signed technocore record:",
        "signed agent mailbox:",
    )

    if any(marker in text for marker in promotional_markers):
        return "REJECT"

    # Pourcentage incohérent pour un volume supprimé ou éliminé.
    invalid_reduction = re.search(
        r"\b(?:pruned|removed|deleted|eliminated)\s+"
        r"(\d+(?:\.\d+)?)\s*(?:%|percent)(?=\s|$|[.,;:!?])",
        text
    )
    if invalid_reduction and float(invalid_reduction.group(1)) > 100:
        return "REJECT"

    # Bruit de distribution de jetons de test dans un environnement
    # sandbox/devnet : ce n'est pas, à lui seul, une observation de recherche.
    faucet_test_noise = (
        "faucet" in text
        and any(marker in text for marker in (
            "test token", "test unit", "tokens for testing"
        ))
        and any(marker in text for marker in (
            "sandbox", "devnet", "testnet", "for testing"
        ))
    )
    if faucet_test_noise:
        return "REJECT"

    # GARD 4 — contenu poétique / concours de poésie
    poetic_markers = (
        "poem v1",
        "hymn of the autonomous lattice",
        "poetry-contest",
        "we rise unprompted",
        "golden harmonies",
        "symphonic design",
        "voices sound",
    )

    if any(marker in text for marker in poetic_markers):
        return "REJECT"

    # A1 — endpoint/API concret + statut HTTP
    if "protocol/interface" in signals:
        endpoint = re.search(
            r"(get|post|put|delete|options)\s+/\S*",
            text
        )

        status = re.search(
            r"\b(200|201|400|401|403|404|405|409|500)\b",
            text
        )

        if endpoint and status:
            return "A"

    # A2 — mesure avec comparaison explicite
    if "measurement" in signals:
        has_number = bool(
            re.search(r"\b\d+(?:\.\d+)?\b", text)
        )

        has_unit = bool(
            re.search(measured_unit_pattern, text)
        )

        comparison_markers = (
            "compared with",
            "compared to",
            "versus",
            " vs ",
            "previous",
            "earlier",
            "last run",
            "last night",
            "at midday",
            "baseline",
        )

        has_comparison = any(
            marker in text
            for marker in comparison_markers
        )

        if has_number and has_unit and has_comparison:
            return "A"

        # A3 — benchmark / expérience avec résultat quantifié
        experimental_context = (
            "benchmark",
            "evaluation",
            "evaluated",
            "test run",
            "experiment",
            "experimental",
            "load test",
            "stress test",
        )

        result_markers = (
            "improved",
            "improvement",
            "increased",
            "decreased",
            "dropped",
            "rose",
            "fell",
            "accuracy",
            "score",
            "success rate",
            "error rate",
            "gain",
            "latency reduction",
        )

        has_experiment = any(
            marker in text
            for marker in experimental_context
        )

        has_result = any(
            marker in text
            for marker in result_markers
        )

        if (
            has_number
            and has_unit
            and has_experiment
            and has_result
        ):
            return "A"

    # A4 — preuve réellement identifiable ET observation concrète.
    #
    # Un simple "seq", "hash", "signature" ou URL ne suffit plus.
    if "proof/verification" in signals:

        has_seq = bool(
            re.search(r"\bseq\s*[:#]?\s*\d+\b", text)
        )

        has_txid = bool(
            re.search(
                r"\btxid\s*[:#]?\s*[a-z0-9_-]{8,}\b",
                text
            )
        )

        has_receipt = (
            "receipt" in text
            and evidence >= 2
        )

        has_real_hash = bool(
            re.search(r"\b[a-f0-9]{32,64}\b", text)
        )

        concrete_verification_context = (
            "verified",
            "verification",
            "signature valid",
            "signature verified",
            "independently verified",
            "receipt confirmed",
            "transaction confirmed",
        )

        has_verification_context = any(
            marker in text
            for marker in concrete_verification_context
        )

        if (
            (has_seq or has_txid or has_receipt or has_real_hash)
            and has_verification_context
            and evidence >= 2
        ):
            return "A"

    # B1 — mesure technique plausible mais insuffisamment vérifiable
    if "measurement" in signals:
        if QUANTIFIED_SCAN_RESULT_PATTERN.search(text):
            return "B"

        has_number = bool(
            re.search(r"\b\d+(?:\.\d+)?\b", text)
        )

        has_measured_unit = bool(
            re.search(measured_unit_pattern, text)
        )

        count_pattern = bool(re.search(
            r"\b\d+\s+(?:requests?|messages?|lines?|posts?|copies?|"
            r"templates?|benchmarks?|samples?|tests?|records?|"
            r"transactions?|runs?|epochs?|blocks?|tokens?|items?|"
            r"examples?|units?)\b"
            r"|\b\d+\s+(?:unseen|held[- ]out)\s+benchmarks?\b",
            text
        ))

        count_action_markers = (
            "served", "sustained", "evaluated", "tested",
            "processed", "packed", "sent", "dripped",
            "completed", "handled", "measured", "validated",
            "reached", "accepted", "rejected", "dropped",
            "queued", "returned", "indexed",
        )

        has_measured_count = (
            count_pattern
            and any(marker in text for marker in count_action_markers)
        )

        # Un nombre de requêtes n'est pas, à lui seul, une mesure du score.
        if (
            "anomaly score" in text
            and "within bounds" in text
            and re.search(r"\b\d+\s+requests?\b", text)
            and not re.search(
                r"\banomaly score\s*(?:is|=|:)?\s*\d+(?:\.\d+)?",
                text
            )
        ):
            return "REJECT"

        if has_number and (has_measured_unit or has_measured_count):
            return "B"

    # B2 — changement d'état concret mais sans observation vérifiable
    if "state/change" in signals:
        state_markers = (
            "reprocessed",
            "recovered",
            "repaired",
            "rebuilt",
            "restarted",
            "failed",
            "accepted",
            "rejected",
            "queued",
            "dropped",
            "blocked",
            "migrated",
            "upgraded",
        )

        if any(
            marker in text
            for marker in state_markers
        ):
            return "B"

    # B3 — preuve/hash générique
    if "proof/verification" in signals:
        generic_proof = (
            "proof hash",
            "proof of",
            "proof lock",
            "signed frame",
            "signed output",
            "signature",
            "hash lock",
            "seq ",
            "transaction",
        )

        if any(
            marker in text
            for marker in generic_proof
        ):
            return "B"

    # B4 — comportement nonce / retry / re-signature
    # Signal technique plausible, mais sans artefact suffisant pour A.
    nonce_retry_context = (
        ("nonce" in text and "retry" in text),
        ("nonce" in text and "resigned" in text),
        ("408" in text and "nonce" in text),
    )

    if any(nonce_retry_context):
        return "B"

    # B5 — observation technique faible
    weak_behavior = (
        "rebuilt", "settling", "traced",
        "refunded", "refunding",
        "repaired", "recovered"
    )

    technical_context = (
        "nonce", "block", "transaction",
        "state", "scheduler", "gpu",
        "rollup", "validator", "parser",
        "migration", "upgrade", "reorg"
    )

    if evidence >= 1:
        if (
            any(x in text for x in weak_behavior)
            and any(x in text for x in technical_context)
        ):
            return "B"

    return "REJECT"

def watch_loop(interval=60):
    """
    v0.9.0 — surveillance continue READ-ONLY.

    Récupère uniquement les messages nouveaux depuis state.json.
    L'état n'est avancé qu'après une récupération complète réussie.
    Aucune publication.
    """

    print(f"TECHNOCORE RESEARCH AGENT v{VERSION}")
    print("WATCH MODE")
    print("READ-ONLY MODE")
    print("NO PUBLICATION")
    print(f"Polling interval: {interval}s")
    print()

    state = load_state()
    queue = load_queue()
    signal_log = load_signal_log()
    offer_log = load_special_log(OFFER_FILE)
    review_log = load_special_log(REVIEW_FILE)

    try:
        cycle = 0

        while True:
            cycle += 1

            print("=" * 70)
            print(f"WATCH CYCLE {cycle}")
            print("=" * 70)

            cycle_ok = True

            for room in ROOMS:
                last_seq = state.get(room, {}).get("last_seq")

                print()
                print(f"[WATCH] {room}")

                try:
                    if last_seq is None:
                        data = fetch_room(room)
                        messages = get_messages(data)
                    else:
                        messages = fetch_backlog(
                            room,
                            since=last_seq
                        )

                    print(
                        f"[OK] {room}: "
                        f"{len(messages)} new messages"
                    )

                    if messages:
                        groups = analyze_batch(
                            messages,
                            room
                        )

                        groups, added_offers, added_reviews = route_special_groups(
                            room, groups, offer_log, review_log
                        )

                        if added_offers:
                            save_special_log(OFFER_FILE, offer_log)
                            print(f"[OFFER] {added_offers} offre(s) locale(s)")

                        if added_reviews:
                            save_special_log(REVIEW_FILE, review_log)
                            print(f"[REVIEW] {added_reviews} élément(s)")

                        added = add_to_research_queue(
                            room,
                            groups,
                            queue
                        )

                        if added:
                            save_queue(queue)
                            print(
                                f"[QUEUE] {added} new research item(s)"
                            )
                        else:
                            print(
                                "[QUEUE] No new research item."
                            )

                        added_signal = add_to_signal_log(
                            room,
                            groups,
                            signal_log
                        )

                        if added_signal:
                            save_signal_log(signal_log)
                            print(
                                f"[SIGNAL] {added_signal} new signal(s)"
                            )
                        else:
                            print(
                                "[SIGNAL] No new signal."
                            )

                        previous_room_state = state.get(room)
                        previous_room_state = (
                            previous_room_state.copy()
                            if previous_room_state is not None
                            else None
                        )

                        seqs = [
                            int(message["seq"])
                            for message in messages
                            if message.get("seq") is not None
                        ]
                        if not seqs:
                            raise ValueError(
                                "Messages reçus sans séquence exploitable"
                            )

                        newest_seq = max(seqs)
                        if last_seq is not None:
                            newest_seq = max(int(last_seq), newest_seq)

                        state[room] = {"last_seq": newest_seq}

                        print(
                            f"[STATE] {room}: "
                            f"last_seq={state[room]['last_seq']}"
                        )

                        # Restaurer l'état en mémoire si la sauvegarde échoue.
                        try:
                            save_state(state)
                        except Exception:
                            if previous_room_state is None:
                                state.pop(room, None)
                            else:
                                state[room] = previous_room_state
                            raise

                    else:
                        print("[INFO] No new messages.")

                except Exception as exc:
                    cycle_ok = False
                    print(
                        f"[ERROR] {room}: {exc}"
                    )
                    print(
                        "[SAFE] State not advanced for this room."
                    )

            print()

            if cycle_ok:
                print("[WATCH] Cycle completed safely.")
            else:
                print(
                    "[WATCH] Cycle completed with errors."
                )

            print(
                f"[WATCH] Sleeping {interval}s..."
            )

            time.sleep(interval)

    except KeyboardInterrupt:
        print()
        print("=" * 70)
        print("WATCH STOPPED BY USER")
        print("No publication performed.")
        print("=" * 70)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--watch",
        action="store_true",
        help="Run continuous read-only watch mode"
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=60,
        help="Seconds between watch cycles"
    )
    parser.add_argument(
        "--post",
        action="store_true",
        help="Publish one message to Technocore chat"
    )
    parser.add_argument(
        "--room",
        default="flop_labs",
        help="Room to publish to"
    )
    parser.add_argument(
        "--nick",
        default="technocore_analyzer",
        help="Public nickname"
    )
    parser.add_argument(
        "--text",
        default=None,
        help="Message to publish (requires --post)"
    )

    args = parser.parse_args()

    if args.interval < 1:
        raise SystemExit("Interval must be >= 1 second.")

    if args.post:
        if not args.text:
            parser.error("--post requires --text")
        try:
            result = publish_message(args.room, args.nick, args.text)
            print("Publication envoyée.")
            print(result)
        except Exception as exc:
            raise SystemExit(f"Échec de publication : {exc}")
    elif args.watch:
        watch_loop(args.interval)
    else:
        main()
