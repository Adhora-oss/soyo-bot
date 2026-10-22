
"""
SOYO DM Auto-Reply Bot
Facebook Messenger + Instagram Messaging API
Flask webhook; configure Meta credentials using environment variables.
"""

import os
import re
import time
import hmac
import hashlib
import logging

import requests
from flask import Flask, request, abort

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("soyo-bot")

# Use a Graph API version currently supported by your Meta app.
GRAPH_VERSION = os.environ.get("GRAPH_VERSION", "v21.0")
GRAPH_BASE = f"https://graph.facebook.com/{GRAPH_VERSION}"

VERIFY_TOKEN = os.environ.get("VERIFY_TOKEN", "")
APP_SECRET = os.environ.get("APP_SECRET", "")

# Facebook Messenger credentials
PAGE_ACCESS_TOKEN = os.environ.get("PAGE_ACCESS_TOKEN", "")

# Instagram Messaging API credentials
IG_ACCESS_TOKEN = os.environ.get("IG_ACCESS_TOKEN", "")
IG_USER_ID = os.environ.get("IG_USER_ID", "")

HANDOFF_SECONDS = 12 * 60 * 60

# In-memory only: use persistent storage for production deployments.
handoff = {}

# ---------------------------------------------------------
# SOYO BRAND MESSAGES
# ---------------------------------------------------------

GREETING = (
    "Welcome to SOYO.\n"
    "Thoughtfully curated for your everyday.\n\n"
    "How may we assist you today?"
)

ANSWERS = {
    "shipping": (
        "SOYO | Delivery Information\n\n"
        "Delivery availability, charges and estimated arrival "
        "depend on your location and order.\n"
        "Please share your area with us for delivery details."
    ),
    "returns": (
        "SOYO | Returns & Exchanges\n\n"
        "Need help with an item? Please message us with your "
        "order number, if applicable, and a brief description "
        "of the issue. Our team will guide you through the "
        "applicable policy."
    ),
    "payment": (
        "SOYO | Orders & Payments\n\n"
        "For current prices, available payment methods, offers "
        "or order changes, please message our team. We will "
        "confirm the details before you proceed."
    ),
    "human": (
        "Of course. Our SOYO team is here to help.\n\n"
        "Please leave your message and order number, if "
        "applicable. A team member will respond as soon as "
        "possible during our support hours."
    ),
}

KEYWORDS = {
    "human": [
        "human", "live agent", "talk to a person",
        "real person", "customer service", "representative",
        "complaint", "speak to someone",
    ],
    "returns": [
        "return", "refund", "exchange", "damaged",
        "broken", "wrong item", "defective", "money back",
    ],
    "shipping": [
        "shipping", "delivery", "deliver", "tracking",
        "track order", "where is my order", "arrived",
        "parcel", "courier", "delivery charge",
    ],
    "payment": [
        "payment", "pay", "card", "bkash", "nagad",
        "discount", "coupon", "promo code", "offer",
        "cancel order", "change order", "price",
    ],
}

MENU = [
    ("Delivery", "shipping"),
    ("Returns & Exchanges", "returns"),
    ("Orders & Payments", "payment"),
    ("Talk to our team", "human"),
]

FALLBACK = (
    "Thank you for contacting SOYO.\n"
    "Please choose a topic below, or type "
    "'Talk to our team' for personal assistance."
)


# ---------------------------------------------------------
# MESSAGE HELPERS
# ---------------------------------------------------------

def quick_replies():
    return [
        {
            "content_type": "text",
            "title": title,
            "payload": f"SOYO_{key.upper()}",
        }
        for title, key in MENU
    ]


def normalize_payload(payload):
    if not payload:
        return None

    value = payload.upper()
    if value.startswith("SOYO_"):
        value = value[5:]

    key = value.lower()
    return key if key in ANSWERS else None


def match_topic(text):
    text = (text or "").lower().strip()

    # Prefer the longest matching phrase within a category.
    for topic in ("human", "returns", "shipping", "payment"):
        phrases = sorted(KEYWORDS[topic], key=len, reverse=True)

        for phrase in phrases:
            pattern = r"(?<!\w)" + re.escape(phrase) + r"(?!\w)"
            if re.search(pattern, text):
                return topic

    return None


def get_endpoint(platform):
    if platform == "instagram":
        if not IG_USER_ID or not IG_ACCESS_TOKEN:
            raise RuntimeError("Instagram credentials are missing.")
        return f"{GRAPH_BASE}/{IG_USER_ID}/messages", IG_ACCESS_TOKEN

    if not PAGE_ACCESS_TOKEN:
        raise RuntimeError("Facebook Page access token is missing.")

    return f"{GRAPH_BASE}/me/messages", PAGE_ACCESS_TOKEN


def send(recipient_id, text, platform, with_menu=True):
    if not recipient_id:
        return

    endpoint, token = get_endpoint(platform)

    message = {"text": text}
    if with_menu:
        message["quick_replies"] = quick_replies()

    body = {
        "recipient": {"id": recipient_id},
        "message": message,
    }

    # Messenger uses messaging_type. Instagram's send API
    # does not require the same field.
    if platform == "facebook":
        body["messaging_type"] = "RESPONSE"

    response = requests.post(
        endpoint,
        json=body,
        headers={"Authorization": f"Bearer {token}"},
        timeout=15,
    )

    if not response.ok:
        logger.error(
            "%s send failed: HTTP %s: %s",
            platform,
            response.status_code,
            response.text[:1000],
        )
        response.raise_for_status()


# ---------------------------------------------------------
# EVENT HANDLING
# ---------------------------------------------------------

def handle_event(event, platform):
    sender = event.get("sender", {}).get("id")
    if not sender:
        return

    message = event.get("message", {})

    # Ignore messages sent by the page/account itself.
    if message.get("is_echo"):
        return

    # Ignore delivery/read notifications and non-message events.
    if not message and not event.get("postback"):
        return

    now = time.time()
    started = handoff.get((platform, sender))

    if started is not None:
        if now - started < HANDOFF_SECONDS:
            return
        handoff.pop((platform, sender), None)

    payload = (
        message.get("quick_reply", {}).get("payload")
        or event.get("postback", {}).get("payload")
    )
    topic = normalize_payload(payload)

    text = message.get("text", "").strip()
    if not topic:
        topic = match_topic(text)

    if topic == "human":
        handoff[(platform, sender)] = now
        send(sender, ANSWERS["human"], platform, with_menu=False)

    elif topic:
        send(sender, ANSWERS[topic], platform)

    elif text:
        # Unknown messages get a helpful, brand-consistent response.
        send(sender, FALLBACK, platform)

    else:
        send(sender, GREETING, platform)


# ---------------------------------------------------------
# WEBHOOK SECURITY
# ---------------------------------------------------------

def valid_signature(raw_body):
    # Fail closed: never silently disable signature checking.
    if not APP_SECRET:
        logger.error("APP_SECRET is not configured.")
        return False

    signature = request.headers.get("X-Hub-Signature-256", "")
    if not signature.startswith("sha256="):
        return False

    expected = "sha256=" + hmac.new(
        APP_SECRET.encode("utf-8"),
        raw_body,
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(signature, expected)


# ---------------------------------------------------------
# ROUTES
# ---------------------------------------------------------

@app.route("/", methods=["GET"])
def home():
    return "SOYO messaging webhook is running.", 200


@app.route("/webhook", methods=["GET"])
def verify():
    mode = request.args.get("hub.mode")
    token = request.args.get("hub.verify_token")
    challenge = request.args.get("hub.challenge")

    if (
        mode == "subscribe"
        and VERIFY_TOKEN
        and token == VERIFY_TOKEN
        and challenge is not None
    ):
        return challenge, 200

    abort(403)


@app.route("/webhook", methods=["POST"])
def webhook():
    raw_body = request.get_data()

    if not valid_signature(raw_body):
        abort(403)

    data = request.get_json(silent=True) or {}
    obj = data.get("object")

    if obj not in ("page", "instagram"):
        return "ok", 200

    platform = "instagram" if obj == "instagram" else "facebook"

    for entry in data.get("entry", []):
        for event in entry.get("messaging", []):
            try:
                handle_event(event, platform)
            except Exception:
                # Log details privately; don't expose tokens to customers.
                logger.exception("Failed to process %s event", platform)

    return "ok", 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port)

SOYO DM auto-reply bot (Facebook Messenger + Instagram DMs)
Free to run. Edit the ANSWERS section below with your real info.
"""
import os
import re
import time
import hmac
import hashlib
import requests
from flask import Flask, request, abort

app = Flask(__name__)

VERIFY_TOKEN = os.environ.get("VERIFY_TOKEN", "")
PAGE_ACCESS_TOKEN = os.environ.get("PAGE_ACCESS_TOKEN", "")
APP_SECRET = os.environ.get("APP_SECRET", "")
GRAPH_URL = "https://graph.facebook.com/v21.0/me/messages"

# After a customer asks for a human, the bot stays quiet this long (seconds)
HANDOFF_SECONDS = 12 * 60 * 60
handoff = {}  # sender_id -> time when handoff started

# ------------------------------------------------------------------
# EDIT THESE: your answers (replace the [brackets] with real info)
# ------------------------------------------------------------------
GREETING = (
    "Hi! Thanks for reaching out to SOYO \U0001FA75\n"
    "Tap a topic below, or just type your question."
)

ANSWERS = {
    "shipping": (
        "\U0001F4E6 Shipping info:\n"
        "• We ship worldwide from our online store\n"
        "• Delivery: [X-X] days depending on your country\n"
        "• Shipping cost: [amount / free over $X], shown at checkout\n"
        "• Tracking link is emailed once your order ships\n"
        "• Order not arrived? Send us your order number \U0001FA75\n"
        "Full details: [your FAQ link]"
    ),
    "returns": (
        "\U0001F501 Returns & refunds:\n"
        "• Returns accepted within [X] days of delivery\n"
        "• Items must be unused and in original packaging\n"
        "• Damaged or wrong item? Send a photo and your order number\n"
        "• Refunds take [X] days after we receive the item\n"
        "• Start a return: [email / link]"
    ),
    "payment": (
        "\U0001F4B3 Payments & offers:\n"
        "• We accept [Visa, Mastercard, PayPal, etc.]\n"
        "• Discount codes: enter them at checkout\n"
        "• Need to change or cancel an order? Message us within [X] hours\n"
        "• Payment failed? Try another method or message us"
    ),
    "human": (
        "Of course \U0001FA75 Send us your question with your order number "
        "(if you have one) and our team will reply within [X hours]."
    ),
}

# Words that trigger each answer when a customer types freely
KEYWORDS = {
    "shipping": [
        "ship", "shipping", "delivery", "deliver", "track", "tracking",
        "arrive", "arrived", "late", "where is my order", "country", "cost",
    ],
    "returns": [
        "return", "refund", "exchange", "damaged", "broken", "wrong item",
        "wrong", "defective", "money back",
    ],
    "payment": [
        "pay", "payment", "card", "paypal", "discount", "code", "coupon",
        "promo", "offer", "cancel", "change order", "price",
    ],
    "human": [
        "human", "agent", "person", "someone", "help", "support", "talk",
        "complaint", "problem",
    ],
}

MENU = [
    ("\U0001F4E6 Shipping", "shipping"),
    ("\U0001F501 Returns", "returns"),
    ("\U0001F4B3 Payment", "payment"),
    ("\U0001F464 Talk to a person", "human"),
]

FALLBACK = (
    "Thanks for your message \U0001FA75 I'm not sure I got that. "
    "Pick a topic below, or choose 'Talk to a person'."
)


# ------------------------------------------------------------------
# Logic
# ------------------------------------------------------------------
def quick_replies():
    return [
        {"content_type": "text", "title": title, "payload": key}
        for title, key in MENU
    ]


def match_topic(text):
    text = text.lower()
    for topic, words in KEYWORDS.items():
        for w in words:
            if re.search(r"\b" + re.escape(w) + r"\b", text):
                return topic
    return None


def send(recipient_id, text, with_menu=True):
    message = {"text": text}
    if with_menu:
        message["quick_replies"] = quick_replies()
    body = {
        "recipient": {"id": recipient_id},
        "messaging_type": "RESPONSE",
        "message": message,
    }
    r = requests.post(
        GRAPH_URL,
        json=body,
        headers={"Authorization": f"Bearer {PAGE_ACCESS_TOKEN}"},
        timeout=10,
    )
    if r.status_code != 200:
        print("Send failed:", r.status_code, r.text)


def handle_event(event):
    sender = event.get("sender", {}).get("id")
    if not sender:
        return

    message = event.get("message", {})
    if message.get("is_echo"):  # our own / a human's outgoing message
        return

    # Stay quiet if a human is handling this customer
    started = handoff.get(sender)
    if started and time.time() - started < HANDOFF_SECONDS:
        return

    payload = (
        message.get("quick_reply", {}).get("payload")
        or event.get("postback", {}).get("payload")
    )
    text = message.get("text", "")

    topic = payload if payload in ANSWERS else match_topic(text)

    if topic == "human":
        handoff[sender] = time.time()
        send(sender, ANSWERS["human"], with_menu=False)
    elif topic:
        send(sender, ANSWERS[topic])
    elif text and not payload:
        # First contact or unknown text
        send(sender, GREETING if len(text) < 12 else FALLBACK)
    else:
        send(sender, GREETING)


def valid_signature(raw_body):
    if not APP_SECRET:
        return True  # skip check if not configured
    sig = request.headers.get("X-Hub-Signature-256", "")
    expected = "sha256=" + hmac.new(
        APP_SECRET.encode(), raw_body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(sig, expected)


# ------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------
@app.route("/", methods=["GET"])
def home():
    return "SOYO bot is running \U0001FA75"


@app.route("/webhook", methods=["GET"])
def verify():
    if (
        request.args.get("hub.mode") == "subscribe"
        and request.args.get("hub.verify_token") == VERIFY_TOKEN
    ):
        return request.args.get("hub.challenge", ""), 200
    abort(403)


@app.route("/webhook", methods=["POST"])
def webhook():
    if not valid_signature(request.get_data()):
        abort(403)
    data = request.get_json(silent=True) or {}
    if data.get("object") in ("page", "instagram"):
        for entry in data.get("entry", []):
            for event in entry.get("messaging", []):
                try:
                    handle_event(event)
                except Exception as e:  # never crash on one bad event
                    print("Error:", e)
    return "ok", 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
