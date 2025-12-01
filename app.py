import json
import html
import hashlib
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import quote_plus
from typing import Dict, List, Optional, Tuple

import requests
import streamlit as st
import extra_streamlit_components as stx

from config import APP_NAME, DB_PATH, DEFAULT_THEME, DEFAULT_USERS

STORE_VERSION = 5
RETIRED_USERNAMES = {"reader1", "reader2", "reader_one", "reader_two"}
RETIRED_DISPLAY_NAMES = {"Reader One", "Reader Two"}
RETIRED_DISPLAY_NAMES_LOWER = {name.lower() for name in RETIRED_DISPLAY_NAMES}
NAV_OPTIONS = ["Home", "Profile", "Discover", "Book Detail", "My Library", "Compare", "Settings"]
DEVICE_COOKIE_NAME = "booxd_device_token"
DEVICE_TOKEN_TTL_DAYS = 30
MAX_DEVICE_TOKENS_PER_USER = 5


# --- Helpers: auth & persistence ------------------------------------------------

def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    """Return a salt and hash for the given password using PBKDF2."""
    salt = salt or secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), 120_000
    ).hex()
    return salt, hashed


def verify_password(password: str, salt: str, password_hash: str) -> bool:
    _, hashed = hash_password(password, salt)
    return secrets.compare_digest(hashed, password_hash)


SHELVES = [
    ("want", "Want to Read"),
    ("reading", "Reading"),
    ("finished", "Finished"),
    ("dropped", "Dropped"),
]


def shelf_label(key: str) -> str:
    for shelf_key, label in SHELVES:
        if shelf_key == key:
            return label
    return key


def safe_key(value: str) -> str:
    return value.replace("/", "-")


def set_nav(target: str) -> None:
    """Queue a navigation change to be applied on the next run."""
    st.session_state["nav_pending"] = target


def now_ts() -> str:
    return datetime.utcnow().isoformat()


class DataStore:
    def __init__(self, path: Path, seed_users: List[Dict]):
        self.path = path
        self.seed_users = seed_users
        self.db = self._load_or_seed()

    def _load_or_seed(self) -> Dict:
        if not self.path.exists():
            self.path.parent.mkdir(parents=True, exist_ok=True)
            return self._seed()
        try:
            with self.path.open("r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            return self._seed()

        data.setdefault("users", {})
        data.setdefault("library", {})
        data.setdefault("books", {})
        data.setdefault("activities", [])
        data.setdefault("device_tokens", {})

        self._prune_retired_users(data)
        self._prune_device_tokens(data)

        # Ensure seed users exist
        for user in self.seed_users:
            username = user["username"]
            if username not in data["users"]:
                salt, pw_hash = hash_password(user["password"])
                data["users"][username] = {
                    "password_hash": pw_hash,
                    "salt": salt,
                    "display_name": user.get("display_name", username),
                    "accent": DEFAULT_THEME["accent"],
                }
            data["library"].setdefault(
                username, {"shelves": {}, "reviews": {}, "favorites": []}
            )
            data["library"][username].setdefault("favorites", [])

        self._write(data)
        return data

    def _seed(self) -> Dict:
        """Create initial database structure with seeded users."""
        data = {"users": {}, "library": {}, "books": {}, "activities": [], "device_tokens": {}}
        for user in self.seed_users:
            salt, pw_hash = hash_password(user["password"])
            username = user["username"]
            data["users"][username] = {
                "password_hash": pw_hash,
                "salt": salt,
                "display_name": user.get("display_name", username),
                "accent": DEFAULT_THEME["accent"],
            }
            data["library"][username] = {"shelves": {}, "reviews": {}, "favorites": []}
        self._write(data)
        return data

    def _prune_retired_users(self, data: Dict) -> None:
        """Drop legacy reader profiles and their data."""
        removed = set()
        for username in list(data["users"].keys()):
            meta = data["users"][username]
            display_name = meta.get("display_name", "")
            if username.lower() in RETIRED_USERNAMES or display_name.lower() in RETIRED_DISPLAY_NAMES_LOWER:
                removed.add(username)
                data["users"].pop(username, None)
                data["library"].pop(username, None)
        if not removed:
            return
        data["activities"] = [act for act in data["activities"] if act.get("username") not in removed]

    def _prune_device_tokens(self, data: Dict) -> None:
        """Remove tokens for deleted users or expired entries and cap per-user count."""
        tokens = data.setdefault("device_tokens", {})
        valid_users = set(data.get("users", {}).keys())
        now = datetime.utcnow()
        for token_hash, meta in list(tokens.items()):
            username = meta.get("username")
            created_at = meta.get("created_at")
            if not username or username not in valid_users:
                tokens.pop(token_hash, None)
                continue
            if created_at:
                try:
                    created_dt = datetime.fromisoformat(created_at)
                    if now - created_dt > timedelta(days=DEVICE_TOKEN_TTL_DAYS + 7):
                        tokens.pop(token_hash, None)
                        continue
                except ValueError:
                    tokens.pop(token_hash, None)
                    continue
        self._cap_tokens_per_user(tokens)

    def _cap_tokens_per_user(self, tokens: Dict[str, Dict]) -> None:
        per_user: Dict[str, List[Tuple[str, Optional[str]]]] = {}
        for token_hash, meta in tokens.items():
            user = meta.get("username")
            if not user:
                continue
            per_user.setdefault(user, []).append((token_hash, meta.get("created_at")))
        for _, entries in per_user.items():
            entries.sort(key=lambda item: item[1] or "", reverse=True)
            for token_hash, _ in entries[MAX_DEVICE_TOKENS_PER_USER:]:
                tokens.pop(token_hash, None)

    def _write(self, data: Dict) -> None:
        with self.path.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def save(self) -> None:
        self._write(self.db)

    # User operations ---------------------------------------------------------
    def verify_user(self, username: str, password: str) -> bool:
        user = self.db["users"].get(username)
        if not user:
            return False
        return verify_password(password, user["salt"], user["password_hash"])

    def _hash_token(self, token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def register_device_token(self, username: str) -> str:
        token = secrets.token_urlsafe(32)
        token_hash = self._hash_token(token)
        tokens = self.db.setdefault("device_tokens", {})
        tokens[token_hash] = {"username": username, "created_at": now_ts()}
        self._cap_tokens_per_user(tokens)
        self.save()
        return token

    def resolve_device_token(self, token: str) -> Optional[str]:
        if not token:
            return None
        token_hash = self._hash_token(token)
        record = self.db.get("device_tokens", {}).get(token_hash)
        if not record:
            return None
        return record.get("username")

    def revoke_device_token(self, token: str) -> None:
        if not token:
            return
        token_hash = self._hash_token(token)
        if token_hash in self.db.get("device_tokens", {}):
            self.db["device_tokens"].pop(token_hash, None)
            self.save()

    def change_password(self, username: str, old_password: str, new_password: str) -> bool:
        user = self.db["users"].get(username)
        if not user or not verify_password(old_password, user["salt"], user["password_hash"]):
            return False
        salt, pw_hash = hash_password(new_password)
        user["salt"] = salt
        user["password_hash"] = pw_hash
        self.save()
        return True

    def set_accent(self, username: str, accent: str) -> None:
        user = self.db["users"].get(username)
        if not user:
            return
        user["accent"] = accent
        self.save()

    # Activity ----------------------------------------------------------------
    def _record_activity(
        self,
        username: str,
        work_key: str,
        title: str,
        action: str,
        rating: Optional[float] = None,
        shelf: Optional[str] = None,
        review: Optional[str] = None,
    ) -> None:
        entry = {
            "username": username,
            "work_key": work_key,
            "title": title,
            "action": action,
            "rating": rating,
            "shelf": shelf,
            "review": review[:400] if review else None,
            "timestamp": now_ts(),
        }
        self.db["activities"].insert(0, entry)
        self.db["activities"] = self.db["activities"][:500]

    def get_activity(self, limit: int = 50) -> List[Dict]:
        return self.db.get("activities", [])[:limit]

    # Library -----------------------------------------------------------------
    def _ensure_book_meta(self, work_key: str, meta: Dict) -> None:
        if not work_key:
            return
        existing = self.db["books"].get(work_key, {})
        merged = {**existing, **meta}
        self.db["books"][work_key] = {
            "title": merged.get("title") or "Untitled",
            "authors": merged.get("authors", []),
            "cover_id": merged.get("cover_id"),
            "first_publish_year": merged.get("first_publish_year"),
            "subjects": merged.get("subjects", []),
        }

    def set_shelf(self, username: str, work_key: str, shelf: str, book_meta: Dict) -> None:
        if shelf not in [key for key, _ in SHELVES]:
            return
        self._ensure_book_meta(work_key, book_meta)
        shelves = self.db["library"][username]["shelves"]
        previous = shelves.get(work_key)
        shelves[work_key] = shelf
        if previous != shelf:
            self._record_activity(
                username=username,
                work_key=work_key,
                title=book_meta.get("title", "Unknown title"),
                action="moved_shelf",
                shelf=shelf,
            )
        self.save()

    def set_review(
        self,
        username: str,
        work_key: str,
        rating: Optional[float],
        review: str,
        shelf: Optional[str],
        book_meta: Dict,
    ) -> None:
        self._ensure_book_meta(work_key, book_meta)
        review = review.strip()
        reviews = self.db["library"][username]["reviews"]
        if not rating and not review:
            reviews.pop(work_key, None)
            self.save()
            return
        reviews[work_key] = {
            "rating": rating,
            "review": review,
            "shelf": shelf,
            "updated_at": now_ts(),
        }
        self._record_activity(
            username=username,
            work_key=work_key,
            title=book_meta.get("title", "Unknown title"),
            action="reviewed",
            rating=rating,
            shelf=shelf,
            review=review,
        )
        self.save()

    def remove_from_shelf(self, username: str, work_key: str) -> None:
        shelves = self.db["library"][username]["shelves"]
        shelves.pop(work_key, None)
        self.db["library"][username]["reviews"].pop(work_key, None)
        favs = self.db["library"][username].get("favorites", [])
        if work_key in favs:
            self.db["library"][username]["favorites"] = [wk for wk in favs if wk != work_key]
        self.save()

    def get_shelf(self, username: str, work_key: str) -> Optional[str]:
        return self.db["library"][username]["shelves"].get(work_key)

    def get_review(self, username: str, work_key: str) -> Dict:
        return self.db["library"][username]["reviews"].get(work_key, {})

    def get_book(self, work_key: str) -> Dict:
        return self.db["books"].get(work_key, {})

    def get_library(self, username: str) -> Dict:
        return self.db["library"][username]

    def get_all_users(self) -> List[str]:
        return list(self.db["users"].keys())

    def get_user_stats(self, username: str) -> Dict:
        lib = self.db["library"][username]
        reviews = lib["reviews"]
        shelves = lib["shelves"]
        finished = [k for k, v in shelves.items() if v == "finished"]
        avg_rating = None
        ratings = [v["rating"] for v in reviews.values() if v.get("rating")]
        if ratings:
            avg_rating = sum(ratings) / len(ratings)
        return {
            "total_rated": len(ratings),
            "avg_rating": avg_rating,
            "finished_count": len(finished),
            "shelf_counts": {key: list(shelves.values()).count(key) for key, _ in SHELVES},
        }

    def get_book_reviews(self, work_key: str) -> Dict[str, Dict]:
        results = {}
        for user, lib in self.db["library"].items():
            review = lib["reviews"].get(work_key)
            if review:
                results[user] = review
        return results

    def get_favorites(self, username: str) -> List[str]:
        lib = self.db["library"].get(username, {})
        return lib.get("favorites", [])

    def set_favorites(self, username: str, work_keys: List[str]) -> None:
        lib = self.db["library"][username]
        unique: List[str] = []
        for wk in work_keys:
            if wk and wk not in unique:
                unique.append(wk)
        lib["favorites"] = unique[:4]
        self.save()


# --- Open Library API helpers ---------------------------------------------------

OPEN_LIBRARY_BASE = "https://openlibrary.org"


@st.cache_data(show_spinner=False, ttl=300)
def search_open_library(query: str, page: int = 1, limit: int = 12) -> Tuple[List[Dict], int]:
    if not query.strip():
        return [], 0
    resp = requests.get(
        f"{OPEN_LIBRARY_BASE}/search.json",
        params={"q": query, "page": page, "limit": limit},
        timeout=8,
    )
    resp.raise_for_status()
    data = resp.json()
    results = []
    for doc in data.get("docs", []):
        work_key = doc.get("key")
        if not work_key:
            continue
        results.append(
            {
                "key": work_key,
                "title": doc.get("title") or "Untitled",
                "authors": doc.get("author_name") or [],
                "first_publish_year": doc.get("first_publish_year"),
                "cover_id": doc.get("cover_i") or doc.get("cover_id"),
                "subjects": (doc.get("subject") or [])[:5],
            }
        )
    return results, data.get("numFound", 0)


@st.cache_data(show_spinner=False, ttl=600)
def fetch_work_detail(work_key: str) -> Optional[Dict]:
    if not work_key:
        return None
    clean_key = work_key.replace("/works/", "")
    resp = requests.get(f"{OPEN_LIBRARY_BASE}/works/{clean_key}.json", timeout=8)
    if resp.status_code != 200:
        return None
    data = resp.json()
    cover_id = None
    covers = data.get("covers") or []
    if covers:
        cover_id = covers[0]
    description = data.get("description")
    if isinstance(description, dict):
        description = description.get("value")
    authors = []
    for auth in data.get("authors", []):
        author_key = auth.get("author", {}).get("key")
        if author_key:
            name = fetch_author_name(author_key)
            if name:
                authors.append(name)
    subjects = data.get("subjects") or []
    return {
        "title": data.get("title") or "Untitled",
        "description": description,
        "cover_id": cover_id,
        "subjects": subjects[:12],
        "authors": authors,
        "created": data.get("created", {}).get("value"),
    }


@st.cache_data(show_spinner=False, ttl=3600)
def fetch_author_name(author_key: str) -> Optional[str]:
    try:
        resp = requests.get(f"{OPEN_LIBRARY_BASE}{author_key}.json", timeout=6)
        if resp.status_code != 200:
            return None
        data = resp.json()
        return data.get("name")
    except Exception:
        return None


def cover_url(cover_id: Optional[int], size: str = "M") -> Optional[str]:
    if not cover_id:
        return None
    return f"https://covers.openlibrary.org/b/id/{cover_id}-{size}.jpg"


# --- UI helpers -----------------------------------------------------------------


def apply_base_style(accent: str) -> None:
    st.markdown(
        f"""
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&display=swap');
        .stApp {{
            background: {DEFAULT_THEME["bg_gradient"]};
            color: #e5e7eb;
            font-family: 'Space Grotesk', 'Helvetica Neue', sans-serif;
        }}
        section.main > div {{ padding-top: 1rem; }}
        .accent {{ color: {accent}; }}
        div.stButton > button {{
            background: {accent};
            color: white;
            border: none;
            border-radius: 8px;
            padding: 0.5rem 1rem;
            font-weight: 600;
        }}
        div[data-testid="stForm"] {{
            background: rgba(17, 24, 39, 0.4);
            padding: 1rem;
            border-radius: 12px;
            border: 1px solid rgba(255, 255, 255, 0.06);
        }}
        .hero {{
            padding: 0.5rem 0 0.75rem;
        }}
        .hero h1 {{
            margin: 0;
            font-size: 2.1rem;
            letter-spacing: -0.02em;
        }}
        .card-row {{
            display: flex;
            gap: 12px;
            overflow-x: auto;
            padding: 0.25rem 0 1rem;
        }}
        .cover-card {{
            display: block;
            min-width: 170px;
            max-width: 190px;
            background: rgba(17, 24, 39, 0.65);
            border: 1px solid rgba(255,255,255,0.08);
            border-radius: 12px;
            box-shadow: 0 10px 24px rgba(0,0,0,0.35);
            transition: transform 120ms ease, border-color 120ms ease;
            text-decoration: none;
            color: inherit;
        }}
        .cover-card:hover {{
            transform: translateY(-4px);
            border-color: {accent};
        }}
        .cover-img {{
            width: 100%;
            aspect-ratio: 2/3;
            background-size: cover;
            background-position: center;
            border-radius: 10px 10px 6px 6px;
        }}
        .cover-meta {{
            padding: 0.6rem 0.75rem 0.7rem;
        }}
        .card-title {{
            font-weight: 700;
            font-size: 0.95rem;
            line-height: 1.2;
        }}
        .card-sub {{
            color: #cbd5e1;
            font-size: 0.8rem;
            margin-top: 0.15rem;
        }}
        .card-footer {{
            color: #9ca3af;
            font-size: 0.75rem;
            margin-top: 0.35rem;
        }}
        .pill {{
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 0.25rem 0.55rem;
            background: rgba(255,255,255,0.08);
            border-radius: 999px;
            font-size: 0.8rem;
            color: #e5e7eb;
        }}
        .placeholder-card {{
            min-width: 170px;
            max-width: 190px;
            height: 255px;
            border: 2px dashed rgba(255,255,255,0.2);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: rgba(255,255,255,0.6);
            font-size: 2.2rem;
            background: rgba(17,24,39,0.35);
        }}
        </style>
        """,
        unsafe_allow_html=True,
    )


def format_authors(authors: List[str]) -> str:
    return ", ".join(authors) if authors else "Unknown author"


def get_current_user_accent(store: DataStore, username: str) -> str:
    user = store.db["users"].get(username, {})
    return user.get("accent") or DEFAULT_THEME["accent"]


def restore_user_from_cookie(store: DataStore, cookie_manager: stx.CookieManager) -> Optional[str]:
    """Return username for a valid device cookie, pruning invalid cookies."""
    token = cookie_manager.get(DEVICE_COOKIE_NAME)
    if not token:
        return None
    username = store.resolve_device_token(token)
    if not username:
        cookie_manager.delete(DEVICE_COOKIE_NAME)
        return None
    return username


# --- Render functions -----------------------------------------------------------


def render_login(store: DataStore, cookie_manager: stx.CookieManager) -> None:
    st.title("📚 Booxd")
    st.caption("A tiny Letterboxd-style tracker for two readers.")

    with st.form("login"):
        username = st.text_input("Username").strip()
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Log in")
        if submitted:
            if store.verify_user(username, password):
                st.session_state["user"] = username
                token = store.register_device_token(username)
                cookie_manager.set(
                    DEVICE_COOKIE_NAME,
                    token,
                    expires_at=datetime.utcnow() + timedelta(days=DEVICE_TOKEN_TTL_DAYS),
                    same_site="lax",
                )
                set_nav("Home")
                st.success("Logged in")
                st.rerun()
            else:
                st.error("Invalid credentials")


def render_profile_sidebar(store: DataStore, username: str, cookie_manager: stx.CookieManager) -> None:
    user = store.db["users"].get(username, {})
    lib = store.get_library(username)
    shelf_counts = {key: 0 for key, _ in SHELVES}
    for shelf in lib["shelves"].values():
        shelf_counts[shelf] = shelf_counts.get(shelf, 0) + 1
    st.sidebar.markdown(
        f"### {user.get('display_name', username)}\n"
        f"`{username}`  \n"
        f"Accent: `{user.get('accent', DEFAULT_THEME['accent'])}`"
    )
    st.sidebar.markdown("#### Shelf counts")
    for key, label in SHELVES:
        st.sidebar.write(f"- {label}: {shelf_counts.get(key,0)}")
    if st.sidebar.button("Log out"):
        token = cookie_manager.get(DEVICE_COOKIE_NAME)
        if token:
            store.revoke_device_token(token)
            cookie_manager.delete(DEVICE_COOKIE_NAME)
        st.session_state.clear()
        st.rerun()


def render_activity(store: DataStore) -> None:
    st.subheader("Recent activity")
    activity = store.get_activity()
    if not activity:
        st.info("Nothing yet. Add to a shelf or leave a review to see the feed update.")
        return
    for entry in activity:
        user = store.db["users"].get(entry["username"], {}).get("display_name", entry["username"])
        ts = entry.get("timestamp")
        line = f"**{user}** "
        if entry["action"] == "moved_shelf":
            line += f"moved **{entry['title']}** to `{shelf_label(entry['shelf'])}`"
        elif entry["action"] == "reviewed":
            line += f"rated **{entry['title']}** {entry.get('rating') or '–'}⭐"
            if entry.get("shelf"):
                line += f" on `{shelf_label(entry['shelf'])}`"
        st.markdown(line)
        if entry.get("review"):
            st.caption(f"“{entry['review']}”")
        if ts:
            st.caption(f"{ts}")
        st.divider()


def render_cover_row(title: str, cards: List[Dict], subtitle: Optional[str] = None, empty_text: Optional[str] = None) -> None:
    st.markdown(f"### {title}")
    if subtitle:
        st.caption(subtitle)
    if not cards:
        st.info(empty_text or "Nothing to show yet.")
        return
    html_cards = []
    for card in cards:
        cover = card.get("cover")
        cover_style = (
            f"background-image: linear-gradient(135deg, rgba(31,41,55,0.7), rgba(30,64,175,0.6));"
            if not cover
            else f"background-image: url('{cover}');"
        )
        work_key = card.get("work_key")
        href = f"?nav=Book%20Detail&work_key={quote_plus(work_key)}" if work_key else None
        wrapper_tag = "a" if href else "div"
        wrapper_attrs = f"href=\"{href}\"" if href else ""
        html_cards.append(
            f"<{wrapper_tag} class='cover-card' {wrapper_attrs}>"
            f"<div class='cover-img' style=\"{cover_style}\"></div>"
            f"<div class='cover-meta'>"
            f"<div class='card-title'>{html.escape(card.get('title', ''))}</div>"
            f"<div class='card-sub'>{html.escape(card.get('meta', ''))}</div>"
            f"<div class='card-footer'>{html.escape(card.get('footer', ''))}</div>"
            f"</div>"
            f"</{wrapper_tag}>"
        )
    markup = "<div class='card-row'>" + "".join(html_cards) + "</div>"
    st.markdown(markup, unsafe_allow_html=True)


def build_activity_cards(store: DataStore, current_user: str) -> List[Dict]:
    cards: List[Dict] = []
    for entry in store.get_activity(limit=12):
        if entry["username"] == current_user:
            continue
        book = store.get_book(entry["work_key"])
        cover = cover_url(book.get("cover_id"))
        user = store.db["users"].get(entry["username"], {}).get("display_name", entry["username"])
        ts = entry.get("timestamp", "")
        date = ts.split("T")[0] if ts else ""
        meta_bits = []
        if entry["action"] == "reviewed":
            if entry.get("rating"):
                meta_bits.append(f"{entry['rating']}⭐")
            if entry.get("shelf"):
                meta_bits.append(shelf_label(entry["shelf"]))
            if entry.get("review"):
                meta_bits.append("Review")
        elif entry["action"] == "moved_shelf":
            meta_bits.append(f"→ {shelf_label(entry['shelf'])}")
        cards.append(
            {
                "title": book.get("title") or entry.get("title") or "Untitled",
                "meta": " · ".join(meta_bits),
                "footer": f"{user}" + (f" • {date}" if date else ""),
                "cover": cover,
                "work_key": entry["work_key"],
            }
        )
    return cards


def build_popular_cards(store: DataStore, limit: int = 10) -> List[Dict]:
    stats: Dict[str, Dict] = {}
    for _, lib in store.db["library"].items():
        for wk, review in lib["reviews"].items():
            rating = review.get("rating")
            if rating is None:
                continue
            stats.setdefault(wk, {"ratings": [], "book": store.get_book(wk)})
            stats[wk]["ratings"].append(rating)

    cards = []
    for wk, data in stats.items():
        ratings = data["ratings"]
        if not ratings:
            continue
        avg = sum(ratings) / len(ratings)
        book = data["book"]
        cards.append(
            {
                "title": book.get("title", "Untitled"),
                "meta": f"{avg:.1f}⭐ · {len(ratings)} rating(s)",
                "footer": format_authors(book.get("authors", [])),
                "cover": cover_url(book.get("cover_id")),
                "work_key": wk,
                "score": avg,
                "count": len(ratings),
            }
        )
    cards.sort(key=lambda c: (c.get("score", 0), c.get("count", 0)), reverse=True)
    trimmed = []
    for card in cards[:limit]:
        card.pop("score", None)
        card.pop("count", None)
        trimmed.append(card)
    return trimmed


def build_favorite_cards(store: DataStore, username: str) -> List[Dict]:
    cards: List[Dict] = []
    favs = store.get_favorites(username)
    for wk in favs:
        book = store.get_book(wk)
        cover = cover_url(book.get("cover_id"))
        review = store.get_review(username, wk)
        meta_bits = []
        if review.get("rating"):
            meta_bits.append(f"{review['rating']}⭐")
        authors = format_authors(book.get("authors", []))
        cards.append(
            {
                "title": book.get("title", "Untitled"),
                "meta": " · ".join(meta_bits) if meta_bits else authors,
                "footer": authors if meta_bits else "",
                "cover": cover,
                "work_key": wk,
            }
        )
    return cards


def build_user_activity_cards(store: DataStore, username: str, limit: int = 8) -> List[Dict]:
    cards: List[Dict] = []
    for entry in store.get_activity(limit=200):
        if entry["username"] != username:
            continue
        book = store.get_book(entry["work_key"])
        cover = cover_url(book.get("cover_id"))
        ts = entry.get("timestamp", "")
        date = ts.split("T")[0] if ts else ""
        meta_bits = []
        if entry["action"] == "reviewed":
            if entry.get("rating"):
                meta_bits.append(f"{entry['rating']}⭐")
            if entry.get("shelf"):
                meta_bits.append(shelf_label(entry["shelf"]))
        elif entry["action"] == "moved_shelf":
            meta_bits.append(f"→ {shelf_label(entry['shelf'])}")
        cards.append(
            {
                "title": book.get("title") or entry.get("title") or "Untitled",
                "meta": " · ".join(meta_bits),
                "footer": date,
                "cover": cover,
                "work_key": entry["work_key"],
            }
        )
        if len(cards) >= limit:
            break
    return cards


def render_home(store: DataStore, username: str) -> None:
    user_meta = store.db["users"].get(username, {})
    accent = user_meta.get("accent", DEFAULT_THEME["accent"])
    display = user_meta.get("display_name", username)
    st.markdown(
        f"""
        <div class="hero">
            <div class="pill" style="background:{accent};color:#0b1224;font-weight:700;">Home feed</div>
            <h1>Welcome back, {html.escape(display)}.</h1>
            <p class="card-sub">Here’s what your friend has been reading and rating.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    render_cover_row("New from friends", build_activity_cards(store, username), subtitle="Latest shelves, ratings, and reviews.")
    render_cover_row(
        "Popular with friends",
        build_popular_cards(store),
        subtitle="Top-rated between you two.",
        empty_text="Rate a few books to see this fill up.",
    )


def render_profile(store: DataStore, current_user: str) -> None:
    users = store.get_all_users()
    name_map = {u: store.db["users"].get(u, {}).get("display_name", u) for u in users}
    default_idx = users.index(current_user) if current_user in users else 0
    target_user = st.selectbox("View profile", users, index=default_idx, format_func=lambda u: name_map[u])
    meta = store.db["users"].get(target_user, {})
    stats = store.get_user_stats(target_user)
    accent = meta.get("accent", DEFAULT_THEME["accent"])

    st.markdown(
        f"""
        <div class="hero" style="padding-top:0;">
            <div class="pill" style="background:{accent};color:#0b1224;font-weight:700;">Profile</div>
            <h1 style="margin-top:0.25rem;">{html.escape(name_map[target_user])}</h1>
            <p class="card-sub">Favorites, stats, and recent activity.</p>
            <div style="display:flex;gap:18px;margin-top:6px;font-weight:600;">
                <span>{stats['finished_count']} finished</span>
                <span>{stats['total_rated']} rated</span>
                <span>{(str(round(stats['avg_rating'],2)) + '⭐ avg') if stats['avg_rating'] else '–'}</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    render_cover_row(
        "Favorite books",
        build_favorite_cards(store, target_user),
        subtitle="Top 4 picks",
        empty_text=None,
    )
    if not store.get_favorites(target_user):
        st.caption("No favorites yet. Add books in Discover/Library, then set your Top 4 below.")
        placeholders = "".join(["<div class='placeholder-card'>+</div>" for _ in range(4)])
        st.markdown(f"<div class='card-row'>{placeholders}</div>", unsafe_allow_html=True)
    render_cover_row(
        "Recent activity",
        build_user_activity_cards(store, target_user),
        subtitle=f"Latest moves from {name_map[target_user]}",
        empty_text="No activity yet.",
    )

    if target_user == current_user:
        st.subheader("Choose your Top 4")
        lib = store.get_library(current_user)
        options = list(lib["shelves"].keys())
        if not options:
            st.info("Add books to a shelf first, then pick your favorites.")
            return
        option_labels = {wk: store.get_book(wk).get("title", wk) for wk in options}
        current_favs = [wk for wk in store.get_favorites(current_user) if wk in options]
        selection = st.multiselect(
            "Pick up to 4 favorites from your library",
            options=options,
            default=current_favs,
            format_func=lambda wk: option_labels.get(wk, wk),
            max_selections=4,
        )
        if st.button("Save favorites"):
            store.set_favorites(current_user, selection[:4])
            st.success("Favorites updated")
            st.rerun()


def render_discover(store: DataStore, username: str) -> None:
    st.header("Discover")
    st.caption("Search Open Library and stash books into your shelves.")

    query = st.text_input("Search by title, author, or subject", value=st.session_state.get("last_query", ""))
    page = st.number_input("Page", min_value=1, step=1, value=st.session_state.get("last_page", 1))
    if st.button("Search"):
        st.session_state["last_query"] = query
        st.session_state["last_page"] = page

    results, total = ([], 0)
    if st.session_state.get("last_query"):
        with st.spinner("Searching Open Library..."):
            try:
                results, total = search_open_library(st.session_state["last_query"], page=st.session_state.get("last_page", 1))
            except Exception as exc:
                st.error(f"Search failed: {exc}")

    if results:
        st.caption(f"{total} results; showing {len(results)}")
    for book in results:
        render_book_card(store, username, book)


def render_book_card(store: DataStore, username: str, book: Dict) -> None:
    work_key = book["key"]
    col_cover, col_meta = st.columns([1, 3])
    cover = cover_url(book.get("cover_id"))
    with col_cover:
        if cover:
            st.image(cover, use_container_width=True)
        else:
            st.write("No cover")
    with col_meta:
        st.subheader(book.get("title", "Untitled"))
        st.caption(format_authors(book.get("authors", [])))
        if book.get("first_publish_year"):
            st.caption(f"First published {book['first_publish_year']}")
        if book.get("subjects"):
            st.caption(" • ".join(book["subjects"]))

        shelf_current = store.get_shelf(username, work_key)
        with st.form(f"shelf-{safe_key(work_key)}"):
            shelf_choice = st.selectbox(
                "Shelf",
                options=[key for key, _ in SHELVES],
                format_func=shelf_label,
                index=[key for key, _ in SHELVES].index(shelf_current) if shelf_current in [k for k, _ in SHELVES] else 0,
            )
            submitted = st.form_submit_button("Save to shelf")
            if submitted:
                store.set_shelf(username, work_key, shelf_choice, book)
                st.success(f"Saved to {shelf_label(shelf_choice)}")

        if st.button("Open details", key=f"detail-{safe_key(work_key)}"):
            st.session_state["selected_work"] = {
                "key": work_key,
                "title": book.get("title"),
                "authors": book.get("authors", []),
                "cover_id": book.get("cover_id"),
                "subjects": book.get("subjects", []),
                "first_publish_year": book.get("first_publish_year"),
            }
            set_nav("Book Detail")
            st.rerun()
    st.divider()


def render_book_detail(store: DataStore, username: str) -> None:
    selected = st.session_state.get("selected_work")
    if not selected:
        st.info("Choose a book from Discover or My Library to see details.")
        return

    work_key = selected["key"]
    detail = fetch_work_detail(work_key)
    merged = {**selected, **(detail or {})}
    cover = cover_url(merged.get("cover_id"), size="L")

    cols = st.columns([1, 2])
    with cols[0]:
        if cover:
            st.image(cover, use_container_width=True)
        st.caption(f"Key: {work_key}")
        if merged.get("subjects"):
            st.caption("Subjects: " + ", ".join(merged["subjects"][:10]))
    with cols[1]:
        st.title(merged.get("title", "Untitled"))
        st.caption(format_authors(merged.get("authors", [])))
        if merged.get("description"):
            st.write(merged["description"])
        elif merged.get("subjects"):
            st.caption(" • ".join(merged["subjects"][:12]))

        existing_review = store.get_review(username, work_key)
        existing_shelf = store.get_shelf(username, work_key) or "want"
        with st.form("review-form"):
            shelf_choice = st.selectbox(
                "Shelf",
                options=[key for key, _ in SHELVES],
                format_func=shelf_label,
                index=[key for key, _ in SHELVES].index(existing_shelf),
            )
            rating = st.slider("Rating", 0.0, 5.0, float(existing_review.get("rating", 0.0)), 0.5)
            review = st.text_area("Review (optional)", value=existing_review.get("review", ""), height=120)
            submitted = st.form_submit_button("Save")
            if submitted:
                store.set_shelf(username, work_key, shelf_choice, merged)
                store.set_review(
                    username,
                    work_key,
                    rating if rating > 0 else None,
                    review,
                    shelf_choice,
                    merged,
                )
                st.success("Saved")

    st.divider()
    st.subheader("What you both thought")
    reviews = store.get_book_reviews(work_key)
    other_users = store.get_all_users()
    for user in other_users:
        meta = store.db["users"].get(user, {})
        review = reviews.get(user)
        st.markdown(f"**{meta.get('display_name', user)}**")
        if review:
            if review.get("rating"):
                st.write(f"Rating: {review['rating']} ⭐")
            if review.get("review"):
                st.write(f"“{review['review']}”")
            st.caption(f"Shelf: {shelf_label(review.get('shelf') or '')}")
        else:
            st.caption("No review yet.")


def render_library(store: DataStore, username: str) -> None:
    st.header("My Library")
    lib = store.get_library(username)
    tabs = st.tabs([label for _, label in SHELVES])
    shelves_keys = [key for key, _ in SHELVES]
    for idx, tab in enumerate(tabs):
        key = shelves_keys[idx]
        with tab:
            items = [wk for wk, shelf in lib["shelves"].items() if shelf == key]
            if not items:
                st.info("Empty shelf.")
                continue
            for wk in items:
                book = store.get_book(wk)
                review = store.get_review(username, wk)
                cols = st.columns([1, 3])
                cover = cover_url(book.get("cover_id"))
                with cols[0]:
                    if cover:
                        st.image(cover, use_container_width=True)
                with cols[1]:
                    st.subheader(book.get("title", "Untitled"))
                    st.caption(format_authors(book.get("authors", [])))
                    if review.get("rating"):
                        st.write(f"Rating: {review['rating']} ⭐")
                    if review.get("review"):
                        st.caption(f"“{review['review']}”")
                    col1, col2 = st.columns(2)
                    with col1:
                        if st.button("Open details", key=f"detail-lib-{safe_key(wk)}"):
                            st.session_state["selected_work"] = {"key": wk, **book}
                            set_nav("Book Detail")
                            st.rerun()
                    with col2:
                        if st.button("Remove", key=f"remove-{safe_key(wk)}"):
                            store.remove_from_shelf(username, wk)
                            st.rerun()
            st.divider()


def render_compare(store: DataStore) -> None:
    st.header("Compare")
    users = store.get_all_users()
    if len(users) < 2:
        st.info("Need two users to compare.")
        return
    u1, u2 = users[:2]
    stats1, stats2 = store.get_user_stats(u1), store.get_user_stats(u2)
    col1, col2 = st.columns(2)
    with col1:
        st.subheader(store.db["users"][u1].get("display_name", u1))
        render_stat_block(stats1)
    with col2:
        st.subheader(store.db["users"][u2].get("display_name", u2))
        render_stat_block(stats2)

    lib1 = set(store.get_library(u1)["shelves"].keys())
    lib2 = set(store.get_library(u2)["shelves"].keys())
    overlap = lib1 & lib2
    st.subheader(f"Overlapping books ({len(overlap)})")
    if not overlap:
        st.info("No overlap yet.")
        return
    for wk in overlap:
        book = store.get_book(wk)
        st.markdown(f"- **{book.get('title', 'Untitled')}** — {format_authors(book.get('authors', []))}")


def render_stat_block(stats: Dict) -> None:
    st.write(f"Finished: {stats['finished_count']}")
    st.write(f"Total rated: {stats['total_rated']}")
    if stats["avg_rating"]:
        st.write(f"Avg rating: {stats['avg_rating']:.2f}")
    st.caption(", ".join([f"{shelf_label(k)}: {v}" for k, v in stats["shelf_counts"].items()]))


def render_settings(store: DataStore, username: str) -> None:
    st.header("Settings")
    with st.form("password-change"):
        st.subheader("Change password")
        old = st.text_input("Current password", type="password")
        new = st.text_input("New password", type="password")
        submitted = st.form_submit_button("Update password")
        if submitted:
            if store.change_password(username, old, new):
                st.success("Password updated")
            else:
                st.error("Could not update password (check current password).")

    with st.form("theme"):
        st.subheader("Accent color")
        current = get_current_user_accent(store, username)
        accent = st.color_picker("Pick an accent", value=current)
        submitted = st.form_submit_button("Save accent")
        if submitted:
            store.set_accent(username, accent)
            st.success("Accent updated")
            st.rerun()


def get_cookie_manager() -> stx.CookieManager:
    """Create or reuse a CookieManager; do not cache to avoid widget-in-cache warning."""
    if "cookie_manager" not in st.session_state:
        st.session_state["cookie_manager"] = stx.CookieManager(key="booxd_cookies")
    return st.session_state["cookie_manager"]


# --- Main ----------------------------------------------------------------------


def main() -> None:
    st.set_page_config(page_title=APP_NAME, page_icon="📚", layout="wide")
    store = get_store(STORE_VERSION)
    cookie_manager = get_cookie_manager()

    user = st.session_state.get("user")
    if not user:
        user = restore_user_from_cookie(store, cookie_manager)
        if user:
            st.session_state["user"] = user
    else:
        # Refresh cookie expiry for an active session
        token = cookie_manager.get(DEVICE_COOKIE_NAME)
        if token and store.resolve_device_token(token) == user:
            cookie_manager.set(
                DEVICE_COOKIE_NAME,
                token,
                expires_at=datetime.utcnow() + timedelta(days=DEVICE_TOKEN_TTL_DAYS),
                same_site="lax",
            )
    accent = get_current_user_accent(store, user) if user else DEFAULT_THEME["accent"]
    apply_base_style(accent)

    params = st.query_params
    work_param = params.get("work_key")
    if isinstance(work_param, list):
        work_param = work_param[0]
    nav_param = params.get("nav")
    if isinstance(nav_param, list):
        nav_param = nav_param[0]
    nav_target = None
    if nav_param:
        nav_target = next((opt for opt in NAV_OPTIONS if opt.lower() == str(nav_param).lower()), None)
    if nav_target:
        set_nav(nav_target)
    if work_param:
        book = store.get_book(work_param) or {"key": work_param}
        st.session_state["selected_work"] = {"key": work_param, **book}
        set_nav("Book Detail")

    if "nav_state" not in st.session_state:
        st.session_state["nav_state"] = "Home"
    pending_nav = st.session_state.pop("nav_pending", None)
    if pending_nav:
        st.session_state["nav_state"] = pending_nav

    if not user:
        render_login(store, cookie_manager)
        return

    nav_current = st.session_state.get("nav_state") or "Home"
    if nav_current not in NAV_OPTIONS:
        nav_current = "Home"
        st.session_state["nav_state"] = nav_current
    st.session_state.setdefault("nav_radio", nav_current)
    nav = st.sidebar.radio("Navigate", NAV_OPTIONS, key="nav_radio")
    if nav != st.session_state["nav_state"]:
        st.session_state["nav_state"] = nav
    nav_current = st.session_state["nav_state"]

    render_profile_sidebar(store, user, cookie_manager)

    if nav == "Home":
        render_home(store, user)
    elif nav == "Profile":
        render_profile(store, user)
    elif nav == "Discover":
        render_discover(store, user)
    elif nav == "Book Detail":
        render_book_detail(store, user)
    elif nav == "My Library":
        render_library(store, user)
    elif nav == "Compare":
        render_compare(store)
    elif nav == "Settings":
        render_settings(store, user)


@st.cache_resource
def get_store(version: int) -> DataStore:
    # version argument busts cache when schema changes
    return DataStore(DB_PATH, DEFAULT_USERS)


if __name__ == "__main__":
    main()
