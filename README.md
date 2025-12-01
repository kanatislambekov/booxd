# Booxd — two-person book tracker

Simple Streamlit app that mimics a tiny Letterboxd for books, built for two users and backed by Open Library.

## Quick start

1) Install deps: `pip install -r requirements.txt`  
2) Run: `streamlit run app.py`  
3) Log in: defaults are `kanat / readerpass1` and `asem / readerpass2` (change in `config.py` before first run or in the app settings).  
4) Data persists to `data/db.json`; it seeds itself on first launch.

## What it does

- Search Open Library for books, view covers/subjects, open a detail view with metadata.
- Shelves: Want to Read, Reading, Finished, Dropped.
- Rate (0–5 ⭐) and review; see both users’ takes on a book.
- Activity feed, personal library tabs, side-by-side compare view with overlaps.
- Settings to change password and accent color.

## Notes

- API calls hit `https://openlibrary.org` (no key needed).
- Passwords are stored hashed (PBKDF2) in the local JSON file; keep the folder private.
