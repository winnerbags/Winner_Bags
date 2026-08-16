import re
"""
rio_erp_api.py — WINNER BAGS ERP v2.0
FastAPI backend replacing the PowerShell script.
Data stored in MongoDB Atlas.

Run locally:
    uvicorn rio_erp_api:app --host 0.0.0.0 --port 8001 --reload

Deploy on Render.com:
    Start command: uvicorn rio_erp_api:app --host 0.0.0.0 --port 8001
"""

import os, re, bcrypt, sys, secrets
import httpx
import httpx
from contextlib import asynccontextmanager
from datetime import datetime, date, timedelta, timedelta
from typing import Optional, Any

from fastapi import FastAPI, Request, Query, Header, Header
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel
from fastapi.responses import JSONResponse, HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.collection import Collection
from bson import ObjectId
from dotenv import load_dotenv

# Use logging so uvicorn captures and displays output properly
import logging
import logging.handlers
import pathlib

# ── Logging setup ────────────────────────────────────────────────
# Windows (local run): writes to C:\Rio\Logs\rio_app.log
# Render / Linux:      stdout only (visible in Render → Logs tab)
import platform as _platform

_fmt = logging.Formatter("%(asctime)s | %(levelname)-5s | %(message)s",
                          datefmt="%Y-%m-%d %H:%M:%S")

# Set up "rio_erp_api" logger cleanly — don't use basicConfig (conflicts with uvicorn)
logger = logging.getLogger("rio_erp_api")
logger.setLevel(logging.DEBUG)
logger.propagate = False   # prevent double-logging via root logger

# Always add stdout handler
_sh = logging.StreamHandler()
_sh.setFormatter(_fmt)
if not logger.handlers:    # avoid adding duplicate handlers on reload
    logger.addHandler(_sh)

# File handler — try C:\Rio\Logs on Windows, fallback to script directory
_LOG_FILE = None
_log_candidates = []
if _platform.system() == "Windows":
    _log_candidates = [
        pathlib.Path(r"C:\Rio\Logs"),
        pathlib.Path(os.path.dirname(os.path.abspath(__file__))) / "logs",
        pathlib.Path.cwd() / "logs",
    ]
else:
    # On Linux/Render: no file needed (use Render Logs tab)
    _log_candidates = []

for _log_candidate_dir in _log_candidates:
    try:
        _log_candidate_dir.mkdir(parents=True, exist_ok=True)
        _test = _log_candidate_dir / ".write_test"
        _test.touch(); _test.unlink()
        _LOG_FILE = _log_candidate_dir / "rio_app.log"
        _fh = logging.handlers.RotatingFileHandler(
            _LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=2, encoding="utf-8"
        )
        _fh.setFormatter(_fmt)
        logger.addHandler(_fh)
        logger.info("=== RIO — Log file: %s ===", _LOG_FILE)
        break
    except Exception as _log_ex:
        logger.debug("Log dir %s not writable: %s", _log_candidate_dir, _log_ex)

if not _LOG_FILE:
    if _platform.system() == "Windows":
        logger.warning("Could not create log file — check C:\\Rio\\Logs permissions")
    else:
        logger.info("=== WINNER BAGS ERP v2.0 — Render — check Logs tab ===")

load_dotenv(override=False)  # Never override Render environment variables

# ─────────────────────────────────────────────
#  CONFIG
# ─────────────────────────────────────────────
MONGO_URI  = os.environ.get("MONGO_URI", "")  # must be set in Render — no hardcoded fallback
MONGO_DB   = os.environ.get("MONGO_DB",  "WINNER_BAGS")
# Rainbow's database name is now configurable (was hardcoded as "RainbowUmbrellas"
# further down in the file), so a test deployment can isolate Rainbow's data too
# via MONGO_DB_RAINBOW, the same way MONGO_DB isolates Rio's. Defaults to the
# existing production database name if unset, so production is unaffected.
MONGO_DB_RAINBOW = os.environ.get("MONGO_DB_RAINBOW", "RainbowUmbrellas")
HTML_FILE  = os.environ.get("HTML_FILE", "WINNER_BAGS_ERP.html")

# ── Startup diagnostics ──
logger.info("=" * 60)
logger.info("WINNER BAGS ERP v2.0 — STARTING UP")
logger.info(f"MONGO_DB  = {MONGO_DB}")
logger.info(f"MONGO_DB_RAINBOW = {MONGO_DB_RAINBOW}")
if MONGO_URI:
    _safe = re.sub(r':(.*?)@', ':***@', MONGO_URI)
    logger.info(f"MONGO_URI = SET → {_safe[:70]}")
else:
    logger.error("MONGO_URI = NOT SET — add it in Render Environment Variables!")
logger.info("=" * 60)

# ─────────────────────────────────────────────
#  DB
# ─────────────────────────────────────────────
_client: MongoClient = None
_db = None

def _ensure_db_blocking() -> bool:
    """Connect to MongoDB if not already connected. Returns True if connected."""
    global _client, _db
    if _db is not None:
        try:
            _client.admin.command("ping")
            return True
        except Exception:
            _client = None
            _db = None
    if not MONGO_URI:
        logger.error("MONGO_URI not set — cannot connect to MongoDB")
        return False
    try:
        _client = MongoClient(
            MONGO_URI,
            serverSelectionTimeoutMS=8000,
            connectTimeoutMS=8000,
            socketTimeoutMS=15000,
        )
        _client.admin.command("ping")
        _db = _client[MONGO_DB]
        logger.info("MongoClient created, pinging Atlas...")
        # Create indexes
        try:
            _db["sales_records"].create_index([("SNo", DESCENDING)])
            _db["daily_expenses"].create_index([("ExpDate", DESCENDING)])
            _db["sales_invoices"].create_index([("InvoiceDate", DESCENDING)])
            _db["quotations"].create_index([("QuotationDate", DESCENDING)])
            _db["attendance"].create_index([("name", ASCENDING), ("date", ASCENDING)], unique=True)
            logger.info("Indexes created")
        except Exception:
            pass
        ensure_default_users()
        ensure_default_debt_loan_auth()
        ensure_default_debt_loan_auth()
        return True
    except Exception as e:
        logger.error(f"MongoDB connection failed: {e}")
        _client = None
        _db = None
        return False

async def ensure_db() -> bool:
    """
    Async-safe wrapper around the blocking MongoDB connection check.
    Runs the actual pymongo calls in a worker thread so a slow/unresponsive
    Atlas connection never freezes the asyncio event loop (which would make
    the ENTIRE server unresponsive to all users, not just this request).
    """
    return await run_in_threadpool(_ensure_db_blocking)

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    except Exception:
        return False


def get_client_ip(request) -> str:
    """The real client IP, not the load balancer's. Render (like most
    hosting platforms) sits the app behind a proxy, so request.client.host
    would just show the proxy's own address - the actual visitor IP is in
    the X-Forwarded-For header instead, which can be a comma-separated
    chain if there are multiple proxies (the first entry is the original
    client)."""
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def parse_user_agent(ua: str) -> dict:
    """Basic OS/browser identification from the User-Agent string - not a
    real device/computer name. Browsers deliberately don't expose the
    actual hostname of the machine to web pages (that would be a
    fingerprinting/privacy risk), so 'machine name' in the login log
    means 'OS + browser', the closest equivalent actually available."""
    ua = ua or ""
    if "Windows" in ua:
        os_name = "Windows"
    elif "Mac OS" in ua or "Macintosh" in ua:
        os_name = "macOS"
    elif "Android" in ua:
        os_name = "Android"
    elif "iPhone" in ua or "iPad" in ua:
        os_name = "iOS"
    elif "Linux" in ua:
        os_name = "Linux"
    else:
        os_name = "Unknown OS"

    if "Edg/" in ua:
        browser = "Edge"
    elif "Chrome/" in ua and "Chromium" not in ua:
        browser = "Chrome"
    elif "Firefox/" in ua:
        browser = "Firefox"
    elif "Safari/" in ua and "Chrome" not in ua:
        browser = "Safari"
    else:
        browser = "Unknown browser"

    return {"os": os_name, "browser": browser}


async def get_ip_geolocation(ip: str) -> dict:
    """City/region/country from a free IP-geolocation lookup - this is
    approximate (based on which ISP block the IP belongs to), not exact
    GPS location, and won't resolve for local/private IPs (e.g. testing
    on localhost). Short timeout so a slow/unreachable lookup never
    delays the actual login - falls back to 'Unknown' if it fails."""
    if not ip or ip in ("unknown", "127.0.0.1", "localhost") or ip.startswith(("10.", "192.168.", "172.")):
        return {"city": "Unknown", "region": "Unknown", "country": "Unknown"}
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            resp = await client.get(f"http://ip-api.com/json/{ip}?fields=status,city,regionName,country")
            data = resp.json()
            if data.get("status") == "success":
                return {"city": data.get("city", "Unknown"), "region": data.get("regionName", "Unknown"), "country": data.get("country", "Unknown")}
    except Exception:
        pass
    return {"city": "Unknown", "region": "Unknown", "country": "Unknown"}

def ensure_default_users():
    """Always ensure admin user exists, with password kept in sync with
    ADMIN_USERNAME/ADMIN_PASSWORD env vars if set (so each deployment can
    have its own real first-login credentials configured on Render,
    created automatically on startup with no manual script needed);
    falls back to the original admin/rio@admin default otherwise, so
    Rio's own existing deployment behaves exactly as before unless those
    vars are explicitly set. Password is re-synced on every startup, not
    just on first creation — otherwise correcting a typo'd password in
    Render's env vars and redeploying would silently do nothing, since
    the old hashed password would already exist in the database."""
    try:
        default_username = os.environ.get("ADMIN_USERNAME", "admin").strip().lower()
        default_password = os.environ.get("ADMIN_PASSWORD", "rio@admin")
        existing = col("winner_bags_users").find_one({"username": default_username})
        if not existing:
            col("winner_bags_users").insert_one({
                "username": default_username,
                "password": hash_password(default_password),
                "role": "admin",
                "name": "Administrator",
                "scope": "all"
            })
            logger.info(f"Admin user created: username={default_username}")
        else:
            update_fields = {"password": hash_password(default_password)}
            if existing.get("role") != "admin":
                update_fields["role"] = "admin"
            if "scope" not in existing:
                update_fields["scope"] = "all"
            col("winner_bags_users").update_one({"username": default_username}, {"$set": update_fields})
    except Exception as e:
        logger.error(f"ensure_default_users error: {e}")


def ensure_default_debt_loan_auth():
    """Debt & Loan has its own, separate login - independent of the main
    winner_bags_users accounts, by explicit request. Single-user tool, so this
    just ensures one set of credentials exists (auto-created on first
    run), the same way ensure_default_users seeds the main admin account.
    Username/password come from DEBT_LOAN_USERNAME/DEBT_LOAN_PASSWORD env
    vars if set, falling back to the original default otherwise, so
    existing deployments behave exactly as before unless those vars are
    explicitly set."""
    try:
        default_username = os.environ.get("DEBT_LOAN_USERNAME", "admin").strip().lower()
        default_password = os.environ.get("DEBT_LOAN_PASSWORD", "debtloan@123")
        existing = col("debt_loan_auth").find_one({"username": default_username})
        if not existing:
            col("debt_loan_auth").insert_one({
                "username": default_username,
                "password": hash_password(default_password),
            })
            logger.info(f"Debt & Loan account created: username={default_username}")
        else:
            col("debt_loan_auth").update_one(
                {"username": default_username},
                {"$set": {"password": hash_password(default_password)}}
            )
    except Exception as e:
        logger.error(f"ensure_default_debt_loan_auth error: {e}")




def get_db():
    return _db

from contextvars import ContextVar
COMPANY_DBS = {"rio": MONGO_DB, "rainbow": MONGO_DB_RAINBOW}
_company_ctx: ContextVar[str] = ContextVar("company", default="rio")

def col(name: str) -> Collection:
    company = _company_ctx.get()
    if _client and company == "rainbow":
        return _client[MONGO_DB_RAINBOW][name]
    return _db[name]

def shared_col(name: str) -> Collection:
    """Always uses RioPrintMedia — for shared data like customers."""
    return _db[name]

# ─────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────
def clean(doc: dict) -> dict:
    """Remove MongoDB _id and convert ObjectId."""
    if doc is None:
        return None
    doc.pop("_id", None)
    return doc

def clean_list(docs) -> list:
    return [clean(d) for d in docs]

def to_float(v, default=None):
    if v is None or v == "":
        return default
    try:
        return float(v)
    except:
        return default

def to_int(v, default=None):
    if v is None or v == "":
        return default
    try:
        return int(v)
    except:
        return default

def fy_from_date(d: str) -> str:
    """Return FY string like '2024-25' from a date string."""
    try:
        dt = datetime.strptime(d[:10], "%Y-%m-%d")
        m, y = dt.month, dt.year
        if m >= 4:
            return f"{y}-{str(y+1)[-2:]}"
        else:
            return f"{y-1}-{str(y)[-2:]}"
    except:
        return ""

def current_fy() -> str:
    return fy_from_date(datetime.now().strftime("%Y-%m-%d"))

def fy_range(fy: str):
    """Return (from_date, to_date) strings for a FY like '2024-25'."""
    try:
        y = int(fy.split("-")[0])
        return f"{y}-04-01", f"{y+1}-03-31"
    except:
        return None, None

def next_invoice_no(inv_type: str, fy: str) -> str:
    """GST invoices: WB01, WB02... | Non-GST invoices: WBN01, WBN02...
    Numbering resets each financial year (matched via FY field / InvoiceDate
    range), matching how GST invoice numbering is normally expected to work.
    Continues from the highest existing number rather than resetting to 01
    outright, so it can't collide with real invoice numbers already issued
    under the old (buggy) WB0101-style scheme."""
    fy_from, fy_to = fy_range(fy)
    company = _company_ctx.get()
    is_rb = (company == "rainbow")
    if inv_type == "GST":
        pfx = "RU" if is_rb else "WB"
        rgx = r"^RU\d+$" if is_rb else r"^WB\d+$"
        skip = 2
        pipeline = [
            {"$match": {
                "InvoiceNo": {"$regex": rgx},
                "$or": [{"FY": fy}, {"$and": [{"FY": None}, {"InvoiceDate": {"$gte": fy_from, "$lte": fy_to}}]}]
            }},
            {"$project": {"num": {"$toInt": {"$substr": ["$InvoiceNo", skip, 10]}}}},
            {"$group": {"_id": None, "max": {"$max": "$num"}}}
        ]
        res = list(col("sales_invoices").aggregate(pipeline))
        n = (res[0]["max"] if res else 0) + 1
        return f"{pfx}{n:02d}"
    else:
        pfx2 = "RUN" if is_rb else "WBN"
        rgx2 = r"^RUN\d+$" if is_rb else r"^WBN\d+$"
        skip2 = 3
        pipeline = [
            {"$match": {
                "InvoiceNo": {"$regex": rgx2},
                "$or": [{"FY": fy}, {"$and": [{"FY": None}, {"InvoiceDate": {"$gte": fy_from, "$lte": fy_to}}]}]
            }},
            {"$project": {"num": {"$toInt": {"$substr": ["$InvoiceNo", skip2, 10]}}}},
            {"$group": {"_id": None, "max": {"$max": "$num"}}}
        ]
        res = list(col("sales_invoices").aggregate(pipeline))
        n = (res[0]["max"] if res else 0) + 1
        return f"{pfx2}{n:02d}"

def next_quotation_no(q_type: str, fy: str) -> str:
    """GST quotes: WB_Q01, WB_Q02... | Non-GST quotes: WB_QN01, WB_QN02...
    Same reset-per-FY / continue-from-max approach as next_invoice_no()."""
    fy_from, fy_to = fy_range(fy)
    if q_type == "GST":
        pipeline = [
            {"$match": {"QuotationNo": {"$regex": r"^WB_Q\d+$"}, "QuotationDate": {"$gte": fy_from, "$lte": fy_to}}},
            {"$project": {"num": {"$toInt": {"$substr": ["$QuotationNo", 4, 10]}}}},
            {"$group": {"_id": None, "max": {"$max": "$num"}}}
        ]
        res = list(col("quotations").aggregate(pipeline))
        n = (res[0]["max"] if res else 0) + 1
        return f"WB_Q{n:02d}"
    else:
        pipeline = [
            {"$match": {"QuotationNo": {"$regex": r"^WB_QN\d+$"}, "QuotationDate": {"$gte": fy_from, "$lte": fy_to}}},
            {"$project": {"num": {"$toInt": {"$substr": ["$QuotationNo", 5, 10]}}}},
            {"$group": {"_id": None, "max": {"$max": "$num"}}}
        ]
        res = list(col("quotations").aggregate(pipeline))
        n = (res[0]["max"] if res else 0) + 1
        return f"WB_QN{n:02d}"

def next_product_code() -> str:
    """Generates WB_P01, WB_P02, WB_P03... using the same atomic counter
    pattern as next_id() below, so codes stay clean and race-condition-free.
    (Previous version hardcoded a "WB_P01" prefix and appended a 3-digit
    counter after it, producing WB_P01001, WB_P01002 instead.)"""
    n = next_id("product_code")
    return f"WB_P{n:02d}"

def next_id(collection_name: str, field: str = "Id") -> int:
    """Atomic ID generation using a counters collection."""
    result = _db["_counters"].find_one_and_update(
        {"_id": collection_name},
        {"$inc": {"seq": 1}},
        upsert=True,
        return_document=True
    )
    return result["seq"]

async def require_db():
    """Call at the start of every endpoint to ensure DB is ready."""
    if not await ensure_db():
        raise Exception("Database not connected")

def init_indexes():
    """Create indexes for fast queries."""
    try:
        _db["sales_records"].create_index([("SNo", DESCENDING)])
        _db["daily_expenses"].create_index([("ExpDate", DESCENDING)])
        _db["sales_invoices"].create_index([("InvoiceDate", DESCENDING)])
        _db["quotations"].create_index([("QuotationDate", DESCENDING)])
        logger.info("Indexes created")
    except Exception as e:
        logger.warning(f"Index creation (non-fatal): {e}")

def init_counters():
    """Seed counters from current max IDs in each collection."""
    collections = [
        ("sales_records", "SNo"), ("daily_expenses", "Id"),
        ("notes", "Id"), ("followups", "Id"), ("rio_clients", "Id"),
        ("expense_categories", "Id"), ("jobs", "Id"), ("account_balances", "Id"),
        ("account_ledger", "Id"), ("products", "Id"), ("sales_invoices", "Id"),
        ("quotations", "Id"),
    ]
    for coll_name, field in collections:
        existing = _db["_counters"].find_one({"_id": coll_name})
        if not existing:
            pipeline = [{"$group": {"_id": None, "max": {"$max": f"${field}"}}}]
            res = list(_db[coll_name].aggregate(pipeline))
            max_val = to_int(res[0]["max"]) if res and res[0].get("max") is not None else 0
            _db["_counters"].update_one(
                {"_id": coll_name},
                {"$setOnInsert": {"seq": max_val}},
                upsert=True
            )

def set_sales_ledger_credits(sno: int, customer: str, job_name: str, payments: list):
    """Delete old ledger entries for a sales record and recreate them.
    After recreating, recalculate running balances for all affected accounts."""
    col("account_ledger").delete_many({"SalesRef": sno})
    affected = set()  # track which (account, fy) pairs need rebalancing
    for pay in payments:
        amt  = to_float(pay.get("Amt"))
        dt   = (pay.get("Date") or "").strip()
        mode = (pay.get("Mode") or "").strip()
        if not amt or amt <= 0 or not dt:
            continue
        acct_map = {
            "KVB MOM":     "KVB MOM",
            "KVB Mani":    "KVB Mani",
            "Indian Bank": "Indian Bank",
            "Cash":        "Cash Balance",
        }
        acct = acct_map.get(mode)
        if not acct:
            continue
        fy = fy_from_date(dt)
        if not fy:
            continue
        jn_str = f" — {job_name}" if job_name else ""
        desc = f"Sales: {customer}{jn_str}"
        col("account_ledger").insert_one({
            "Id": next_id("account_ledger"), "AccountName": acct, "EntryDate": dt,
            "Description": desc, "CreditAmt": amt, "DebitAmt": 0,
            "Balance": 0, "EntryType": "Credit", "FY": fy,
            "ExpenseRef": None, "SalesRef": sno
        })
        affected.add((acct, fy))
    # Recalculate running balances for all affected accounts
    for acct, fy in affected:
        recalc_ledger_balances(acct, fy)

def recalc_ledger_balances(account_name: str, fy: str):
    """
    Recalculate running balances for all entries of an account in a given FY,
    sorted by EntryDate then Id. Called after any edit or delete of a ledger entry
    to ensure the Balance column stays accurate throughout.
    """
    entries = list(col("account_ledger").find(
        {"AccountName": account_name, "FY": fy},
        sort=[("EntryDate", ASCENDING), ("Id", ASCENDING)]
    ))
    if not entries:
        return
    running = 0.0
    for entry in entries:
        running += to_float(entry.get("CreditAmt", 0))
        running -= to_float(entry.get("DebitAmt", 0))
        col("account_ledger").update_one(
            {"_id": entry["_id"]},
            {"$set": {"Balance": round(running, 2)}}
        )

# ─────────────────────────────────────────────
#  APP STARTUP
# ─────────────────────────────────────────────
_db_connected = False  # track real connection state

def _connect_mongo():
    """Attempt MongoDB connection. Returns True on success, False on failure."""
    global _client, _db, _db_connected
    if not MONGO_URI:
        logger.error("=" * 60)
        logger.error("MONGO_URI IS NOT SET!")
        logger.error("Go to Render → your service → Environment → Add:")
        logger.error("  MONGO_URI = mongodb+srv://user:pass@cluster...")
        logger.error("  MONGO_DB  = RioPrintMedia")
        logger.error("Then click Save and Manual Deploy")
        logger.error("=" * 60)
        _db_connected = False
        return False
    # Mask password for safe logging
    safe_uri = re.sub(r':(.*?)@', ':***@', MONGO_URI) if MONGO_URI else MONGO_URI
    logger.info(f"Connecting to MongoDB Atlas...")
    logger.info(f"URI: {safe_uri}")
    logger.info(f"DB:  {MONGO_DB}")
    try:
        _client = MongoClient(
            MONGO_URI,
            serverSelectionTimeoutMS=25000,
            connectTimeoutMS=25000,
            socketTimeoutMS=30000,
            tls=True,
            retryWrites=True,
        )
        logger.info("MongoClient created, pinging Atlas...")
        _client.admin.command("ping")
        _db = _client[MONGO_DB]
        _db_connected = True
        logger.info(f"✓ MongoDB Atlas connected: {MONGO_DB}")
        return True
    except Exception as e:
        _db_connected = False
        err_str = str(e)
        logger.error(f"✗ MongoDB connection FAILED: {err_str}")
        if "Authentication failed" in err_str or "auth" in err_str.lower():
            logger.error("→ CHECK: Username and password in MONGO_URI")
            logger.error("→ Special chars in password must be URL-encoded (@ = %40)")
        elif "network" in err_str.lower() or "timeout" in err_str.lower() or "timed out" in err_str.lower():
            logger.error("→ CHECK: MongoDB Atlas Network Access")
            logger.error("→ Go to Atlas → Network Access → Add IP: 0.0.0.0/0 (Allow All)")
            logger.error("→ Render uses dynamic IPs, so 0.0.0.0/0 is required")
        elif "SSL" in err_str or "TLS" in err_str:
            logger.error("→ SSL/TLS error — check Atlas cluster TLS settings")
        logger.error(f"→ URI used (masked): {safe_uri[:60]}...")
        return False

@asynccontextmanager
async def lifespan(app: FastAPI):
    # DO NOT raise — keep server alive even if DB is temporarily down.
    # Render cold starts can be slow; server retries on first real request.
    connected = _connect_mongo()
    if connected:
        try:
            init_indexes()
            logger.info("Indexes ready")
        except Exception as e:
            logger.warning(f"init_indexes error (non-fatal): {e}")
        try:
            init_counters()
            logger.info("Counters initialised")
        except Exception as e:
            logger.warning(f"init_counters error (non-fatal): {e}")
        try:
            ensure_default_users()
            logger.info("Users ready")
        except Exception as e:
            logger.warning(f"ensure_default_users error (non-fatal): {e}")
        try:
            ensure_default_debt_loan_auth()
            logger.info("Debt & Loan auth ready")
        except Exception as e:
            logger.warning(f"ensure_default_debt_loan_auth error (non-fatal): {e}")
        try:
            ensure_default_debt_loan_auth()
            logger.info("Debt & Loan auth ready")
        except Exception as e:
            logger.warning(f"ensure_default_debt_loan_auth error (non-fatal): {e}")
    else:
        logger.warning("Server started WITHOUT DB — will retry on first request")
    yield
    if _client:
        _client.close()
        logger.info("MongoDB connection closed")

app = FastAPI(title="WINNER BAGS ERP v3.0", lifespan=lifespan)

# ── Build/version marker ─────────────────────────────────────────
# Bump this string every time this file is packaged, so it's possible
# to confirm from the browser console (fetch('/api/version')) exactly
# which build is actually running on the live server — instead of
# guessing from behavior when something looks stale or cached.
BUILD_VERSION = "v95-2026-07-03"

@app.get("/api/version")
async def get_version():
    return {"build": BUILD_VERSION, "mobile_toggle_route": True}

@app.put("/api/quotations/{qid}")
async def update_quotation(qid: str, request: Request):
    if not await ensure_db(): return err("Database not connected", 503)
    try:
        data = await request.json()
        data.pop("_id", None)
        items = data.get("Items", [])
        for item in items:
            item["TaxableValue"] = to_float(item.get("TaxableValue"))
            item["GSTRate"]      = to_float(item.get("GSTRate"))
            item["Total"]        = to_float(item.get("Total"))
        from bson import ObjectId
        col("quotations").update_one(
            {"_id": ObjectId(qid)},
            {"$set": data}
        )
        return {"success": True, "quotationNo": data.get("QuotationNo", "")}
    except Exception as e:
        return err(str(e), 500)


@app.middleware("http")
async def set_company_context(request, call_next):
    company = request.query_params.get("company", "rio")
    token = _company_ctx.set("rainbow" if company == "rainbow" else "rio")
    try:
        response = await call_next(request)
    finally:
        _company_ctx.reset(token)
    return response

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

def ok(data=None, **kwargs):
    if data is not None:
        return JSONResponse(content=data)
    return JSONResponse(content={"ok": True, **kwargs})

def err(msg, status=400):
    return JSONResponse(content={"error": msg}, status_code=status)

# ─────────────────────────────────────────────
#  LIVE HTML PATCHER — applied every request
# ─────────────────────────────────────────────
# ─────────────────────────────────────────────
#  SERVE HTML DASHBOARD
# ─────────────────────────────────────────────
# ── In-memory HTML cache ────────────────────────────────────────
# The main dashboard HTML is several MB. Re-reading it from disk on
# every single page load means every concurrent request holds its own
# full copy in memory at once — on Render's free 512MB tier, a handful
# of simultaneous loads can be enough to trigger an OOM kill (which
# shows up to users as every endpoint suddenly returning 502). Loading
# it once at startup and reusing the same string avoids that entirely,
# and is also faster since there's no disk I/O per request.
_HTML_CACHE = {}

def _load_html_cached(file_path):
    if file_path in _HTML_CACHE:
        return _HTML_CACHE[file_path]
    if not os.path.exists(file_path):
        return None
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()
    _HTML_CACHE[file_path] = content
    logger.info(f"Cached {file_path} in memory ({len(content)} bytes)")
    return content


@app.get("/", response_class=HTMLResponse)
async def serve_dashboard(request: Request):
    html = _load_html_cached(HTML_FILE)
    if html is None:
        logger.error(f"HTML file not found: {HTML_FILE} — cwd={os.getcwd()}")
        return HTMLResponse(f"<h2>File not found: {HTML_FILE}</h2><p>CWD: {os.getcwd()}</p><p>Files: {os.listdir('.')[:20]}</p>", 404)
    return HTMLResponse(html)

@app.get("/cmy-tool", response_class=HTMLResponse)
async def serve_cmy_tool(request: Request, token: str = ""):
    if not await ensure_db():
        return _access_denied_page("Database not connected — please try again in a moment.")
    if not verify_admin_token(token):
        return _access_denied_page("This tool is restricted to admin accounts, and your session could not be verified.")
    cmy_file = os.environ.get("CMY_TOOL_FILE", "CMY_Color_Correction.html")
    html = _load_html_cached(cmy_file)
    if html is None:
        return HTMLResponse(f"<h2>CMY tool file not found: {cmy_file}</h2><p>CWD: {os.getcwd()}</p>", 404)
    return HTMLResponse(html)

@app.get("/cmy-layer-proof", response_class=HTMLResponse)
async def serve_cmy_layer_proof(request: Request, token: str = ""):
    if not await ensure_db():
        return _access_denied_page("Database not connected — please try again in a moment.")
    if not verify_admin_token(token):
        return _access_denied_page("This tool is restricted to admin accounts, and your session could not be verified.")
    layer_file = os.environ.get("CMY_LAYER_TOOL_FILE", "CMY_Layer_Proof_PSD.html")
    html = _load_html_cached(layer_file)
    if html is None:
        return HTMLResponse(f"<h2>CMY Layer Proof file not found: {layer_file}</h2><p>CWD: {os.getcwd()}</p>", 404)
    return HTMLResponse(html)

@app.get("/renu-contacts", response_class=HTMLResponse)
async def serve_renu_contacts(request: Request):
    """Standalone Renu Contacts page — separate URL, separate HTML file,
    own DB collection. No login required by design: opening this URL
    directly (e.g. rio-print-media.onrender.com/renu-contacts) shows the
    page immediately, on both desktop and mobile."""
    if not await ensure_db():
        return _access_denied_page("Database not connected — please try again in a moment.")
    renu_file = os.environ.get("RENU_CONTACTS_FILE", "Renu_Contacts.html")
    html = _load_html_cached(renu_file)
    if html is None:
        return HTMLResponse(f"<h2>Renu Contacts file not found: {renu_file}</h2><p>CWD: {os.getcwd()}</p>", 404)
    return HTMLResponse(html)

@app.get("/debt-and-loan", response_class=HTMLResponse)
async def serve_debt_and_loan(request: Request):
    """Standalone Debt & Loan tracker — separate URL, separate HTML file,
    own DB collections, and its OWN independent login (not the main
    winner_bags_users accounts). The page itself loads freely so its login form
    can display; the actual protection is enforced API-side, on every
    /api/debt-members and /api/debt-transactions call, via a token this
    page's own login endpoint issues."""
    if not await ensure_db():
        return _access_denied_page("Database not connected — please try again in a moment.")
    dl_file = os.environ.get("DEBT_LOAN_FILE", "Debt_and_Loan.html")
    html = _load_html_cached(dl_file)
    if html is None:
        return HTMLResponse(f"<h2>Debt and Loan file not found: {dl_file}</h2><p>CWD: {os.getcwd()}</p>", 404)
    return HTMLResponse(html)

@app.get("/pay", response_class=HTMLResponse)
async def redirect_to_upi(pa: str = "", pn: str = "", am: str = "", tn: str = "", cu: str = "INR"):
    """Shows explicit GPay / PhonePe / Paytm / Other-UPI-app buttons rather
    than auto-redirecting straight to the generic upi:// scheme. Auto-
    redirecting hands the choice to the phone's OS-level "default app for
    this link type" setting - which is very often the bank's own app
    (many bank apps register as UPI handlers too), not a real chooser.
    Giving separate buttons, each using that app's own deep-link scheme,
    means the customer picks the app themselves instead of the OS
    deciding silently on their behalf."""
    import html as html_module
    # This route is publicly reachable, so every query param must be
    # HTML-escaped before being embedded in the response - otherwise
    # anyone could craft a /pay?pn=<script>... URL and have it execute.
    safe_pa, safe_pn, safe_am, safe_tn, safe_cu = (html_module.escape(v) for v in (pa, pn, am, tn, cu))

    def build_params(extra=""):
        params = [f"pa={safe_pa}", f"pn={safe_pn}", f"cu={safe_cu}"]
        if safe_am:
            params.append(f"am={safe_am}")
        if safe_tn:
            params.append(f"tn={safe_tn}")
        return "&".join(params) + extra

    upi_generic = "upi://pay?" + build_params()
    gpay_link = "tez://upi/pay?" + build_params()
    phonepe_link = "phonepe://pay?" + build_params()
    paytm_link = "paytmmp://pay?" + build_params()

    amount_line = f"Amount: ₹{safe_am}" if safe_am else "You'll be asked to enter the amount"
    # QR image rendered via a free QR-generation image API (no JS library
    # needed) - encodes the same generic UPI link, so scanning it with
    # any UPI app's own QR scanner works exactly like tapping the link.
    from urllib.parse import quote as _urlquote
    qr_img_url = "https://api.qrserver.com/v1/create-qr-code/?size=220x220&data=" + _urlquote(upi_generic)
    html_out = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Pay {safe_pn}</title>
<style>
  body {{ font-family: -apple-system, sans-serif; text-align:center; padding:40px 20px; background:#f0f2f8; margin:0; }}
  .card {{ background:white; border-radius:14px; padding:28px 20px; max-width:360px; margin:0 auto; box-shadow:0 4px 20px rgba(0,0,0,0.08); }}
  h2 {{ margin:0 0 4px; font-size:1.1rem; color:#1a1a2e; }}
  p.sub {{ color:#888; font-size:0.85rem; margin:0 0 24px; }}
  a.app-btn, button.app-btn {{ display:flex; align-items:center; justify-content:center; gap:10px; height:48px; border-radius:10px; margin-bottom:12px; text-decoration:none; font-weight:700; font-size:0.9rem; border:none; width:100%; cursor:pointer; font-family:inherit; }}
  .gpay {{ background:#fff; border:1.5px solid #ddd; color:#1a1a2e; }}
  .phonepe {{ background:#5f259f; color:white; }}
  .paytm {{ background:#00baf2; color:white; }}
  .other {{ background:#f5f5f5; color:#555; border:1.5px solid #ddd; }}
  .qrbtn {{ background:white; color:#2e7d32; border:1.5px solid #2e7d32; }}
  .bankbtn {{ background:white; color:#1565c0; border:1.5px solid #1565c0; }}
  .bankgo {{ background:#1565c0; color:white; margin-top:8px; height:40px; }}
  #qr-box {{ display:none; margin-top:6px; }}
  #qr-box img {{ border-radius:10px; border:1.5px solid #eee; }}
  #bank-box {{ display:none; margin-top:6px; text-align:left; }}
  #bank-select {{ width:100%; height:44px; border:1.5px solid #ddd; border-radius:8px; padding:0 12px; font-size:0.85rem; font-family:inherit; margin-bottom:8px; }}
</style>
</head>
<body>
<div class="card">
<h2>Pay {safe_pn}</h2>
<p class="sub">{amount_line}</p>
<a class="app-btn gpay" href="{gpay_link}">Pay with GPay</a>
<a class="app-btn phonepe" href="{phonepe_link}">Pay with PhonePe</a>
<a class="app-btn paytm" href="{paytm_link}">Pay with Paytm</a>
<a class="app-btn other" href="{upi_generic}">Other UPI App</a>
<button class="app-btn qrbtn" onclick="document.getElementById('qr-box').style.display = document.getElementById('qr-box').style.display === 'none' ? 'block' : 'none';">Show &amp; Scan QR</button>
<div id="qr-box"><img src="{qr_img_url}" width="220" height="220" alt="UPI QR code"><p style="font-size:0.7rem;color:#888;margin-top:8px;">Scan this with any UPI app's camera/QR scanner</p></div>

<button class="app-btn bankbtn" onclick="document.getElementById('bank-box').style.display = document.getElementById('bank-box').style.display === 'none' ? 'block' : 'none';">Open Mobile Banking</button>
<div id="bank-box">
  <select id="bank-select">
    <option value="">Select your bank…</option>
    <option value="sbiyono://">SBI (YONO)</option>
    <option value="hdfcbank://">HDFC Bank</option>
    <option value="icicibank://">ICICI Bank (iMobile)</option>
    <option value="axismobile://">Axis Bank</option>
    <option value="kotak811://">Kotak Mahindra Bank</option>
    <option value="pnbone://">Punjab National Bank</option>
    <option value="indianbank://">Indian Bank</option>
  </select>
  <button class="app-btn bankgo" onclick="openBankApp()">Go</button>
  <p id="bank-error" style="font-size:0.72rem;color:#c62828;margin-top:8px;display:none;"></p>
  <p style="font-size:0.65rem;color:#aaa;margin-top:8px;">Note: this opens your bank's own app to make a transfer manually — it won't carry over the amount or payee automatically like the UPI options above.</p>
</div>

<p style="font-size:0.7rem;color:#aaa;margin-top:16px;">If a button doesn't open its app, that app may not be installed - try another option above.</p>
</div>
<script>
function openBankApp() {{
  const scheme = document.getElementById('bank-select').value;
  const errEl = document.getElementById('bank-error');
  errEl.style.display = 'none';
  if (!scheme) {{ errEl.textContent = 'Select a bank first'; errEl.style.display = 'block'; return; }}
  // There's no reliable way for a web page to confirm whether a specific
  // app is actually installed - browsers intentionally don't expose that
  // (it would be a fingerprinting/privacy risk). This timeout-based
  // approach is the common workaround: attempt the app link, and if the
  // page is still visible after ~1.5s (meaning nothing intercepted it
  // and took over), assume the app isn't installed and show a message.
  // It's an approximation, not a guarantee.
  let appOpened = false;
  window.addEventListener('blur', function onBlur() {{ appOpened = true; window.removeEventListener('blur', onBlur); }});
  window.location.href = scheme;
  setTimeout(() => {{
    if (!appOpened) {{
      errEl.textContent = "This bank's app doesn't seem to be installed, or doesn't support this link.";
      errEl.style.display = 'block';
    }}
  }}, 1500);
}}
</script>
</body></html>"""
    return HTMLResponse(html_out)

@app.get("/ledger", response_class=HTMLResponse)
async def serve_ledger(request: Request):
    """Standalone ledger diagnostic page"""
    LEDGER_FILE = "RIO_PRINT_MEDIA_ERP_ledger.html"
    if not os.path.exists(LEDGER_FILE):
        return HTMLResponse(f"<h2>Ledger file not found: {LEDGER_FILE}</h2>", 404)
    with open(LEDGER_FILE, "r", encoding="utf-8") as f:
        html = f.read()
    return HTMLResponse(html)

# ─────────────────────────────────────────────
#  MOBILE APP
# ─────────────────────────────────────────────


@app.post("/api/log")
async def client_log(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(content={"ok": False}, status_code=400)
    level   = str(body.get("level",  "INFO")).upper()
    user    = str(body.get("user",   "unknown"))
    action  = str(body.get("action", ""))
    detail  = str(body.get("detail", ""))
    msg = f"[CLIENT] user={user} | {action} | {detail}"
    if level == "ERROR":
        logger.error(msg)
    elif level == "WARN":
        logger.warning(msg)
    else:
        logger.info(msg)
    return {"ok": True}


@app.get("/api/ping")
async def ping():
    connected = await ensure_db()
    if not connected:
        return JSONResponse(
            content={"ok": False, "error": "MongoDB not connected. Check MONGO_URI on Render.", "db": MONGO_DB},
            status_code=503
        )
    # ensure_db() already verified the connection with a fresh ping internally
    # (in a worker thread) — no need to block the event loop again here.
    return {"ok": True, "db": MONGO_DB, "server": "MongoDB Atlas", "connected": True}

@app.get("/api/companies")
def list_companies():
    return JSONResponse({"companies":[{"id":"rio","name":"WINNER BAGS"},{"id":"rainbow","name":"RAINBOW UMBRELLAS"}]})

@app.post("/api/sync-rainbow")
def sync_rainbow():
    if not _client: return JSONResponse({"ok":False,"error":"DB not connected"},status_code=503)
    rio_db=_client[MONGO_DB]; rb_db=_client[MONGO_DB_RAINBOW]
    results={}
    for c in ["clients","rio_clients","products","categories","sizes"]:
        try:
            docs=list(rio_db[c].find({},{"_id":0}))
            if docs: rb_db[c].delete_many({}); rb_db[c].insert_many(docs); results[c]=len(docs)
            else: results[c]=0
        except Exception as e: results[c]=f"err:{e}"
    return JSONResponse({"ok":True,"synced":results})

@app.get("/api/debug")
async def debug_info():
    """Public debug endpoint — shows connection state without exposing credentials"""
    safe_uri = re.sub(r':(.*?)@', ':***@', MONGO_URI) if MONGO_URI else "NOT SET"
    return JSONResponse(content={
        "mongo_uri_set": bool(MONGO_URI),
        "mongo_uri_masked": safe_uri[:80] if MONGO_URI else "NOT SET",
        "mongo_db": MONGO_DB,
        "db_connected": _db_connected,
        "hint": "If db_connected=false, go to MongoDB Atlas → Network Access → Add 0.0.0.0/0"
    })

# ─────────────────────────────────────────────
#  SALES RECORDS
# ─────────────────────────────────────────────
@app.get("/api/sales")
async def get_sales(
    limit: int = Query(2000, ge=1, le=5000),
    skip: int = Query(0, ge=0),
    fy: Optional[str] = Query(None),
    fr: Optional[str] = Query(None, alias="from"),
    to: Optional[str] = Query(None),
    scope: Optional[str] = Query(None),
    user: Optional[str] = Query(None)
):
    if not await ensure_db():
        return JSONResponse(content=[], status_code=503)
    try:
        query = {}
        if fy:
            fy_from, fy_to = fy_range(fy)
            if fy_from and fy_to:
                query = {"$or": [
                    {"FY": fy},
                    {"$and": [{"FY": {"$in": [None, ""]}}, {"OrderDate": {"$gte": fy_from, "$lte": fy_to}}]}
                ]}
        if fr or to:
            # OrderDate stored as YYYY-MM-DD — filter by range
            date_q = {}
            if fr: date_q["$gte"] = fr
            if to: date_q["$lte"] = to
            if query:
                query = {"$and": [query, {"OrderDate": date_q}]}
            else:
                query["OrderDate"] = date_q
        if scope == "own" and user:
            query["createdBy"] = user
        rows = list(col("sales_records").find(query, {"_id": 0})
                    .sort("SNo", DESCENDING).skip(skip).limit(limit))
        return JSONResponse(content=rows)
    except Exception as e:
        logger.error(f"get_sales error: {e}")
        return JSONResponse(content=[], status_code=500)

def _write_sales_stock_out(sno, items, order_date):
    """Automatically writes Stock OUT entries for a sale's line items, mirroring
    how create_purchase() auto-writes Stock IN entries. Matches products by
    ProductName (same field Purchases uses), since both the Sales and Purchase
    product dropdowns are sourced from the same master Products list, so the
    names always line up exactly — no free-text mismatch risk.
    Tags each entry with Reference=f"SALE-{sno}" so put_sales/delete_sales can
    find and clear the old entries before writing fresh ones (keeps stock
    correct across edits instead of double-counting)."""
    ref = f"SALE-{sno}"
    col("stock_ledger").delete_many({"Reference": ref})
    if not items:
        return
    for it in items:
        name = (it.get("ProductName") or "").strip()
        qty = to_float(it.get("Qty"), 0.0)
        if not name or qty <= 0:
            continue
        stock_id = next_id("stock_ledger")
        col("stock_ledger").insert_one({
            "Id":          stock_id,
            "Date":        order_date or datetime.now().strftime("%Y-%m-%d"),
            "ProductName": name,
            "Type":        "OUT",
            "Qty":         qty,
            "Unit":        "Nos",
            "Rate":        to_float(it.get("Rate"), 0.0),
            "Reference":   ref,
            "Remarks":     f"Sales entry S{sno}",
            "CreatedAt":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        })

def _sanitize_sale_items(items):
    """Validates/cleans the Rio dynamic multi-product Items array before storage.
    Unlimited products (Add Product button) — each item is a distinct product row
    with its own size/qty/rate/GST rate, unlike the old fixed Size1/2/3 fields."""
    if not isinstance(items, list):
        return []
    out = []
    for it in items:
        if not isinstance(it, dict):
            continue
        qty = to_float(it.get("Qty"), 0.0)
        rate = to_float(it.get("Rate"), 0.0)
        if not (it.get("ProductId") or qty or rate):
            continue
        out.append({
            "ProductId":   it.get("ProductId", ""),
            "ProductName": it.get("ProductName", ""),
            "HSN":         it.get("HSN", ""),
            "HSN":         it.get("HSN", ""),
            "Size":        it.get("Size", ""),
            "Qty":         qty,
            "Rate":        rate,
            "Amt":         to_float(it.get("Amt"), 0.0),
            "GSTRate":     to_float(it.get("GSTRate"), 0.0),
        })
    return out

@app.post("/api/sales")
async def post_sales(request: Request):
    if not await ensure_db(): return err("Database not connected", 503)
    b = await request.json()
    sno = next_id("sales_records", "SNo")
    doc = {
        "SNo": sno,
        "createdBy":          b.get("createdBy", ""),
        "Customer":           b.get("Customer", ""),
        "Category":           b.get("Category", ""),
        "ProductSize":        b.get("ProductSize", ""),
        "Size1":              b.get("Size1", ""),
        "Qty1":               b.get("Qty1", ""),
        "Size2":              b.get("Size2", ""),
        "Qty2":               b.get("Qty2", ""),
        "Size3":              b.get("Size3", ""),
        "Qty3":               b.get("Qty3", ""),
        "Items":              _sanitize_sale_items(b.get("Items")),
        "BillingType":        b.get("BillingType", ""),
        "JobName":            b.get("JobName", ""),
        "OrderDate":          b.get("OrderDate"),
        "TotalAmount":        to_float(b.get("TotalAmount")),
        "AdvanceAmt":         to_float(b.get("AdvanceAmt")),
        "AdvanceDate":        b.get("AdvanceDate"),
        "AdvanceMode":        b.get("AdvanceMode", ""),
        "AdvanceDetails":     b.get("AdvanceDetails", ""),
        "BalanceSettledAmt":  to_float(b.get("BalanceSettledAmt")),
        "BalanceDate":        b.get("BalanceDate"),
        "BalanceMode":        b.get("BalanceMode", ""),
        "Balance1Details":    b.get("Balance1Details", ""),
        "Balance2Amt":        to_float(b.get("Balance2Amt")),
        "Balance2Date":       b.get("Balance2Date"),
        "Balance2Mode":       b.get("Balance2Mode", ""),
        "Balance2Details":    b.get("Balance2Details", ""),
        "Balance3Amt":        to_float(b.get("Balance3Amt")),
        "Balance3Date":       b.get("Balance3Date"),
        "Balance3Mode":       b.get("Balance3Mode", ""),
        "Balance3Details":    b.get("Balance3Details", ""),
        "RemainingBalance":   to_float(b.get("RemainingBalance")),
        "CustomerGST":        b.get("CustomerGST", ""),
        "CustomerStateCode":  b.get("CustomerStateCode", ""),
        "ProductId":          to_int(b.get("ProductId")),
        "ProductId2":         to_int(b.get("ProductId2")),
        "Rate1":              to_float(b.get("Rate1")),
        "Rate2":              to_float(b.get("Rate2")),
        "Rate3":              to_float(b.get("Rate3")),
        "Amt1":               to_float(b.get("Amt1"), 0.0),
        "Amt2":               to_float(b.get("Amt2"), 0.0),
        "Amt3":               to_float(b.get("Amt3"), 0.0),
        "GSTRate1":           to_float(b.get("GSTRate1"), 0.0),
        "GSTRate2":           to_float(b.get("GSTRate2"), 0.0),
        "GSTRate3":           to_float(b.get("GSTRate3"), 0.0),
        "InvoiceNo":          b.get("InvoiceNo", ""),
        "PFDesc":             b.get("PFDesc", ""),
        "PFAmt":              to_float(b.get("PFAmt"), 0.0),
        "PFGst":              to_float(b.get("PFGst"), 0.0),
        "PFTotal":            to_float(b.get("PFTotal"), 0.0),
        "EyeletQty":          to_float(b.get("EyeletQty"), 0.0),
        "EyeletRate":         to_float(b.get("EyeletRate"), 0.0),
        "EyeletTotal":        to_float(b.get("EyeletTotal"), 0.0),
        "FY":                 fy_from_date(b.get("OrderDate") or datetime.now().strftime("%Y-%m-%d")),
        "UpdatedAt":          datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    col("sales_records").insert_one(doc)
    # Automatically write Stock OUT entries for each product sold
    _write_sales_stock_out(sno, doc.get("Items"), doc.get("OrderDate"))
    # Auto-add client
    if doc["Customer"]:
        shared_col("rio_clients").update_one(
            {"ClientName": doc["Customer"]},
            {"$setOnInsert": {"Id": next_id("rio_clients"), "ClientName": doc["Customer"], "createdBy": doc.get("createdBy", "")}},
            upsert=True
        )
    # Ledger credits
    payments = [
        {"Amt": doc["AdvanceAmt"],        "Date": doc["AdvanceDate"],  "Mode": doc["AdvanceMode"]},
        {"Amt": doc["BalanceSettledAmt"], "Date": doc["BalanceDate"],  "Mode": doc["BalanceMode"]},
        {"Amt": doc["Balance2Amt"],       "Date": doc["Balance2Date"], "Mode": doc["Balance2Mode"]},
        {"Amt": doc["Balance3Amt"],       "Date": doc["Balance3Date"], "Mode": doc["Balance3Mode"]},
    ]
    set_sales_ledger_credits(sno, doc["Customer"], doc["JobName"], payments)
    return ok({"ok": True, "SNo": sno})

@app.put("/api/sales/{sno}")
async def put_sales(sno: int, request: Request):
    if not await ensure_db(): return err("Database not connected", 503)
    b = await request.json()
    update = {
        "Customer":           b.get("Customer", ""),
        "Category":           b.get("Category", ""),
        "ProductSize":        b.get("ProductSize", ""),
        "Size1":              b.get("Size1", ""),
        "Qty1":               b.get("Qty1", ""),
        "Size2":              b.get("Size2", ""),
        "Qty2":               b.get("Qty2", ""),
        "Size3":              b.get("Size3", ""),
        "Qty3":               b.get("Qty3", ""),
        "Items":              _sanitize_sale_items(b.get("Items")),
        "BillingType":        b.get("BillingType", ""),
        "JobName":            b.get("JobName", ""),
        "OrderDate":          b.get("OrderDate"),
        "TotalAmount":        to_float(b.get("TotalAmount")),
        "AdvanceAmt":         to_float(b.get("AdvanceAmt")),
        "AdvanceDate":        b.get("AdvanceDate"),
        "AdvanceMode":        b.get("AdvanceMode", ""),
        "AdvanceDetails":     b.get("AdvanceDetails", ""),
        "BalanceSettledAmt":  to_float(b.get("BalanceSettledAmt")),
        "BalanceDate":        b.get("BalanceDate"),
        "BalanceMode":        b.get("BalanceMode", ""),
        "Balance1Details":    b.get("Balance1Details", ""),
        "Balance2Amt":        to_float(b.get("Balance2Amt")),
        "Balance2Date":       b.get("Balance2Date"),
        "Balance2Mode":       b.get("Balance2Mode", ""),
        "Balance2Details":    b.get("Balance2Details", ""),
        "Balance3Amt":        to_float(b.get("Balance3Amt")),
        "Balance3Date":       b.get("Balance3Date"),
        "Balance3Mode":       b.get("Balance3Mode", ""),
        "Balance3Details":    b.get("Balance3Details", ""),
        "RemainingBalance":   to_float(b.get("RemainingBalance")),
        "CustomerGST":        b.get("CustomerGST", ""),
        "CustomerStateCode":  b.get("CustomerStateCode", ""),
        "ProductId":          to_int(b.get("ProductId")),
        "ProductId2":         to_int(b.get("ProductId2")),
        "Rate1":              to_float(b.get("Rate1")),
        "Rate2":              to_float(b.get("Rate2")),
        "Rate3":              to_float(b.get("Rate3")),
        "Amt1":               to_float(b.get("Amt1"), 0.0),
        "Amt2":               to_float(b.get("Amt2"), 0.0),
        "Amt3":               to_float(b.get("Amt3"), 0.0),
        "GSTRate1":           to_float(b.get("GSTRate1"), 0.0),
        "GSTRate2":           to_float(b.get("GSTRate2"), 0.0),
        "GSTRate3":           to_float(b.get("GSTRate3"), 0.0),
        "PFDesc":             b.get("PFDesc", ""),
        "PFAmt":              to_float(b.get("PFAmt"), 0.0),
        "PFGst":              to_float(b.get("PFGst"), 0.0),
        "PFTotal":            to_float(b.get("PFTotal"), 0.0),
        "EyeletQty":          to_float(b.get("EyeletQty"), 0.0),
        "EyeletRate":         to_float(b.get("EyeletRate"), 0.0),
        "EyeletTotal":        to_float(b.get("EyeletTotal"), 0.0),
        "FY":                 fy_from_date(b.get("OrderDate") or datetime.now().strftime("%Y-%m-%d")),
        "UpdatedAt":          datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    col("sales_records").update_one({"SNo": sno}, {"$set": update})
    # Re-write Stock OUT entries to match the edited quantities/products
    _write_sales_stock_out(sno, update.get("Items"), update.get("OrderDate"))
    payments = [
        {"Amt": update["AdvanceAmt"],        "Date": update["AdvanceDate"],  "Mode": update["AdvanceMode"]},
        {"Amt": update["BalanceSettledAmt"], "Date": update["BalanceDate"],  "Mode": update["BalanceMode"]},
        {"Amt": update["Balance2Amt"],       "Date": update["Balance2Date"], "Mode": update["Balance2Mode"]},
        {"Amt": update["Balance3Amt"],       "Date": update["Balance3Date"], "Mode": update["Balance3Mode"]},
    ]
    set_sales_ledger_credits(sno, update["Customer"], update["JobName"], payments)
    return ok()

@app.delete("/api/sales/{sno}")
async def delete_sales(sno: int):
    if not await ensure_db(): return err("Database not connected", 503)
    # Find affected accounts before deleting so we can recalc their balances
    affected_entries = list(col("account_ledger").find(
        {"SalesRef": sno}, {"AccountName": 1, "FY": 1}
    ))
    affected = set((e["AccountName"], e["FY"]) for e in affected_entries if e.get("AccountName") and e.get("FY"))
    col("account_ledger").delete_many({"SalesRef": sno})
    col("sales_records").delete_one({"SNo": sno})
    col("stock_ledger").delete_many({"Reference": f"SALE-{sno}"})
    # Recalculate running balances for all affected accounts
    for acct, fy in affected:
        recalc_ledger_balances(acct, fy)
    return ok()

@app.post("/api/sales/{sno}/invoiceno")
async def patch_sales_invoiceno(sno: int, request: Request):
    if not await ensure_db(): return err("Database not connected", 503)
    b = await request.json()
    col("sales_records").update_one({"SNo": sno}, {"$set": {"InvoiceNo": b.get("InvoiceNo", "")}})
    return ok()

# ─────────────────────────────────────────────
#  EXPENSES
# ─────────────────────────────────────────────
@app.get("/api/expenses")
async def get_expenses(scope: Optional[str] = Query(None), user: Optional[str] = Query(None)):
    if not await ensure_db(): return JSONResponse(content=[], status_code=503)
    query = {}
    if scope == "own" and user:
        query["createdBy"] = user
    rows = list(col("daily_expenses").find(query, {"_id": 0}).sort([("ExpDate", DESCENDING), ("Id", DESCENDING)]))
    return JSONResponse(content=rows)

@app.post("/api/expenses")
async def post_expenses(request: Request):
    if not await ensure_db(): return err("Database not connected", 503)
    b = await request.json()
    new_id = next_id("daily_expenses")
    amt = to_float(b.get("Amount"), 0.0)
    doc = {
        "Id":          new_id,
        "createdBy":   (b.get("createdBy") or "").strip(),
        "ExpDate":     b.get("ExpDate"),
        "Category":    b.get("Category", ""),
        "SubCategory": b.get("SubCategory", ""),
        "PaymentMode": b.get("PaymentMode", ""),
        "Description": b.get("Description", ""),
        "Amount":      amt,
    }
    col("daily_expenses").insert_one(doc)
    # Auto-create ledger debit
    pm = (b.get("PaymentMode") or "").strip()
    acct_map = {"KVB MOM":"KVB MOM","KVB Mani":"KVB Mani","Indian Bank":"Indian Bank","Cash":"Cash Balance"}
    acct = acct_map.get(pm)
    if acct and new_id:
        exp_date = (b.get("ExpDate") or "").strip()
        fy = fy_from_date(exp_date)
        if fy:
            sub_cat = (b.get("SubCategory") or "").strip()
            desc_str = (b.get("Description") or "").strip()
            desc = f"Expense: {sub_cat} — {desc_str}" if desc_str else f"Expense: {sub_cat}"
            last = col("account_ledger").find_one(
                {"AccountName": acct, "FY": fy},
                sort=[("EntryDate", DESCENDING), ("Id", DESCENDING)]
            )
            prev_bal = to_float(last["Balance"]) if last else 0.0
            new_bal  = prev_bal - amt
            led_id   = next_id("account_ledger")
            col("account_ledger").insert_one({
                "Id": led_id, "AccountName": acct, "EntryDate": exp_date,
                "Description": desc, "CreditAmt": 0, "DebitAmt": amt,
                "Balance": new_bal, "EntryType": "Expense", "FY": fy,
                "ExpenseRef": new_id, "SalesRef": None
            })
    return ok({"ok": True, "id": new_id})


@app.put("/api/expense/{exp_id}")
@app.put("/api/billing/expense/{exp_id}")
async def put_expense(exp_id: int, request: Request):
    if not await ensure_db(): return err("Database not connected", 503)
    b = await request.json()
    amt = to_float(b.get("Amount"), 0.0)
    result = col("daily_expenses").update_one(
        {"Id": exp_id},
        {"$set": {
            "ExpDate":     b.get("ExpDate", ""),
            "Category":    b.get("Category", ""),
            "SubCategory": b.get("SubCategory", ""),
            "PaymentMode": b.get("PaymentMode", ""),
            "Description": b.get("Description", ""),
            "Amount":      amt,
        }}
    )
    if result.matched_count == 0:
        return err("Expense not found", 404)
    return ok({"success": True})

@app.delete("/api/expenses/{exp_id}")
async def delete_expense(exp_id: int):
    if not await ensure_db(): return err("Database not connected", 503)
    col("account_ledger").delete_many({"ExpenseRef": exp_id})
    col("daily_expenses").delete_one({"Id": exp_id})
    return ok()

# ─────────────────────────────────────────────
#  NOTES
# ─────────────────────────────────────────────
@app.get("/api/notes")
async def get_notes(fr: Optional[str] = Query(None, alias="from"), to: Optional[str] = Query(None)):
    query = {}
    if fr: query["NoteDate"] = {"$gte": fr}
    if to: query.setdefault("NoteDate", {})["$lte"] = to
    rows = list(col("notes").find(query, {"_id": 0}).sort([("NoteDate", DESCENDING), ("Id", DESCENDING)]))
    return JSONResponse(content=rows)

@app.post("/api/notes")
async def post_notes(request: Request):
    if not await ensure_db(): return err("Database not connected", 503)
    b = await request.json()
    new_id = next_id("notes")
    col("notes").insert_one({"Id": new_id, "NoteDate": b.get("NoteDate"), "NoteText": b.get("NoteText", ""), "NoteDescription": b.get("NoteDescription", "")})
    return ok()

@app.put("/api/notes/{note_id}")
async def put_notes(note_id: int, request: Request):
    if not await ensure_db(): return err("Database not connected", 503)
    b = await request.json()
    col("notes").update_one({"Id": note_id}, {"$set": {"NoteDate": b.get("NoteDate"), "NoteText": b.get("NoteText", ""), "NoteDescription": b.get("NoteDescription", "")}})
    return ok()

@app.delete("/api/notes/{note_id}")
async def delete_notes(note_id: int):
    if not await ensure_db(): return err("Database not connected", 503)
    col("notes").delete_one({"Id": note_id})
    return ok()

# ─────────────────────────────────────────────
#  FOLLOWUPS
# ─────────────────────────────────────────────
def get_user_from_request(request: Request):
    """Extracts the current logged-in user from the Authorization: Bearer
    header the frontend's api() helper already sends on every call, reusing
    the same session_token lookup Renu Contacts uses for its query-param
    version. Returns None if there's no valid session."""
    auth = request.headers.get("authorization", "")
    token = auth[7:] if auth.lower().startswith("bearer ") else ""
    return verify_user_token(token)

@app.get("/api/followups")
async def get_followups():
    if not await ensure_db(): return JSONResponse(content=[], status_code=503)
    rows = list(col("followups").find({}, {"_id": 0}).sort([("IsAddressed", ASCENDING), ("FollowupDate", ASCENDING), ("Id", ASCENDING)]))
    return JSONResponse(content=rows)

@app.post("/api/followups")
async def post_followups(request: Request):
    if not await ensure_db(): return err("Database not connected", 503)
    b = await request.json()
    new_id = next_id("followups")
    user = get_user_from_request(request)
    user = get_user_from_request(request)
    col("followups").insert_one({
        "Id": new_id,
        "FollowupDate": b.get("FollowupDate"),
        "FollowupTime": b.get("FollowupTime") or "09:00",
        "FollowupTime": b.get("FollowupTime") or "09:00",
        "Priority":     b.get("Priority", ""),
        "FollowupText": b.get("FollowupText", ""),
        "IsAddressed":  0,
        "CreatedBy":    user.get("username") if user else None,
        "SnoozedUntil": None,
        "CreatedBy":    user.get("username") if user else None,
        "SnoozedUntil": None,
    })
    return ok()


# ─────────────────────────────────────────────
#  CONTACTS
# ─────────────────────────────────────────────

@app.get("/api/contacts")
async def get_contacts(
    search: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    user: Optional[str] = Query(None)
):
    if not await ensure_db(): return err("Database not connected", 503)
    query = {}
    if search:
        rgx = {"$regex": search, "$options": "i"}
        query["$or"] = [{"Name": rgx}, {"Phone": rgx}, {"Place": rgx}]
    if category and category != "all":
        query["Category"] = category
    skip = (page - 1) * limit
    total = shared_col("contacts").count_documents(query)
    rows = list(shared_col("contacts").find(query, {"_id": 0})
                .sort("Name", 1).skip(skip).limit(limit))
    return JSONResponse(content={"total": total, "page": page, "limit": limit, "rows": rows})

@app.post("/api/contacts")
async def save_contact(request: Request):
    if not await ensure_db(): return err("Database not connected", 503)
    b = await request.json()
    b.pop("_id", None)
    contact_id = b.get("Id")
    if contact_id:
        # Update existing
        shared_col("contacts").update_one({"Id": contact_id}, {"$set": b})
    else:
        # Check duplicate phone
        phone = b.get("Phone", "").strip()
        if phone:
            existing = shared_col("contacts").find_one({"Phone": phone}, {"_id": 0})
            if existing:
                return err(f"Phone {phone} already exists for {existing.get('Name','')}", 409)
        new_id = next_id("contacts")
        b["Id"] = new_id
        shared_col("contacts").insert_one(b)
    return ok({"Id": b.get("Id")})

@app.delete("/api/contacts/{contact_id}")
async def delete_contact(contact_id: int):
    if not await ensure_db(): return err("Database not connected", 503)
    shared_col("contacts").delete_one({"Id": contact_id})
    return ok()

# ── Renu Contacts — separate feature, separate collection, Rio-only (not
# shared with Rainbow the way the main Contacts tab is) ────────────────
@app.get("/api/renu-contacts")
async def get_renu_contacts(
    search: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
):
    if not await ensure_db(): return err("Database not connected", 503)
    query = {}
    if search:
        rgx = {"$regex": search, "$options": "i"}
        query["$or"] = [{"Name": rgx}, {"Phone": rgx}, {"Place": rgx}, {"Details": rgx}]
    skip = (page - 1) * limit
    total = col("renu_contacts").count_documents(query)
    rows = list(col("renu_contacts").find(query, {"_id": 0})
                .sort("Name", 1).skip(skip).limit(limit))
    return JSONResponse(content={"total": total, "page": page, "limit": limit, "rows": rows})

@app.post("/api/renu-contacts")
async def save_renu_contact(request: Request):
    if not await ensure_db(): return err("Database not connected", 503)
    b = await request.json()
    b.pop("_id", None)
    contact_id = b.get("Id")
    if contact_id:
        col("renu_contacts").update_one({"Id": contact_id}, {"$set": b})
    else:
        phone = (b.get("Phone") or "").strip()
        if phone:
            existing = col("renu_contacts").find_one({"Phone": phone}, {"_id": 0})
            if existing:
                return err(f"Phone {phone} already exists for {existing.get('Name','')}", 409)
        new_id = next_id("renu_contacts")
        b["Id"] = new_id
        col("renu_contacts").insert_one(b)
    return ok({"Id": b.get("Id")})

@app.delete("/api/renu-contacts/{contact_id}")
async def delete_renu_contact(contact_id: int):
    if not await ensure_db(): return err("Database not connected", 503)
    col("renu_contacts").delete_one({"Id": contact_id})
    return ok()

# ── Debt & Loan — personal money lent to / borrowed from friends.
# Own, separate login here (not the main winner_bags_users accounts) - a single
# set of credentials, auto-created on first run by ensure_default_debt_loan_auth.
def verify_debt_loan_token(token: str):
    if not token:
        return None
    acct = col("debt_loan_auth").find_one({"session_token": token}, {"_id": 0})
    return acct

@app.post("/api/debt-loan/login")
async def debt_loan_login(request: Request):
    if not await ensure_db(): return err("Database not connected", 503)
    b = await request.json()
    username = (b.get("username") or "").strip().lower()
    password = (b.get("password") or "").strip()
    if not username or not password:
        return err("Username and password required", 400)
    acct = col("debt_loan_auth").find_one({"username": username})
    if not acct or not verify_password(password, acct["password"]):
        return err("Invalid username or password", 401)
    token = secrets.token_hex(32)
    col("debt_loan_auth").update_one({"username": username}, {"$set": {"session_token": token}})
    return JSONResponse(content={"ok": True, "username": username, "token": token})

@app.post("/api/debt-loan/change-password")
async def debt_loan_change_password(request: Request):
    if not await ensure_db(): return err("Database not connected", 503)
    b = await request.json()
    token = (b.get("token") or "").strip()
    old_password = (b.get("old_password") or "").strip()
    new_password = (b.get("new_password") or "").strip()
    acct = verify_debt_loan_token(token)
    if not acct:
        return err("Session expired. Please log in again.", 401)
    if not verify_password(old_password, acct["password"]):
        return err("Current password is incorrect", 401)
    if len(new_password) < 6:
        return err("New password must be at least 6 characters", 400)
    col("debt_loan_auth").update_one(
        {"username": acct["username"]},
        {"$set": {"password": hash_password(new_password)}}
    )
    return ok()

# Two collections: members (the people), transactions (each amount
# given/taken/returned, referencing a member by Id). Rio-only, not
# shared with Rainbow. Balances are never stored directly — always
# computed live from the transaction history, so the numbers can't
# silently drift out of sync with reality.
@app.get("/api/debt-members")
async def get_debt_members(x_debt_token: str = Header(None)):
    if not await ensure_db(): return err("Database not connected", 503)
    if not verify_debt_loan_token(x_debt_token): return err("Not logged in", 401)
    members = list(col("debt_members").find({}, {"_id": 0}).sort("Name", 1))
    txns = list(col("debt_transactions").find({}, {"_id": 0}))
    balances = {}
    for t in txns:
        mid = t.get("MemberId")
        amt = float(t.get("Amount") or 0)
        bal = balances.get(mid, 0.0)
        ttype = t.get("Type")
        if ttype == "gave": bal += amt
        elif ttype == "returned_by_them": bal -= amt
        elif ttype == "took": bal -= amt
        elif ttype == "returned_by_me": bal += amt
        balances[mid] = bal
    for m in members:
        m["Balance"] = round(balances.get(m.get("Id"), 0.0), 2)
    return JSONResponse(content={"rows": members})

@app.post("/api/debt-members")
async def save_debt_member(request: Request, x_debt_token: str = Header(None)):
    if not await ensure_db(): return err("Database not connected", 503)
    if not verify_debt_loan_token(x_debt_token): return err("Not logged in", 401)
    b = await request.json()
    b.pop("_id", None)
    member_id = b.get("Id")
    if member_id:
        col("debt_members").update_one({"Id": member_id}, {"$set": b})
    else:
        name = (b.get("Name") or "").strip()
        if not name:
            return err("Name is required", 400)
        new_id = next_id("debt_members")
        b["Id"] = new_id
        col("debt_members").insert_one(b)
    return ok({"Id": b.get("Id")})

@app.delete("/api/debt-members/{member_id}")
async def delete_debt_member(member_id: int, x_debt_token: str = Header(None)):
    if not await ensure_db(): return err("Database not connected", 503)
    if not verify_debt_loan_token(x_debt_token): return err("Not logged in", 401)
    col("debt_members").delete_one({"Id": member_id})
    col("debt_transactions").delete_many({"MemberId": member_id})
    return ok()

@app.get("/api/debt-transactions")
async def get_debt_transactions(member_id: Optional[int] = Query(None), x_debt_token: str = Header(None)):
    if not await ensure_db(): return err("Database not connected", 503)
    if not verify_debt_loan_token(x_debt_token): return err("Not logged in", 401)
    query = {"MemberId": member_id} if member_id is not None else {}
    rows = list(col("debt_transactions").find(query, {"_id": 0}).sort("Date", -1))
    return JSONResponse(content={"rows": rows})

@app.post("/api/debt-transactions")
async def save_debt_transaction(request: Request, x_debt_token: str = Header(None)):
    if not await ensure_db(): return err("Database not connected", 503)
    if not verify_debt_loan_token(x_debt_token): return err("Not logged in", 401)
    b = await request.json()
    b.pop("_id", None)
    if not b.get("MemberId"):
        return err("MemberId is required", 400)
    if b.get("Type") not in ("gave", "returned_by_them", "took", "returned_by_me"):
        return err("Invalid transaction Type", 400)
    txn_id = b.get("Id")
    if txn_id:
        col("debt_transactions").update_one({"Id": txn_id}, {"$set": b})
    else:
        new_id = next_id("debt_transactions")
        b["Id"] = new_id
        col("debt_transactions").insert_one(b)
    return ok({"Id": b.get("Id")})

@app.delete("/api/debt-transactions/{txn_id}")
async def delete_debt_transaction(txn_id: int, x_debt_token: str = Header(None)):
    if not await ensure_db(): return err("Database not connected", 503)
    if not verify_debt_loan_token(x_debt_token): return err("Not logged in", 401)
    col("debt_transactions").delete_one({"Id": txn_id})
    return ok()

# ── Debt & Loan: Bank Loans — multiple separate loans taken from banks,
# each with its own monthly repayments (each repayment tagged with which
# member paid it) and its own "lent out to friends" balance, since money
# given to a friend can be sourced from a specific bank loan rather than
# your own money - see BankLoanId on debt_transactions below.
@app.get("/api/debt-bank-loans")
async def get_bank_loans(x_debt_token: str = Header(None)):
    if not await ensure_db(): return err("Database not connected", 503)
    if not verify_debt_loan_token(x_debt_token): return err("Not logged in", 401)
    loans = list(col("debt_bank_loans").find({}, {"_id": 0}).sort("DateTaken", -1))
    payments = list(col("debt_bank_loan_payments").find({}, {"_id": 0}))
    lent_out_txns = list(col("debt_transactions").find({"Source": "bank_loan"}, {"_id": 0}))
    repaid_by_loan = {}
    for p in payments:
        lid = p.get("BankLoanId")
        repaid_by_loan[lid] = repaid_by_loan.get(lid, 0.0) + float(p.get("Amount") or 0)
    lent_by_loan = {}
    for t in lent_out_txns:
        lid = t.get("BankLoanId")
        lent_by_loan[lid] = lent_by_loan.get(lid, 0.0) + float(t.get("Amount") or 0)
    for l in loans:
        principal = float(l.get("PrincipalAmount") or 0)
        repaid = round(repaid_by_loan.get(l.get("Id"), 0.0), 2)
        lent_out = round(lent_by_loan.get(l.get("Id"), 0.0), 2)
        # Outstanding must be measured against the TOTAL repayment (the
        # sum of every month's expected EMI, which includes interest when
        # the loan has any) - not the bare principal. Using bare principal
        # was the bug: once enough months are paid that repaid exceeds the
        # principal alone (which happens well before the loan is actually
        # finished whenever interest is involved), this went negative /
        # hit zero early, instead of tracking correctly to the real end.
        schedule = l.get("EMISchedule") or []
        total_repayment = sum(float(e.get("ExpectedAmount") or 0) for e in schedule) if schedule else principal
        l["RepaidToBank"] = repaid
        l["OutstandingToBank"] = round(max(total_repayment - repaid, 0), 2)
        l["LentOutToFriends"] = lent_out
        l["AvailableWithYou"] = round(principal - lent_out, 2)
    return JSONResponse(content={"rows": loans})

@app.post("/api/debt-bank-loans")
async def save_bank_loan(request: Request, x_debt_token: str = Header(None)):
    if not await ensure_db(): return err("Database not connected", 503)
    if not verify_debt_loan_token(x_debt_token): return err("Not logged in", 401)
    b = await request.json()
    b.pop("_id", None)
    loan_id = b.get("Id")
    if loan_id:
        col("debt_bank_loans").update_one({"Id": loan_id}, {"$set": b})
    else:
        name = (b.get("LoanName") or "").strip()
        if not name:
            return err("Loan name is required", 400)
        if not b.get("PrincipalAmount"):
            return err("Principal amount is required", 400)
        new_id = next_id("debt_bank_loans")
        b["Id"] = new_id
        col("debt_bank_loans").insert_one(b)
    return ok({"Id": b.get("Id")})

@app.delete("/api/debt-bank-loans/{loan_id}")
async def delete_bank_loan(loan_id: int, x_debt_token: str = Header(None)):
    if not await ensure_db(): return err("Database not connected", 503)
    if not verify_debt_loan_token(x_debt_token): return err("Not logged in", 401)
    col("debt_bank_loans").delete_one({"Id": loan_id})
    col("debt_bank_loan_payments").delete_many({"BankLoanId": loan_id})
    return ok()

@app.get("/api/debt-bank-loan-payments")
async def get_bank_loan_payments(loan_id: Optional[int] = Query(None), x_debt_token: str = Header(None)):
    if not await ensure_db(): return err("Database not connected", 503)
    if not verify_debt_loan_token(x_debt_token): return err("Not logged in", 401)
    query = {"BankLoanId": loan_id} if loan_id is not None else {}
    rows = list(col("debt_bank_loan_payments").find(query, {"_id": 0}).sort("Date", -1))
    return JSONResponse(content={"rows": rows})

@app.post("/api/debt-bank-loan-payments")
async def save_bank_loan_payment(request: Request, x_debt_token: str = Header(None)):
    if not await ensure_db(): return err("Database not connected", 503)
    if not verify_debt_loan_token(x_debt_token): return err("Not logged in", 401)
    b = await request.json()
    b.pop("_id", None)
    if not b.get("BankLoanId"):
        return err("BankLoanId is required", 400)
    if not b.get("Amount"):
        return err("Amount is required", 400)
    pay_id = b.get("Id")
    if pay_id:
        col("debt_bank_loan_payments").update_one({"Id": pay_id}, {"$set": b})
    else:
        new_id = next_id("debt_bank_loan_payments")
        b["Id"] = new_id
        col("debt_bank_loan_payments").insert_one(b)
    return ok({"Id": b.get("Id")})

@app.delete("/api/debt-bank-loan-payments/{payment_id}")
async def delete_bank_loan_payment(payment_id: int, x_debt_token: str = Header(None)):
    if not await ensure_db(): return err("Database not connected", 503)
    if not verify_debt_loan_token(x_debt_token): return err("Not logged in", 401)
    col("debt_bank_loan_payments").delete_one({"Id": payment_id})
    return ok()

# ── Login Logs — audit trail of every successful login, recorded from
# within /api/auth/login itself. Tracks what's actually available from a
# server-side request: IP address, OS/browser (parsed from User-Agent -
# not a real "machine name", since browsers don't expose the device's
# actual hostname to web pages), and an approximate city from IP
# geolocation. See get_client_ip / parse_user_agent / get_ip_geolocation.
@app.get("/api/login-logs")
async def get_login_logs(
    username: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
):
    if not await ensure_db(): return err("Database not connected", 503)
    query = {}
    if username:
        query["Username"] = {"$regex": username, "$options": "i"}
    skip = (page - 1) * limit
    total = col("rio_login_logs").count_documents(query)
    rows = list(col("rio_login_logs").find(query, {"_id": 0})
                .sort("LoginTime", -1).skip(skip).limit(limit))
    return JSONResponse(content={"total": total, "page": page, "limit": limit, "rows": rows})

@app.get("/api/contacts/categories")
async def get_contact_categories():
    if not await ensure_db(): return err("Database not connected", 503)
    # Get custom categories + defaults
    custom = list(shared_col("contact_categories").find({}, {"_id": 0}).sort("Name", 1))
    defaults = [
        {"Name": "Customer", "Color": "#1565c0"},
        {"Name": "Vendor",   "Color": "#e65100"},
        {"Name": "Staff",    "Color": "#2e7d32"},
        {"Name": "Other",    "Color": "#6a1b9a"}
    ]
    # Merge: custom overrides defaults if same name
    custom_names = {c["Name"] for c in custom}
    merged = [d for d in defaults if d["Name"] not in custom_names] + custom
    merged.sort(key=lambda x: x["Name"])
    return JSONResponse(content=merged)

@app.post("/api/contacts/categories")
async def save_contact_category(request: Request):
    if not await ensure_db(): return err("Database not connected", 503)
    b = await request.json()
    name = b.get("Name", "").strip()
    if not name: return err("Category name required")
    color = b.get("Color", "#607d8b")
    shared_col("contact_categories").update_one(
        {"Name": name}, {"$set": {"Name": name, "Color": color}}, upsert=True)
    return ok()

@app.delete("/api/contacts/categories/{name}")
async def delete_contact_category(name: str):
    if not await ensure_db(): return err("Database not connected", 503)
    shared_col("contact_categories").delete_one({"Name": name})
    return ok()


@app.put("/api/followups/{fid}/address")
async def address_followup(fid: int):
    if not await ensure_db(): return err("Database not connected", 503)
    col("followups").update_one({"Id": fid}, {"$set": {"IsAddressed": 1}})
    return ok()

@app.put("/api/followups/{fid}/reopen")
async def reopen_followup(fid: int, request: Request):
    if not await ensure_db(): return err("Database not connected", 503)
    b = await request.json()
    new_date = b.get("FollowupDate") or datetime.now().strftime("%Y-%m-%d")
    col("followups").update_one({"Id": fid}, {"$set": {"IsAddressed": 0, "FollowupDate": new_date}})
    return ok()

@app.put("/api/followups/{fid}")
async def put_followup(fid: int, request: Request):
    if not await ensure_db(): return err("Database not connected", 503)
    b = await request.json()
    col("followups").update_one({"Id": fid}, {"$set": {
        "FollowupDate": b.get("FollowupDate"),
        "FollowupTime": b.get("FollowupTime") or "09:00",
        "FollowupTime": b.get("FollowupTime") or "09:00",
        "Priority":     b.get("Priority", ""),
        "FollowupText": b.get("FollowupText", ""),
    }})
    return ok()

@app.put("/api/followups/{fid}/snooze")
async def snooze_followup(fid: int, request: Request):
    """Pushes SnoozedUntil forward by the requested number of minutes from
    now, so the reminder popup won't re-trigger for this item until that
    time passes - checked client-side alongside FollowupDate/Time."""
    if not await ensure_db(): return err("Database not connected", 503)
    b = await request.json()
    minutes = int(b.get("minutes") or 10)
    snoozed_until = (datetime.now() + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%S")
    col("followups").update_one({"Id": fid}, {"$set": {"SnoozedUntil": snoozed_until}})
    return ok({"SnoozedUntil": snoozed_until})

@app.delete("/api/followups/{fid}")
async def delete_followup(fid: int):
    if not await ensure_db(): return err("Database not connected", 503)
    col("followups").delete_one({"Id": fid})
    return ok()

# ─────────────────────────────────────────────
#  CLIENTS
# ─────────────────────────────────────────────
@app.get("/api/clients")
async def get_clients():
    # Clients list is a shared lookup — always return all (used for sales dropdown autocomplete)
    if not await ensure_db(): return JSONResponse(content=[], status_code=503)
    rows = list(shared_col("rio_clients").find({}, {"_id": 0, "ClientName": 1}).sort("ClientName", ASCENDING))
    return JSONResponse(content=[r["ClientName"] for r in rows if r.get("ClientName")])

@app.get("/api/rio_clients")
async def get_rio_clients(q: Optional[str] = Query(None)):
    """Alias for /api/billing/customers — used by customer autocomplete."""
    if not await ensure_db(): return JSONResponse(content=[], status_code=503)
    query = {}
    if q: query["Name"] = {"$regex": q, "$options": "i"}
    rows = list(shared_col("rio_clients").find(query, {"_id": 0}).sort("ClientName", ASCENDING))
    # Rename ClientName → Name for billing compatibility
    result = [{"Id": r.get("Id"), "Name": r.get("ClientName", r.get("Name", "")),
               "Mobile": r.get("Mobile",""), "GSTNo": r.get("GSTNo",""),
               "State": r.get("State",""), "StateCode": r.get("StateCode",""),
               "Type": r.get("Type","")} for r in rows]
    return JSONResponse(content=result)


@app.post("/api/clients")
async def post_clients(request: Request):
    if not await ensure_db(): return err("Database not connected", 503)
    b = await request.json()
    name = (b.get("ClientName") or "").strip()
    created_by = (b.get("createdBy") or "").strip()
    if name:
        shared_col("rio_clients").update_one(
            {"ClientName": name},
            {"$setOnInsert": {"Id": next_id("rio_clients"), "ClientName": name, "createdBy": created_by}},
            upsert=True
        )
    return ok()

# ─────────────────────────────────────────────
#  CATEGORIES
# ─────────────────────────────────────────────
@app.delete("/api/clients/{client_name:path}")
async def delete_client(client_name: str):
    """Delete a client from the sales tracker clientsList."""
    if not await ensure_db(): return JSONResponse(content={"error":"DB offline"}, status_code=503)
    name = client_name.strip()
    shared_col("rio_clients").delete_one({"ClientName": {"$regex": f"^{re.escape(name)}$", "$options": "i"}})
    return ok({"success": True, "deleted": name})


@app.get("/api/categories")
async def get_categories():
    if not await ensure_db(): return JSONResponse(content=[], status_code=503)
    rows = list(col("expense_categories").distinct("CategoryName"))
    return JSONResponse(content=sorted(rows))

@app.get("/api/expense_categories")
async def get_expense_categories_alias():
    """Alias for /api/categories — used by mobile/expense dropdown."""
    if not await ensure_db(): return JSONResponse(content=[], status_code=503)
    rows = list(col("expense_categories").find({}, {"_id": 0}).sort(
        [("CategoryName", ASCENDING), ("SubCategoryName", ASCENDING)]))
    return JSONResponse(content=rows)


@app.get("/api/categories/all")
async def get_categories_all():
    if not await ensure_db(): return JSONResponse(content=[], status_code=503)
    rows = list(col("expense_categories").find({}, {"_id": 0}).sort([("CategoryName", ASCENDING), ("SubCategoryName", ASCENDING)]))
    from collections import defaultdict
    mp = defaultdict(list)
    for r in rows:
        mp[r["CategoryName"]].append(r["SubCategoryName"])
    return JSONResponse(content=[{"category": k, "subcats": v} for k, v in mp.items()])

@app.get("/api/categories/subcats")
async def get_subcats(cat: str = Query("")):
    if not await ensure_db(): return JSONResponse(content=[], status_code=503)
    rows = list(col("expense_categories").find({"CategoryName": cat}, {"_id": 0, "SubCategoryName": 1}).sort("SubCategoryName", ASCENDING))
    subs = [r["SubCategoryName"] for r in rows]
    return JSONResponse(content=subs if subs else ["Other"])

@app.post("/api/categories")
async def post_category(request: Request):
    if not await ensure_db(): return err("Database not connected", 503)
    b = await request.json()
    cn = (b.get("CategoryName") or "").strip()
    sn = (b.get("SubCategoryName") or "").strip()
    if cn and sn:
        exists = col("expense_categories").find_one({"CategoryName": cn, "SubCategoryName": sn})
        if not exists:
            new_id = next_id("expense_categories")
            col("expense_categories").insert_one({"Id": new_id, "CategoryName": cn, "SubCategoryName": sn})
    return ok()

@app.post("/api/categories/sync")
async def sync_categories(request: Request):
    rows = await request.json()
    inserted = 0
    for row in (rows if isinstance(rows, list) else []):
        cn = (row.get("CategoryName") or "").strip()
        sn = (row.get("SubCategoryName") or "").strip()
        if cn and sn:
            exists = col("expense_categories").find_one({"CategoryName": cn, "SubCategoryName": sn})
            if not exists:
                new_id = next_id("expense_categories")
                col("expense_categories").insert_one({"Id": new_id, "CategoryName": cn, "SubCategoryName": sn})
                inserted += 1
    return ok({"ok": True, "inserted": inserted})

@app.delete("/api/categories/{cat_id}")
async def delete_category(cat_id: int):
    if not await ensure_db(): return err("Database not connected", 503)
    col("expense_categories").delete_one({"Id": cat_id})
    return ok()

# ─────────────────────────────────────────────
#  JOBS
# ─────────────────────────────────────────────
@app.get("/api/jobs")
async def get_jobs(fr: Optional[str] = Query(None, alias="from"), to: Optional[str] = Query(None)):
    if not await ensure_db(): return JSONResponse(content=[], status_code=503)
    query = {}
    if fr: query["ConfirmedDate"] = {"$gte": fr}
    if to: query.setdefault("ConfirmedDate", {})["$lte"] = to
    rows = list(col("jobs").find(query, {"_id": 0}).sort("Id", DESCENDING))
    return JSONResponse(content=rows)

@app.post("/api/jobs")
async def post_jobs(request: Request):
    if not await ensure_db(): return err("Database not connected", 503)
    b = await request.json()
    new_id = next_id("jobs")
    # Auto-generate JobNo if not provided: J001, J002, ...
    job_no = (b.get("JobNo") or "").strip()
    if not job_no:
        pipeline = [{"$group": {"_id": None, "max": {"$max": "$Id"}}}]
        res = list(col("jobs").aggregate(pipeline))
        max_id = to_int(res[0]["max"]) if res else 0
        job_no = f"J{(max_id + 1):03d}"
    col("jobs").insert_one({
        "Id":           new_id,
        "JobNo":        job_no,
        "Customer":     b.get("Customer", ""),
        "JobName":      b.get("JobName", ""),
        "ConfirmedDate":b.get("ConfirmedDate"),
        "ProductSize":  b.get("ProductSize", ""),
        "Qty":          to_int(b.get("Qty")),
        "Status":       b.get("Status", ""),
        "DispatchDate": b.get("DispatchDate"),
    })
    return ok({"ok": True, "id": new_id, "jobNo": job_no})

@app.put("/api/jobs/{job_id}")
async def put_jobs(job_id: int, request: Request):
    if not await ensure_db(): return err("Database not connected", 503)
    b = await request.json()
    update = {
        "Customer":     b.get("Customer", ""),
        "JobName":      b.get("JobName", ""),
        "ConfirmedDate":b.get("ConfirmedDate"),
        "ProductSize":  b.get("ProductSize", ""),
        "Qty":          to_int(b.get("Qty")),
        "Status":       b.get("Status", ""),
        "DispatchDate": b.get("DispatchDate"),
    }
    # Only update JobNo if provided (don't overwrite existing)
    if b.get("JobNo"):
        update["JobNo"] = b.get("JobNo")
    col("jobs").update_one({"Id": job_id}, {"$set": update})
    return ok()

@app.delete("/api/jobs/{job_id}")
async def delete_jobs(job_id: int):
    if not await ensure_db(): return err("Database not connected", 503)
    col("jobs").delete_one({"Id": job_id})
    return ok()

# ─────────────────────────────────────────────
#  ACCOUNT BALANCES
# ─────────────────────────────────────────────
@app.get("/api/accountbalances")
async def get_acct_balances():
    if not await ensure_db(): return JSONResponse(content=[], status_code=503)
    rows = list(col("account_balances").find({}, {"_id": 0}).sort([("EntryDate", DESCENDING), ("Id", DESCENDING)]))
    return JSONResponse(content=rows)

@app.post("/api/accountbalances")
async def post_acct_balance(request: Request):
    if not await ensure_db(): return err("Database not connected", 503)
    b = await request.json()
    new_id = next_id("account_balances")
    col("account_balances").insert_one({
        "Id":          new_id,
        "AccountName": b.get("AccountName", ""),
        "EntryDate":   b.get("EntryDate"),
        "Balance":     to_float(b.get("Balance"), 0.0),
        "Notes":       b.get("Notes", ""),
    })
    return ok({"ok": True, "id": new_id})

@app.delete("/api/accountbalances/{ab_id}")
async def delete_acct_balance(ab_id: int):
    if not await ensure_db(): return err("Database not connected", 503)
    col("account_balances").delete_one({"Id": ab_id})
    return ok()

# ─────────────────────────────────────────────
#  LEDGER
# ─────────────────────────────────────────────
@app.get("/api/ledger/debug")
async def ledger_debug():
    total = col("account_ledger").count_documents({})
    rows = list(col("account_ledger").find({}, {"_id": 0}).sort("Id", DESCENDING).limit(20))
    return JSONResponse(content={"total": total, "rows": rows})

@app.get("/api/ledger/prev-closing")
async def ledger_prev_closing(fy: str = Query("")):
    if not fy:
        return JSONResponse(content=[])
    fy_year = int(fy.split("-")[0])
    prev_fy = f"{fy_year-1}-{str(fy_year)[-2:]}"
    result = []
    for acct in ["KVB MOM", "KVB Mani", "Indian Bank", "Cash Balance"]:
        last = col("account_ledger").find_one(
            {"AccountName": acct, "FY": prev_fy},
            sort=[("EntryDate", DESCENDING), ("Id", DESCENDING)]
        )
        bal = to_float(last["Balance"]) if last else 0.0
        result.append({"AccountName": acct, "ClosingBalance": bal})
    return JSONResponse(content=result)

@app.get("/api/ledger/opening")
async def get_ledger_opening(fy: str = Query("")):
    if not fy:
        return JSONResponse(content=[])
    rows = list(col("account_opening_balances").find({"FY": fy}, {"_id": 0}))
    return JSONResponse(content=rows)

@app.post("/api/ledger/opening")
async def post_ledger_opening(request: Request):
    if not await ensure_db(): return err("Database not connected", 503)
    b = await request.json()
    fy = (b.get("FY") or "").strip()
    if not fy:
        return err("FY required")
    for acct in ["KVB MOM", "KVB Mani", "Indian Bank", "Cash Balance"]:
        val = to_float(b.get(acct), 0.0)
        exists = col("account_opening_balances").find_one({"AccountName": acct, "FY": fy})
        if exists:
            col("account_opening_balances").update_one(
                {"AccountName": acct, "FY": fy},
                {"$set": {"OpeningBal": val}}
            )
        else:
            col("account_opening_balances").insert_one({"AccountName": acct, "FY": fy, "OpeningBal": val})
    return ok()

@app.delete("/api/ledger/clear-opening")
async def clear_ledger_opening(fy: str = Query("")):
    if not await ensure_db(): return err("Database not connected", 503)
    if not fy:
        return ok({"ok": False})
    col("account_ledger").delete_many({"EntryType": "Opening", "FY": fy})
    col("account_opening_balances").delete_many({"FY": fy})
    return ok()

@app.get("/api/ledger")
async def get_ledger(
    account: Optional[str] = Query(None),
    fy: Optional[str] = Query(None),
    month: Optional[str] = Query(None)
):
    if not await ensure_db(): return JSONResponse(content=[], status_code=503)
    if not fy:
        return JSONResponse(content=[])
    query = {"FY": fy}
    if account: query["AccountName"] = account
    if month:   query["EntryDate"] = {"$regex": f"^{month}"}
    rows = list(col("account_ledger").find(query, {"_id": 0}).sort([("EntryDate", ASCENDING), ("Id", ASCENDING)]))
    return JSONResponse(content=rows)

@app.post("/api/ledger")
async def post_ledger(request: Request):
    if not await ensure_db(): return err("Database not connected", 503)
    b = await request.json()
    acct  = (b.get("AccountName") or "").strip()
    dt    = (b.get("EntryDate") or "").strip() or datetime.now().strftime("%Y-%m-%d")
    desc  = (b.get("Description") or "").strip()
    cr    = to_float(b.get("CreditAmt"), 0.0)
    dr    = to_float(b.get("DebitAmt"), 0.0)
    etype = (b.get("EntryType") or "Manual").strip()
    fy    = (b.get("FY") or "").strip()
    if not acct: return err("AccountName required")
    if not fy:   return err("FY required")
    if cr > 0 and dr > 0:
        return err("A ledger entry can only be a Credit or a Debit, not both — please enter one amount and leave the other at 0")
    if etype == "Opening":
        new_bal = cr - dr
    else:
        last = col("account_ledger").find_one(
            {"AccountName": acct, "FY": fy},
            sort=[("EntryDate", DESCENDING), ("Id", DESCENDING)]
        )
        if last:
            prev = to_float(last["Balance"], 0.0)
        else:
            ob = col("account_opening_balances").find_one({"AccountName": acct, "FY": fy})
            prev = to_float(ob["OpeningBal"]) if ob else 0.0
        new_bal = prev + cr - dr
    new_id = next_id("account_ledger")
    col("account_ledger").insert_one({
        "Id": new_id, "AccountName": acct, "EntryDate": dt,
        "Description": desc, "CreditAmt": cr, "DebitAmt": dr,
        "Balance": new_bal, "EntryType": etype, "FY": fy,
        "ExpenseRef": None, "SalesRef": None
    })
    return ok({"ok": True, "balance": new_bal})

@app.delete("/api/ledger/reset")
async def ledger_reset():
    if not await ensure_db(): return err("Database not connected", 503)
    col("account_ledger").delete_many({})
    col("account_opening_balances").delete_many({})
    return ok()

@app.delete("/api/ledger/{led_id}")
async def delete_ledger_entry(led_id: int):
    if not await ensure_db(): return err("Database not connected", 503)
    col("account_ledger").delete_one({"Id": led_id})
    return ok()

@app.post("/api/ledger/migrate")
async def ledger_migrate(request: Request):
    b = await request.json()
    fy = (b.get("FY") or "").strip()
    if not fy: return err("FY required")
    fy_from, fy_to = fy_range(fy)
    exp_count = sales_count = skip_count = 0

    # Import expenses
    exp_rows = list(col("daily_expenses").find(
        {"ExpDate": {"$gte": fy_from, "$lte": fy_to}},
        {"_id": 0}
    ).sort([("ExpDate", ASCENDING), ("Id", ASCENDING)]))

    for row in exp_rows:
        exp_id = to_int(row.get("Id"))
        already = col("account_ledger").count_documents({"ExpenseRef": exp_id})
        if already > 0: skip_count += 1; continue
        pm = (row.get("PaymentMode") or "").strip()
        acct_map = {"KVB MOM":"KVB MOM","KVB Mani":"KVB Mani","Indian Bank":"Indian Bank","Cash":"Cash Balance"}
        acct = acct_map.get(pm)
        if not acct: skip_count += 1; continue
        exp_date = row.get("ExpDate", "")
        amt = to_float(row.get("Amount"), 0.0)
        sub_cat = (row.get("SubCategory") or "").strip()
        desc_str = (row.get("Description") or "").strip()
        desc = f"Expense: {sub_cat} — {desc_str}" if desc_str else f"Expense: {sub_cat}"
        last = col("account_ledger").find_one({"AccountName": acct, "FY": fy}, sort=[("EntryDate", DESCENDING), ("Id", DESCENDING)])
        prev = to_float(last["Balance"]) if last else 0.0
        new_bal = prev - amt
        led_id = next_id("account_ledger")
        col("account_ledger").insert_one({
            "Id": led_id, "AccountName": acct, "EntryDate": exp_date,
            "Description": desc, "CreditAmt": 0, "DebitAmt": amt,
            "Balance": new_bal, "EntryType": "Expense", "FY": fy,
            "ExpenseRef": exp_id, "SalesRef": None
        })
        exp_count += 1

    # Import sales payments
    sales_rows = list(col("sales_records").find(
        {"OrderDate": {"$gte": fy_from, "$lte": fy_to}},
        {"_id": 0}
    ).sort([("OrderDate", ASCENDING), ("SNo", ASCENDING)]))

    acct_map = {"KVB MOM":"KVB MOM","KVB Mani":"KVB Mani","Indian Bank":"Indian Bank","Cash":"Cash Balance"}
    for row in sales_rows:
        sno = to_int(row.get("SNo"))
        already = col("account_ledger").count_documents({"SalesRef": sno})
        if already > 0: skip_count += 1; continue
        cust = (row.get("Customer") or "").strip()
        job  = (row.get("JobName") or "").strip()
        jn_str = f" — {job}" if job else ""
        desc = f"Sales: {cust}{jn_str}"
        payments = [
            {"Amt": row.get("AdvanceAmt"),        "Date": row.get("AdvanceDate"),  "Mode": row.get("AdvanceMode","")},
            {"Amt": row.get("BalanceSettledAmt"), "Date": row.get("BalanceDate"),  "Mode": row.get("BalanceMode","")},
            {"Amt": row.get("Balance2Amt"),       "Date": row.get("Balance2Date"), "Mode": row.get("Balance2Mode","")},
            {"Amt": row.get("Balance3Amt"),       "Date": row.get("Balance3Date"), "Mode": row.get("Balance3Mode","")},
        ]
        added = False
        for pay in payments:
            amt  = to_float(pay["Amt"])
            pdate = (pay["Date"] or "").strip()
            mode = (pay["Mode"] or "").strip()
            if not amt or amt <= 0 or not pdate: continue
            acct = acct_map.get(mode)
            if not acct: continue
            last = col("account_ledger").find_one({"AccountName": acct, "FY": fy}, sort=[("EntryDate", DESCENDING), ("Id", DESCENDING)])
            prev = to_float(last["Balance"]) if last else 0.0
            new_bal = prev + amt
            led_id = next_id("account_ledger")
            col("account_ledger").insert_one({
                "Id": led_id, "AccountName": acct, "EntryDate": pdate,
                "Description": desc, "CreditAmt": amt, "DebitAmt": 0,
                "Balance": new_bal, "EntryType": "Credit", "FY": fy,
                "ExpenseRef": None, "SalesRef": sno
            })
            added = True
            sales_count += 1
        if not added: skip_count += 1

    return ok({"ok": True, "expenseEntries": exp_count, "salesEntries": sales_count, "skipped": skip_count})

# ─────────────────────────────────────────────
#  BILLING — CUSTOMERS
# ─────────────────────────────────────────────
@app.get("/api/billing/status")
async def billing_status():
    cc = shared_col("rio_clients").count_documents({})
    pc = col("products").count_documents({})
    ic = col("sales_invoices").count_documents({})
    return JSONResponse(content={"ready": True, "server": "MongoDB Atlas", "database": MONGO_DB, "version": "3.0", "customers": cc, "products": pc, "invoices": ic})

@app.get("/api/billing/customers")
async def billing_get_customers(q: Optional[str] = Query(None), scope: Optional[str] = Query(None), user: Optional[str] = Query(None)):
    if q:
        query = {"$or": [
            {"ClientName": {"$regex": q, "$options": "i"}},
            {"Mobile": {"$regex": q, "$options": "i"}},
            {"GSTNo": {"$regex": q, "$options": "i"}},
        ]}
    else:
        query = {}
    # Customers are shared data — do NOT filter by createdBy/scope.
    # Scope (own/all) applies only to transactional data (sales, invoices, quotations).
    rows = list(shared_col("rio_clients").find(query, {"_id": 0}).sort("ClientName", ASCENDING))
    # Rename ClientName → Name for billing compatibility
    result = []
    for r in rows:
        result.append({
            "Id": r.get("Id"), "Name": r.get("ClientName",""),
            "BillToAddress": r.get("BillToAddress",""), "ShipToAddress": r.get("ShipToAddress",""),
            "State": r.get("State",""), "StateCode": r.get("StateCode",""),
            "Mobile": r.get("Mobile",""), "GSTNo": r.get("GSTNo",""),
            "Email": r.get("Email",""), "CustomerType": r.get("CustomerType",""),
        })
    return JSONResponse(content=result)

@app.post("/api/billing/customers")
async def billing_post_customer(request: Request):
    b = await request.json()
    name = (b.get("Name") or "").strip()
    if not name: return err("Name required")
    existing = shared_col("rio_clients").find_one({"ClientName": name})
    update_doc = {
        "BillToAddress": b.get("BillToAddress",""), "ShipToAddress": b.get("ShipToAddress",""),
        "State": b.get("State",""), "StateCode": b.get("StateCode",""),
        "Mobile": b.get("Mobile",""), "GSTNo": b.get("GSTNo",""),
        "Email": b.get("Email",""), "CustomerType": b.get("CustomerType",""),
    }
    if existing:
        shared_col("rio_clients").update_one({"ClientName": name}, {"$set": update_doc})
        return ok({"success": True, "id": existing["Id"]})
    else:
        new_id = next_id("rio_clients")
        created_by = (b.get("createdBy") or "").strip()
        shared_col("rio_clients").insert_one({"Id": new_id, "ClientName": name, "createdBy": created_by, **update_doc})
        return ok({"success": True, "id": new_id})

@app.get("/api/billing/customers/byname")
async def billing_customer_byname(name: str = Query("")):
    if not name: return err("name required")
    r = shared_col("rio_clients").find_one({"ClientName": name}, {"_id": 0})
    if not r:
        r = shared_col("rio_clients").find_one({"ClientName": {"$regex": name, "$options": "i"}}, {"_id": 0})
    if not r: return err("Not found", 404)
    return JSONResponse(content={"Id": r.get("Id"), "Name": r.get("ClientName",""), **{k: r.get(k,"") for k in ["BillToAddress","ShipToAddress","State","StateCode","Mobile","GSTNo","Email","CustomerType"]}})

@app.get("/api/billing/customers/{cust_id}")
async def billing_get_customer(cust_id: int):
    r = shared_col("rio_clients").find_one({"Id": cust_id}, {"_id": 0})
    if not r: return err("Not found", 404)
    return JSONResponse(content={"Id": r.get("Id"), "Name": r.get("ClientName",""), **{k: r.get(k,"") for k in ["BillToAddress","ShipToAddress","State","StateCode","Mobile","GSTNo","Email","CustomerType"]}})

@app.put("/api/billing/customers/{cust_id}")
async def billing_put_customer(cust_id: int, request: Request):
    if not await ensure_db(): return err("Database not connected", 503)
    b = await request.json()
    name = (b.get("Name") or "").strip()
    if not name:
        return err("Customer name required")
    ship = (b.get("ShipToAddress") or "").strip() or (b.get("BillToAddress") or "").strip()
    existing = shared_col("rio_clients").find_one({"Id": cust_id}, {"_id": 0, "ClientName": 1, "Name": 1, "PreviousNames": 1}) or {}
    update_set = {
        "ClientName":    name,
        "Name":          name,
        "Address":       b.get("Address", b.get("BillToAddress", "")),
        "BillToAddress": b.get("BillToAddress", ""),
        "ShipToAddress": ship,
        "State":         b.get("State", ""),
        "StateCode":     b.get("StateCode", ""),
        "Mobile":        b.get("Mobile", ""),
        "GSTNo":         b.get("GSTNo", ""),
        "Email":         b.get("Email", ""),
        "CustomerType":  b.get("CustomerType", ""),
    }
    # If the name actually changed, remember the old name so "Update
    # Everywhere" can still find historical sales/invoices/quotations that
    # were saved under that old spelling, even after this rename.
    old_name = (existing.get("ClientName") or existing.get("Name") or "").strip()
    if old_name and old_name.lower() != name.lower():
        prev = existing.get("PreviousNames") or []
        if old_name not in prev:
            prev.append(old_name)
        update_set["PreviousNames"] = prev
    result = shared_col("rio_clients").update_one({"Id": cust_id}, {"$set": update_set})
    if result.matched_count == 0:
        return err("Customer not found", 404)
    return ok({"success": True})

@app.post("/api/customers/{cust_id}/update-everywhere")
@app.post("/api/billing/customers/{cust_id}/update-everywhere")
async def customer_update_everywhere(cust_id: int, request: Request):
    """
    Push this customer's CURRENT details (name, GST, state, mobile, email,
    address) onto every existing sales record, invoice and quotation that
    was saved under this customer's current name OR any of its previously
    known names (tracked automatically whenever the customer is renamed).
    This does not change any totals/amounts — only the customer-identifying
    text fields that were copied onto those records at the time they were
    created.

    Optional body: {"oldName": "..."} — manually add an old spelling to
    search for, useful if a rename happened before this tracking existed.
    """
    if not await ensure_db(): return err("Database not connected", 503)
    cust = shared_col("rio_clients").find_one({"Id": cust_id}, {"_id": 0})
    if not cust:
        return err("Customer not found", 404)

    try:
        body = await request.json()
    except Exception:
        body = {}
    manual_old_name = (body.get("oldName") or "").strip() if isinstance(body, dict) else ""

    current_name = (cust.get("ClientName") or cust.get("Name") or "").strip()
    if not current_name:
        return err("This customer has no name on record", 400)
    prev_names = cust.get("PreviousNames") or []
    all_names = list({current_name, *prev_names})
    if manual_old_name:
        all_names.append(manual_old_name)
        # Persist it for next time too, so this only needs to be done once.
        if manual_old_name not in prev_names:
            shared_col("rio_clients").update_one(
                {"Id": cust_id},
                {"$addToSet": {"PreviousNames": manual_old_name}}
            )

    name_regex = {"$in": [re.compile(f"^{re.escape(n)}$", re.IGNORECASE) for n in all_names]}

    # ── Sales records: only the plain Customer text field exists here ──
    sales_result = col("sales_records").update_many(
        {"Customer": name_regex},
        {"$set": {"Customer": current_name}}
    )

    # ── Invoices: name + GST + state code + address/mobile/email ──
    inv_update = {
        "CustomerName":       current_name,
        "CustomerGST":        cust.get("GSTNo", ""),
        "CustomerStateCode":  cust.get("StateCode", ""),
        "CustomerAddress":    cust.get("BillToAddress", ""),
        "CustomerState":      cust.get("State", ""),
        "CustomerMobile":     cust.get("Mobile", ""),
        "CustomerEmail":      cust.get("Email", ""),
    }
    inv_result = col("sales_invoices").update_many(
        {"$or": [{"CustomerId": cust_id}, {"CustomerName": name_regex}]},
        {"$set": inv_update}
    )

    # ── Quotations: same fields as invoices ──
    quot_result = col("quotations").update_many(
        {"$or": [{"CustomerId": cust_id}, {"CustomerName": name_regex}]},
        {"$set": inv_update}
    )

    return ok({
        "success": True,
        "sales": sales_result.modified_count,
        "invoices": inv_result.modified_count,
        "quotations": quot_result.modified_count,
    })

@app.delete("/api/billing/customers/{cust_id}")
async def billing_delete_customer(cust_id: int, user: Optional[str] = Query(None), scope: Optional[str] = Query(None)):
    if not await ensure_db(): return err("Database not connected", 503)
    # IMPORTANT: find_one with an inclusion projection like {"createdBy": 1}
    # returns an EMPTY DICT {} (not None) when the document exists but has
    # no createdBy field — and {} is falsy in Python, so `if not record`
    # incorrectly treated "found, but no createdBy" the same as "not found".
    # Fix: check existence explicitly with `record is None`, and rely on
    # full deletion only after we've confirmed it actually exists.
    exists = shared_col("rio_clients").count_documents({"Id": cust_id}, limit=1) > 0
    if not exists:
        return err("Customer not found", 404)
    record = shared_col("rio_clients").find_one({"Id": cust_id}, {"_id": 0, "createdBy": 1}) or {}
    # Scope check: scoped users can only delete their own records
    if scope == "own" and user:
        record_owner = record.get("createdBy", "")
        if record_owner and record_owner != user:
            return err("Access denied — you can only delete customers you created.", 403)
    shared_col("rio_clients").delete_one({"Id": cust_id})
    return ok({"success": True})

# ─────────────────────────────────────────────
#  BILLING — PRODUCTS
# ─────────────────────────────────────────────
@app.get("/api/billing/products/nextcode")
async def billing_nextcode():
    return JSONResponse(content={"code": next_product_code()})

@app.get("/api/billing/products")
async def billing_get_products(q: Optional[str] = Query(None)):
    if q:
        query = {"$or": [{"Name": {"$regex": q, "$options": "i"}}, {"Code": {"$regex": q, "$options": "i"}}]}
    else:
        query = {}
    rows = list(col("products").find(query, {"_id": 0}).sort("Code", ASCENDING))
    return JSONResponse(content=rows)

@app.post("/api/billing/products")
async def billing_post_product(request: Request):
    b = await request.json()
    name = (b.get("Name") or "").strip()
    if not name: return err("Name required")
    code = (b.get("Code") or "").strip() or next_product_code()
    new_id = next_id("products")
    col("products").insert_one({
        "Id": new_id, "Code": code, "Name": name,
        "createdBy": (b.get("createdBy") or "").strip(),
        "PrintName": b.get("PrintName",""), "HSN": b.get("HSN",""),
        "Category": b.get("Category",""), "Unit": b.get("Unit","Nos"),
        "GSTRate": to_float(b.get("GSTRate"), 18.0),
    })
    return ok({"success": True, "id": new_id, "code": code})

@app.get("/api/billing/products/{prod_id}")
async def billing_get_product(prod_id: int):
    r = col("products").find_one({"Id": prod_id}, {"_id": 0})
    if not r: return err("Not found", 404)
    return JSONResponse(content=r)

@app.put("/api/billing/products/{prod_id}")
async def billing_put_product(prod_id: int, request: Request):
    b = await request.json()
    col("products").update_one({"Id": prod_id}, {"$set": {
        "Code": b.get("Code",""), "Name": b.get("Name",""),
        "PrintName": b.get("PrintName",""), "HSN": b.get("HSN",""),
        "Category": b.get("Category",""), "Unit": b.get("Unit","Nos"),
        "GSTRate": to_float(b.get("GSTRate"), 18.0),
    }})
    return ok({"success": True})

@app.delete("/api/billing/products/{prod_id}")
async def billing_delete_product(prod_id: int, user: Optional[str] = Query(None), scope: Optional[str] = Query(None)):
    if not await ensure_db(): return err("Database not connected", 503)
    exists = col("products").count_documents({"Id": prod_id}, limit=1) > 0
    if not exists:
        return err("Product not found", 404)
    record = col("products").find_one({"Id": prod_id}, {"_id": 0, "createdBy": 1}) or {}
    # Scope check: scoped users can only delete their own records
    if scope == "own" and user:
        record_owner = record.get("createdBy", "")
        if record_owner and record_owner != user:
            return err("Access denied — you can only delete products you created.", 403)
    col("products").delete_one({"Id": prod_id})
    return ok({"success": True})

# ─────────────────────────────────────────────
#  BILLING — INVOICE SEQUENCES
# ─────────────────────────────────────────────
@app.get("/api/billing/invoices/peek")
async def billing_invoice_peek(type: str = Query("GST"), fy: str = Query("")):
    if not fy: fy = current_fy()
    return JSONResponse(content={"invoiceNo": next_invoice_no(type, fy)})

@app.get("/api/billing/invoices/next")
async def billing_invoice_next(type: str = Query("GST"), fy: str = Query("")):
    if not fy: fy = current_fy()
    return JSONResponse(content={"invoiceNo": next_invoice_no(type, fy)})

@app.post("/api/billing/invoices/resetsequence")
async def billing_reset_sequence(type: str = Query("GST")):
    return ok({"success": True, "type": type})

# ─────────────────────────────────────────────
#  BILLING — INVOICES
# ─────────────────────────────────────────────
@app.get("/api/billing/invoices/byno")
async def billing_invoice_byno(invno: str = Query(""), fy: str = Query("")):
    if not invno: return err("invno required")
    query = {"InvoiceNo": invno}
    if fy:
        fy_from, fy_to = fy_range(fy)
        query["InvoiceDate"] = {"$gte": fy_from, "$lte": fy_to}
    inv = col("sales_invoices").find_one(query, {"_id": 0}, sort=[("Id", DESCENDING)])
    if not inv: return err("Not found", 404)
    inv_id = inv.get("Id")
    items = list(col("sales_items").find({"InvoiceId": inv_id}, {"_id": 0}).sort("SNo", ASCENDING))
    # Fetch customer details
    cust = {}
    if inv.get("CustomerId"):
        c = shared_col("rio_clients").find_one({"Id": inv["CustomerId"]}, {"_id": 0})
        if c:
            cust = {"CustomerAddress": c.get("BillToAddress",""), "CustomerState": c.get("State",""),
                    "CustomerStateCode": c.get("StateCode",""), "CustomerMobile": c.get("Mobile",""),
                    "CustomerGST": c.get("GSTNo",""), "CustomerEmail": c.get("Email","")}
    # Keep InvoiceDate as the raw YYYY-MM-DD stored in MongoDB. Previously
    # this was reformatted to DD-MM-YYYY, which broke the edit form's date
    # input (which requires YYYY-MM-DD) and is unreliable for fd()'s
    # new Date(d) parsing on the frontend (DD-MM-YYYY is ambiguous/invalid
    # in JS Date parsing across browsers).
    return JSONResponse(content={**inv, **cust, "Items": items})

@app.get("/api/billing/invoices")
async def billing_get_invoices(
    page: int = Query(1), pageSize: int = Query(50),
    fr: Optional[str] = Query(None, alias="from"), to: Optional[str] = Query(None),
    type: Optional[str] = Query(None), q: Optional[str] = Query(None),
    scope: Optional[str] = Query(None), user: Optional[str] = Query(None)
):
    pageSize = max(1, min(pageSize, 500))
    query = {}
    if fr or to:
        query["InvoiceDate"] = {}
        if fr: query["InvoiceDate"]["$gte"] = fr
        if to: query["InvoiceDate"]["$lte"] = to
    if type == "GST":    query["BillingType"] = {"$in": ["GST", "IGST"]}
    if type == "NONGST": query["BillingType"] = "NON-GST"
    if q:
        # Also search by product name — find invoice IDs that have matching items
        matching_item_inv_ids = [
            r["InvoiceId"] for r in col("sales_items").find(
                {"ProductName": {"$regex": q, "$options": "i"}}, {"InvoiceId": 1, "_id": 0}
            )
        ]
        query["$or"] = [
            {"CustomerName": {"$regex": q, "$options": "i"}},
            {"InvoiceNo":    {"$regex": q, "$options": "i"}},
            {"Id":           {"$in": matching_item_inv_ids}},
        ]
    if scope == "own" and user: query["createdBy"] = user
    total = col("sales_invoices").count_documents(query)
    skip  = (page - 1) * pageSize
    rows  = list(col("sales_invoices").find(query, {"_id": 0, "Id":1,"InvoiceNo":1,"InvoiceDate":1,"CustomerName":1,"BillingType":1,"SubTotal":1,"CGST":1,"SGST":1,"IGST":1,"TotalAmount":1,"Counter":1,"PaymentTerms":1,"createdBy":1,"CustomerGST":1,"PlaceOfSupply":1})
                .sort([("InvoiceDate", DESCENDING), ("Id", DESCENDING)]).skip(skip).limit(pageSize))
    
    # Build product HSN lookup map (Name/PrintName → HSN)
    hsn_lookup = {}
    try:
        for prod in col("products").find({}, {"_id": 0, "Name": 1, "PrintName": 1, "HSN": 1}):
            hsn = prod.get("HSN", "")
            if prod.get("Name"):  hsn_lookup[prod["Name"].strip().lower()] = hsn
            if prod.get("PrintName"): hsn_lookup[prod["PrintName"].strip().lower()] = hsn
    except Exception:
        pass

    # Fetch HSN and Qty from sales_items for each invoice
    processed_rows = []
    for r in rows:
        row_data = dict(r)
        row_data["HSN"] = ""
        row_data["Quantity"] = 0

        # Get first item from sales_items collection
        item = col("sales_items").find_one({"InvoiceId": r.get("Id")}, {"_id": 0, "HSN": 1, "Qty": 1, "ProductName": 1, "Description": 1})
        if item:
            hsn = (item.get("HSN") or "").strip()
            # If HSN empty in item, look up from product catalog
            if not hsn:
                pname = (item.get("ProductName") or item.get("Description") or "").strip().lower()
                hsn = hsn_lookup.get(pname, "")
            row_data["HSN"] = hsn
            row_data["Quantity"] = to_float(item.get("Qty", 0), 0)

        processed_rows.append(row_data)
    
    return JSONResponse(content={"data": processed_rows, "total": total, "page": page, "pageSize": pageSize})

@app.post("/api/admin/backfill-hsn")
async def backfill_hsn():
    """One-time fix for invoices/sales created before HSN capture existed.
    Matches each old line item to the product catalog by ProductId first
    (most reliable), falling back to a case-insensitive name match, and
    fills in HSN wherever a match with a real HSN value is found. Items
    whose product has no HSN in the catalog either are left as-is and
    reported separately, since there's nothing to backfill them from."""
    if not await ensure_db(): return err("Database not connected", 503)

    products = list(col("products").find({}, {"_id": 0, "Id": 1, "Name": 1, "PrintName": 1, "HSN": 1}))
    by_id = {str(p.get("Id")): p.get("HSN", "") for p in products if p.get("Id")}
    by_name = {}
    for p in products:
        hsn = p.get("HSN", "")
        if not hsn:
            continue
        for key in (p.get("Name", ""), p.get("PrintName", "")):
            k = (key or "").strip().lower()
            if k:
                by_name[k] = hsn

    def resolve_hsn(product_id, product_name):
        hsn = by_id.get(str(product_id), "")
        if hsn:
            return hsn
        return by_name.get((product_name or "").strip().lower(), "")

    results = {}
    for coll_name, is_invoice_items in [("sales_items", True), ("sales_records", False)]:
        fixed = 0
        unmatched = 0
        if is_invoice_items:
            for doc in col(coll_name).find({"$or": [{"HSN": ""}, {"HSN": {"$exists": False}}]}):
                hsn = resolve_hsn(doc.get("ProductId"), doc.get("ProductName"))
                if hsn:
                    col(coll_name).update_one({"_id": doc["_id"]}, {"$set": {"HSN": hsn}})
                    fixed += 1
                elif doc.get("ProductName"):
                    unmatched += 1
        else:
            for doc in col(coll_name).find({"Items": {"$exists": True, "$ne": []}}):
                items = doc.get("Items") or []
                changed = False
                for it in items:
                    if it.get("HSN"):
                        continue
                    hsn = resolve_hsn(it.get("ProductId"), it.get("ProductName"))
                    if hsn:
                        it["HSN"] = hsn
                        changed = True
                        fixed += 1
                    elif it.get("ProductName"):
                        unmatched += 1
                if changed:
                    col(coll_name).update_one({"_id": doc["_id"]}, {"$set": {"Items": items}})
        results[coll_name] = {"fixed": fixed, "still_unmatched_no_catalog_hsn": unmatched}

    return ok(results)

@app.get("/api/billing/invoices/{inv_id}")
async def billing_get_invoice(inv_id: int):
    r = col("sales_invoices").find_one({"Id": inv_id}, {"_id": 0})
    if not r: return err("Invoice not found", 404)
    # Include line items and customer details in the same response so the
    # frontend doesn't need a second round-trip (to /byno) just to get them —
    # that extra call was adding a real, avoidable delay every time an
    # invoice was opened for editing.
    items = list(col("sales_items").find({"InvoiceId": inv_id}, {"_id": 0}).sort("SNo", ASCENDING))
    cust = {}
    if r.get("CustomerId"):
        c = shared_col("rio_clients").find_one({"Id": r["CustomerId"]}, {"_id": 0})
        if c:
            cust = {"CustomerAddress": c.get("BillToAddress",""), "CustomerState": c.get("State",""),
                    "CustomerStateCode": c.get("StateCode",""), "CustomerMobile": c.get("Mobile",""),
                    "CustomerGST": c.get("GSTNo",""), "CustomerEmail": c.get("Email","")}
    return JSONResponse(content={**r, **cust, "Items": items})

@app.post("/api/billing/invoices")
async def billing_post_invoice(request: Request):
    if not await ensure_db(): return err("Database not connected", 503)
    b = await request.json()
    inv_no = (b.get("InvoiceNo") or "").strip()
    if not inv_no: return err("InvoiceNo required")
    raw_date = b.get("InvoiceDate", "")
    try:
        inv_date = datetime.strptime(raw_date[:10], "%Y-%m-%d").strftime("%Y-%m-%d")
    except:
        inv_date = datetime.now().strftime("%Y-%m-%d")
    fy = fy_from_date(inv_date)
    new_id = next_id("sales_invoices")
    doc = {
        "Id": new_id, "Branch": "HO", "InvoiceNo": inv_no, "InvoiceDate": inv_date,
        "createdBy": (b.get("createdBy") or "").strip(),
        "CustomerId": to_int(b.get("CustomerId"), 0),
        "CustomerName": b.get("CustomerName",""), "BillingType": b.get("BillingType",""),
        "CustomerGST": b.get("CustomerGST",""),
        "PlaceOfSupply": b.get("PlaceOfSupply",""), "PlaceOfSupplyCode": b.get("PlaceOfSupplyCode",""),
        "SubTotal": to_float(b.get("SubTotal"),0), "CGST": to_float(b.get("CGST"),0),
        "SGST": to_float(b.get("SGST"),0), "IGST": to_float(b.get("IGST"),0),
        "TotalAmount": to_float(b.get("TotalAmount"),0),
        "Counter": b.get("Counter",""), "PaymentTerms": b.get("PaymentTerms",""), "FY": fy
    }
    col("sales_invoices").insert_one(doc)
    sno = 1
    for item in (b.get("Items") or []):
        if not item: continue
        qty = to_float(item.get("Qty"),0); rate = to_float(item.get("Rate"),0)
        tv  = to_float(item.get("TaxableValue"), qty*rate if qty and rate else 0)
        it  = to_float(item.get("Total"), tv)
        if not item.get("ProductName") and not tv: continue
        col("sales_items").insert_one({
            "InvoiceId": new_id, "SNo": sno,
            "ProductName": item.get("ProductName",""), "HSN": item.get("HSN",""),
            "Qty": qty, "Rate": rate, "TaxableValue": tv,
            "GSTRate": to_float(item.get("GSTRate"),0), "Total": it,
            "SizeNotes": item.get("SizeNotes","")
        })
        sno += 1
    return ok({"success": True, "id": new_id, "invoiceNo": inv_no})


@app.patch("/api/billing/invoices/{inv_id}/refresh-customer")
async def refresh_invoice_customer(inv_id: int):
    if not await ensure_db(): return err("Database not connected", 503)
    exists = col("sales_invoices").count_documents({"Id": inv_id}, limit=1) > 0
    if not exists: return err("Invoice not found", 404)
    inv = col("sales_invoices").find_one({"Id": inv_id}, {"_id": 0, "CustomerId": 1}) or {}
    cust_id = inv.get("CustomerId")
    if not cust_id: return err("No customer linked to this invoice", 400)
    cust = shared_col("rio_clients").find_one({"Id": cust_id}, {"_id": 0})
    if not cust: return err("Customer not found", 404)
    update = {
        "CustomerName":    cust.get("Name") or cust.get("ClientName") or "",
        "CustomerGST":     cust.get("GSTNo") or cust.get("GSTIN") or "",
        "CustomerMobile":  cust.get("Mobile") or cust.get("Phone") or "",
        "CustomerEmail":   cust.get("Email") or "",
        "BillToAddress":   cust.get("BillToAddress") or cust.get("Address") or "",
        "ShipToAddress":   cust.get("ShipToAddress") or cust.get("BillToAddress") or cust.get("Address") or "",
        "PlaceOfSupply":   cust.get("State") or "",
    }
    col("sales_invoices").update_one({"Id": inv_id}, {"$set": update})
    return ok({"success": True, "updated": update})

@app.patch("/api/quotations/{qid}/refresh-customer")
async def refresh_quotation_customer(qid: str):
    if not await ensure_db(): return err("Database not connected", 503)
    try: qid_int = int(qid)
    except: qid_int = None
    query = {"Id": qid_int} if qid_int else {"_id": __import__("bson").ObjectId(qid)}
    exists = col("quotations").count_documents(query, limit=1) > 0
    if not exists: return err("Quotation not found", 404)
    quot = col("quotations").find_one(query, {"_id": 0, "CustomerId": 1, "CustomerName": 1}) or {}
    cust_id = quot.get("CustomerId")
    cust = None
    if cust_id:
        cust = shared_col("rio_clients").find_one({"Id": cust_id}, {"_id": 0})
    if not cust:
        # Quotations created by typing a customer name (e.g. from the mobile
        # "New Quote" form) never get a CustomerId — fall back to a
        # case-insensitive name match so Update still works for them.
        cust_name = (quot.get("CustomerName") or "").strip()
        if not cust_name: return err("No customer linked to this quotation", 400)
        import re as _re
        cust = shared_col("rio_clients").find_one(
            {"Name": {"$regex": f"^{_re.escape(cust_name)}$", "$options": "i"}},
            {"_id": 0}
        )
        if not cust:
            return err("No matching customer record found for '" + cust_name + "'", 404)
    update = {
        "CustomerName":   cust.get("Name") or cust.get("ClientName") or "",
        "CustomerGST":    cust.get("GSTNo") or cust.get("GSTIN") or "",
        "CustomerMobile": cust.get("Mobile") or cust.get("Phone") or "",
        "CustomerEmail":  cust.get("Email") or "",
        "BillToAddress":  cust.get("BillToAddress") or cust.get("Address") or "",
        "ShipToAddress":  cust.get("ShipToAddress") or cust.get("BillToAddress") or cust.get("Address") or "",
        "PlaceOfSupply":  cust.get("State") or "",
    }
    col("quotations").update_one(query, {"$set": update})
    return ok({"success": True, "updated": update})

# Alias with /billing/ prefix so mobile can use a consistent URL pattern
@app.patch("/api/billing/quotations/{qid}/refresh-customer")
async def billing_refresh_quotation_customer(qid: str):
    return await refresh_quotation_customer(qid)

# Alias without /billing/ prefix for invoice (was missing — needed for mobile Update button)
@app.patch("/api/invoices/{inv_id}/refresh-customer")
async def refresh_invoice_customer_alias(inv_id: int):
    return await refresh_invoice_customer(inv_id)

async def billing_put_invoice(inv_id: int, request: Request):
    if not await ensure_db(): return err("Database not connected", 503)
    b = await request.json()
    raw_date = b.get("InvoiceDate","")
    try: inv_date = datetime.strptime(raw_date[:10], "%Y-%m-%d").strftime("%Y-%m-%d")
    except: inv_date = datetime.now().strftime("%Y-%m-%d")
    col("sales_invoices").update_one({"Id": inv_id}, {"$set": {
        "InvoiceDate": inv_date, "FY": fy_from_date(inv_date),
        "CustomerId": to_int(b.get("CustomerId"),0),
        "CustomerName": b.get("CustomerName",""), "BillingType": b.get("BillingType",""),
        "CustomerGST": b.get("CustomerGST",""),
        "PlaceOfSupply": b.get("PlaceOfSupply",""), "PlaceOfSupplyCode": b.get("PlaceOfSupplyCode",""),
        "SubTotal": to_float(b.get("SubTotal"),0), "CGST": to_float(b.get("CGST"),0),
        "SGST": to_float(b.get("SGST"),0), "IGST": to_float(b.get("IGST"),0),
        "TotalAmount": to_float(b.get("TotalAmount"),0),
        "Counter": b.get("Counter",""), "PaymentTerms": b.get("PaymentTerms",""),
    }})
    col("sales_items").delete_many({"InvoiceId": inv_id})
    sno = 1
    for item in (b.get("Items") or []):
        if not item: continue
        qty = to_float(item.get("Qty"),0); rate = to_float(item.get("Rate"),0)
        tv  = to_float(item.get("TaxableValue"), qty*rate if qty and rate else 0)
        it  = to_float(item.get("Total"), tv)
        if not item.get("ProductName") and not tv: continue
        col("sales_items").insert_one({
            "InvoiceId": inv_id, "SNo": sno,
            "ProductName": item.get("ProductName",""), "HSN": item.get("HSN",""),
            "Qty": qty, "Rate": rate, "TaxableValue": tv,
            "GSTRate": to_float(item.get("GSTRate"),0), "Total": it,
            "SizeNotes": item.get("SizeNotes","")
        })
        sno += 1
    inv_no = col("sales_invoices").find_one({"Id": inv_id}, {"InvoiceNo": 1})
    return ok({"success": True, "id": inv_id, "invoiceNo": inv_no.get("InvoiceNo","") if inv_no else ""})

@app.delete("/api/billing/invoices/{inv_id}")
async def billing_delete_invoice(inv_id: int):
    if not await ensure_db(): return err("Database not connected", 503)
    exists = col("sales_invoices").count_documents({"Id": inv_id}, limit=1) > 0
    if not exists: return err("Invoice not found", 404)
    inv = col("sales_invoices").find_one({"Id": inv_id}, {"InvoiceNo": 1}) or {}
    inv_no = inv.get("InvoiceNo","")
    # Only allow deleting the most recent invoice in its series
    # Determine prefix family: WBN/WB (Winner Bags) or RUN/RN/RU/R (legacy Rainbow)
    if inv_no.startswith("WBN"):
        regex = r"^WBN\d+$"
    elif inv_no.startswith("WB"):
        regex = r"^WB\d+$"
    elif inv_no.startswith("RUN"):
        regex = r"^RUN"
    elif inv_no.startswith("RN"):
        regex = r"^RN\d"
    elif inv_no.startswith("RU"):
        regex = r"^RU\d"
    else:
        regex = r"^R\d"
    latest = col("sales_invoices").find_one({"InvoiceNo": {"$regex": regex}}, sort=[("Id", DESCENDING)])
    if not latest or latest.get("Id") != inv_id:
        return err("Only the most recent invoice in this series can be deleted.", 403)
    col("sales_items").delete_many({"InvoiceId": inv_id})
    col("sales_invoices").delete_one({"Id": inv_id})
    col("sales_records").update_many({"InvoiceNo": inv_no}, {"$set": {"InvoiceNo": ""}})
    return ok({"success": True, "invoiceNo": inv_no})

# ─────────────────────────────────────────────
#  BILLING — QUOTATIONS
# ─────────────────────────────────────────────
@app.get("/api/billing/quotations/peek")
async def billing_quotation_peek(type: str = Query("GST"), fy: str = Query("")):
    if not fy: fy = current_fy()
    return JSONResponse(content={"quotationNo": next_quotation_no(type, fy)})

@app.get("/api/billing/quotations/next")
async def billing_quotation_next(type: str = Query("GST"), fy: str = Query("")):
    if not fy: fy = current_fy()
    return JSONResponse(content={"quotationNo": next_quotation_no(type, fy)})

@app.get("/api/billing/quotations/byno")
async def billing_quotation_byno(qno: str = Query("")):
    if not qno: return err("qno required")
    q = col("quotations").find_one({"QuotationNo": qno}, {"_id": 0})
    if not q: return err("Not found", 404)
    q_id = q.get("Id")
    items = list(col("quotation_items").find({"QuotationId": q_id}, {"_id": 0}).sort("SNo", ASCENDING))
    # Keep QuotationDate/ValidTill as raw YYYY-MM-DD from MongoDB. Previously
    # reformatted to DD-MM-YYYY, which broke the edit form's date input
    # (requires YYYY-MM-DD) and is unreliable for fd()'s new Date(d) parsing
    # on the frontend.
    return JSONResponse(content={**q, "Items": items})

@app.get("/api/billing/quotations")
async def billing_get_quotations(
    page: int = Query(1), pageSize: int = Query(50),
    fr: Optional[str] = Query(None, alias="from"), to: Optional[str] = Query(None),
    type: Optional[str] = Query(None), q: Optional[str] = Query(None),
    scope: Optional[str] = Query(None), user: Optional[str] = Query(None),
    mobile: Optional[str] = Query(None)
):
    pageSize = max(1, min(pageSize, 500))
    query = {}
    if fr or to:
        query["QuotationDate"] = {}
        if fr: query["QuotationDate"]["$gte"] = fr
        if to: query["QuotationDate"]["$lte"] = to
    if type == "GST":    query["BillingType"] = {"$in": ["GST","IGST"]}
    if type == "NONGST": query["BillingType"] = "NON-GST"
    if q:
        # Also search by product name — find quotation IDs that have matching items
        matching_item_quot_ids = [
            r["QuotationId"] for r in col("quotation_items").find(
                {"ProductName": {"$regex": q, "$options": "i"}}, {"QuotationId": 1, "_id": 0}
            )
        ]
        query["$or"] = [
            {"CustomerName":  {"$regex": q, "$options": "i"}},
            {"QuotationNo":   {"$regex": q, "$options": "i"}},
            {"Id":            {"$in": matching_item_quot_ids}},
        ]
    if scope == "own" and user: query["createdBy"] = user
    if mobile == "true": query["mobile_visible"] = True
    total = col("quotations").count_documents(query)
    skip  = (page - 1) * pageSize
    rows  = list(col("quotations").find(query, {"_id": 0})
                .sort([("QuotationDate", DESCENDING), ("Id", DESCENDING)]).skip(skip).limit(pageSize))
    return JSONResponse(content={"data": rows, "total": total, "page": page, "pageSize": pageSize})

@app.get("/api/billing/quotations/{quot_id}")
async def billing_get_quotation(quot_id: int):
    q = col("quotations").find_one({"Id": quot_id}, {"_id": 0})
    if not q: return err("Quotation not found", 404)
    items = list(col("quotation_items").find({"QuotationId": quot_id}, {"_id": 0}).sort("SNo", ASCENDING))
    return JSONResponse(content={**q, "Items": items})

@app.post("/api/billing/quotations")
async def billing_post_quotation(request: Request):
    if not await ensure_db(): return err("Database not connected", 503)
    b = await request.json()
    q_no = (b.get("QuotationNo") or "").strip()
    if not q_no: return err("QuotationNo required")
    try: q_date = datetime.strptime(b.get("QuotationDate","")[:10], "%Y-%m-%d").strftime("%Y-%m-%d")
    except: q_date = datetime.now().strftime("%Y-%m-%d")
    try: vt = datetime.strptime(b.get("ValidTill","")[:10], "%Y-%m-%d").strftime("%Y-%m-%d")
    except: vt = q_date
    new_id = next_id("quotations")
    doc = {
        "Id": new_id, "QuotationNo": q_no, "QuotationDate": q_date,
        "createdBy": (b.get("createdBy") or "").strip(),
        "CustomerId": to_int(b.get("CustomerId"),0),
        "CustomerName": b.get("CustomerName",""), "BillingType": b.get("BillingType",""),
        "PlaceOfSupply": b.get("PlaceOfSupply",""), "PlaceOfSupplyCode": b.get("PlaceOfSupplyCode",""),
        "SubTotal": to_float(b.get("SubTotal"),0), "CGST": to_float(b.get("CGST"),0),
        "SGST": to_float(b.get("SGST"),0), "IGST": to_float(b.get("IGST"),0),
        "TotalAmount": to_float(b.get("TotalAmount"),0),
        "PaymentTerms": b.get("PaymentTerms",""), "ValidTill": vt
    }
    col("quotations").insert_one(doc)
    sno = 1
    for item in (b.get("Items") or []):
        if not item: continue
        qty = to_float(item.get("Qty"),0); rate = to_float(item.get("Rate"),0)
        tv  = to_float(item.get("TaxableValue"), qty*rate if qty and rate else 0)
        it  = to_float(item.get("Total"), tv)
        if not item.get("ProductName") and not tv: continue
        col("quotation_items").insert_one({
            "QuotationId": new_id, "SNo": sno,
            "ProductName": item.get("ProductName",""), "HSN": item.get("HSN",""),
            "Qty": qty, "Rate": rate, "TaxableValue": tv,
            "GSTRate": to_float(item.get("GSTRate"),0), "Total": it,
            "SizeNotes": item.get("SizeNotes","")
        })
        sno += 1
    return ok({"success": True, "id": new_id, "quotationNo": q_no})


@app.put("/api/billing/quotations/{quot_id}")
async def billing_put_quotation(quot_id: int, request: Request):
    if not await ensure_db(): return err("Database not connected", 503)
    b = await request.json()
    q_no = (b.get("QuotationNo") or "").strip()
    if not q_no: return err("QuotationNo required")
    try: q_date = datetime.strptime(b.get("QuotationDate","")[:10], "%Y-%m-%d").strftime("%Y-%m-%d")
    except: q_date = datetime.now().strftime("%Y-%m-%d")
    try: vt = datetime.strptime(b.get("ValidTill","")[:10], "%Y-%m-%d").strftime("%Y-%m-%d")
    except: vt = q_date
    update_doc = {
        "QuotationNo": q_no, "QuotationDate": q_date,
        "CustomerId": to_int(b.get("CustomerId"),0),
        "CustomerName": b.get("CustomerName",""), "BillingType": b.get("BillingType",""),
        "PlaceOfSupply": b.get("PlaceOfSupply",""), "PlaceOfSupplyCode": b.get("PlaceOfSupplyCode",""),
        "SubTotal": to_float(b.get("SubTotal"),0), "CGST": to_float(b.get("CGST"),0),
        "SGST": to_float(b.get("SGST"),0), "IGST": to_float(b.get("IGST"),0),
        "TotalAmount": to_float(b.get("TotalAmount"),0),
        "PaymentTerms": b.get("PaymentTerms",""), "ValidTill": vt
    }
    col("quotations").update_one({"Id": quot_id}, {"$set": update_doc})
    # Replace items
    col("quotation_items").delete_many({"QuotationId": quot_id})
    sno = 1
    for item in (b.get("Items") or []):
        if not item: continue
        qty = to_float(item.get("Qty"),0); rate = to_float(item.get("Rate"),0)
        tv  = to_float(item.get("TaxableValue"), qty*rate if qty and rate else 0)
        it  = to_float(item.get("Total"), tv)
        if not item.get("ProductName") and not tv: continue
        col("quotation_items").insert_one({
            "QuotationId": quot_id, "SNo": sno,
            "ProductName": item.get("ProductName",""), "HSN": item.get("HSN",""),
            "Qty": qty, "Rate": rate, "TaxableValue": tv,
            "GSTRate": to_float(item.get("GSTRate"),0), "Total": it,
            "SizeNotes": item.get("SizeNotes","")
        })
        sno += 1
    return ok({"success": True, "quotationNo": q_no})

@app.delete("/api/billing/quotations/{quot_id}")
async def billing_delete_quotation(quot_id: int):
    if not await ensure_db(): return err("Database not connected", 503)
    # Find this quotation first to determine its series (GST vs Non-GST)
    quot_exists = col("quotations").count_documents({"Id": quot_id}, limit=1) > 0
    if not quot_exists:
        return err("Quotation not found", 404)
    this_quot = col("quotations").find_one({"Id": quot_id}, {"QuotationNo": 1}) or {}
    qno = this_quot.get("QuotationNo", "")
    # Find the latest quotation in the SAME series
    if qno.startswith("QN"):
        latest = col("quotations").find_one({"QuotationNo": {"$regex": r"^WB_QN\d+$"}}, sort=[("Id", DESCENDING)])
    else:
        latest = col("quotations").find_one({"QuotationNo": {"$regex": r"^WB_Q\d+$"}}, sort=[("Id", DESCENDING)])
    if not latest or latest.get("Id") != quot_id:
        return err("Only the most recent quotation in this series can be deleted.", 403)
    col("quotation_items").delete_many({"QuotationId": quot_id})
    col("quotations").delete_one({"Id": quot_id})
    return ok({"success": True})

# ─────────────────────────────────────────────
#  BILLING — REPORTS
# ─────────────────────────────────────────────
@app.get("/api/billing/reports/sales")
async def billing_reports_sales(
    fr: Optional[str] = Query(None, alias="from"), to: Optional[str] = Query(None),
    type: Optional[str] = Query(None)
):
    query = {}
    if fr or to:
        query["InvoiceDate"] = {}
        if fr: query["InvoiceDate"]["$gte"] = fr
        if to: query["InvoiceDate"]["$lte"] = to
    if type == "GST":    query["BillingType"] = {"$in": ["GST","IGST"]}
    if type == "NONGST": query["BillingType"] = "NON-GST"
    rows = list(col("sales_invoices").find(query, {"_id":0,"InvoiceNo":1,"InvoiceDate":1,"CustomerName":1,"CustomerGST":1,"PlaceOfSupply":1,"Items":1,"BillingType":1,"CreatedBy":1,"SubTotal":1,"CGST":1,"SGST":1,"IGST":1,"TotalAmount":1})
                .sort([("InvoiceDate", DESCENDING), ("Id", DESCENDING)]))
    
    # Process rows to extract HSN and Quantity from sales_items collection
    processed_rows = []
    for r in rows:
        row_data = {
            "InvoiceNo": r.get("InvoiceNo", ""),
            "InvoiceDate": r.get("InvoiceDate", ""),
            "CustomerName": r.get("CustomerName", ""),
            "CustomerGST": r.get("CustomerGST", ""),
            "PlaceOfSupply": r.get("PlaceOfSupply", ""),
            "HSN": "",
            "Quantity": 0,
            "BillingType": r.get("BillingType", ""),
            "CreatedBy": r.get("CreatedBy", ""),
            "SubTotal": r.get("SubTotal", 0),
            "CGST": r.get("CGST", 0),
            "SGST": r.get("SGST", 0),
            "IGST": r.get("IGST", 0),
            "TotalAmount": r.get("TotalAmount", 0)
        }
        
        # Get first item from sales_items collection
        item = col("sales_items").find_one({"InvoiceId": r.get("Id")}, {"_id": 0, "HSN": 1, "Qty": 1})
        if item:
            row_data["HSN"] = item.get("HSN", "")
            row_data["Quantity"] = to_float(item.get("Qty", 0), 0)
        
        processed_rows.append(row_data)
    
    totals = {"SubTotal":0,"CGST":0,"SGST":0,"IGST":0,"TotalAmount":0}
    for r in processed_rows:
        for k in totals:
            totals[k] += to_float(r.get(k),0)
    return JSONResponse(content={"data": processed_rows, "count": len(processed_rows), "totals": totals})

# ─────────────────────────────────────────────
#  BILLING — BACKUP (stub — data is in MongoDB)
# ─────────────────────────────────────────────
@app.post("/api/billing/backup")
async def billing_backup():
    return ok({"success": True, "message": "Data is stored in MongoDB Atlas — no local backup needed. Use MongoDB Atlas backup features.", "recentBackups": []})

@app.get("/api/billing/backups")
async def billing_backups():
    return JSONResponse(content=[])

@app.post("/api/billing/reset-sequences")
async def billing_reset_sequences():
    return ok({"message": "Sequences are auto-calculated from existing records in MongoDB.", "invoiceCount": 0, "quotationCount": 0})

# ─────────────────────────────────────────────
#  REPORTS (non-billing)
# ─────────────────────────────────────────────
@app.get("/api/reports/sales")
async def reports_sales(
    fr: Optional[str] = Query(None, alias="from"), to: Optional[str] = Query(None),
    type: Optional[str] = Query(None)
):
    return await billing_reports_sales(fr=fr, to=to, type=type)

# ─────────────────────────────────────────────
#  CLIENT-SIDE LOGGING  →  uses main logger
# ─────────────────────────────────────────────
# Reuse the top-level logger (already configured above with file + stdout)
_log = logging.getLogger("rio_erp_api")
# LOG_FILE exposed for /api/log/tail endpoint
LOG_FILE = _LOG_FILE  # None on Render, Path on Windows

class LogEntry(BaseModel):
    level:   str = "INFO"
    user:    str = "unknown"
    action:  str = ""
    detail:  str = ""
    page:    str = ""
    ts:      str = ""

@app.get("/api/log/where")
async def log_where():
    """Shows where the log file is (or tells you it's on Render stdout)."""
    import platform as _p
    return {
        "platform": _p.system(),
        "log_file": str(LOG_FILE) if LOG_FILE else None,
        "log_exists": LOG_FILE.exists() if LOG_FILE else False,
        "note": (
            f"Log file at: {LOG_FILE}" if LOG_FILE and LOG_FILE.exists()
            else "Running on Render/Linux — logs go to Render dashboard Logs tab, not a file."
        )
    }

@app.get("/api/log/tail")
async def log_tail(n: int = 100):
    """Return last n lines of the log file (Windows only; Render uses stdout)."""
    if not LOG_FILE or not LOG_FILE.exists():
        return {"lines": [], "note": "Log file not available on this platform. On Render, check the Logs tab in the dashboard."}
    try:
        lines = LOG_FILE.read_text(encoding="utf-8").splitlines()
        return {"lines": lines[-n:], "total": len(lines), "file": str(LOG_FILE)}
    except Exception as e:
        return {"lines": [], "error": str(e)}


# ─────────────────────────────────────────────
#  ATTENDANCE — matches PS1 v2.1 structure
#  Collection: att_records, att_staff
# ─────────────────────────────────────────────
@app.get("/api/attendance/ping")
async def att_ping():
    if not await ensure_db(): return JSONResponse(content={"ok": False}, status_code=503)
    return {"ok": True}

@app.get("/api/attendance/staff")
async def get_att_staff():
    if not await ensure_db(): return JSONResponse(content=[], status_code=503)
    try:
        rows = list(col("att_staff").find({}, {"_id": 0}).sort("name", ASCENDING))
        return JSONResponse(content=rows)
    except Exception as e:
        return JSONResponse(content=[], status_code=500)

@app.post("/api/attendance/delete-employee")
async def delete_employee_attendance(request: Request):
    if not await ensure_db(): return err("Database not connected", 503)
    b = await request.json()
    name = b.get("name", "").strip()
    if not name: return err("Employee name required", 400)
    result = col("attendance").delete_many({"name": name})
    return ok({"success": True, "deleted": result.deleted_count})

@app.post("/api/attendance/staff")
async def post_att_staff(request: Request):
    staff = await request.json()
    if not isinstance(staff, list): return err("Expected array")
    if not await ensure_db(): return err("DB offline")
    try:
        col("att_staff").delete_many({})
        if staff:
            col("att_staff").insert_many(
                [{k:v for k,v in s.items()} for s in staff], ordered=False
            )
    except Exception as e:
        return err(str(e))
    return ok({"success": True})

# get_attendance: replaced by full version from attendance_api below
@app.post("/api/attendance/upsert")
async def att_upsert(request: Request):
    rec = await request.json()
    if not await ensure_db(): return err("DB offline")
    try:
        rec_id = rec.get("id")
        name   = rec.get("name","").strip()
        date   = rec.get("date","").strip()
        if not name or not date: return err("name and date required")
        # Remove MongoDB _id if present
        rec.pop("_id", None)
        col("att_records").replace_one({"name": name, "date": date}, rec, upsert=True)
        return ok({"success": True})
    except Exception as e:
        return err(str(e))

@app.get("/api/attendance/all")
async def att_get_all():
    if not await ensure_db(): return JSONResponse(content=[], status_code=503)
    try:
        rows = list(col("att_records").find({}, {"_id": 0}).sort([("date", ASCENDING), ("name", ASCENDING)]))
        return JSONResponse(content=rows)
    except Exception as e:
        return JSONResponse(content=[], status_code=500)

@app.get("/api/attendance/search")
async def att_search(
    fr:   Optional[str] = Query(None, alias="from"),
    to:   Optional[str] = Query(None),
    name: Optional[str] = Query(None),
    jobType: Optional[str] = Query(None)
):
    if not await ensure_db(): return JSONResponse(content=[], status_code=503)
    try:
        query = {}
        if fr or to:
            query["date"] = {}
            if fr: query["date"]["$gte"] = fr
            if to: query["date"]["$lte"] = to
        if name:    query["name"]    = name
        if jobType: query["jobType"] = jobType
        rows = list(col("att_records").find(query, {"_id": 0}).sort([("date", ASCENDING), ("name", ASCENDING)]))
        return JSONResponse(content=rows)
    except Exception as e:
        return JSONResponse(content=[], status_code=500)

@app.delete("/api/attendance/delete")
async def att_delete(
    fr:   Optional[str] = Query(None, alias="from"),
    to:   Optional[str] = Query(None),
    name: Optional[str] = Query(None)
):
    if not await ensure_db(): return err("DB offline")
    try:
        query = {}
        if fr or to:
            query["date"] = {}
            if fr: query["date"]["$gte"] = fr
            if to: query["date"]["$lte"] = to
        if name: query["name"] = name
        result = col("att_records").delete_many(query)
        return ok({"deleted": result.deleted_count})
    except Exception as e:
        return err(str(e))

# upsert_attendance: replaced by attendance_api version below
@app.post("/api/auth/login")
async def login(request: Request):
    if not await ensure_db():
        return JSONResponse(content={"ok": False, "error": "Database not connected. Please try again in a moment."}, status_code=503)
    b = await request.json()
    username = (b.get("username") or "").strip().lower()
    password = (b.get("password") or "").strip()
    if not username or not password:
        return err("Username and password required", 400)
    user = _db["winner_bags_users"].find_one({"username": username}, {"_id": 0})
    if not user:
        return err("Invalid username or password", 401)
    if not verify_password(password, user["password"]):
        return err("Invalid username or password", 401)
    # Accept any role — built-in or custom roles created in User Management
    role = user.get("role", "guest") or "guest"
    scope = user.get("scope", "all")
    # Generate a session token and store it so protected endpoints can verify
    token = secrets.token_hex(32)
    _db["winner_bags_users"].update_one(
        {"username": username},
        {"$set": {"session_token": token}}
    )
    mobile_access = bool(user.get("mobile_access", False))
    # If login is from mobile app, block users without mobile_access
    source = (b.get("source") or "web").strip().lower()
    if source == "mobile" and not mobile_access and role != "admin":
        return err("Mobile access not enabled for this account. Please contact your administrator.", 403)

    # Record this login in the audit log - IP, OS/browser (there's no way
    # to get a real "machine name"/hostname from a browser, this is the
    # closest actual equivalent), and an approximate city from IP
    # geolocation. Wrapped in try/except so a logging failure never blocks
    # an otherwise-successful login.
    try:
        client_ip = get_client_ip(request)
        ua_info = parse_user_agent(request.headers.get("user-agent", ""))
        geo = await get_ip_geolocation(client_ip)
        col("rio_login_logs").insert_one({
            "Id": next_id("rio_login_logs"),
            "Username": username,
            "Role": role,
            "LoginTime": datetime.utcnow().isoformat(),
            "IP": client_ip,
            "OS": ua_info["os"],
            "Browser": ua_info["browser"],
            "City": geo["city"],
            "Region": geo["region"],
            "Country": geo["country"],
            "Source": source,
        })
    except Exception as e:
        logger.warning(f"Login logging failed (non-fatal): {e}")


    # Record this login in the audit log - IP, OS/browser (there's no way
    # to get a real "machine name"/hostname from a browser, this is the
    # closest actual equivalent), and an approximate city from IP
    # geolocation. Wrapped in try/except so a logging failure never blocks
    # an otherwise-successful login.
    try:
        client_ip = get_client_ip(request)
        ua_info = parse_user_agent(request.headers.get("user-agent", ""))
        geo = await get_ip_geolocation(client_ip)
        col("rio_login_logs").insert_one({
            "Id": next_id("rio_login_logs"),
            "Username": username,
            "Role": role,
            "LoginTime": datetime.utcnow().isoformat(),
            "IP": client_ip,
            "OS": ua_info["os"],
            "Browser": ua_info["browser"],
            "City": geo["city"],
            "Region": geo["region"],
            "Country": geo["country"],
            "Source": source,
        })
    except Exception as e:
        logger.warning(f"Login logging failed (non-fatal): {e}")

    return JSONResponse(content={
        "ok": True,
        "username": user["username"],
        "name": user.get("name", username),
        "role": role,
        "scope": scope,
        "token": token,
        "mobile_access": mobile_access
    })

@app.get("/api/billing/users")
@app.get("/api/auth/users")
async def get_users():
    if not await ensure_db():
        return JSONResponse(content={"error": "Database not connected"}, status_code=503)
    # Always read from master DB regardless of company context
    users = list(_db["winner_bags_users"].find({}, {"_id": 0, "password": 0, "session_token": 0}))
    return JSONResponse(content=users)

@app.post("/api/auth/users")
async def create_user(request: Request):
    b = await request.json()
    username = (b.get("username") or "").strip().lower()
    password = (b.get("password") or "").strip()
    role     = (b.get("role") or "expense").strip()
    name     = (b.get("name") or username).strip()
    if not username or not password:
        return err("Username and password required")
    # Accept any role — including custom roles created in User Management
    if not role:
        role = "guest"
    if col("winner_bags_users").find_one({"username": username}):
        return err("Username already exists")
    scope = (b.get("scope") or "all").strip()
    if scope not in {"all", "own"}: scope = "all"
    mobile_access_flag = bool(b.get("mobile_access", False))
    col("winner_bags_users").insert_one({
        "username": username,
        "password": hash_password(password),
        "role": role,
        "name": name,
        "scope": scope,
        "mobile_access": mobile_access_flag
    })
    return ok({"ok": True})

@app.put("/api/auth/users/{username}")
async def update_user(username: str, request: Request):
    b = await request.json()
    update = {}
    if b.get("password"): update["password"] = hash_password(b["password"])
    if b.get("role"):     update["role"]     = b["role"]
    if b.get("name"):     update["name"]     = b["name"]
    if b.get("scope") in {"all","own"}: update["scope"] = b["scope"]
    if "mobile_access" in b: update["mobile_access"] = bool(b["mobile_access"])
    if not update:
        return err(f"No fields to update", 400)
    result = col("winner_bags_users").update_one({"username": username}, {"$set": update})
    if result.matched_count == 0:
        # Nothing matched — this used to silently no-op and still report
        # success, making password changes look like they "didn't work"
        # with no error shown. Try a case-insensitive fallback match
        # before giving up, since login() lowercases usernames but this
        # endpoint's path parameter never did.
        fallback = col("winner_bags_users").find_one(
            {"username": {"$regex": f"^{re.escape(username)}$", "$options": "i"}}
        )
        if fallback:
            col("winner_bags_users").update_one({"username": fallback["username"]}, {"$set": update})
        else:
            return err(f"User '{username}' not found — nothing was updated", 404)
    return ok()

@app.delete("/api/auth/users/{username}")
async def delete_user(username: str):
    if username == "admin":
        return err("Cannot delete admin user")
    result = col("winner_bags_users").delete_one({"username": username})
    if result.deleted_count == 0:
        return err(f"User '{username}' not found — nothing was deleted", 404)
    return ok()


# ══════════════════════════════════════════════════════════════
# MOBILE — quotation toggle, split-up CRUD
# ══════════════════════════════════════════════════════════════

@app.patch("/api/quotations/{qid}/mobile-toggle")
async def mobile_toggle_quotation(qid: int):
    """Toggle mobile_visible flag on a quotation."""
    if not await ensure_db(): return err("Database not connected", 503)
    q = col("quotations").find_one({"Id": qid}, {"_id": 0, "mobile_visible": 1})
    if not q: return err("Quotation not found", 404)
    new_val = not bool(q.get("mobile_visible", False))
    col("quotations").update_one({"Id": qid}, {"$set": {"mobile_visible": new_val}})
    return JSONResponse(content={"ok": True, "mobile_visible": new_val})

@app.get("/api/mobile/splitups")
async def get_mobile_splitups(
    user: Optional[str] = Query(None),
    role: Optional[str] = Query(None),
    limit: int = Query(100)
):
    """List split-ups. Admin sees all; others see only their own."""
    if not await ensure_db(): return err("Database not connected", 503)
    query = {}
    if role != "admin" and user:
        query["createdBy"] = user
    rows = list(col("mobile_splitups").find(query, {"_id": 0})
                .sort("createdAt", DESCENDING).limit(limit))
    return JSONResponse(content={"data": rows, "total": len(rows)})

@app.post("/api/mobile/splitups")
async def post_mobile_splitup(request: Request):
    """Save a new split-up calculation."""
    if not await ensure_db(): return err("Database not connected", 503)
    b = await request.json()
    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc)
    doc = {
        "size":        b.get("size", ""),
        "billingType": b.get("billingType", "GST"),
        "qty":         int(b.get("qty", 0)),
        "gstQty":      int(b.get("gstQty", 0)),
        "nonGstQty":   int(b.get("nonGstQty", 0)),
        "rate":        float(b.get("rate", 0)),
        "gstRate":     float(b.get("gstRate", 18)),
        "gstAmount":   float(b.get("gstAmount", 0)),
        "gstValue":    float(b.get("gstValue", 0)),
        "gstTotal":    float(b.get("gstTotal", 0)),
        "nonGstAmount":float(b.get("nonGstAmount", 0)),
        "nonGstTotal": float(b.get("nonGstTotal", 0)),
        "grandTotal":  float(b.get("grandTotal", 0)),
        "createdBy":   b.get("createdBy", ""),
        "customerName": b.get("customerName", ""),
    }
    # Belt-and-braces dedup: an identical calculation from the same user
    # within the last 15s is a double-fire (double tap / duplicate event),
    # not a new entry — return the already-saved record instead of inserting.
    cutoff = (now - timedelta(seconds=15)).isoformat()
    dup = col("mobile_splitups").find_one(
        {**doc, "createdAt": {"$gte": cutoff}}, {"Id": 1, "_id": 0}
    )
    if dup:
        return JSONResponse(content={"ok": True, "Id": dup.get("Id"), "deduped": True})
    last = col("mobile_splitups").find_one({}, {"Id": 1, "_id": 0}, sort=[("Id", DESCENDING)])
    new_id = (last["Id"] if last and "Id" in last else 0) + 1
    doc["Id"] = new_id
    doc["createdAt"] = now.isoformat()
    col("mobile_splitups").insert_one(doc)
    return JSONResponse(content={"ok": True, "Id": new_id})

@app.delete("/api/mobile/splitups/{split_id}")
async def delete_mobile_splitup(split_id: int):
    """Delete a split-up record."""
    if not await ensure_db(): return err("Database not connected", 503)
    r = col("mobile_splitups").delete_one({"Id": split_id})
    if r.deleted_count == 0: return err("Split-up not found", 404)
    return JSONResponse(content={"ok": True})


# ══════════════════════════════════════════════════════════════
# CUSTOM ROLES — stored in MongoDB so all machines share them
# ══════════════════════════════════════════════════════════════

@app.get("/api/sizes")
async def get_sizes(company: str = "rio"):
    """Return the sizes list for a company. Stored in MongoDB sizes_list collection
    (one document per company); falls back to a legacy shared doc, then to defaults."""
    if not await ensure_db(): return err("Database not connected", 503)
    company = (company or "rio").lower()
    stored = col("sizes_list").find_one({"company": company}, {"_id": 0})
    if stored and stored.get("sizes"):
        return JSONResponse(content={"sizes": stored["sizes"]})
    # Legacy shared doc (pre-company-scoping) — use once, then let POST re-save per company
    legacy = col("sizes_list").find_one({"type": "main"}, {"_id": 0})
    if legacy and legacy.get("sizes"):
        return JSONResponse(content={"sizes": legacy["sizes"]})
    # Return hardcoded defaults
    defaults = [
        "16x6 Inches","18x6 Inches","12x18 Inches","12x12 Inches",
        "16x16 Inches","24x18 Inches","24x12 Inches","24x24 Inches",
        "36x12 Inches","36x24 Inches","48x4 Inches","Others"
    ]
    return JSONResponse(content={"sizes": defaults})

@app.post("/api/sizes")
async def save_sizes(request: Request):
    """Persist the full sizes list for a company to MongoDB, so every device
    (desktop and mobile) reads the same list via GET /api/sizes?company=..."""
    if not await ensure_db(): return err("Database not connected", 503)
    b = await request.json()
    company = (b.get("company") or "rio").lower()
    sizes = b.get("sizes")
    if not isinstance(sizes, list):
        return err("sizes must be a list")
    col("sizes_list").update_one(
        {"company": company},
        {"$set": {"company": company, "sizes": sizes, "UpdatedAt": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}},
        upsert=True
    )
    return JSONResponse(content={"success": True, "count": len(sizes)})

@app.post("/api/sizes/rename")
async def rename_size(request: Request):
    """Cascade a size rename across all sales records, invoice items, and quotation items."""
    b = await request.json()
    old_name = (b.get("oldName") or "").strip()
    new_name = (b.get("newName") or "").strip()
    if not old_name or not new_name or old_name == new_name:
        return err("oldName and newName required and must differ")
    results = {}
    # Sales records: Size1, Size2 and Size3 fields
    r1 = col("sales_records").update_many({"Size1": old_name}, {"$set": {"Size1": new_name}})
    r2 = col("sales_records").update_many({"Size2": old_name}, {"$set": {"Size2": new_name}})
    r2b = col("sales_records").update_many({"Size3": old_name}, {"$set": {"Size3": new_name}})
    results["sales"] = r1.modified_count + r2.modified_count + r2b.modified_count
    # Invoice line items: SizeNotes field
    r3 = col("sales_items").update_many({"SizeNotes": old_name}, {"$set": {"SizeNotes": new_name}})
    results["invoice_items"] = r3.modified_count
    # Quotation line items: SizeNotes field
    r4 = col("quotation_items").update_many({"SizeNotes": old_name}, {"$set": {"SizeNotes": new_name}})
    results["quotation_items"] = r4.modified_count
    logger.info(f"Size rename '{old_name}' → '{new_name}': {results}")
    return ok({"renamed": results})

@app.post("/api/billing/invoices/{inv_id}/sync-from-sales")
async def sync_invoice_from_sales(inv_id: int):
    """Fully sync an invoice from its linked sales record — rebuilds all items and recalculates totals."""
    if not await ensure_db(): return err("Database not connected", 503)
    inv = col("sales_invoices").find_one({"Id": inv_id}, {"_id": 0})
    if not inv: return err("Invoice not found", 404)
    inv_no = inv.get("InvoiceNo", "")
    if not inv_no: return err("Invoice has no InvoiceNo", 400)

    # Find the linked sales record
    sale = col("sales_records").find_one({"InvoiceNo": inv_no}, {"_id": 0})
    if not sale: return err(f"No sales record linked to invoice {inv_no}", 404)

    # Determine billing type
    is_gst = sale.get("BillingType", "") == "With Bill"
    billing_type_str = "GST"  # default — overridden below with IGST if needed

    # Look up product for HSN and GSTRate
    prod_name = sale.get("ProductSize") or sale.get("Category") or ""
    hsn = ""; gst_rate = 18.0
    product = col("rio_products").find_one(
        {"$or": [{"Name": prod_name}, {"name": prod_name}]}, {"_id": 0}
    )
    if product:
        hsn      = product.get("HSN") or product.get("hsn") or ""
        gst_rate = to_float(product.get("GSTRate") or product.get("gstrate"), 18.0)

    # Build line items — same logic as generateInvoiceFromSales
    items = []
    sno = 1
    q1 = to_float(sale.get("Qty1"), 0); r1 = to_float(sale.get("Rate1"), 0)
    if q1 > 0 and r1 > 0:
        tax1 = round(q1 * r1, 2)
        items.append({"SNo": sno, "ProductName": prod_name, "HSN": hsn,
                      "Qty": q1, "Rate": r1, "TaxableValue": tax1,
                      "GSTRate": gst_rate, "Total": tax1, "SizeNotes": sale.get("Size1", "")})
        sno += 1
    q2 = to_float(sale.get("Qty2"), 0); r2 = to_float(sale.get("Rate2"), 0)
    if q2 > 0 and r2 > 0:
        tax2 = round(q2 * r2, 2)
        items.append({"SNo": sno, "ProductName": prod_name, "HSN": hsn,
                      "Qty": q2, "Rate": r2, "TaxableValue": tax2,
                      "GSTRate": gst_rate, "Total": tax2, "SizeNotes": sale.get("Size2", "")})
        sno += 1
    q3 = to_float(sale.get("Qty3"), 0); r3 = to_float(sale.get("Rate3"), 0)
    if q3 > 0 and r3 > 0:
        tax3 = round(q3 * r3, 2)
        items.append({"SNo": sno, "ProductName": prod_name, "HSN": hsn,
                      "Qty": q3, "Rate": r3, "TaxableValue": tax3,
                      "GSTRate": gst_rate, "Total": tax3, "SizeNotes": sale.get("Size3", "")})
        sno += 1

    # Packing & Forwarding line
    pf_amt   = to_float(sale.get("PFAmt"), 0)
    pf_gst   = to_float(sale.get("PFGst"), 0)
    pf_total = to_float(sale.get("PFTotal"), 0)
    if pf_amt > 0:
        pf_taxable = pf_amt
        items.append({"SNo": sno, "ProductName": "Packing and Forwarding", "HSN": "",
                      "Qty": 1, "Rate": pf_amt, "TaxableValue": pf_taxable,
                      "GSTRate": pf_gst, "Total": pf_total if pf_total > 0 else pf_taxable,
                      "SizeNotes": ""})
        sno += 1

    if not items:
        return err("Sales record has no line items (Qty/Rate missing)")

    # Look up customer state for IGST vs CGST/SGST
    cust_state = "Tamil Nadu"; cust_state_code = "33"; cust_id = inv.get("CustomerId", 0)
    cust_doc = shared_col("rio_clients").find_one({"ClientName": sale.get("Customer", "")}, {"_id": 0})
    if cust_doc:
        cust_state      = cust_doc.get("State")     or "Tamil Nadu"
        cust_state_code = cust_doc.get("StateCode") or "33"
        cust_id         = cust_doc.get("Id", cust_id)
    is_same_state = not cust_state or "tamil" in cust_state.lower()

    # Calculate totals per item GSTRate
    sub_total = round(sum(it["TaxableValue"] for it in items), 2)
    cgst = sgst = igst = 0.0
    if is_gst:
        for it in items:
            tax_amt = round(it["TaxableValue"] * it["GSTRate"] / 100, 2)
            if is_same_state:
                cgst += round(tax_amt / 2, 2); sgst += round(tax_amt / 2, 2)
            else:
                igst += tax_amt
        cgst = round(cgst, 2); sgst = round(sgst, 2); igst = round(igst, 2)
        billing_type_str = "GST" if is_same_state else "IGST"
    else:
        billing_type_str = "NON-GST"

    grand = round(sub_total + cgst + sgst + igst)

    # Rebuild sales_items
    col("sales_items").delete_many({"InvoiceId": inv_id})
    for it in items:
        col("sales_items").insert_one({
            "InvoiceId": inv_id,
            "SNo": it["SNo"], "ProductName": it["ProductName"], "HSN": it["HSN"],
            "Qty": it["Qty"], "Rate": it["Rate"], "TaxableValue": it["TaxableValue"],
            "GSTRate": it["GSTRate"], "Total": it["Total"], "SizeNotes": it["SizeNotes"]
        })

    # Update invoice header
    update = {
        "CustomerName":      sale.get("Customer", inv.get("CustomerName", "")),
        "CustomerId":        cust_id,
        "CustomerGST":       cust_doc.get("GSTNo", "") if cust_doc else inv.get("CustomerGST", ""),
        "BillingType":       billing_type_str,
        "PlaceOfSupply":     cust_state,
        "PlaceOfSupplyCode": cust_state_code,
        "SubTotal":          sub_total,
        "CGST":              cgst, "SGST": sgst, "IGST": igst,
        "TotalAmount":       grand,
        "PFDesc":            sale.get("PFDesc", ""),
        "PFAmt":             pf_amt, "PFGst": pf_gst, "PFTotal": pf_total,
        "PaymentTerms":      "NEFT" if is_gst else "Cash",
    }
    col("sales_invoices").update_one({"Id": inv_id}, {"$set": update})
    logger.info(f"Full sync: Invoice {inv_no} rebuilt from sales SNo={sale.get('SNo')} — {len(items)} items, Total={grand}")
    return ok({"synced": True, "invoiceNo": inv_no, "items": len(items), "total": grand,
               "billingType": billing_type_str, "CGST": cgst, "SGST": sgst, "IGST": igst})

@app.get("/api/roles")
async def get_roles():
    if not await ensure_db():
        return JSONResponse(content=[], status_code=503)
    roles = list(col("rio_custom_roles").find({}, {"_id": 0}))
    return JSONResponse(content=roles)

@app.post("/api/roles")
async def save_role(request: Request):
    if not await ensure_db(): return err("Database not connected", 503)
    b = await request.json()
    role_id = (b.get("id") or "").strip()
    if not role_id: return err("role id required")
    col("rio_custom_roles").update_one(
        {"id": role_id},
        {"$set": b},
        upsert=True
    )
    return ok({"ok": True})

@app.delete("/api/roles/{role_id}")
async def delete_role(role_id: str):
    if not await ensure_db(): return err("Database not connected", 503)
    col("rio_custom_roles").delete_one({"id": role_id})
    return ok()

# ══════════════════════════════════════════════════════════════
# ATTENDANCE TRACKER — routes on /api/attendance/*
# ══════════════════════════════════════════════════════════════

SHIFT_START = 9  * 60   # 09:00 in minutes
SHIFT_END   = 20 * 60   # 20:00 in minutes
MAX_OUT     = 26 * 60   # safety cap

# ── Calculation helpers ───────────────────────────────────────────────────────
DAY_NAMES = ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"]

def to_mins(t: str) -> int:
    if not t or ":" not in t:
        return 0
    parts = t.split(":")
    return int(parts[0]) * 60 + int(parts[1])

def get_day_name(ds: str) -> str:
    """Return weekday name for a YYYY-MM-DD date string."""
    try:
        parts = ds.split("-")
        if len(parts[0]) == 4:
            dt = date(int(parts[0]), int(parts[1]), int(parts[2]))
        else:
            dt = date(int(parts[2]), int(parts[1]), int(parts[0]))
        return DAY_NAMES[(dt.weekday() + 1) % 7]
    except Exception:
        return "?"

def norm_date(d: str) -> str:
    """Normalize to YYYY-MM-DD."""
    d = d.strip().replace("/", "-").replace("\\", "-")
    parts = d.split("-")
    if len(parts) != 3:
        return d
    if len(parts[0]) == 4:
        return f"{parts[0]}-{parts[1].zfill(2)}-{parts[2].zfill(2)}"
    return f"{parts[2]}-{parts[1].zfill(2)}-{parts[0].zfill(2)}"

def calc(in_t: str, out_t: str, ds: str, rec_type: str, job_type: str = "fulltime", perm_mins: int = 0) -> dict:
    """Replicate PowerShell Calc() function."""
    if rec_type == "holiday":
        return {"totalWorked": 0, "extraHrs": 0, "lateHrs": 0, "status": "holiday"}
    if rec_type == "sunday-off":
        return {"totalWorked": 0, "extraHrs": 0, "lateHrs": 0, "status": "sunday"}
    if job_type == "parttime" and (not in_t or not out_t):
        return {"totalWorked": 0, "extraHrs": 0, "lateHrs": 0, "status": "absent"}
    if rec_type == "absent" or (not in_t and not out_t):
        return {"totalWorked": 0, "extraHrs": 0, "lateHrs": 0, "status": "absent"}
    if not in_t or not out_t:
        return {"totalWorked": 0, "extraHrs": 0, "lateHrs": 0, "status": "absent"}

    in_m  = to_mins(in_t)
    out_m = to_mins(out_t)
    if out_m <= in_m:
        out_m += 1440
    cap = min(out_m, MAX_OUT)
    tw  = cap - in_m

    if job_type == "parttime":
        st = "sunday" if get_day_name(ds) == "Sunday" else "ok"
        return {"totalWorked": max(0, tw - perm_mins), "extraHrs": 0, "lateHrs": 0, "status": st, "permMins": perm_mins}

    if get_day_name(ds) == "Sunday":
        tw_net = max(0, tw - perm_mins)
        return {"totalWorked": tw_net, "extraHrs": tw_net, "lateHrs": 0, "status": "sunday", "permMins": perm_mins}

    eh = max(0, SHIFT_START - in_m) + max(0, cap - SHIFT_END)
    la = max(0, in_m - SHIFT_START)
    lv = max(0, SHIFT_END - out_m) if out_m < SHIFT_END else 0
    lh = la + lv
    if in_m < SHIFT_START:
        st = "early"
    elif in_m > SHIFT_START:
        st = "late"
    else:
        st = "ok"
    tw_net = max(0, tw - perm_mins)
    return {"totalWorked": tw_net, "extraHrs": eh, "lateHrs": lh, "status": st, "permMins": perm_mins}

def rec_to_doc(r: dict) -> dict:
    """Strip MongoDB _id before returning to client."""
    r.pop("_id", None)
    return r

# ── Ping ──────────────────────────────────────────────────────────────────────
# /api/attendance/ping is already defined above — skipping duplicate

# ── Employees list ────────────────────────────────────────────────────────────
@app.get("/api/attendance/employees")
async def get_employees():
    if not await ensure_db():
        return JSONResponse(content=[], status_code=503)
    names = col("attendance").distinct("name")
    return JSONResponse(content=sorted(names))

# ── Get records ───────────────────────────────────────────────────────────────
@app.get("/api/attendance")
async def get_attendance(
    name:     Optional[str] = Query(None),
    job_type: Optional[str] = Query(None),
    date_from:Optional[str] = Query(None),
    date_to:  Optional[str] = Query(None),
):
    if not await ensure_db():
        return JSONResponse(content=[], status_code=503)

    query = {}
    if name:      query["name"] = name
    if job_type:  query["jobType"] = job_type

    rows = list(col("attendance").find(query, {"_id": 0}).sort([("date", ASCENDING), ("name", ASCENDING)]))

    # Date range filter in Python (dates stored as YYYY-MM-DD strings)
    if date_from or date_to:
        filtered = []
        for r in rows:
            rd = r.get("date", "")
            try:
                p = rd.split("-")
                if len(p[0]) == 4:
                    rdate = date(int(p[0]), int(p[1]), int(p[2]))
                else:
                    rdate = date(int(p[2]), int(p[1]), int(p[0]))
                if date_from:
                    df = date_from.split("-")
                    if rdate < date(int(df[0]), int(df[1]), int(df[2])):
                        continue
                if date_to:
                    dt = date_to.split("-")
                    if rdate > date(int(dt[0]), int(dt[1]), int(dt[2])):
                        continue
                filtered.append(r)
            except Exception:
                filtered.append(r)
        rows = filtered

    return JSONResponse(content=rows)

# ── Upsert (add or update) ────────────────────────────────────────────────────
@app.post("/api/attendance")
async def upsert_attendance(request: Request):
    if not await ensure_db():
        return err("Database not connected", 503)
    b = await request.json()

    name     = (b.get("name") or "").strip()
    date_str = norm_date((b.get("date") or "").strip())
    rec_type = (b.get("type") or "work").strip().lower()
    job_type = (b.get("jobType") or "fulltime").strip().lower()
    in_t      = (b.get("inTime") or "").strip()
    out_t     = (b.get("outTime") or "").strip()
    perm_mins = int(b.get("permMins") or 0)

    if not name:      return err("name is required")
    if not date_str:  return err("date is required")

    # Recalculate
    c = calc(in_t, out_t, date_str, rec_type, job_type, perm_mins)

    doc = {
        "name":        name,
        "date":        date_str,
        "type":        rec_type,
        "jobType":     job_type,
        "inTime":      in_t  if rec_type == "work" else "",
        "outTime":     out_t if rec_type == "work" else "",
        "permMins":    perm_mins,
        "totalWorked": c["totalWorked"],
        "extraHrs":    c["extraHrs"],
        "lateHrs":     c["lateHrs"],
        "status":      c["status"],
    }

    col("attendance").update_one(
        {"name": name, "date": date_str},
        {"$set": doc},
        upsert=True
    )
    return ok({"record": doc})

# ── Bulk upsert (CSV import) ──────────────────────────────────────────────────
@app.post("/api/attendance/bulk")
async def bulk_upsert(request: Request):
    if not await ensure_db():
        return err("Database not connected", 503)
    b    = await request.json()
    rows = b if isinstance(b, list) else b.get("records", [])
    imported = 0
    skipped  = 0
    for row in rows:
        name     = (row.get("name") or "").strip()
        date_str = norm_date((row.get("date") or "").strip())
        if not name or not date_str:
            skipped += 1
            continue
        rec_type = (row.get("type") or "work").strip().lower()
        job_type = (row.get("jobType") or "fulltime").strip().lower()
        in_t     = (row.get("inTime") or "").strip()
        out_t    = (row.get("outTime") or "").strip()
        perm_mins_row = int(row.get("permMins") or 0)
        c = calc(in_t, out_t, date_str, rec_type, job_type, perm_mins_row)
        doc = {
            "name":        name,
            "date":        date_str,
            "type":        rec_type,
            "jobType":     job_type,
            "inTime":      in_t  if rec_type == "work" else "",
            "outTime":     out_t if rec_type == "work" else "",
            "permMins":    perm_mins_row,
            "totalWorked": c["totalWorked"],
            "extraHrs":    c["extraHrs"],
            "lateHrs":     c["lateHrs"],
            "status":      c["status"],
        }
        col("attendance").update_one({"name": name, "date": date_str}, {"$set": doc}, upsert=True)
        imported += 1
    return ok({"imported": imported, "skipped": skipped})

# ── Recalculate all ───────────────────────────────────────────────────────────
@app.post("/api/attendance/recalculate")
async def recalculate_all():
    if not await ensure_db():
        return err("Database not connected", 503)
    rows  = list(col("attendance").find({}, {"_id": 0}))
    count = 0
    for r in rows:
        c = calc(r.get("inTime",""), r.get("outTime",""), r.get("date",""), r.get("type","work"), r.get("jobType","fulltime"), int(r.get("permMins") or 0))
        col("attendance").update_one(
            {"name": r["name"], "date": r["date"]},
            {"$set": {"totalWorked": c["totalWorked"], "extraHrs": c["extraHrs"], "lateHrs": c["lateHrs"], "status": c["status"], "permMins": int(r.get("permMins") or 0)}}
        )
        count += 1
    return ok({"recalculated": count})

# ── Delete records ────────────────────────────────────────────────────────────
@app.delete("/api/attendance")
async def delete_attendance(
    name:      Optional[str] = Query(None),
    date_from: Optional[str] = Query(None),
    date_to:   Optional[str] = Query(None),
):
    if not await ensure_db():
        return err("Database not connected", 503)

    # If no filters at all — delete EVERYTHING in the collection
    if not name and not date_from and not date_to:
        result = col("attendance").delete_many({})
        return ok({"deleted": result.deleted_count})

    # Filtered delete — build query
    query = {}
    if name: query["name"] = name
    rows = list(col("attendance").find(query, {"_id": 1, "date": 1}))

    ids_to_delete = []
    for r in rows:
        rd = r.get("date", "")
        try:
            p = rd.split("-")
            if len(p[0]) == 4:
                rdate = date(int(p[0]), int(p[1]), int(p[2]))
            else:
                rdate = date(int(p[2]), int(p[1]), int(p[0]))
            if date_from:
                df = date_from.split("-")
                if rdate < date(int(df[0]), int(df[1]), int(df[2])):
                    continue
            if date_to:
                dt = date_to.split("-")
                if rdate > date(int(dt[0]), int(dt[1]), int(dt[2])):
                    continue
            ids_to_delete.append(r["_id"])
        except Exception:
            ids_to_delete.append(r["_id"])  # include undated records

    if ids_to_delete:
        result = col("attendance").delete_many({"_id": {"$in": ids_to_delete}})
        deleted = result.deleted_count
    else:
        deleted = 0

    return ok({"deleted": deleted})

# ── Delete ALL records (both collections) ────────────────────────────────────
@app.delete("/api/attendance/all")
async def delete_all_attendance():
    if not await ensure_db():
        return err("Database not connected", 503)
    try:
        r1 = col("attendance").delete_many({})
        r2 = col("att_records").delete_many({})
        return ok({"deleted": r1.deleted_count + r2.deleted_count,
                   "attendance": r1.deleted_count,
                   "att_records": r2.deleted_count})
    except Exception as e:
        return err(str(e))

# ── Delete single record by name+date ─────────────────────────────────────────

@app.get("/api/company")
async def get_company():
    # Uses col() which auto-routes to Rio or Rainbow DB
    record = col("company_details").find_one({}, {"_id": 0})
    return record or {}

@app.post("/api/company")
async def save_company(request: Request):
    data = await request.json()
    data.pop("_id", None)
    # Save only the specific section to avoid overwriting other sections
    section = data.pop("section", None)
    col("company_details").update_one({}, {"$set": data}, upsert=True)
    return {"success": True}



@app.post("/api/sales/migrate-customer-gst")
@app.post("/api/billing/sales/migrate-customer-gst")
async def migrate_customer_gst():
    """One-time migration: copy CustomerGST and StateCode from customers into sales records."""
    if not await ensure_db():
        return err("Database not connected", 503)
    try:
        # Build customer lookup map: Name → {GSTNo, StateCode}
        customers = list(col("customers").find({}, {"_id":0,"Name":1,"GSTNo":1,"StateCode":1}))
        cust_map = {c.get("Name","").strip().lower(): c for c in customers if c.get("Name")}

        # Find all sales records that don't have CustomerGST yet
        sales = list(col("sales_records").find(
            {"$or": [{"CustomerGST": {"$exists": False}}, {"CustomerGST": ""}]},
            {"_id":1, "Customer":1}
        ))
        updated = 0
        for s in sales:
            name = (s.get("Customer") or "").strip().lower()
            c = cust_map.get(name)
            if c and (c.get("GSTNo") or c.get("StateCode")):
                col("sales_records").update_one(
                    {"_id": s["_id"]},
                    {"$set": {
                        "CustomerGST": c.get("GSTNo", ""),
                        "CustomerStateCode": c.get("StateCode", "")
                    }}
                )
                updated += 1
        return {"success": True, "updated": updated, "total": len(sales)}
    except Exception as e:
        return err(str(e), 500)


@app.post("/api/customers/merge-shared")
@app.post("/api/billing/customers/merge-shared")
async def merge_customers_to_shared():
    """One-time migration: copy Rainbow customers into RioPrintMedia.rio_clients."""
    if not await ensure_db(): return err("Database not connected", 503)
    try:
        if not _client: return err("No DB client")
        rainbow_clients = list(_client[MONGO_DB_RAINBOW]["rio_clients"].find({}, {"_id": 0}))
        merged = 0
        skipped = 0
        for c in rainbow_clients:
            name = (c.get("ClientName") or c.get("Name") or "").strip()
            if not name:
                continue
            exists = shared_col("rio_clients").find_one({"ClientName": {"$regex": f"^{re.escape(name)}$", "$options": "i"}})
            if exists:
                skipped += 1
                continue
            # Assign new Id
            new_id = next_id("rio_clients")
            c["Id"] = new_id
            c.pop("_id", None)
            shared_col("rio_clients").insert_one(c)
            merged += 1
        return ok({"success": True, "merged": merged, "skipped": skipped, "total": len(rainbow_clients)})
    except Exception as e:
        return err(str(e), 500)


@app.put("/api/categories")
@app.put("/api/billing/categories")
async def put_category(request: Request):
    """Rename a category or subcategory."""
    if not await ensure_db(): return err("Database not connected", 503)
    b = await request.json()
    old_cat = (b.get("oldCategory") or "").strip()
    new_cat = (b.get("newCategory") or "").strip()
    old_sub = (b.get("oldSubCategory") or "").strip()
    new_sub = (b.get("newSubCategory") or "").strip()
    try:
        if old_sub and new_sub:
            # Rename subcategory
            col("expense_categories").update_many(
                {"CategoryName": old_cat, "SubCategoryName": old_sub},
                {"$set": {"SubCategoryName": new_sub}}
            )
            # Update existing expense records
            col("daily_expenses").update_many(
                {"Category": old_cat, "SubCategory": old_sub},
                {"$set": {"SubCategory": new_sub}}
            )
        elif old_cat and new_cat:
            # Rename category
            col("expense_categories").update_many(
                {"CategoryName": old_cat},
                {"$set": {"CategoryName": new_cat}}
            )
            # Update existing expense records
            col("daily_expenses").update_many(
                {"Category": old_cat},
                {"$set": {"Category": new_cat}}
            )
        return ok({"success": True})
    except Exception as e:
        return err(str(e), 500)

@app.delete("/api/categories/byname")
@app.delete("/api/billing/categories/byname")
async def delete_category_byname(category: str = Query(""), subcategory: str = Query("")):
    """Delete a category or subcategory by name."""
    if not await ensure_db(): return err("Database not connected", 503)
    try:
        if subcategory:
            # Delete specific subcategory
            col("expense_categories").delete_many({"CategoryName": category, "SubCategoryName": subcategory})
        elif category:
            # Check if any expenses use this category
            count = col("daily_expenses").count_documents({"Category": category})
            if count > 0:
                return err(f"Cannot delete: {count} expense records use this category", 400)
            col("expense_categories").delete_many({"CategoryName": category})
        return ok({"success": True})
    except Exception as e:
        return err(str(e), 500)

@app.post("/api/categories/add")
@app.post("/api/billing/categories/add")
async def add_category(request: Request):
    """Add a new category (no subcategory required)."""
    if not await ensure_db(): return err("Database not connected", 503)
    b = await request.json()
    cat = (b.get("CategoryName") or "").strip()
    sub = (b.get("SubCategoryName") or "").strip()
    if not cat: return err("Category name required")
    try:
        if sub:
            exists = col("expense_categories").find_one({"CategoryName": cat, "SubCategoryName": sub})
            if not exists:
                new_id = next_id("expense_categories")
                col("expense_categories").insert_one({"Id": new_id, "CategoryName": cat, "SubCategoryName": sub})
        else:
            # Add category with empty placeholder sub if it doesn't exist at all
            exists = col("expense_categories").find_one({"CategoryName": cat})
            if not exists:
                new_id = next_id("expense_categories")
                col("expense_categories").insert_one({"Id": new_id, "CategoryName": cat, "SubCategoryName": ""})
        return ok({"success": True})
    except Exception as e:
        return err(str(e), 500)


@app.post("/api/billing/sales/migrate-gst-rates")
@app.post("/api/sales/migrate-gst-rates")
async def migrate_gst_rates():
    """Patch GSTRate1 on old sales records from products collection."""
    if not await ensure_db(): return err("Database not connected", 503)
    try:
        sales = list(col("sales").find({"$or": [{"GSTRate1": {"$exists": False}}, {"GSTRate1": 0}]}))
        products = {p.get("ProductCode") or p.get("Id"): p for p in col("products").find({})}
        updated = 0
        for s in sales:
            pid = s.get("ProductId")
            if pid and str(pid) in products:
                gst = products[str(pid)].get("GSTRate") or products[str(pid)].get("gstRate") or 0
                if gst:
                    col("sales").update_one({"_id": s["_id"]}, {"$set": {"GSTRate1": float(gst)}})
                    updated += 1
        return ok({"success": True, "updated": updated})
    except Exception as e:
        return err(str(e), 500)


@app.delete("/api/attendance/record")
async def delete_record(name: str = Query(...), date: str = Query(...)):
    if not await ensure_db():
        return err("Database not connected", 503)
    result = col("attendance").delete_one({"name": name, "date": norm_date(date)})
    return ok({"deleted": result.deleted_count})

# ══════════════════════════════════════════════════════════════
# END ATTENDANCE
# ══════════════════════════════════════════════════════════════

# ══════════════════════════════════════════════════════════════
# PURCHASE AND STOCK MODULE
# ══════════════════════════════════════════════════════════════
# Collections (company-separated via existing middleware):
#   suppliers        — supplier master
#   purchases        — purchase headers (P001, P002…)
#   purchase_items   — line items per purchase
#   stock_ledger     — every IN/OUT movement with running balance

# ── SUPPLIERS ─────────────────────────────────────────────────

@app.get("/api/billing/suppliers")
async def get_suppliers(q: Optional[str] = Query(None)):
    if not await ensure_db(): return err("Database not connected", 503)
    query = {}
    if q:
        query = {"$or": [
            {"Name":    {"$regex": q, "$options": "i"}},
            {"GSTNo":   {"$regex": q, "$options": "i"}},
            {"Phone":   {"$regex": q, "$options": "i"}},
        ]}
    docs = list(col("suppliers").find(query, {"_id": 0}).sort("Name", 1))
    return JSONResponse(content={"data": docs, "total": len(docs)})

@app.get("/api/billing/suppliers/{sup_id}")
async def get_supplier(sup_id: int):
    if not await ensure_db(): return err("Database not connected", 503)
    doc = col("suppliers").find_one({"Id": sup_id}, {"_id": 0})
    if not doc: return err("Supplier not found", 404)
    return JSONResponse(content=doc)

@app.post("/api/billing/suppliers")
async def create_supplier(request: Request):
    if not await ensure_db(): return err("Database not connected", 503)
    data = await request.json()
    if not data.get("Name"): return err("Name is required")
    new_id = next_id("suppliers")
    doc = {
        "Id":            new_id,
        "Name":          data.get("Name", "").strip(),
        "ContactPerson": data.get("ContactPerson", "").strip(),
        "Phone":         data.get("Phone", "").strip(),
        "Email":         data.get("Email", "").strip(),
        "GSTNo":         data.get("GSTNo", "").strip(),
        "BillToAddress": data.get("BillToAddress", "").strip(),
        "BankDetails":   data.get("BankDetails", "").strip(),
        "CreatedAt":     datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    col("suppliers").insert_one(doc)
    return ok({"Id": new_id, "Name": doc["Name"]})

@app.put("/api/billing/suppliers/{sup_id}")
async def update_supplier(sup_id: int, request: Request):
    if not await ensure_db(): return err("Database not connected", 503)
    data = await request.json()
    if not data.get("Name"): return err("Name is required")
    update = {
        "Name":          data.get("Name", "").strip(),
        "ContactPerson": data.get("ContactPerson", "").strip(),
        "Phone":         data.get("Phone", "").strip(),
        "Email":         data.get("Email", "").strip(),
        "GSTNo":         data.get("GSTNo", "").strip(),
        "BillToAddress": data.get("BillToAddress", "").strip(),
        "BankDetails":   data.get("BankDetails", "").strip(),
    }
    result = col("suppliers").update_one({"Id": sup_id}, {"$set": update})
    if result.matched_count == 0: return err("Supplier not found", 404)
    return ok({"updated": True})

@app.delete("/api/billing/suppliers/{sup_id}")
async def delete_supplier(sup_id: int):
    if not await ensure_db(): return err("Database not connected", 503)
    # Block deletion if there are purchases referencing this supplier
    if col("purchases").find_one({"SupplierId": sup_id}):
        return err("Cannot delete — supplier has purchase records", 400)
    result = col("suppliers").delete_one({"Id": sup_id})
    if result.deleted_count == 0: return err("Supplier not found", 404)
    return ok({"deleted": True})

# ── PURCHASES ─────────────────────────────────────────────────

@app.get("/api/billing/purchases/next-no")
async def get_next_purchase_no():
    if not await ensure_db(): return err("Database not connected", 503)
    last = col("purchases").find_one({}, sort=[("Id", -1)])
    next_num = (last["Id"] + 1) if last else 1
    return ok({"PurchaseNo": f"P{next_num:03d}", "next": next_num})

@app.get("/api/billing/purchases")
async def get_purchases(q: Optional[str] = Query(None),
                        supplier_id: Optional[int] = Query(None),
                        page: int = Query(1), page_size: int = Query(50)):
    if not await ensure_db(): return err("Database not connected", 503)
    query = {}
    if q:
        query["$or"] = [
            {"PurchaseNo":    {"$regex": q, "$options": "i"}},
            {"SupplierName":  {"$regex": q, "$options": "i"}},
        ]
    if supplier_id:
        query["SupplierId"] = supplier_id
    total = col("purchases").count_documents(query)
    skip  = (page - 1) * page_size
    docs  = list(col("purchases").find(query, {"_id": 0})
                 .sort("Id", -1).skip(skip).limit(page_size))
    return JSONResponse(content={"data": docs, "total": total, "page": page, "pageSize": page_size})

@app.get("/api/billing/purchases/{purchase_id}")
async def get_purchase(purchase_id: int):
    if not await ensure_db(): return err("Database not connected", 503)
    doc = col("purchases").find_one({"Id": purchase_id}, {"_id": 0})
    if not doc: return err("Purchase not found", 404)
    items = list(col("purchase_items").find(
        {"PurchaseId": purchase_id}, {"_id": 0}).sort("SNo", 1))
    return JSONResponse(content={**doc, "Items": items})

@app.post("/api/billing/purchases")
async def create_purchase(request: Request):
    if not await ensure_db(): return err("Database not connected", 503)
    data = await request.json()
    if not data.get("SupplierId"): return err("SupplierId is required")
    items = data.get("Items", [])
    if not items: return err("At least one item is required")

    purchase_id   = next_id("purchases")
    purchase_no   = f"P{purchase_id:03d}"
    purchase_date = data.get("PurchaseDate", datetime.now().strftime("%Y-%m-%d"))
    supplier      = col("suppliers").find_one({"Id": int(data["SupplierId"])}, {"_id": 0})
    supplier_name = supplier["Name"] if supplier else data.get("SupplierName", "")

    sub_total = 0.0
    processed = []
    for i, it in enumerate(items):
        qty    = float(it.get("Qty", 0))
        rate   = float(it.get("Rate", 0))
        total  = qty * rate
        sub_total += total
        processed.append({
            "PurchaseId":  purchase_id,
            "SNo":         i + 1,
            "ProductId":   it.get("ProductId", ""),
            "ProductName": it.get("ProductName", "").strip(),
            "HSN":         it.get("HSN", "").strip(),
            "Qty":         qty,
            "Unit":        it.get("Unit", "Nos").strip(),
            "Rate":        rate,
            "Total":       round(total, 2),
        })

    doc = {
        "Id":           purchase_id,
        "PurchaseNo":   purchase_no,
        "PurchaseDate": purchase_date,
        "SupplierId":   int(data["SupplierId"]),
        "SupplierName": supplier_name,
        "InvoiceRef":   data.get("InvoiceRef", "").strip(),
        "SubTotal":     round(sub_total, 2),
        "TotalAmount":  round(sub_total, 2),
        "Notes":        data.get("Notes", "").strip(),
        "CreatedAt":    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    col("purchases").insert_one(doc)
    if processed:
        col("purchase_items").insert_many(processed)

    # Automatically write Stock IN entries for each item
    for it in processed:
        if it["ProductName"] and it["Qty"] > 0:
            stock_id = next_id("stock_ledger")
            col("stock_ledger").insert_one({
                "Id":          stock_id,
                "Date":        purchase_date,
                "ProductName": it["ProductName"],
                "Type":        "IN",
                "Qty":         it["Qty"],
                "Unit":        it["Unit"],
                "Rate":        it["Rate"],
                "Reference":   purchase_no,
                "Remarks":     f"Purchase from {supplier_name}",
                "CreatedAt":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            })

    return ok({"Id": purchase_id, "PurchaseNo": purchase_no})

@app.put("/api/billing/purchases/{purchase_id}")
async def update_purchase(purchase_id: int, request: Request):
    if not await ensure_db(): return err("Database not connected", 503)
    purchase = col("purchases").find_one({"Id": purchase_id})
    if not purchase: return err("Purchase not found", 404)
    data = await request.json()
    if not data.get("SupplierId"): return err("SupplierId is required")
    items = data.get("Items", [])
    if not items: return err("At least one item is required")

    old_no        = purchase["PurchaseNo"]
    purchase_date = data.get("PurchaseDate", purchase.get("PurchaseDate"))
    supplier      = col("suppliers").find_one({"Id": int(data["SupplierId"])}, {"_id": 0})
    supplier_name = supplier["Name"] if supplier else data.get("SupplierName", "")

    sub_total = 0.0
    processed = []
    for i, it in enumerate(items):
        qty    = float(it.get("Qty", 0))
        rate   = float(it.get("Rate", 0))
        total  = qty * rate
        sub_total += total
        processed.append({
            "PurchaseId":  purchase_id,
            "SNo":         i + 1,
            "ProductId":   it.get("ProductId", ""),
            "ProductName": it.get("ProductName", "").strip(),
            "HSN":         it.get("HSN", "").strip(),
            "Qty":         qty,
            "Unit":        it.get("Unit", "Nos").strip(),
            "Rate":        rate,
            "Total":       round(total, 2),
        })

    col("purchases").update_one({"Id": purchase_id}, {"$set": {
        "PurchaseDate": purchase_date,
        "SupplierId":   int(data["SupplierId"]),
        "SupplierName": supplier_name,
        "InvoiceRef":   data.get("InvoiceRef", "").strip(),
        "SubTotal":     round(sub_total, 2),
        "TotalAmount":  round(sub_total, 2),
        "Notes":        data.get("Notes", "").strip(),
    }})

    # Replace purchase_items
    col("purchase_items").delete_many({"PurchaseId": purchase_id})
    if processed:
        col("purchase_items").insert_many(processed)

    # Replace the auto-generated Stock IN entries for this purchase
    col("stock_ledger").delete_many({"Reference": old_no, "Type": "IN"})
    for it in processed:
        if it["ProductName"] and it["Qty"] > 0:
            stock_id = next_id("stock_ledger")
            col("stock_ledger").insert_one({
                "Id":          stock_id,
                "Date":        purchase_date,
                "ProductName": it["ProductName"],
                "Type":        "IN",
                "Qty":         it["Qty"],
                "Unit":        it["Unit"],
                "Rate":        it["Rate"],
                "Reference":   old_no,
                "Remarks":     f"Purchase from {supplier_name}",
                "CreatedAt":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            })

    return ok({"Id": purchase_id, "PurchaseNo": old_no})

@app.delete("/api/billing/purchases/{purchase_id}")
async def delete_purchase(purchase_id: int):
    if not await ensure_db(): return err("Database not connected", 503)
    purchase = col("purchases").find_one({"Id": purchase_id})
    if not purchase: return err("Purchase not found", 404)
    # Remove the auto-generated stock IN entries for this purchase
    col("stock_ledger").delete_many({"Reference": purchase["PurchaseNo"], "Type": "IN"})
    col("purchase_items").delete_many({"PurchaseId": purchase_id})
    col("purchases").delete_one({"Id": purchase_id})
    return ok({"deleted": True})

# ── STOCK LEDGER ──────────────────────────────────────────────

@app.get("/api/billing/stock/ledger")
async def get_stock_ledger(product: Optional[str] = Query(None),
                           type_filter: Optional[str] = Query(None),
                           date_from: Optional[str] = Query(None),
                           date_to: Optional[str] = Query(None)):
    if not await ensure_db(): return err("Database not connected", 503)
    query = {}
    if product:
        query["ProductName"] = {"$regex": product, "$options": "i"}
    if type_filter in ("IN", "OUT"):
        query["Type"] = type_filter
    if date_from or date_to:
        query["Date"] = {}
        if date_from: query["Date"]["$gte"] = date_from
        if date_to:   query["Date"]["$lte"] = date_to
    docs = list(col("stock_ledger").find(query, {"_id": 0}).sort([("Date", 1), ("Id", 1)]))
    # Compute running balance per product
    balances = {}
    for d in docs:
        p = d["ProductName"]
        balances.setdefault(p, 0)
        qty = float(d.get("Qty", 0))
        if d["Type"] == "IN":  balances[p] += qty
        else:                  balances[p] -= qty
        d["Balance"] = round(balances[p], 2)
    docs.reverse()   # most recent first for display
    return JSONResponse(content={"data": docs, "total": len(docs)})

@app.get("/api/billing/stock/products")
async def get_stock_products():
    """Distinct product names that appear in the ledger — for dropdowns."""
    if not await ensure_db(): return err("Database not connected", 503)
    names = col("stock_ledger").distinct("ProductName")
    names.sort()
    return JSONResponse(content={"data": names})

@app.get("/api/billing/stock/summary")
async def get_stock_summary():
    """Current balance per product — for dashboard widget."""
    if not await ensure_db(): return err("Database not connected", 503)
    pipeline = [
        {"$group": {
            "_id": "$ProductName",
            "in_qty":  {"$sum": {"$cond": [{"$eq": ["$Type","IN"]},  {"$toDouble": "$Qty"}, 0]}},
            "out_qty": {"$sum": {"$cond": [{"$eq": ["$Type","OUT"]}, {"$toDouble": "$Qty"}, 0]}},
        }},
        {"$project": {
            "ProductName": "$_id",
            "Balance": {"$subtract": ["$in_qty", "$out_qty"]},
            "InTotal": "$in_qty", "OutTotal": "$out_qty",
        }},
        {"$sort": {"ProductName": 1}}
    ]
    docs = list(col("stock_ledger").aggregate(pipeline))
    for d in docs: d.pop("_id", None)
    return JSONResponse(content={"data": docs})

@app.post("/api/billing/stock/in")
async def add_stock_in(request: Request):
    """Manual IN entry — used for opt-in opening-stock pushes (e.g. from
    Investment > Implementation > Add Products) and any other one-off
    stock-in that isn't a regular Purchase."""
    if not await ensure_db(): return err("Database not connected", 503)
    data = await request.json()
    product = data.get("ProductName", "").strip()
    qty     = float(data.get("Qty", 0))
    if not product: return err("ProductName is required")
    if qty <= 0:    return err("Qty must be positive")
    stock_id = next_id("stock_ledger")
    col("stock_ledger").insert_one({
        "Id":          stock_id,
        "Date":        data.get("Date", datetime.now().strftime("%Y-%m-%d")),
        "ProductName": product,
        "Type":        "IN",
        "Qty":         qty,
        "Unit":        data.get("Unit", "Nos").strip(),
        "Rate":        float(data.get("Rate", 0)),
        "Reference":   data.get("Reference", "").strip(),
        "Remarks":     data.get("Remarks", "").strip(),
        "CreatedAt":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    })
    return ok({"Id": stock_id})

@app.post("/api/billing/stock/out")
async def add_stock_out(request: Request):
    """Manual OUT entry — posted by office after raising an invoice."""
    if not await ensure_db(): return err("Database not connected", 503)
    data = await request.json()
    product = data.get("ProductName", "").strip()
    qty     = float(data.get("Qty", 0))
    if not product: return err("ProductName is required")
    if qty <= 0:    return err("Qty must be positive")
    stock_id = next_id("stock_ledger")
    col("stock_ledger").insert_one({
        "Id":          stock_id,
        "Date":        data.get("Date", datetime.now().strftime("%Y-%m-%d")),
        "ProductName": product,
        "Type":        "OUT",
        "Qty":         qty,
        "Unit":        data.get("Unit", "Nos").strip(),
        "Rate":        float(data.get("Rate", 0)),
        "CustomerName": data.get("CustomerName", "").strip(),
        "JobName":     data.get("JobName", "").strip(),
        "JobSize":     data.get("JobSize", "").strip(),
        "JobQty":      data.get("JobQty", "").strip(),
        "UpdatedBy":   data.get("UpdatedBy", "").strip(),
        "Reference":   data.get("Reference", "").strip(),
        "Remarks":     data.get("Remarks", "").strip(),
        "CreatedAt":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    })
    return ok({"Id": stock_id})

@app.put("/api/billing/stock/ledger/{entry_id}")
async def update_stock_entry(entry_id: int, request: Request):
    """Edit a manual OUT entry only (auto IN entries are only changed via the Purchase)."""
    if not await ensure_db(): return err("Database not connected", 503)
    data = await request.json()
    entry = col("stock_ledger").find_one({"Id": entry_id})
    if not entry: return err("Entry not found", 404)
    if entry.get("Type") == "IN":
        return err("Cannot edit an auto IN entry — edit the Purchase instead", 400)
    product = data.get("ProductName", "").strip()
    qty     = float(data.get("Qty", 0))
    if not product: return err("ProductName is required")
    if qty <= 0:    return err("Qty must be positive")
    col("stock_ledger").update_one({"Id": entry_id}, {"$set": {
        "Date":        data.get("Date", entry.get("Date")),
        "ProductName": product,
        "Qty":         qty,
        "Unit":        data.get("Unit", "Nos").strip(),
        "Rate":        float(data.get("Rate", 0)),
        "CustomerName": data.get("CustomerName", "").strip(),
        "JobName":     data.get("JobName", "").strip(),
        "JobSize":     data.get("JobSize", "").strip(),
        "JobQty":      data.get("JobQty", "").strip(),
        "UpdatedBy":   data.get("UpdatedBy", "").strip(),
        "Reference":   data.get("Reference", "").strip(),
        "Remarks":     data.get("Remarks", "").strip(),
    }})
    return ok({"updated": True})

@app.delete("/api/billing/stock/ledger/{entry_id}")
async def delete_stock_entry(entry_id: int):
    """Delete a manual OUT entry only (auto IN entries deleted via purchase delete)."""
    if not await ensure_db(): return err("Database not connected", 503)
    entry = col("stock_ledger").find_one({"Id": entry_id})
    if not entry: return err("Entry not found", 404)
    if entry.get("Type") == "IN":
        return err("Cannot delete an auto IN entry — delete the Purchase instead", 400)
    col("stock_ledger").delete_one({"Id": entry_id})
    return ok({"deleted": True})

# ── PURCHASE PRODUCTS CATALOG (Name + HSN, used by Purchases and Stock OUT) ──

@app.get("/api/billing/purchase-products")
async def get_purchase_products():
    if not await ensure_db(): return err("Database not connected", 503)
    docs = list(col("purchase_products").find({}, {"_id": 0}).sort("Name", 1))
    return JSONResponse(content={"data": docs})

@app.post("/api/billing/purchase-products")
async def add_purchase_product(request: Request):
    if not await ensure_db(): return err("Database not connected", 503)
    data = await request.json()
    name = data.get("Name", "").strip()
    if not name: return err("Product name is required")
    prod_id = next_id("purchase_products")
    col("purchase_products").insert_one({
        "Id": prod_id, "Name": name, "Size": data.get("Size", "").strip(), "HSN": data.get("HSN", "").strip(),
        "CreatedAt": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    })
    return ok({"Id": prod_id})

@app.put("/api/billing/purchase-products/{prod_id}")
async def update_purchase_product(prod_id: int, request: Request):
    if not await ensure_db(): return err("Database not connected", 503)
    data = await request.json()
    name = data.get("Name", "").strip()
    if not name: return err("Product name is required")
    r = col("purchase_products").update_one({"Id": prod_id}, {"$set": {
        "Name": name, "Size": data.get("Size", "").strip(), "HSN": data.get("HSN", "").strip(),
    }})
    if r.matched_count == 0: return err("Product not found", 404)
    return ok({"updated": True})

@app.delete("/api/billing/purchase-products/{prod_id}")
async def delete_purchase_product(prod_id: int):
    if not await ensure_db(): return err("Database not connected", 503)
    col("purchase_products").delete_one({"Id": prod_id})
    return ok({"deleted": True})

# ── EMPLOYEES (used by "Updated By" on Stock OUT entries) ────────────

@app.get("/api/billing/employees")
async def get_employees():
    if not await ensure_db(): return err("Database not connected", 503)
    docs = list(col("employees").find({}, {"_id": 0}).sort("Name", 1))
    return JSONResponse(content={"data": docs})

@app.post("/api/billing/employees")
async def add_employee(request: Request):
    if not await ensure_db(): return err("Database not connected", 503)
    data = await request.json()
    name = data.get("Name", "").strip()
    if not name: return err("Employee name is required")
    emp_id = next_id("employees")
    col("employees").insert_one({
        "Id": emp_id, "Name": name,
        "CreatedAt": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    })
    return ok({"Id": emp_id})

@app.put("/api/billing/employees/{emp_id}")
async def update_employee(emp_id: int, request: Request):
    if not await ensure_db(): return err("Database not connected", 503)
    data = await request.json()
    name = data.get("Name", "").strip()
    if not name: return err("Employee name is required")
    r = col("employees").update_one({"Id": emp_id}, {"$set": {"Name": name}})
    if r.matched_count == 0: return err("Employee not found", 404)
    return ok({"updated": True})

@app.delete("/api/billing/employees/{emp_id}")
async def delete_employee(emp_id: int):
    if not await ensure_db(): return err("Database not connected", 503)
    col("employees").delete_one({"Id": emp_id})
    return ok({"deleted": True})

# ── STOCK MOBILE PIN GATE + ACCESS LOG ────────────────────────
# Shared across both companies (one link, one team) — not company-scoped.

def _client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

DEFAULT_STOCK_PIN = "1234"  # change this on first use via the Access Log screen in Purchase & Stock
DEFAULT_STOCK_PIN_SESSION_DAYS = 7

@app.get("/api/billing/stock-pin/config")
async def get_stock_pin_config():
    """Returns whether a PIN is set and how many days a device stays remembered.
    Never returns the PIN itself."""
    if not await ensure_db(): return err("Database not connected", 503)
    cfg = shared_col("stock_pin_config").find_one({"_key": "main"}, {"_id": 0})
    return JSONResponse(content={
        "sessionDays": (cfg or {}).get("SessionDays", DEFAULT_STOCK_PIN_SESSION_DAYS),
        "configured": bool(cfg and cfg.get("Pin")),
    })

@app.post("/api/billing/stock-pin/set")
async def set_stock_pin(request: Request):
    """Admin-only in practice (gated on the frontend, like other admin actions in this app)."""
    if not await ensure_db(): return err("Database not connected", 503)
    data = await request.json()
    pin = str(data.get("Pin", "")).strip()
    if not re.fullmatch(r"\d{4}", pin):
        return err("PIN must be exactly 4 digits")
    session_days = int(data.get("SessionDays", DEFAULT_STOCK_PIN_SESSION_DAYS) or DEFAULT_STOCK_PIN_SESSION_DAYS)
    shared_col("stock_pin_config").update_one(
        {"_key": "main"},
        {"$set": {"_key": "main", "Pin": pin, "SessionDays": session_days,
                   "UpdatedAt": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}},
        upsert=True
    )
    return ok({"updated": True})

@app.post("/api/billing/stock-pin/verify")
async def verify_stock_pin(request: Request):
    if not await ensure_db(): return err("Database not connected", 503)
    data = await request.json()
    pin = str(data.get("Pin", "")).strip()
    device = str(data.get("Device", "")).strip()[:200]
    cfg = shared_col("stock_pin_config").find_one({"_key": "main"}, {"_id": 0})
    correct_pin = (cfg or {}).get("Pin", DEFAULT_STOCK_PIN)
    success = (pin == correct_pin)
    log_id = next_id("stock_access_log")
    shared_col("stock_access_log").insert_one({
        "Id": log_id,
        "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "IP": _client_ip(request),
        "Device": device or request.headers.get("user-agent", "unknown")[:200],
        "Success": success,
    })
    if not success:
        return err("Incorrect PIN", 401)
    return ok({"verified": True, "sessionDays": (cfg or {}).get("SessionDays", DEFAULT_STOCK_PIN_SESSION_DAYS)})

@app.get("/api/billing/stock-access-log")
async def get_stock_access_log(limit: int = Query(100, ge=1, le=500)):
    if not await ensure_db(): return err("Database not connected", 503)
    docs = list(shared_col("stock_access_log").find({}, {"_id": 0}).sort("Id", -1).limit(limit))
    return JSONResponse(content={"data": docs})

# ══════════════════════════════════════════════════════════════
# END PURCHASE AND STOCK
# ══════════════════════════════════════════════════════════════
