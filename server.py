#!/usr/bin/env python3

import base64
import cgi
import hashlib
import hmac
import json
import mimetypes
import os
import secrets
import shutil
import sqlite3
import time
import threading
import urllib.parse
import uuid

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import queue


HOST = os.environ.get("LAN_SHARE_HOST", "127.0.0.1")
PORT = int(os.environ.get("LAN_SHARE_PORT", "8765"))

BASE = Path(os.environ.get("LAN_SHARE_DATA_DIR", str(Path(__file__).resolve().parent / "data")))
STATIC = Path(__file__).resolve().parent / "static"
UPLOADS = BASE / "uploads"
DB_PATH = BASE / "share.db"
SECRET_PATH = BASE / "secret.key"

MAX_FILE_BYTES = 8 * 1024**3
MAX_TEXT_BYTES = 1024 * 1024
PBKDF2_ROUNDS = 150_000


BASE.mkdir(parents=True, exist_ok=True)
UPLOADS.mkdir(parents=True, exist_ok=True)

if not SECRET_PATH.exists():
    SECRET_PATH.write_bytes(secrets.token_bytes(32))
    os.chmod(SECRET_PATH, 0o600)

SECRET = SECRET_PATH.read_bytes()


def db():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    with db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at INTEGER NOT NULL,
            expires_at INTEGER,
            text TEXT NOT NULL DEFAULT '',
            password_salt BLOB,
            password_hash BLOB
        );

        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            item_id INTEGER NOT NULL
                REFERENCES items(id) ON DELETE CASCADE,
            stored_name TEXT NOT NULL,
            original_name TEXT NOT NULL,
            mime TEXT NOT NULL,
            size INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_items_created
            ON items(created_at DESC);

        CREATE INDEX IF NOT EXISTS idx_items_expires
            ON items(expires_at);

        CREATE INDEX IF NOT EXISTS idx_files_item
            ON files(item_id);
        """)


def cleanup_expired():
    now = int(time.time())

    with db() as conn:
        rows = conn.execute(
            "SELECT id FROM items "
            "WHERE expires_at IS NOT NULL AND expires_at <= ?",
            (now,)
        ).fetchall()

        for (item_id,) in rows:
            files = conn.execute(
                "SELECT stored_name FROM files WHERE item_id=?",
                (item_id,)
            ).fetchall()

            for (stored,) in files:
                try:
                    (UPLOADS / stored).unlink(missing_ok=True)
                except OSError:
                    pass

            conn.execute("DELETE FROM items WHERE id=?", (item_id,))



# ==================================================
# DIRECT TRANSFER
#
# Ephemeral by design:
# - metadata lives only in RAM
# - file bytes are never written to disk
# - bounded queue prevents large RAM use
# - pending requests disappear after timeout/reboot
# ==================================================

DIRECT_TRANSFERS = {}
DIRECT_LOCK = threading.RLock()
DIRECT_COND = threading.Condition(DIRECT_LOCK)
DIRECT_REV = 0

DIRECT_CHUNK = 256 * 1024
DIRECT_BUFFER_CHUNKS = 8          # ~2 MiB max per active transfer
DIRECT_PENDING_TIMEOUT = 10 * 60
DIRECT_ACTIVE_TIMEOUT = 60 * 60
DIRECT_FINISHED_KEEP = 60


class DirectTransfer:
    def __init__(
        self,
        transfer_id,
        sender_token,
        sender_client,
        sender_name,
        name,
        size,
        mime
    ):
        self.id = transfer_id
        self.sender_token = sender_token
        self.sender_client = sender_client
        self.sender_name = sender_name
        self.name = name
        self.size = size
        self.mime = mime
        self.created = time.time()
        self.updated = self.created
        self.state = "pending"
        self.receiver_name = ""
        self.receiver_token = ""
        self.bytes_sent = 0
        self.queue = queue.Queue(
            maxsize=DIRECT_BUFFER_CHUNKS
        )
        self.receiver_ready = threading.Event()
        self.sender_ready = threading.Event()
        self.finished = threading.Event()
        self.cancelled = threading.Event()


def _direct_bump_locked():
    global DIRECT_REV
    DIRECT_REV += 1
    DIRECT_COND.notify_all()


def _direct_cancel_locked(transfer, state="cancelled"):
    if transfer.state in ("finished", "cancelled", "expired"):
        return
    transfer.state = state
    transfer.updated = time.time()
    transfer.cancelled.set()
    _direct_bump_locked()


def _direct_cleanup_locked():
    now = time.time()
    remove = []
    for transfer_id, transfer in list(DIRECT_TRANSFERS.items()):
        age = now - transfer.created
        idle = now - transfer.updated
        if transfer.state == "pending":
            if age > DIRECT_PENDING_TIMEOUT:
                _direct_cancel_locked(transfer, "expired")
        elif transfer.state in ("accepted", "transferring"):
            if idle > DIRECT_ACTIVE_TIMEOUT:
                _direct_cancel_locked(transfer, "expired")
        elif transfer.state in ("finished", "cancelled", "expired"):
            if idle > DIRECT_FINISHED_KEEP:
                remove.append(transfer_id)
    for transfer_id in remove:
        DIRECT_TRANSFERS.pop(transfer_id, None)


def direct_create(sender_client, sender_name, name, size, mime):
    transfer_id = secrets.token_urlsafe(10)
    sender_token = secrets.token_urlsafe(24)
    transfer = DirectTransfer(
        transfer_id,
        sender_token,
        sender_client,
        sender_name,
        name,
        size,
        mime
    )
    with DIRECT_COND:
        _direct_cleanup_locked()
        DIRECT_TRANSFERS[transfer_id] = transfer
        _direct_bump_locked()
    return transfer


def direct_public(transfer):
    return {
        "id": transfer.id,
        "sender_name": transfer.sender_name,
        "name": transfer.name,
        "size": transfer.size,
        "mime": transfer.mime,
        "created": int(transfer.created),
        "state": transfer.state,
        "receiver_name": transfer.receiver_name
    }


def direct_sender_status(transfer):
    return {
        "id": transfer.id,
        "state": transfer.state,
        "receiver_name": transfer.receiver_name,
        "bytes_sent": transfer.bytes_sent
    }


def direct_wait_events(since, client_id):
    with DIRECT_COND:
        _direct_cleanup_locked()
        if DIRECT_REV == since:
            DIRECT_COND.wait(timeout=25)
        _direct_cleanup_locked()
        return (
            DIRECT_REV,
            [
                direct_public(t)
                for t in DIRECT_TRANSFERS.values()
                if t.state == "pending" and t.sender_client != client_id
            ]
        )


def direct_wait_sender(transfer_id, sender_token, since):
    with DIRECT_COND:
        _direct_cleanup_locked()
        transfer = DIRECT_TRANSFERS.get(transfer_id)
        if (
            not transfer
            or not hmac.compare_digest(transfer.sender_token, sender_token)
        ):
            return None, DIRECT_REV
        if DIRECT_REV == since:
            DIRECT_COND.wait(timeout=25)
        _direct_cleanup_locked()
        transfer = DIRECT_TRANSFERS.get(transfer_id)
        if not transfer:
            return None, DIRECT_REV
        return direct_sender_status(transfer), DIRECT_REV


def storage_info():
    usage = shutil.disk_usage(UPLOADS)

    return {
        "total": usage.total,
        "used": usage.used,
        "free": usage.free
    }


def make_password(password):
    salt = secrets.token_bytes(16)

    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        PBKDF2_ROUNDS
    )

    return salt, digest


def password_ok(password, salt, expected):
    if not salt or not expected:
        return False

    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        PBKDF2_ROUNDS
    )

    return hmac.compare_digest(digest, expected)


def make_token(item_id, purpose="view", ttl=900):
    expiry = int(time.time()) + ttl

    message = f"{item_id}:{purpose}:{expiry}".encode()

    signature = hmac.new(
        SECRET,
        message,
        hashlib.sha256
    ).digest()[:18]

    encoded = base64.urlsafe_b64encode(
        signature
    ).decode().rstrip("=")

    return f"{expiry}.{encoded}"


def token_ok(item_id, token, purpose="view"):
    try:
        expiry_s, encoded = token.split(".", 1)
        expiry = int(expiry_s)

        if expiry < int(time.time()):
            return False

        padding = "=" * (-len(encoded) % 4)
        signature = base64.urlsafe_b64decode(
            encoded + padding
        )

        message = f"{item_id}:{purpose}:{expiry}".encode()

        expected = hmac.new(
            SECRET,
            message,
            hashlib.sha256
        ).digest()[:18]

        return hmac.compare_digest(signature, expected)

    except Exception:
        return False


def item_payload(conn, row, include_secret=False, token=""):
    (
        item_id,
        created_at,
        expires_at,
        text,
        _salt,
        pw_hash
    ) = row

    protected = pw_hash is not None

    files = conn.execute(
        """
        SELECT id, original_name, mime, size
        FROM files
        WHERE item_id=?
        ORDER BY id
        """,
        (item_id,)
    ).fetchall()

    result = {
        "id": item_id,
        "created_at": created_at,
        "expires_at": expires_at,
        "protected": protected,
        "file_count": len(files)
    }

    if include_secret or not protected:
        result["text"] = text

        result["files"] = []

        for fid, name, mime, size in files:
            url = f"file/{fid}"

            if token:
                url += "?token=" + urllib.parse.quote(token)

            result["files"].append({
                "id": fid,
                "name": name,
                "mime": mime,
                "size": size,
                "url": url
            })

    return result


HTML = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>LAN Share</title>
<link rel="manifest" href="static/manifest.webmanifest">
<meta name="theme-color" content="#111318">
<link rel="icon" href="static/icon.svg">

<style>
:root {
    color-scheme: light dark;
    --bg:#f5f6f8;
    --card:#fff;
    --fg:#16181d;
    --muted:#6d7480;
    --line:#dfe3e8;
    --accent:#3567d6;
    --danger:#b42318;
}

@media(prefers-color-scheme:dark) {
    :root {
        --bg:#101216;
        --card:#181b21;
        --fg:#f1f3f5;
        --muted:#9aa2ad;
        --line:#2a3038;
        --accent:#78a2ff;
        --danger:#ff7b72;
    }
}

* { box-sizing:border-box; }

body {
    margin:0;
    background:var(--bg);
    color:var(--fg);
    font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
}

.wrap {
    max-width:880px;
    margin:auto;
    padding:18px;
}

h1 {
    font-size:1.45rem;
    margin:3px 0 14px;
}


.topbar {
    display:flex;
    align-items:center;
    justify-content:space-between;
    gap:12px;
}

.lang-switch {
    display:flex;
    gap:5px;
}

.lang-switch button.active {
    background:var(--accent);
    color:white;
    border-color:var(--accent);
}


.incoming-card {
    border-inline-start:4px solid var(--accent);
}

.qr-box {
    margin:14px 0 4px;
    display:flex;
    justify-content:center;
}

.qr-box img,
.qr-box canvas {
    background:white;
    padding:8px;
    border-radius:10px;
    max-width:200px;
    height:auto;
}

.sender-status {
    margin-top:10px;
    font-weight:600;
}

.device-name {
    font-weight:650;
}

.device-button {
    max-width:210px;
    overflow:hidden;
    white-space:nowrap;
    text-overflow:ellipsis;
}

.direct-card {
    border:1px solid var(--line);
    border-radius:12px;
    padding:12px;
    margin-top:12px;
}

.direct-title {
    font-weight:650;
    margin-bottom:5px;
}

.direct-file {
    margin-top:9px;
    padding:9px;
    border-radius:9px;
    background:var(--bg);
}

.direct-progress {
    height:8px;
    margin-top:8px;
    overflow:hidden;
    border-radius:999px;
    background:var(--line);
}

.direct-progress > div {
    width:0;
    height:100%;
    background:var(--accent);
    transition:width .15s linear;
}

.direct-link {
    width:100%;
    margin-top:8px;
    font-family:ui-monospace,SFMono-Regular,Consolas,monospace;
}

.warning-box {
    border:1px solid #d29422;
    border-radius:10px;
    padding:10px;
    margin-top:10px;
}

.storage-box {
    margin:0 0 14px;
}

.storage-header {
    display:flex;
    justify-content:space-between;
    gap:10px;
    margin-bottom:6px;
    color:var(--muted);
    font-size:.86rem;
}

.storage-track {
    height:9px;
    overflow:hidden;
    border-radius:999px;
    background:var(--line);
}

.storage-fill {
    height:100%;
    width:0;
    border-radius:999px;
    transition:width .25s ease;
}

.storage-fill.ok {
    background:#299764;
}

.storage-fill.warn {
    background:#d29422;
}

.storage-fill.danger {
    background:#d14343;
}

.card {
    background:var(--card);
    border:1px solid var(--line);
    border-radius:14px;
    padding:14px;
    margin-bottom:14px;
}

textarea,input,select,button {
    font:inherit;
}

textarea,input[type=password],select {
    width:100%;
    border:1px solid var(--line);
    background:transparent;
    color:var(--fg);
    border-radius:9px;
    padding:10px;
}

textarea {
    min-height:105px;
    resize:vertical;
}

.row {
    display:grid;
    grid-template-columns:1fr 1fr;
    gap:10px;
    margin-top:10px;
}

@media(max-width:620px) {
    .row { grid-template-columns:1fr; }
}

.drop {
    display:block;
    border:1px dashed var(--line);
    border-radius:10px;
    padding:12px;
    margin-top:10px;
    text-align:center;
    color:var(--muted);
    cursor:pointer;
}

.drop.drag {
    border-color:var(--accent);
    color:var(--accent);
}

.actions {
    display:flex;
    gap:8px;
    justify-content:flex-end;
    align-items:center;
    margin-top:10px;
    flex-wrap:wrap;
}

button,.btn {
    border:1px solid var(--line);
    background:transparent;
    color:var(--fg);
    border-radius:9px;
    padding:7px 10px;
    cursor:pointer;
    text-decoration:none;
}

button.primary {
    background:var(--accent);
    border-color:var(--accent);
    color:white;
}

button.danger {
    color:var(--danger);
}

button:disabled {
    opacity:.5;
    cursor:not-allowed;
}

.topline {
    display:flex;
    align-items:center;
    justify-content:space-between;
    gap:10px;
}

.muted {
    color:var(--muted);
    font-size:.9rem;
}

.item-text {
    white-space:pre-wrap;
    word-break:break-word;
    margin:10px 0;
    font-family:ui-monospace,SFMono-Regular,Consolas,monospace;
}

.file {
    border-top:1px solid var(--line);
    padding-top:10px;
    margin-top:10px;
}

.file img {
    display:block;
    max-width:100%;
    max-height:360px;
    border-radius:9px;
    margin:8px 0;
}

.file video,.file audio {
    display:block;
    max-width:100%;
    margin:8px 0;
}

.lockrow {
    display:flex;
    gap:8px;
    margin-top:10px;
}

.lockrow input {
    flex:1;
}

.empty {
    text-align:center;
    color:var(--muted);
    padding:28px 8px;
}

.attachments {
    display:flex;
    flex-direction:column;
    gap:7px;
    margin-top:9px;
}

.attachment {
    display:flex;
    align-items:center;
    justify-content:space-between;
    gap:10px;
    padding:8px 10px;
    border:1px solid var(--line);
    border-radius:9px;
    background:var(--bg);
}

.attachment-info {
    display:flex;
    align-items:center;
    gap:9px;
    min-width:0;
}

.attachment-thumb {
    width:38px;
    height:38px;
    object-fit:cover;
    border-radius:7px;
    flex:none;
}

.attachment-icon {
    width:38px;
    height:38px;
    display:grid;
    place-items:center;
    font-size:1.3rem;
    flex:none;
}

.attachment-text {
    min-width:0;
}

.attachment-name {
    font-size:.9rem;
    font-weight:600;
    overflow:hidden;
    white-space:nowrap;
    text-overflow:ellipsis;
}

.attachment-size {
    color:var(--muted);
    font-size:.78rem;
}

.attachment-remove {
    flex:none;
    color:var(--danger);
    padding:5px 8px;
}

.status {
    min-height:1.2em;
    color:var(--muted);
    font-size:.9rem;
}

.badge {
    display:inline-block;
    border:1px solid var(--line);
    border-radius:999px;
    padding:2px 7px;
    font-size:.78rem;
    color:var(--muted);
}
</style>
</head>

<body>
<div class="wrap">

<div class="topbar">
<h1 id="pageTitle">LAN Share</h1>

<div class="lang-switch">
<button id="deviceButton"
        class="device-button"
        type="button"
        title="Device name">📱</button>
<button id="langAR" type="button">ع</button>
<button id="langEN" type="button">EN</button>
</div>
</div>

<div class="storage-box">
<div class="storage-header">
<span id="storageLabel">Storage</span>
<span id="storageText">…</span>
</div>

<div class="storage-track">
<div id="storageFill"
     class="storage-fill ok"></div>
</div>
</div>

<div id="directPanel" class="card">
<div class="topline">
<div>
<div id="directTitle" class="direct-title">
Direct transfer
</div>
<div id="directDescription" class="muted">
Send a file without storing it on the server.
</div>
</div>

<button id="directChoose" type="button">
Choose file
</button>
</div>

<input id="directFile"
       type="file"
       hidden>

<div id="directArea"></div>
</div>

<section id="incomingSection" style="display:none">
<div class="topline">
<h2 id="incomingTitle" style="font-size:1.05rem;margin:4px 0 10px">
Incoming direct transfers
</h2>
</div>
<div id="incomingTransfers"></div>
</section>

<form id="composer" class="card">

<textarea
    id="text"
    placeholder="Paste text, a URL, a note…"></textarea>

<label id="drop" class="drop">
    <span id="dropText">Drop files here or tap to choose</span>
    <input id="files" type="file" multiple hidden>
</label>

<div id="fileNames"
     class="attachments"></div>

<div class="row">

<label>
<span id="expiryLabel">Expires</span>
<select id="expiry">
    <option id="exp1h" value="3600">1 hour</option>
    <option id="exp1d" value="86400" selected>1 day</option>
    <option id="exp7d" value="604800">7 days</option>
    <option id="exp30d" value="2592000">30 days</option>
    <option id="expNever" value="0">Never</option>
</select>
</label>

<label>
<span id="passwordLabel">Password</span>
<span id="optionalLabel" class="muted">(optional)</span>
<input
    id="password"
    type="password"
    autocomplete="new-password"
    placeholder="Leave empty for normal item">
</label>

</div>

<div class="actions">
<span id="status" class="status"></span>
<button
    id="submit"
    class="primary"
    type="submit">Share</button>
</div>

</form>

<div class="topline">
<h2 id="recentTitle"
style="font-size:1.05rem;margin:4px 0 10px">
Recent
</h2>
<button id="refresh" type="button">Refresh</button>
</div>

<div id="items"></div>

</div>

<script src="static/qrcode.min.js"></script>
<script>
const $ = s => document.querySelector(s);

const translations = {
    ar: {
        title: 'مشاركة الشبكة',
        storage: 'مساحة التخزين',
        free: 'متاح',
        of: 'من',
        textPlaceholder: 'الصق نصاً، رابطاً، ملاحظة…',
        drop: 'اسحب الملفات هنا أو اضغط للاختيار',
        expires: 'انتهاء الصلاحية',
        h1: 'ساعة واحدة',
        d1: 'يوم واحد',
        d7: '7 أيام',
        d30: '30 يوماً',
        never: 'أبداً',
        password: 'كلمة المرور',
        optional: '(اختياري)',
        passwordPlaceholder: 'اتركها فارغة للمشاركة العادية',
        share: 'مشاركة',
        recent: 'الأحدث',
        refresh: 'تحديث',
        directTitle: 'إرسال مباشر',
        directDescription: 'أرسل ملفاً بدون حفظه على الخادم.',
        directChoose: 'اختيار ملف',
        directReady: 'جاهز للإرسال',
        directCopy: 'نسخ الرابط',
        directWaiting: 'بانتظار جهاز الاستقبال…',
        directSending: 'جارٍ الإرسال…',
        directDone: 'اكتمل الإرسال',
        directReceiver: 'افتح الرابط على الجهاز المستقبِل ثم ابدأ الإرسال',
        directStart: 'بدء الإرسال',
        directTooLarge: 'الملف أكبر من المساحة المتاحة',
        directInstead: 'إرسال مباشر بدون حفظ',
        incoming: 'طلبات النقل المباشر',
        from: 'من',
        receive: 'استقبال',
        reject: 'رفض',
        cancel: 'إلغاء',
        scanQr: 'امسح الرمز من الجهاز المستقبِل',
        waitingReceiver: 'بانتظار جهاز للاستقبال…',
        acceptedBy: 'يستقبل الآن',
        transferCancelled: 'تم إلغاء الإرسال',
        transferExpired: 'انتهت مهلة الإرسال',
        receiverGone: 'انقطع جهاز الاستقبال',
        nameDevice: 'اسم هذا الجهاز',
        changeDevice: 'تغيير اسم الجهاز',
        device: 'الجهاز',
        anotherAccepted: 'جهاز آخر استقبل هذا الملف',
        transferFinished: 'اكتمل الإرسال',
        receiving: 'جارٍ الاستقبال…',
        activeDirectExists: 'يوجد إرسال مباشر قيد التشغيل بالفعل',
        directAnother: 'إرسال ملف آخر',
        close: 'إغلاق'
    },

    en: {
        title: 'LAN Share',
        storage: 'Storage',
        free: 'free',
        of: 'of',
        textPlaceholder: 'Paste text, a URL, a note…',
        drop: 'Drop files here or tap to choose',
        expires: 'Expires',
        h1: '1 hour',
        d1: '1 day',
        d7: '7 days',
        d30: '30 days',
        never: 'Never',
        password: 'Password',
        optional: '(optional)',
        passwordPlaceholder: 'Leave empty for normal item',
        share: 'Share',
        recent: 'Recent',
        refresh: 'Refresh',
        directTitle: 'Direct transfer',
        directDescription: 'Send a file without storing it on the server.',
        directChoose: 'Choose file',
        directReady: 'Ready to send',
        directCopy: 'Copy link',
        directWaiting: 'Waiting for receiver…',
        directSending: 'Sending…',
        directDone: 'Transfer complete',
        directReceiver: 'Open the link on the receiving device, then start sending',
        directStart: 'Start transfer',
        directTooLarge: 'File is larger than available storage',
        directInstead: 'Send directly without storing',
        incoming: 'Incoming direct transfers',
        from: 'From',
        receive: 'Receive',
        reject: 'Reject',
        cancel: 'Cancel',
        scanQr: 'Scan this QR code on the receiving device',
        waitingReceiver: 'Waiting for a receiving device…',
        acceptedBy: 'Now receiving',
        transferCancelled: 'Transfer cancelled',
        transferExpired: 'Transfer expired',
        receiverGone: 'Receiver disconnected',
        nameDevice: 'Name this device',
        changeDevice: 'Change device name',
        device: 'Device',
        anotherAccepted: 'Another device accepted this file',
        transferFinished: 'Transfer complete',
        receiving: 'Receiving…',
        activeDirectExists: 'A direct transfer is already active',
        directAnother: 'Send another file',
        close: 'Close'
    }
};

let language =
    localStorage.getItem('lanShareLanguage') || 'ar';

function tr(key) {
    return translations[language][key] ||
           translations.en[key] ||
           key;
}

function applyLanguage() {

    document.documentElement.lang = language;
    document.documentElement.dir =
        language === 'ar' ? 'rtl' : 'ltr';

    $('#pageTitle').textContent = tr('title');
    $('#storageLabel').textContent = tr('storage');

    $('#text').placeholder = tr('textPlaceholder');
    $('#dropText').textContent = tr('drop');

    $('#expiryLabel').textContent = tr('expires');
    $('#exp1h').textContent = tr('h1');
    $('#exp1d').textContent = tr('d1');
    $('#exp7d').textContent = tr('d7');
    $('#exp30d').textContent = tr('d30');
    $('#expNever').textContent = tr('never');

    $('#passwordLabel').textContent = tr('password');
    $('#optionalLabel').textContent = tr('optional');
    $('#password').placeholder =
        tr('passwordPlaceholder');

    $('#submit').textContent = tr('share');
    $('#recentTitle').textContent = tr('recent');
    $('#refresh').textContent = tr('refresh');
    $('#directTitle').textContent =
        tr('directTitle');

    $('#directDescription').textContent =
        tr('directDescription');

    $('#directChoose').textContent =
        tr('directChoose');

    if ($('#incomingTitle')) {
        $('#incomingTitle').textContent = tr('incoming');
    }

    updateDeviceButton();

    $('#langAR').classList.toggle(
        'active',
        language === 'ar'
    );

    $('#langEN').classList.toggle(
        'active',
        language === 'en'
    );

    loadStorage().catch(() => {});
}

$('#langAR').onclick = () => {
    language = 'ar';
    localStorage.setItem(
        'lanShareLanguage',
        language
    );
    applyLanguage();
};

$('#langEN').onclick = () => {
    language = 'en';
    localStorage.setItem(
        'lanShareLanguage',
        language
    );
    applyLanguage();
};


let directSelectedFile = null;
let currentDirect = null;
let directRev = -1;
let currentStorage = null;

const directFileInput = $('#directFile');
const directArea = $('#directArea');
const incomingSection = $('#incomingSection');
const incomingTransfers = $('#incomingTransfers');

function getClientId() {
    let id = localStorage.getItem('lanShareClientId');
    if (!id) {
        if (window.crypto && crypto.randomUUID) {
            id = crypto.randomUUID();
        } else {
            id = Date.now().toString(36) + '-' + Math.random().toString(36).slice(2);
        }
        localStorage.setItem('lanShareClientId', id);
    }
    return id;
}

function getDeviceName(askIfMissing=true) {
    let name = localStorage.getItem('lanShareDeviceName');
    if (!name && askIfMissing) {
        name = prompt(tr('nameDevice'), '');
        if (name) {
            name = name.trim().slice(0,80);
            if (name) localStorage.setItem('lanShareDeviceName', name);
        }
    }
    updateDeviceButton();
    return name || tr('device');
}

function updateDeviceButton() {
    const el = $('#deviceButton');
    if (!el) return;
    const name = localStorage.getItem('lanShareDeviceName');
    el.textContent = name ? '📱 ' + name : '📱';
    el.title = tr('changeDevice');
}

$('#deviceButton').onclick = () => {
    const old = localStorage.getItem('lanShareDeviceName') || '';
    let name = prompt(tr('nameDevice'), old);
    if (name === null) return;
    name = name.trim().slice(0,80);
    if (name) localStorage.setItem('lanShareDeviceName', name);
    else localStorage.removeItem('lanShareDeviceName');
    updateDeviceButton();
};

$('#directChoose').onclick = () => {
    if (currentDirect && !currentDirect.done) {
        alert(tr('activeDirectExists'));
        return;
    }
    directFileInput.click();
};

directFileInput.onchange = () => {
    const file = directFileInput.files[0];
    if (file) prepareDirectTransfer(file);
};

function prepareDirectTransfer(file) {
    directSelectedFile = file;
    directArea.textContent = '';
    const box = document.createElement('div');
    box.className = 'direct-card';
    const title = document.createElement('div');
    title.className = 'attachment-name';
    title.textContent = file.name;
    const meta = document.createElement('div');
    meta.className = 'muted';
    meta.textContent = size(file.size);
    const actions = document.createElement('div');
    actions.className = 'actions';
    const remove = button('✕', () => {
        directSelectedFile = null;
        directFileInput.value = '';
        directArea.textContent = '';
    });
    const start = button(tr('directStart'), async () => {
        start.disabled = true;
        remove.disabled = true;
        try {
            await beginDirectTransfer(file, box);
        } catch(e) {
            alert(e.message);
            start.disabled = false;
            remove.disabled = false;
        }
    }, 'primary');
    actions.append(remove,start);
    box.append(title,meta,actions);
    directArea.append(box);
}

function makeReceivePageUrl(id) {
    const url = new URL(location.href);
    url.search = '';
    url.hash = '';
    url.searchParams.set('direct', id);
    return url.href;
}

function drawQr(element,text) {
    element.textContent = '';
    if (typeof QRCode === 'undefined') {
        element.textContent = text;
        return;
    }
    new QRCode(element, {
        text,
        width:180,
        height:180,
        correctLevel:QRCode.CorrectLevel.M
    });
}

async function beginDirectTransfer(file,box) {
    const senderName = getDeviceName(true);
    const created = await jfetch('api/direct/create', {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({
            name:file.name,
            size:file.size,
            mime:file.type || 'application/octet-stream',
            sender_name:senderName,
            client_id:getClientId()
        })
    });

    currentDirect = {
        id:created.id,
        token:created.sender_token,
        file,
        xhr:null,
        cancelled:false,
        done:false,
        uploadStarted:false
    };

    box.textContent = '';
    const title = document.createElement('div');
    title.className = 'attachment-name';
    title.textContent = file.name;
    const meta = document.createElement('div');
    meta.className = 'muted';
    meta.textContent = size(file.size) + ' · ' + senderName;
    const status = document.createElement('div');
    status.className = 'sender-status';
    status.textContent = tr('waitingReceiver');
    const qrText = document.createElement('div');
    qrText.className = 'muted';
    qrText.style.marginTop = '10px';
    qrText.textContent = tr('scanQr');
    const qr = document.createElement('div');
    qr.className = 'qr-box';
    const receivePage = makeReceivePageUrl(created.id);
    drawQr(qr, receivePage);
    const link = document.createElement('input');
    link.className = 'direct-link';
    link.readOnly = true;
    link.value = receivePage;
    const progress = document.createElement('div');
    progress.className = 'direct-progress';
    const fill = document.createElement('div');
    progress.append(fill);
    const actions = document.createElement('div');
    actions.className = 'actions';
    const copy = button(tr('directCopy'), () => copyText(receivePage));
    const cancel = button(tr('cancel'), async () => {
        await cancelCurrentDirect(status);
    }, 'danger');
    actions.append(copy,cancel);
    box.append(title,meta,status,qrText,qr,link,progress,actions);
    watchSenderTransfer(currentDirect,status,fill);
}


function finishDirectUI(direct, statusEl, fill) {
    if (fill) fill.style.width = '100%';

    direct.done = true;

    if (statusEl) {
        statusEl.textContent = '✓ ' + tr('transferFinished');
    }

    const box = statusEl ? statusEl.closest('.direct-card') : null;
    if (!box) {
        if (currentDirect === direct) currentDirect = null;
        return;
    }

    // QR/link/cancel are no longer useful once the transfer is done.
    const qr = box.querySelector('.qr-box');
    if (qr) qr.remove();

    const link = box.querySelector('.direct-link');
    if (link) link.remove();

    const qrHint = [...box.querySelectorAll('.muted')].find(
        el => el.textContent === tr('scanQr')
    );
    if (qrHint) qrHint.remove();

    const oldActions = box.querySelector('.actions');
    if (oldActions) oldActions.remove();

    const actions = document.createElement('div');
    actions.className = 'actions';

    const again = button(tr('directAnother'), () => {
        if (currentDirect === direct) currentDirect = null;
        directSelectedFile = null;
        directFileInput.value = '';
        directArea.textContent = '';

        // Open picker immediately.
        directFileInput.click();
    }, 'primary');

    const close = button(tr('close'), () => {
        if (currentDirect === direct) currentDirect = null;
        directSelectedFile = null;
        directFileInput.value = '';
        directArea.textContent = '';
    });

    actions.append(again, close);
    box.append(actions);

    // The finished transfer must not block another transfer.
    if (currentDirect === direct) currentDirect = null;
}


async function cancelCurrentDirect(statusEl) {
    const d = currentDirect;
    if (!d || d.done) return;
    d.cancelled = true;
    if (d.xhr) {
        try { d.xhr.abort(); } catch (_) {}
    }
    try {
        await jfetch('api/direct/cancel', {
            method:'POST',
            headers:{'Content-Type':'application/json'},
            body:JSON.stringify({id:d.id,token:d.token})
        });
    } catch (_) {}
    d.done = true;
    statusEl.textContent = tr('transferCancelled');

    // A cancelled transfer is dead: remove its QR/link/card
    // and immediately allow another direct transfer.
    if (currentDirect === d) {
        currentDirect = null;
    }

    directSelectedFile = null;
    directFileInput.value = '';
    directArea.textContent = '';
}

async function watchSenderTransfer(direct,statusEl,fill) {
    let rev = -1;
    while (currentDirect === direct && !direct.done) {
        let state;
        try {
            state = await jfetch(
                'api/direct/status/' + encodeURIComponent(direct.id) +
                '?token=' + encodeURIComponent(direct.token) +
                '&since=' + encodeURIComponent(rev)
            );
        } catch(e) {
            if (!direct.done) statusEl.textContent = e.message;
            return;
        }
        rev = state.rev;
        if (state.state === 'accepted' || state.state === 'transferring') {
            if (state.receiver_name) {
                statusEl.textContent = tr('acceptedBy') + ': ' + state.receiver_name;
            }
            if (!direct.uploadStarted) {
                direct.uploadStarted = true;
                try {
                    await uploadDirectFile(direct,fill,statusEl);
                    if (!direct.cancelled) {
                        finishDirectUI(direct, statusEl, fill);
                    }
                } catch(e) {
                    if (!direct.cancelled) statusEl.textContent = e.message;
                    direct.done = true;
                }
                return;
            }
        }
        if (state.state === 'finished') {
            finishDirectUI(direct, statusEl, fill);
            return;
        }
        if (state.state === 'cancelled') {
            statusEl.textContent = tr('transferCancelled');
            direct.done = true;
            return;
        }
        if (state.state === 'expired') {
            statusEl.textContent = tr('transferExpired');
            direct.done = true;
            return;
        }
    }
}

function uploadDirectFile(direct,fill,statusEl) {
    return new Promise((resolve,reject) => {
        const xhr = new XMLHttpRequest();
        direct.xhr = xhr;
        xhr.open(
            'POST',
            'direct/send/' + encodeURIComponent(direct.id) +
            '?token=' + encodeURIComponent(direct.token)
        );
        xhr.setRequestHeader('Content-Type', direct.file.type || 'application/octet-stream');
        xhr.upload.onprogress = e => {
            if (e.lengthComputable) {
                const pct = e.loaded / e.total * 100;
                fill.style.width = pct.toFixed(1) + '%';
                statusEl.textContent = direct.cancelled
                    ? tr('transferCancelled')
                    : Math.floor(pct) + '%';
            }
        };
        xhr.onload = () => {
            if (xhr.status >= 200 && xhr.status < 300) resolve();
            else reject(new Error(tr('receiverGone')));
        };
        xhr.onerror = () => reject(new Error(tr('receiverGone')));
        xhr.onabort = () => reject(new Error(tr('transferCancelled')));
        xhr.send(direct.file);
    });
}

function dismissedDirectIds() {
    try {
        return new Set(JSON.parse(
            sessionStorage.getItem('lanShareDismissedDirect') || '[]'
        ));
    } catch (_) {
        return new Set();
    }
}

function dismissDirect(id) {
    const ids = dismissedDirectIds();
    ids.add(id);
    sessionStorage.setItem('lanShareDismissedDirect', JSON.stringify([...ids]));
}

function renderIncoming(pending) {
    const dismissed = dismissedDirectIds();
    const wanted = new URL(location.href).searchParams.get('direct');
    if (wanted) dismissed.delete(wanted);
    let visible = pending.filter(item => !dismissed.has(item.id));

    // A QR/direct link is an explicit request for one transfer.
    // Focus the page on that transfer instead of showing unrelated requests.
    if (wanted) {
        visible = visible.filter(item => item.id === wanted);
    }
    incomingTransfers.textContent = '';
    if (!visible.length) {
        incomingSection.style.display = 'none';
        return;
    }
    incomingSection.style.display = '';
    $('#incomingTitle').textContent = tr('incoming');

    for (const item of visible) {
        const card = document.createElement('div');
        card.className = 'card incoming-card';
        card.dataset.directId = item.id;
        const sender = document.createElement('div');
        sender.className = 'device-name';
        sender.textContent = tr('from') + ': ' + item.sender_name;
        const filename = document.createElement('div');
        filename.className = 'attachment-name';
        filename.style.marginTop = '8px';
        filename.textContent = item.name;
        const meta = document.createElement('div');
        meta.className = 'muted';
        meta.textContent = size(item.size);
        const actions = document.createElement('div');
        actions.className = 'actions';
        const reject = button(tr('reject'), () => {
            dismissDirect(item.id);
            card.remove();
            if (!incomingTransfers.children.length) {
                incomingSection.style.display = 'none';
            }
        });
        const receive = button(tr('receive'), async () => {
            receive.disabled = true;
            reject.disabled = true;
            const receiverName = getDeviceName(true);
            try {
                const result = await jfetch('api/direct/accept', {
                    method:'POST',
                    headers:{'Content-Type':'application/json'},
                    body:JSON.stringify({id:item.id,receiver_name:receiverName})
                });
                receive.textContent = tr('receiving');
                const a = document.createElement('a');
                a.href = result.receive_url;
                a.download = item.name;
                a.style.display = 'none';
                document.body.append(a);
                a.click();
                a.remove();

                // We have accepted the QR-targeted transfer.
                // Return URL to the normal /share/ address without reloading.
                const pageUrl = new URL(location.href);
                if (pageUrl.searchParams.get('direct') === item.id) {
                    pageUrl.searchParams.delete('direct');
                    history.replaceState(null, '', pageUrl.pathname + pageUrl.search + pageUrl.hash);
                }
            } catch(e) {
                alert(e.message || tr('anotherAccepted'));
                card.remove();
            }
        }, 'primary');
        actions.append(reject,receive);
        card.append(sender,filename,meta,actions);
        incomingTransfers.append(card);
    }

    if (wanted) {
        const target = incomingTransfers.querySelector(
            '[data-direct-id="' + CSS.escape(wanted) + '"]'
        );
        if (target) {
            target.scrollIntoView({behavior:'smooth',block:'center'});
        }
    }
}

async function watchIncomingTransfers() {
    while (true) {
        try {
            const result = await jfetch(
                'api/direct/events' +
                '?since=' + encodeURIComponent(directRev) +
                '&client=' + encodeURIComponent(getClientId())
            );
            directRev = result.rev;
            renderIncoming(result.pending);
        } catch(_) {
            await new Promise(r => setTimeout(r,2000));
        }
    }
}

async function loadStorage() {

    const info = await jfetch('api/storage');

    currentStorage = info;

    const percent =
        info.total > 0
        ? (info.used / info.total) * 100
        : 0;

    const bar = $('#storageFill');

    bar.style.width =
        Math.min(100, percent).toFixed(1) + '%';

    bar.classList.remove(
        'ok',
        'warn',
        'danger'
    );

    if (percent >= 90)
        bar.classList.add('danger');
    else if (percent >= 70)
        bar.classList.add('warn');
    else
        bar.classList.add('ok');

    $('#storageText').textContent =
        size(info.free) + ' ' +
        tr('free') + ' · ' +
        size(info.total) + ' ' +
        tr('of');
}


const itemsEl = $('#items');

function age(ts) {
    let s = Math.max(
        0,
        Math.floor(Date.now()/1000-ts)
    );

    if (s < 60) return 'just now';
    if (s < 3600) return Math.floor(s/60)+'m ago';
    if (s < 86400) return Math.floor(s/3600)+'h ago';

    return Math.floor(s/86400)+'d ago';
}

function expLabel(ts) {
    if (!ts)
        return 'never expires';

    let s = ts-Math.floor(Date.now()/1000);

    if (s <= 0)
        return 'expired';

    if (s < 3600)
        return 'expires in '+Math.ceil(s/60)+'m';

    if (s < 86400)
        return 'expires in '+Math.ceil(s/3600)+'h';

    return 'expires in '+Math.ceil(s/86400)+'d';
}

function size(n) {
    for (const u of ['B','KB','MB','GB']) {
        if (n < 1024 || u === 'GB')
            return (
                u === 'B'
                ? n
                : n.toFixed(n < 10 ? 1 : 0)
            )+' '+u;

        n /= 1024;
    }
}

async function jfetch(url,opt) {
    let r = await fetch(url,opt);

    let j = await r.json().catch(
        () => ({error:'Request failed'})
    );

    if (!r.ok)
        throw new Error(
            j.error || ('HTTP '+r.status)
        );

    return j;
}

function button(txt,fn,cls='') {
    let b = document.createElement('button');

    b.type='button';
    b.textContent=txt;

    if (cls)
        b.className=cls;

    b.onclick=fn;

    return b;
}

async function copyText(text) {
    try {
        await navigator.clipboard.writeText(text);
    } catch (_) {
        let x=document.createElement('textarea');

        x.value=text;
        x.style.position='fixed';
        x.style.opacity='0';

        document.body.append(x);

        x.select();
        document.execCommand('copy');

        x.remove();
    }
}

function addFile(parent,f) {

    let d=document.createElement('div');
    d.className='file';

    let head=document.createElement('div');
    head.className='topline';

    let name=document.createElement('span');
    name.textContent=f.name+' · '+size(f.size);

    head.append(name);

    let links=document.createElement('span');

    let open=document.createElement('a');
    open.className='btn';
    open.textContent='Open';
    open.target='_blank';
    open.rel='noopener';
    open.href=f.url;

    links.append(open);

    let dl=document.createElement('a');
    dl.className='btn';
    dl.textContent='Download';

    dl.href =
        f.url +
        (f.url.includes('?') ? '&' : '?') +
        'download=1';

    links.append(dl);

    head.append(links);
    d.append(head);

    if (f.mime.startsWith('image/')) {

        let img=document.createElement('img');

        img.loading='lazy';
        img.src=f.url;

        d.append(img);

    } else if (f.mime.startsWith('video/')) {

        let video=document.createElement('video');

        video.controls=true;
        video.preload='none';
        video.src=f.url;

        d.append(video);

    } else if (f.mime.startsWith('audio/')) {

        let audio=document.createElement('audio');

        audio.controls=true;
        audio.preload='none';
        audio.src=f.url;

        d.append(audio);
    }

    parent.append(d);
}

function renderContent(card,item) {

    let body=card.querySelector('.body');

    body.textContent='';

    if (item.text) {

        let p=document.createElement('div');

        p.className='item-text';
        p.textContent=item.text;

        body.append(p);

        let actions=document.createElement('div');

        actions.className='actions';
        actions.style.justifyContent='flex-start';

        actions.append(
            button(
                'Copy',
                () => copyText(item.text)
            )
        );

        if (/^https?:\/\/\S+$/i.test(
            item.text.trim()
        )) {

            let a=document.createElement('a');

            a.className='btn';
            a.textContent='Open link';
            a.target='_blank';
            a.rel='noopener';
            a.href=item.text.trim();

            actions.append(a);
        }

        body.append(actions);
    }

    for (const f of (item.files || []))
        addFile(body,f);
}

async function deleteItem(
    item,
    card,
    token,
    password
) {

    if (!confirm('Delete this item?'))
        return;

    try {

        await jfetch(
            'api/delete',
            {
                method:'POST',
                headers:{
                    'Content-Type':'application/json'
                },
                body:JSON.stringify({
                    id:item.id,
                    token:token || '',
                    password:password || ''
                })
            }
        );

        card.remove();

    } catch(e) {
        alert(e.message);
    }
}

function renderItem(item) {

    let card=document.createElement('div');
    card.className='card';

    let top=document.createElement('div');
    top.className='topline';

    let meta=document.createElement('div');

    meta.innerHTML =
        '<span class="badge">' +
        (item.protected ? '🔒 protected' : 'open') +
        '</span> ' +
        '<span class="muted">' +
        age(item.created_at) +
        ' · ' +
        expLabel(item.expires_at) +
        '</span>';

    top.append(meta);
    card.append(top);

    let body=document.createElement('div');

    body.className='body';
    card.append(body);

    if (!item.protected) {

        renderContent(card,item);

        let actions=document.createElement('div');

        actions.className='actions';

        actions.append(
            button(
                'Delete',
                () => deleteItem(
                    item,
                    card,
                    '',
                    ''
                ),
                'danger'
            )
        );

        card.append(actions);

    } else {

        let info=document.createElement('div');

        info.className='muted';
        info.style.marginTop='10px';

        info.textContent =
            'Protected item' +
            (
                item.file_count
                ? ' · ' +
                  item.file_count +
                  ' file' +
                  (
                    item.file_count === 1
                    ? ''
                    : 's'
                  )
                : ''
            );

        body.append(info);

        let row=document.createElement('div');
        row.className='lockrow';

        let input=document.createElement('input');

        input.type='password';
        input.placeholder='Password';
        input.autocomplete='current-password';

        let unlock = button(
            'Unlock',
            async () => {

                try {

                    let result = await jfetch(
                        'api/unlock',
                        {
                            method:'POST',
                            headers:{
                                'Content-Type':
                                    'application/json'
                            },
                            body:JSON.stringify({
                                id:item.id,
                                password:input.value
                            })
                        }
                    );

                    renderContent(
                        card,
                        result.item
                    );

                    row.remove();

                    let actions=
                        document.createElement('div');

                    actions.className='actions';

                    actions.append(
                        button(
                            'Delete',
                            () => deleteItem(
                                item,
                                card,
                                result.token,
                                ''
                            ),
                            'danger'
                        )
                    );

                    card.append(actions);

                } catch(e) {
                    alert(e.message);
                }
            }
        );

        input.onkeydown = e => {
            if (e.key === 'Enter') {
                e.preventDefault();
                unlock.click();
            }
        };

        row.append(input,unlock);
        body.append(row);
    }

    return card;
}

async function load() {

    itemsEl.innerHTML =
        '<div class="empty">Loading…</div>';

    try {

        let result=await jfetch('api/items');

        itemsEl.textContent='';

        if (!result.items.length) {
            itemsEl.innerHTML =
                '<div class="empty">' +
                'Nothing here yet.' +
                '</div>';

            return;
        }

        for (const item of result.items)
            itemsEl.append(
                renderItem(item)
            );

    } catch(e) {

        itemsEl.innerHTML =
            '<div class="empty">' +
            e.message +
            '</div>';
    }
}

$('#refresh').onclick=load;

const fileInput=$('#files');
const drop=$('#drop');
const names=$('#fileNames');

let selectedFiles=[];

function fileKey(f) {
    return [
        f.name,
        f.size,
        f.lastModified
    ].join(':');
}

function addFiles(list) {

    for (const file of list) {

        if (
            currentStorage &&
            file.size >
                Math.max(
                    0,
                    currentStorage.free -
                    64*1024*1024
                )
        ) {

            const useDirect = confirm(
                tr('directTooLarge') +
                '\n\n' +
                tr('directInstead') +
                '?'
            );

            if (useDirect) {
                prepareDirectTransfer(file);
                continue;
            }
        }

        if (
            !selectedFiles.some(
                x => fileKey(x) === fileKey(file)
            )
        ) {
            selectedFiles.push(file);
        }
    }

    renderSelectedFiles();
}

function renderSelectedFiles() {

    names.textContent='';

    selectedFiles.forEach((file,index) => {

        const row=document.createElement('div');
        row.className='attachment';

        const info=document.createElement('div');
        info.className='attachment-info';

        if (file.type.startsWith('image/')) {

            const img=document.createElement('img');
            img.className='attachment-thumb';

            const objectUrl=URL.createObjectURL(file);
            img.src=objectUrl;

            img.onload=() => URL.revokeObjectURL(objectUrl);

            info.append(img);

        } else {

            const icon=document.createElement('div');
            icon.className='attachment-icon';

            if (file.type.startsWith('video/'))
                icon.textContent='🎬';
            else if (file.type.startsWith('audio/'))
                icon.textContent='🎵';
            else
                icon.textContent='📎';

            info.append(icon);
        }

        const text=document.createElement('div');
        text.className='attachment-text';

        const filename=document.createElement('div');
        filename.className='attachment-name';
        filename.textContent=file.name;

        const filesize=document.createElement('div');
        filesize.className='attachment-size';
        filesize.textContent=size(file.size);

        text.append(filename,filesize);
        info.append(text);

        const remove=document.createElement('button');
        remove.type='button';
        remove.className='attachment-remove';
        remove.textContent='✕ Remove';

        remove.onclick=() => {
            selectedFiles.splice(index,1);
            renderSelectedFiles();
        };

        row.append(info,remove);
        names.append(row);
    });
}

fileInput.onchange=() => {

    addFiles(fileInput.files);

    // Reset the real input so you can remove a file
    // and then select that exact same file again.
    fileInput.value='';
};

['dragenter','dragover'].forEach(
    type => drop.addEventListener(
        type,
        e => {
            e.preventDefault();
            drop.classList.add('drag');
        }
    )
);

['dragleave','drop'].forEach(
    type => drop.addEventListener(
        type,
        e => {
            e.preventDefault();
            drop.classList.remove('drag');
        }
    )
);

drop.addEventListener(
    'drop',
    e => {
        addFiles(e.dataTransfer.files);
    }
);

$('#composer').onsubmit = async e => {

    e.preventDefault();

    let button=$('#submit');
    let status=$('#status');
    let files=[...selectedFiles];

    if (
        !$('#text').value.trim() &&
        !files.length
    ) {
        status.textContent=
            'Add text or a file';

        return;
    }

    button.disabled=true;
    status.textContent='Saving…';

    let created=null;

    try {

        created=await jfetch(
            'api/create',
            {
                method:'POST',
                headers:{
                    'Content-Type':
                        'application/json'
                },
                body:JSON.stringify({
                    text:$('#text').value,
                    expiry:Number(
                        $('#expiry').value
                    ),
                    password:
                        $('#password').value,
                    file_count:files.length
                })
            }
        );

        for (
            let i=0;
            i<files.length;
            i++
        ) {

            let file=files[i];

            status.textContent =
                'Uploading ' +
                (i+1) +
                '/' +
                files.length +
                '…';

            let response=await fetch(
                'api/upload?id=' +
                created.id +
                '&token=' +
                encodeURIComponent(
                    created.upload_token
                ),
                {
                    method:'POST',
                    headers:{
                        'X-File-Name':
                            encodeURIComponent(
                                file.name
                            ),
                        'Content-Type':
                            file.type ||
                            'application/octet-stream'
                    },
                    body:file
                }
            );

            if (!response.ok) {

                let result=
                    await response.json()
                    .catch(
                        () => ({
                            error:'Upload failed'
                        })
                    );

                throw new Error(
                    result.error ||
                    'Upload failed'
                );
            }
        }

        $('#text').value='';
        $('#password').value='';

        fileInput.value='';
        selectedFiles=[];
        renderSelectedFiles();

        status.textContent='Saved';

        await load();
        await loadStorage();

        setTimeout(
            () => status.textContent='',
            1200
        );

    } catch(err) {

        status.textContent=err.message;

        if (created) {

            fetch(
                'api/delete',
                {
                    method:'POST',
                    headers:{
                        'Content-Type':
                            'application/json'
                    },
                    body:JSON.stringify({
                        id:created.id,
                        token:
                            created.upload_token
                    })
                }
            ).catch(() => {});
        }

    } finally {
        button.disabled=false;
    }
};

applyLanguage();
load();
loadStorage().catch(() => {});
watchIncomingTransfers();

/* LAN_SHARE_PWA_SERVICE_WORKER */
if (
    'serviceWorker' in navigator &&
    location.protocol === 'https:'
) {
    navigator.serviceWorker.register(
        'static/sw.js'
    ).catch(err => {
        console.warn(
            'LAN Share service worker:',
            err
        );
    });
}

</script>

</body>
</html>'''


class Handler(BaseHTTPRequestHandler):

    server_version = "LANShare/1.0"

    def log_message(self, *_):
        # nginx already has access logs.
        pass

    def common_headers(self):
        self.send_header(
            "X-Content-Type-Options",
            "nosniff"
        )
        self.send_header(
            "Referrer-Policy",
            "no-referrer"
        )
        self.send_header(
            "Cache-Control",
            "no-store"
        )

    def json_response(self,status,obj):

        body=json.dumps(
            obj,
            ensure_ascii=False
        ).encode()

        self.send_response(status)
        self.common_headers()

        self.send_header(
            "Content-Type",
            "application/json; charset=utf-8"
        )

        self.send_header(
            "Content-Length",
            str(len(body))
        )

        self.end_headers()
        self.wfile.write(body)

    def html_response(self):

        body=HTML.encode()

        self.send_response(200)
        self.common_headers()

        self.send_header(
            "Content-Type",
            "text/html; charset=utf-8"
        )

        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; "
            "style-src 'unsafe-inline'; "
            "script-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: blob:; "
            "media-src 'self'; "
            "connect-src 'self'; "
            "base-uri 'none'; "
            "frame-ancestors 'none'"
        )

        self.send_header(
            "Content-Length",
            str(len(body))
        )

        self.end_headers()
        self.wfile.write(body)

    def read_json(
        self,
        max_bytes=2*1024*1024
    ):
        try:
            length=int(
                self.headers.get(
                    "Content-Length",
                    "0"
                )
            )

            if (
                length <= 0 or
                length > max_bytes
            ):
                return None

            return json.loads(
                self.rfile.read(
                    length
                ).decode()
            )

        except Exception:
            return None

    def parse_request(self):
        if not super().parse_request():
            return False
        if self.path == "/share":
            self.path = "/"
        elif self.path.startswith("/share/"):
            self.path = self.path[len("/share"):]
        return True

    def do_GET(self):

        cleanup_expired()

        parsed=urllib.parse.urlsplit(
            self.path
        )

        static_assets = {
            "/static/manifest.webmanifest": ("manifest.webmanifest", "application/manifest+json"),
            "/static/sw.js": ("sw.js", "application/javascript"),
            "/static/icon.svg": ("icon.svg", "image/svg+xml"),
            "/static/icon-192.png": ("icon-192.png", "image/png"),
            "/static/icon-512.png": ("icon-512.png", "image/png"),
        }
        if parsed.path in static_assets:
            name, mime = static_assets[parsed.path]
            body = (STATIC / name).read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-cache")
            if name == "sw.js":
                self.send_header("Service-Worker-Allowed", "/share/")
            self.end_headers()
            self.wfile.write(body)
            return

        if parsed.path == "/static/qrcode.min.js":
            qr_path = STATIC / "qrcode.min.js"
            if not qr_path.is_file():
                self.send_response(404)
                self.end_headers()
                return
            body = qr_path.read_bytes()
            self.send_response(200)
            self.send_header(
                "Content-Type",
                "application/javascript; charset=utf-8"
            )
            self.send_header(
                "Cache-Control",
                "public, max-age=31536000, immutable"
            )
            self.send_header(
                "Content-Length",
                str(len(body))
            )
            self.end_headers()
            self.wfile.write(body)
            return

        if parsed.path in ("","/"):
            return self.html_response()

        if parsed.path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
            return

        if parsed.path.startswith(
            "/direct/receive/"
        ):
            transfer_id = parsed.path.rsplit("/", 1)[1]
            query = urllib.parse.parse_qs(parsed.query)
            token = query.get("token", [""])[0]
            return self.direct_receive(transfer_id, token)

        if parsed.path == "/api/direct/events":
            query = urllib.parse.parse_qs(parsed.query)
            try:
                since = int(query.get("since", ["-1"])[0])
            except Exception:
                since = -1
            client_id = query.get("client", [""])[0][:100]
            rev, pending = direct_wait_events(since, client_id)
            return self.json_response(
                200,
                {"rev": rev, "pending": pending}
            )

        if parsed.path.startswith(
            "/api/direct/status/"
        ):
            transfer_id = parsed.path.rsplit("/", 1)[1]
            query = urllib.parse.parse_qs(parsed.query)
            sender_token = query.get("token", [""])[0]
            try:
                since = int(query.get("since", ["-1"])[0])
            except Exception:
                since = -1
            status, rev = direct_wait_sender(
                transfer_id,
                sender_token,
                since
            )
            if status is None:
                return self.json_response(
                    404,
                    {"error":"Transfer no longer exists"}
                )
            status["rev"] = rev
            return self.json_response(200, status)

        if parsed.path == "/api/storage":
            return self.json_response(
                200,
                storage_info()
            )

        if parsed.path == "/api/items":

            with db() as conn:

                rows=conn.execute(
                    """
                    SELECT
                        id,
                        created_at,
                        expires_at,
                        text,
                        password_salt,
                        password_hash
                    FROM items
                    ORDER BY created_at DESC
                    LIMIT 100
                    """
                ).fetchall()

                return self.json_response(
                    200,
                    {
                        "items":[
                            item_payload(
                                conn,
                                row
                            )
                            for row in rows
                        ]
                    }
                )

        if parsed.path.startswith(
            "/file/"
        ):

            try:
                file_id=int(
                    parsed.path.rsplit(
                        "/",
                        1
                    )[1]
                )
            except ValueError:
                return self.json_response(
                    404,
                    {"error":"Not found"}
                )

            return self.serve_file(
                file_id,
                urllib.parse.parse_qs(
                    parsed.query
                ),
                False
            )

        return self.json_response(
            404,
            {"error":"Not found"}
        )

    def do_HEAD(self):

        cleanup_expired()

        parsed=urllib.parse.urlsplit(
            self.path
        )

        if parsed.path.startswith(
            "/file/"
        ):

            try:
                file_id=int(
                    parsed.path.rsplit(
                        "/",
                        1
                    )[1]
                )
            except ValueError:
                self.send_response(404)
                self.end_headers()
                return

            return self.serve_file(
                file_id,
                urllib.parse.parse_qs(
                    parsed.query
                ),
                True
            )

        self.send_response(405)
        self.end_headers()

    def do_POST(self):

        cleanup_expired()

        parsed=urllib.parse.urlsplit(
            self.path
        )

        if parsed.path == "/share-target":
            return self.share_target()

        if parsed.path == "/api/direct/create":
            return self.direct_create_request()

        if parsed.path == "/api/direct/accept":
            return self.direct_accept_request()

        if parsed.path == "/api/direct/cancel":
            return self.direct_cancel_request()

        if parsed.path.startswith(
            "/direct/send/"
        ):
            transfer_id = parsed.path.rsplit("/", 1)[1]
            query = urllib.parse.parse_qs(parsed.query)
            sender_token = query.get("token", [""])[0]
            return self.direct_send(
                transfer_id,
                sender_token
            )

        if parsed.path == "/api/create":
            return self.create_item()

        if parsed.path == "/api/upload":
            return self.upload_file(
                urllib.parse.parse_qs(
                    parsed.query
                )
            )

        if parsed.path == "/api/unlock":
            return self.unlock_item()

        if parsed.path == "/api/delete":
            return self.delete_item()

        return self.json_response(
            404,
            {"error":"Not found"}
        )


    def direct_create_request(self):
        data = self.read_json()
        if not data:
            return self.json_response(400, {"error":"Bad request"})
        try:
            size = int(data.get("size", 0))
        except Exception:
            size = 0
        if size <= 0:
            return self.json_response(400, {"error":"Invalid file size"})
        name = Path(str(data.get("name", "file"))).name[:240] or "file"
        mime = str(data.get("mime", "application/octet-stream"))[:200]
        sender_name = str(data.get("sender_name", "Device")).strip()[:80] or "Device"
        sender_client = str(data.get("client_id", ""))[:100]
        transfer = direct_create(
            sender_client,
            sender_name,
            name,
            size,
            mime
        )
        return self.json_response(
            201,
            {"id":transfer.id,"sender_token":transfer.sender_token}
        )


    def direct_accept_request(self):
        data = self.read_json()
        if not data:
            return self.json_response(400, {"error":"Bad request"})
        transfer_id = str(data.get("id", ""))
        receiver_name = str(data.get("receiver_name", "Device")).strip()[:80] or "Device"
        with DIRECT_COND:
            _direct_cleanup_locked()
            transfer = DIRECT_TRANSFERS.get(transfer_id)
            if not transfer:
                return self.json_response(404, {"error":"Transfer no longer exists"})
            if transfer.state != "pending":
                return self.json_response(
                    409,
                    {"error":"Another device already accepted this transfer"}
                )
            transfer.receiver_name = receiver_name
            transfer.receiver_token = secrets.token_urlsafe(24)
            transfer.state = "accepted"
            transfer.updated = time.time()
            _direct_bump_locked()
            token = transfer.receiver_token
        return self.json_response(
            200,
            {
                "ok":True,
                "receive_url":
                    "direct/receive/" + urllib.parse.quote(transfer_id) +
                    "?token=" + urllib.parse.quote(token)
            }
        )


    def direct_cancel_request(self):
        data = self.read_json()
        if not data:
            return self.json_response(400, {"error":"Bad request"})
        transfer_id = str(data.get("id", ""))
        sender_token = str(data.get("token", ""))
        with DIRECT_COND:
            transfer = DIRECT_TRANSFERS.get(transfer_id)
            if (
                not transfer
                or not hmac.compare_digest(transfer.sender_token, sender_token)
            ):
                return self.json_response(404, {"error":"Transfer not found"})
            _direct_cancel_locked(transfer)
        return self.json_response(200, {"ok":True})


    def direct_send(self, transfer_id, sender_token):
        with DIRECT_COND:
            transfer = DIRECT_TRANSFERS.get(transfer_id)
            if (
                not transfer
                or not hmac.compare_digest(transfer.sender_token, sender_token)
            ):
                return self.json_response(404, {"error":"Transfer not found"})
            if transfer.sender_ready.is_set():
                return self.json_response(409, {"error":"Sender already connected"})
            if transfer.state not in ("accepted", "transferring"):
                return self.json_response(409, {"error":"No receiver has accepted yet"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except Exception:
            length = 0
        if length != transfer.size:
            return self.json_response(400, {"error":"File size mismatch"})
        transfer.sender_ready.set()
        transfer.updated = time.time()
        if not transfer.receiver_ready.wait(300):
            with DIRECT_COND:
                _direct_cancel_locked(transfer)
            return self.json_response(408, {"error":"Receiver did not connect"})
        remaining = length
        try:
            while remaining > 0:
                if transfer.cancelled.is_set():
                    raise ConnectionError("Transfer cancelled")
                chunk = self.rfile.read(min(DIRECT_CHUNK, remaining))
                if not chunk:
                    raise ConnectionError("Sender disconnected")
                while True:
                    if transfer.cancelled.is_set():
                        raise ConnectionError("Transfer cancelled")
                    try:
                        transfer.queue.put(chunk, timeout=1)
                        break
                    except queue.Full:
                        continue
                remaining -= len(chunk)
                transfer.updated = time.time()
            while True:
                if transfer.cancelled.is_set():
                    raise ConnectionError("Transfer cancelled")
                try:
                    transfer.queue.put(None, timeout=1)
                    break
                except queue.Full:
                    continue
            transfer.finished.wait(timeout=60)
            if transfer.cancelled.is_set():
                return self.json_response(499, {"error":"Transfer cancelled"})
            return self.json_response(200, {"ok":True})
        except Exception:
            with DIRECT_COND:
                if transfer.state not in ("finished", "cancelled"):
                    _direct_cancel_locked(transfer)
            return self.json_response(500, {"error":"Direct transfer interrupted"})


    def direct_receive(self, transfer_id, receiver_token):
        with DIRECT_COND:
            _direct_cleanup_locked()
            transfer = DIRECT_TRANSFERS.get(transfer_id)
            if (
                not transfer
                or not transfer.receiver_token
                or not hmac.compare_digest(transfer.receiver_token, receiver_token)
            ):
                self.send_response(404)
                self.end_headers()
                return
            if transfer.receiver_ready.is_set():
                self.send_response(409)
                self.end_headers()
                return
            if transfer.state not in ("accepted", "transferring"):
                self.send_response(410)
                self.end_headers()
                return
            transfer.state = "transferring"
            transfer.updated = time.time()
            transfer.receiver_ready.set()
            _direct_bump_locked()
        encoded_name = urllib.parse.quote(transfer.name)
        self.send_response(200)
        self.send_header("Content-Type", transfer.mime or "application/octet-stream")
        self.send_header("Content-Length", str(transfer.size))
        self.send_header(
            "Content-Disposition",
            "attachment; filename*=UTF-8''" + encoded_name
        )
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        success = False
        try:
            while True:
                if transfer.cancelled.is_set():
                    break
                try:
                    chunk = transfer.queue.get(timeout=1)
                except queue.Empty:
                    continue
                if chunk is None:
                    success = True
                    break
                self.wfile.write(chunk)
                self.wfile.flush()
                transfer.bytes_sent += len(chunk)
                transfer.updated = time.time()
        except (BrokenPipeError, ConnectionResetError):
            success = False
        finally:
            with DIRECT_COND:
                if success and transfer.bytes_sent >= transfer.size:
                    transfer.state = "finished"
                    transfer.updated = time.time()
                    transfer.finished.set()
                    _direct_bump_locked()
                elif transfer.state != "cancelled":
                    _direct_cancel_locked(transfer)


    def share_target(self):

        # Android Web Share Target sends multipart/form-data.
        try:
            length = int(
                self.headers.get(
                    "Content-Length",
                    "0"
                )
            )
        except Exception:
            length = 0

        if length <= 0:
            return self.json_response(
                400,
                {"error":"Empty share"}
            )

        content_type = self.headers.get(
            "Content-Type",
            ""
        )

        if "multipart/form-data" not in content_type:
            return self.json_response(
                400,
                {"error":"Unsupported share format"}
            )

        # Refuse the request before parsing if the entire
        # body cannot possibly fit on the TF card.
        free = shutil.disk_usage(UPLOADS).free
        reserve = 64 * 1024 * 1024

        if length > max(0, free - reserve):
            return self.json_response(
                507,
                {"error":"Not enough storage"}
            )

        try:
            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={
                    "REQUEST_METHOD":"POST",
                    "CONTENT_TYPE":content_type,
                    "CONTENT_LENGTH":str(length)
                },
                keep_blank_values=True
            )
        except Exception:
            return self.json_response(
                400,
                {"error":"Could not read shared data"}
            )

        def field_text(name):

            try:
                value = form.getfirst(
                    name,
                    ""
                )
            except Exception:
                return ""

            if value is None:
                return ""

            if isinstance(value, bytes):
                value = value.decode(
                    "utf-8",
                    "replace"
                )

            return str(value).strip()

        title = field_text("title")
        text = field_text("text")
        url = field_text("url")

        text_parts = []

        for value in (title, text, url):
            if value and value not in text_parts:
                text_parts.append(value)

        shared_text = "\n".join(text_parts)

        if len(shared_text.encode()) > MAX_TEXT_BYTES:
            shared_text = (
                shared_text.encode()[:MAX_TEXT_BYTES]
                .decode("utf-8", "ignore")
            )

        file_parts = []

        file_parts = []

        for part in (form.list or []):

            if (
                part.name == "files"
                and
                getattr(part, "filename", None)
            ):
                file_parts.append(part)

        if not shared_text.strip() and not file_parts:
            return self.json_response(
                400,
                {"error":"Nothing was shared"}
            )

        now = int(time.time())

        # Same default as the normal LAN Share composer:
        # one day.
        expires_at = now + 86400

        with db() as conn:

            cursor = conn.execute(
                """
                INSERT INTO items(
                    created_at,
                    expires_at,
                    text,
                    password_salt,
                    password_hash
                )
                VALUES(?,?,?,?,?)
                """,
                (
                    now,
                    expires_at,
                    shared_text,
                    None,
                    None
                )
            )

            item_id = cursor.lastrowid

        saved_paths = []

        try:

            for part in file_parts:

                original = Path(
                    str(part.filename)
                ).name[:240] or "file"

                mime = (
                    getattr(part, "type", "")
                    or
                    mimetypes.guess_type(original)[0]
                    or
                    "application/octet-stream"
                )

                stored = (
                    uuid.uuid4().hex +
                    Path(original).suffix[:20]
                )

                destination = UPLOADS / stored

                try:
                    part.file.seek(0)
                except Exception:
                    pass

                total = 0

                with destination.open("wb") as output:

                    while True:

                        chunk = part.file.read(
                            1024 * 1024
                        )

                        if not chunk:
                            break

                        total += len(chunk)

                        if total > MAX_FILE_BYTES:
                            raise ValueError(
                                "Shared file too large"
                            )

                        # Check remaining storage while streaming.
                        if (
                            shutil.disk_usage(UPLOADS).free
                            < len(chunk) + reserve
                        ):
                            raise OSError(
                                "Not enough storage"
                            )

                        output.write(chunk)

                if total == 0:
                    destination.unlink(
                        missing_ok=True
                    )
                    continue

                saved_paths.append(destination)

                with db() as conn:

                    conn.execute(
                        """
                        INSERT INTO files(
                            item_id,
                            stored_name,
                            original_name,
                            mime,
                            size
                        )
                        VALUES(?,?,?,?,?)
                        """,
                        (
                            item_id,
                            stored,
                            original,
                            mime,
                            total
                        )
                    )

        except Exception as exc:

            for path in saved_paths:
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    pass

            # Also remove a partially-written current file.
            try:
                destination.unlink(missing_ok=True)
            except Exception:
                pass

            with db() as conn:
                conn.execute(
                    "DELETE FROM items WHERE id=?",
                    (item_id,)
                )

            return self.json_response(
                500,
                {
                    "error":
                        "Could not save shared content"
                }
            )

        # Return to LAN Share after Android hands us the data.
        self.send_response(303)

        self.send_header(
            "Location",
            "/share/?shared=1"
        )

        self.send_header(
            "Cache-Control",
            "no-store"
        )

        self.send_header(
            "Content-Length",
            "0"
        )

        self.end_headers()


    def create_item(self):

        data=self.read_json()

        if not data:
            return self.json_response(
                400,
                {"error":"Bad request"}
            )

        text=str(
            data.get("text","")
        )

        if len(
            text.encode()
        ) > MAX_TEXT_BYTES:

            return self.json_response(
                413,
                {"error":"Text is too large"}
            )

        try:
            file_count=max(
                0,
                int(
                    data.get(
                        "file_count",
                        0
                    )
                )
            )
        except Exception:
            file_count=0

        if (
            not text.strip() and
            file_count == 0
        ):

            return self.json_response(
                400,
                {
                    "error":
                        "Add text or a file"
                }
            )

        try:
            expiry=int(
                data.get(
                    "expiry",
                    86400
                )
            )
        except Exception:
            expiry=86400

        if expiry not in (
            0,
            3600,
            86400,
            604800,
            2592000
        ):
            expiry=86400

        password=str(
            data.get(
                "password",
                ""
            )
        ).strip()

        salt=None
        pw_hash=None

        if password:
            salt,pw_hash=make_password(
                password
            )

        now=int(time.time())

        expires_at=(
            None
            if expiry == 0
            else now+expiry
        )

        with db() as conn:

            cursor=conn.execute(
                """
                INSERT INTO items(
                    created_at,
                    expires_at,
                    text,
                    password_salt,
                    password_hash
                )
                VALUES(?,?,?,?,?)
                """,
                (
                    now,
                    expires_at,
                    text,
                    salt,
                    pw_hash
                )
            )

            item_id=cursor.lastrowid

        token=make_token(
            item_id,
            "upload",
            900
        )

        return self.json_response(
            201,
            {
                "ok":True,
                "id":item_id,
                "upload_token":token
            }
        )

    def upload_file(self,query):

        try:
            item_id=int(
                query.get(
                    "id",
                    [""]
                )[0]
            )
        except Exception:
            return self.json_response(
                400,
                {"error":"Bad item"}
            )

        token=query.get(
            "token",
            [""]
        )[0]

        if not token_ok(
            item_id,
            token,
            "upload"
        ):

            return self.json_response(
                403,
                {
                    "error":
                        "Upload token expired"
                }
            )

        try:
            length=int(
                self.headers.get(
                    "Content-Length",
                    "0"
                )
            )
        except Exception:
            length=0

        if length <= 0:
            return self.json_response(
                400,
                {"error":"Empty file"}
            )

        if length > MAX_FILE_BYTES:
            return self.json_response(
                413,
                {
                    "error":
                        "File is too large"
                }
            )

        # Keep a little breathing room on the filesystem.
        free = shutil.disk_usage(UPLOADS).free
        reserve = 64 * 1024 * 1024

        if length > max(0, free - reserve):
            return self.json_response(
                507,
                {
                    "error":
                        "Not enough storage for this file"
                }
            )

        with db() as conn:
            exists=conn.execute(
                "SELECT 1 FROM items WHERE id=?",
                (item_id,)
            ).fetchone()

        if not exists:
            return self.json_response(
                404,
                {"error":"Item not found"}
            )

        raw_name=self.headers.get(
            "X-File-Name",
            "file"
        )

        try:
            original=Path(
                urllib.parse.unquote(
                    raw_name
                )
            ).name[:240] or "file"

        except Exception:
            original="file"

        mime=(
            self.headers.get(
                "Content-Type",
                ""
            )
            or
            mimetypes.guess_type(
                original
            )[0]
            or
            "application/octet-stream"
        )

        stored=(
            uuid.uuid4().hex +
            Path(original).suffix[:20]
        )

        destination=UPLOADS/stored

        remaining=length

        try:

            with destination.open(
                "wb"
            ) as output:

                while remaining:

                    chunk=self.rfile.read(
                        min(
                            1024*1024,
                            remaining
                        )
                    )

                    if not chunk:
                        raise IOError(
                            "upload ended early"
                        )

                    output.write(chunk)

                    remaining -= len(chunk)

            with db() as conn:

                cursor=conn.execute(
                    """
                    INSERT INTO files(
                        item_id,
                        stored_name,
                        original_name,
                        mime,
                        size
                    )
                    VALUES(?,?,?,?,?)
                    """,
                    (
                        item_id,
                        stored,
                        original,
                        mime,
                        length
                    )
                )

                file_id=cursor.lastrowid

            return self.json_response(
                201,
                {
                    "ok":True,
                    "file_id":file_id
                }
            )

        except Exception:

            try:
                destination.unlink(
                    missing_ok=True
                )
            except OSError:
                pass

            return self.json_response(
                500,
                {
                    "error":
                        "Could not save file"
                }
            )

    def unlock_item(self):

        data=self.read_json()

        if not data:
            return self.json_response(
                400,
                {"error":"Bad request"}
            )

        try:
            item_id=int(
                data.get("id")
            )
        except Exception:
            return self.json_response(
                400,
                {"error":"Bad item"}
            )

        password=str(
            data.get(
                "password",
                ""
            )
        )

        with db() as conn:

            row=conn.execute(
                """
                SELECT
                    id,
                    created_at,
                    expires_at,
                    text,
                    password_salt,
                    password_hash
                FROM items
                WHERE id=?
                """,
                (item_id,)
            ).fetchone()

            if not row:
                return self.json_response(
                    404,
                    {
                        "error":
                            "Item not found"
                    }
                )

            if (
                row[5] is not None and
                not password_ok(
                    password,
                    row[4],
                    row[5]
                )
            ):

                return self.json_response(
                    403,
                    {
                        "error":
                            "Wrong password"
                    }
                )

            token=(
                make_token(
                    item_id,
                    "view",
                    900
                )
                if row[5] is not None
                else ""
            )

            item=item_payload(
                conn,
                row,
                True,
                token
            )

        return self.json_response(
            200,
            {
                "item":item,
                "token":token
            }
        )

    def delete_item(self):

        data=self.read_json()

        if not data:
            return self.json_response(
                400,
                {"error":"Bad request"}
            )

        try:
            item_id=int(
                data.get("id")
            )
        except Exception:
            return self.json_response(
                400,
                {"error":"Bad item"}
            )

        token=str(
            data.get(
                "token",
                ""
            )
        )

        password=str(
            data.get(
                "password",
                ""
            )
        )

        with db() as conn:

            row=conn.execute(
                """
                SELECT
                    password_salt,
                    password_hash
                FROM items
                WHERE id=?
                """,
                (item_id,)
            ).fetchone()

            if not row:
                return self.json_response(
                    404,
                    {
                        "error":
                            "Item not found"
                    }
                )

            allowed=(
                row[1] is None
                or token_ok(
                    item_id,
                    token,
                    "view"
                )
                or token_ok(
                    item_id,
                    token,
                    "upload"
                )
                or password_ok(
                    password,
                    row[0],
                    row[1]
                )
            )

            if not allowed:
                return self.json_response(
                    403,
                    {
                        "error":
                            "Password required"
                    }
                )

            files=conn.execute(
                """
                SELECT stored_name
                FROM files
                WHERE item_id=?
                """,
                (item_id,)
            ).fetchall()

            for (stored,) in files:

                try:
                    (UPLOADS/stored).unlink(
                        missing_ok=True
                    )
                except OSError:
                    pass

            conn.execute(
                "DELETE FROM items WHERE id=?",
                (item_id,)
            )

        return self.json_response(
            200,
            {"ok":True}
        )

    def serve_file(
        self,
        file_id,
        query,
        head_only
    ):

        with db() as conn:

            row=conn.execute(
                """
                SELECT
                    f.item_id,
                    f.stored_name,
                    f.original_name,
                    f.mime,
                    i.password_hash
                FROM files f
                JOIN items i
                    ON i.id=f.item_id
                WHERE f.id=?
                """,
                (file_id,)
            ).fetchone()

        if not row:
            self.send_response(404)
            self.end_headers()
            return

        (
            item_id,
            stored,
            original,
            mime,
            pw_hash
        )=row

        if pw_hash is not None:

            token=query.get(
                "token",
                [""]
            )[0]

            if not token_ok(
                item_id,
                token,
                "view"
            ):
                self.send_response(403)
                self.end_headers()
                return

        path=UPLOADS/stored

        if not path.is_file():
            self.send_response(404)
            self.end_headers()
            return

        size=path.stat().st_size

        start=0
        end=size-1

        status=200

        range_header=self.headers.get(
            "Range",
            ""
        )

        if (
            size and
            range_header.startswith(
                "bytes="
            )
        ):

            try:

                spec=range_header[
                    6:
                ].split(",",1)[0]

                a,b=spec.split("-",1)

                if a:
                    start=int(a)

                    end=(
                        int(b)
                        if b
                        else size-1
                    )

                else:
                    tail=int(b)
                    start=max(
                        0,
                        size-tail
                    )
                    end=size-1

                start=max(
                    0,
                    min(
                        start,
                        size-1
                    )
                )

                end=max(
                    start,
                    min(
                        end,
                        size-1
                    )
                )

                status=206

            except Exception:
                start=0
                end=size-1
                status=200

        length=(
            0
            if size == 0
            else end-start+1
        )

        self.send_response(status)

        self.send_header(
            "Content-Type",
            mime or
            "application/octet-stream"
        )

        self.send_header(
            "Accept-Ranges",
            "bytes"
        )

        self.send_header(
            "Content-Length",
            str(length)
        )

        if status == 206:

            self.send_header(
                "Content-Range",
                f"bytes {start}-{end}/{size}"
            )

        disposition=(
            "attachment"
            if query.get(
                "download",
                [""]
            )[0] == "1"
            else "inline"
        )

        encoded_name=urllib.parse.quote(
            original
        )

        self.send_header(
            "Content-Disposition",
            disposition +
            "; filename*=UTF-8''" +
            encoded_name
        )

        self.send_header(
            "X-Content-Type-Options",
            "nosniff"
        )

        self.end_headers()

        if head_only or length == 0:
            return

        with path.open("rb") as f:

            f.seek(start)

            remaining=length

            while remaining:

                chunk=f.read(
                    min(
                        1024*1024,
                        remaining
                    )
                )

                if not chunk:
                    break

                try:
                    self.wfile.write(
                        chunk
                    )
                except (
                    BrokenPipeError,
                    ConnectionResetError
                ):
                    break

                remaining -= len(chunk)


if __name__ == "__main__":

    init_db()
    cleanup_expired()

    server=ThreadingHTTPServer(
        (HOST,PORT),
        Handler
    )

    server.daemon_threads=True

    server.serve_forever(
        poll_interval=1.0
    )
