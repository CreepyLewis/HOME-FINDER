from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_from_directory
import sqlite3, os, re, uuid, json, bcrypt
from datetime import datetime, timedelta
from functools import wraps
from werkzeug.utils import secure_filename


app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-me-in-production-please")

# ── Config ──────────────────────────────────────────────────
DB_PATH          = os.environ.get("DB_PATH", "instance/vacancies.db")
UPLOAD_FOLDER    = "static/uploads"
MAX_IMAGE_BYTES  = 10 * 1024 * 1024
MAX_VIDEO_BYTES  = 50 * 1024 * 1024
LISTINGS_PER_PAGE = 10
MAX_LISTINGS     = 10
LISTING_EXPIRY_DAYS = 30
ADSENSE_CLIENT   = os.environ.get("ADSENSE_CLIENT", "ca-pub-1639085960004144")
ADSENSE_SLOT     = os.environ.get("ADSENSE_SLOT", "")   # set your ad slot id here

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs("instance", exist_ok=True)

PLANS = {
    "free":     {"label": "Free",     "price": 0,   "features": "Basic listing",                  "featured": 0, "boost": 0},
    "boost":    {"label": "Boost",    "price": 100, "features": "Highlighted listing",            "featured": 0, "boost": 1},
    "featured": {"label": "Featured", "price": 300, "features": "Top placement",                  "featured": 1, "boost": 0},
    "premium":  {"label": "Premium",  "price": 500, "features": "Top placement + priority",       "featured": 1, "boost": 1},
}

HOUSE_TYPES    = ["Bedsitter","1BR","2BR","3BR","Single Room","Other"]
AMENITY_OPTIONS = ["Water 💧","WiFi 📶","Parking 🚗","Electricity ⚡","Security 🔒","Gym 🏋️","Pool 🏊"]
PHONE_RE       = re.compile(r"^(\+254|254|0)?7\d{8}$")

DEFAULT_TOWNS = [
    "Nairobi","Westlands","Kasarani","Embakasi","Langata","Kilimani","Karen",
    "Rongai","Kibera","Kileleshwa","Gachie","Ruaka","Runda","Nyari","Loresho",
    "Muthaiga","Ruai","Thome","South C","Hardy","Gataka",
]

# ── Database ─────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def init_db():
    with get_db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS vacancies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            location TEXT,
            house_type TEXT DEFAULT 'Not specified',
            rent REAL DEFAULT 0,
            phone TEXT,
            description TEXT,
            image TEXT DEFAULT '',
            video TEXT DEFAULT '',
            featured INTEGER DEFAULT 0,
            pending_featured INTEGER DEFAULT 0,
            pending_payment INTEGER DEFAULT 0,
            latitude REAL, longitude REAL,
            owner TEXT,
            reports INTEGER DEFAULT 0,
            amenities TEXT DEFAULT '',
            plan TEXT DEFAULT 'free',
            boost INTEGER DEFAULT 0,
            expires_at TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'owner',
            status TEXT DEFAULT 'active',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS towns (
            name TEXT PRIMARY KEY
        );
        CREATE TABLE IF NOT EXISTS visits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            visitor_id TEXT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS listing_reports (
            visitor_id TEXT NOT NULL,
            listing_id INTEGER NOT NULL,
            PRIMARY KEY (visitor_id, listing_id)
        );
        """)
        # Ensure admin exists
        admin_pw = os.environ.get("ADMIN_PASSWORD", "Admin@1234!")
        hashed   = bcrypt.hashpw(admin_pw.encode(), bcrypt.gensalt()).decode()
        try:
            conn.execute("INSERT OR IGNORE INTO users (username,password,role,status) VALUES (?,?,?,?)",
                         ("admin", hashed, "admin", "active"))
            conn.commit()
        except Exception:
            pass

init_db()

# ── Helpers ──────────────────────────────────────────────────
def validate_phone(phone):
    cleaned = phone.strip().replace(" ","").replace("-","")
    return bool(PHONE_RE.match(cleaned))

def format_phone(phone):
    p = str(phone).replace(" ","").replace("-","")
    if p.startswith("+254"): return p[1:]
    if p.startswith("254"):  return p
    if p.startswith("0"):    return "254" + p[1:]
    if p.startswith("7"):    return "254" + p
    return p

def mask_phone(phone):
    p = str(phone).strip()
    return p[:4] + "*****" if len(p) >= 4 else p

def hash_password(pw):   return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
def check_password(pw, h): return bcrypt.checkpw(pw.encode(), h.encode())

def valid_password(p):
    return (len(p) >= 8 and re.search(r"[A-Z]",p) and re.search(r"[0-9]",p)
            and re.search(r"[!@#$%^&*(),.?\":{}|<>]",p))

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get("role") != "admin":
            flash("Admin access only.", "danger")
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated

def get_towns():
    with get_db() as conn:
        rows = conn.execute("SELECT name FROM towns").fetchall()
    db_towns = {r["name"] for r in rows}
    return sorted(set(DEFAULT_TOWNS) | db_towns)

def save_visit():
    vid = session.get("visitor_id", str(uuid.uuid4()))
    session["visitor_id"] = vid
    try:
        with get_db() as conn:
            conn.execute("INSERT INTO visits (visitor_id) VALUES (?)", (vid,))
            conn.commit()
    except Exception:
        pass

# ── Context processor ────────────────────────────────────────
@app.context_processor
def inject_globals():
    return dict(
        adsense_client=ADSENSE_CLIENT,
        adsense_slot=ADSENSE_SLOT,
        current_user=session.get("username"),
        current_role=session.get("role",""),
        plans=PLANS,
        house_types=HOUSE_TYPES,
        amenity_options=AMENITY_OPTIONS,
        mask_phone=mask_phone,
        format_phone=format_phone,
        now=datetime.now(),
    )

# ── Routes ───────────────────────────────────────────────────
@app.route("/ads.txt")
def ads_txt():
    return "google.com, pub-1639085960004144, DIRECT, f08c47fec0942fa0", 200, {"Content-Type": "text/plain"}

@app.route("/robots.txt")
def robots_txt():
    return "User-agent: *\nAllow: /\nSitemap: /sitemap.xml", 200, {"Content-Type": "text/plain"}

@app.route("/sitemap.xml")
def sitemap():
    with get_db() as conn:
        listings = conn.execute("SELECT id, created_at FROM vacancies WHERE reports < 3").fetchall()
    urls = [{"loc": url_for("listing_detail", vid=r["id"], _external=True),
             "lastmod": (r["created_at"] or "")[:10]} for r in listings]
    xml = render_template("sitemap.xml", urls=urls)
    return xml, 200, {"Content-Type": "application/xml"}

@app.route("/")
def index():
    save_visit()
    page       = int(request.args.get("page", 0))
    town       = request.args.get("town", "All")
    house_type = request.args.get("house_type", "All")
    search     = request.args.get("search", "").strip()
    min_rent   = request.args.get("min_rent", type=int, default=0)
    max_rent   = request.args.get("max_rent", type=int, default=0)

    now_str = datetime.now().isoformat()
    base    = "SELECT * FROM vacancies WHERE reports < 3 AND (expires_at IS NULL OR expires_at > ?)"
    count_q = "SELECT COUNT(*) FROM vacancies WHERE reports < 3 AND (expires_at IS NULL OR expires_at > ?)"
    params  = [now_str]

    if town and town != "All":
        base += " AND location = ?"; count_q += " AND location = ?"; params.append(town)
    if house_type and house_type != "All":
        base += " AND LOWER(house_type) LIKE ?"; count_q += " AND LOWER(house_type) LIKE ?"; params.append(f"%{house_type.lower()}%")
    if min_rent > 0:
        base += " AND rent >= ?"; count_q += " AND rent >= ?"; params.append(min_rent)
    if max_rent > 0:
        base += " AND rent <= ?"; count_q += " AND rent <= ?"; params.append(max_rent)
    if search:
        clause = " AND (title LIKE ? OR description LIKE ? OR location LIKE ? OR house_type LIKE ?)"
        base += clause; count_q += clause; params.extend([f"%{search}%"]*4)

    base += " ORDER BY featured DESC, boost DESC, id DESC LIMIT ? OFFSET ?"
    with get_db() as conn:
        total    = conn.execute(count_q, params).fetchone()[0]
        listings = conn.execute(base, params + [LISTINGS_PER_PAGE, page * LISTINGS_PER_PAGE]).fetchall()
        listings = [dict(r) for r in listings]

    for lst in listings:
        try: lst["amenities_data"] = json.loads(lst.get("amenities") or "{}")
        except: lst["amenities_data"] = {}

    total_pages = max(1, (total + LISTINGS_PER_PAGE - 1) // LISTINGS_PER_PAGE)
    towns       = get_towns()

    return render_template("index.html",
        listings=listings, towns=towns, total=total,
        page=page, total_pages=total_pages,
        filters={"town": town, "house_type": house_type, "search": search,
                 "min_rent": min_rent, "max_rent": max_rent})

@app.route("/listing/<int:vid>")
def listing_detail(vid):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM vacancies WHERE id=?", (vid,)).fetchone()
    if not row:
        flash("Listing not found.", "warning")
        return redirect(url_for("index"))
    lst = dict(row)
    try: lst["amenities_data"] = json.loads(lst.get("amenities") or "{}")
    except: lst["amenities_data"] = {}
    return render_template("listing_detail.html", listing=lst)

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","").strip()
        with get_db() as conn:
            user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if user and user["status"] != "blocked" and check_password(password, user["password"]):
            session["username"] = user["username"]
            session["role"]     = user["role"]
            flash(f"Welcome back, {username}!", "success")
            return redirect(url_for("dashboard") if user["role"]=="admin" else url_for("my_listings"))
        flash("Invalid credentials or account blocked.", "danger")
    return render_template("login.html")

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","").strip()
        if len(username) < 3 or " " in username:
            flash("Username: min 3 chars, no spaces.", "danger")
        elif not valid_password(password):
            flash("Password needs: 8+ chars, uppercase, number, special char.", "danger")
        else:
            try:
                with get_db() as conn:
                    conn.execute("INSERT INTO users (username,password,role,status) VALUES (?,?,?,?)",
                                 (username, hash_password(password), "owner", "active"))
                    conn.commit()
                session["username"] = username
                session["role"]     = "owner"
                flash("Registered successfully!", "success")
                return redirect(url_for("my_listings"))
            except Exception:
                flash("Username already exists.", "danger")
    return render_template("register.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("index"))

@app.route("/post", methods=["GET","POST"])
@login_required
def post_listing():
    if session.get("role") != "owner":
        flash("Owner account required.", "warning")
        return redirect(url_for("index"))

    towns = get_towns()
    if request.method == "POST":
        title      = request.form.get("title","").strip()
        location   = request.form.get("new_town","").strip().title() or request.form.get("location","")
        house_type = request.form.get("house_type","")
        if house_type == "Other":
            house_type = request.form.get("custom_type","Other").strip().title()
        rent       = float(request.form.get("rent", 0) or 0)
        phone      = request.form.get("phone","").strip()
        desc       = request.form.get("description","").strip()
        plan       = request.form.get("plan","free")
        errors     = []

        if not title:             errors.append("Title is required.")
        if not phone:             errors.append("Phone is required.")
        elif not validate_phone(phone): errors.append("Enter a valid Kenyan mobile number.")
        if rent <= 0:             errors.append("Enter a valid rent amount.")

        with get_db() as conn:
            count = conn.execute("SELECT COUNT(*) FROM vacancies WHERE owner=?",
                                 (session["username"],)).fetchone()[0]
        if count >= MAX_LISTINGS:
            errors.append(f"Maximum of {MAX_LISTINGS} listings reached.")

        # Amenities
        amenities = {}
        for am in AMENITY_OPTIONS:
            if request.form.get(f"am_{am}"):
                fp  = request.form.get(f"am_fp_{am}", "Free")
                amt = request.form.get(f"am_amt_{am}", "").strip()
                amenities[am] = f"Paid — {amt}" if fp == "Paid" and amt else ("Paid" if fp == "Paid" else "Free ✓")

        # Image upload
        image_ref = ""
        img_file  = request.files.get("image")
        if img_file and img_file.filename:
            if img_file.content_length and img_file.content_length > MAX_IMAGE_BYTES:
                errors.append("Image too large (max 10MB).")
            else:
                fname     = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{secure_filename(img_file.filename)}"
                img_file.save(os.path.join(UPLOAD_FOLDER, fname))
                image_ref = fname

        if errors:
            for e in errors: flash(e, "danger")
            return render_template("post_listing.html", towns=towns)

        plan_cfg   = PLANS.get(plan, PLANS["free"])
        expires_at = (datetime.now() + timedelta(days=LISTING_EXPIRY_DAYS)).isoformat()

        with get_db() as conn:
            cur = conn.execute("""
                INSERT INTO vacancies
                (title,location,house_type,rent,phone,description,image,featured,
                 boost,plan,amenities,owner,expires_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (title, location, house_type, rent, phone, desc, image_ref,
                  plan_cfg["featured"], plan_cfg["boost"], plan,
                  json.dumps(amenities), session["username"], expires_at))
            conn.commit()
            new_id = cur.lastrowid

        if location and location not in DEFAULT_TOWNS:
            with get_db() as conn:
                conn.execute("INSERT OR IGNORE INTO towns (name) VALUES (?)", (location,))
                conn.commit()

        flash("✅ Vacancy posted successfully!", "success")
        return redirect(url_for("listing_detail", vid=new_id))

    return render_template("post_listing.html", towns=towns)

@app.route("/my-listings")
@login_required
def my_listings():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM vacancies WHERE owner=? ORDER BY id DESC",
                            (session["username"],)).fetchall()
    listings = []
    for r in rows:
        lst = dict(r)
        try: lst["amenities_data"] = json.loads(lst.get("amenities") or "{}")
        except: lst["amenities_data"] = {}
        listings.append(lst)
    return render_template("my_listings.html", listings=listings)

@app.route("/delete/<int:vid>", methods=["POST"])
@login_required
def delete_listing(vid):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM vacancies WHERE id=?", (vid,)).fetchone()
    if row and (session["username"] == row["owner"] or session.get("role") == "admin"):
        if row["image"] and not row["image"].startswith("http"):
            try: os.remove(os.path.join(UPLOAD_FOLDER, row["image"]))
            except: pass
        with get_db() as conn:
            conn.execute("DELETE FROM vacancies WHERE id=?", (vid,))
            conn.commit()
        flash("Listing deleted.", "success")
    return redirect(request.referrer or url_for("my_listings"))

@app.route("/report/<int:vid>", methods=["POST"])
def report_listing(vid):
    visitor_id = session.get("visitor_id", str(uuid.uuid4()))
    session["visitor_id"] = visitor_id
    try:
        with get_db() as conn:
            conn.execute("INSERT OR IGNORE INTO listing_reports (visitor_id,listing_id) VALUES (?,?)",
                         (visitor_id, vid))
            conn.execute("UPDATE vacancies SET reports=reports+1 WHERE id=?", (vid,))
            conn.commit()
        flash("Listing reported.", "info")
    except Exception:
        flash("Could not report listing.", "danger")
    return redirect(request.referrer or url_for("index"))

@app.route("/admin")
@login_required
@admin_required
def dashboard():
    with get_db() as conn:
        total_listings = conn.execute("SELECT COUNT(*) FROM vacancies").fetchone()[0]
        featured_count = conn.execute("SELECT COUNT(*) FROM vacancies WHERE featured=1").fetchone()[0]
        hidden_count   = conn.execute("SELECT COUNT(*) FROM vacancies WHERE reports>=3").fetchone()[0]
        total_visits   = conn.execute("SELECT COUNT(*) FROM visits").fetchone()[0]
        unique_visitors= conn.execute("SELECT COUNT(DISTINCT visitor_id) FROM visits").fetchone()[0]
        all_listings   = conn.execute("SELECT * FROM vacancies ORDER BY id DESC LIMIT 100").fetchall()
        all_users      = conn.execute("SELECT * FROM users WHERE role='owner' ORDER BY id DESC").fetchall()
    return render_template("admin.html",
        total_listings=total_listings, featured_count=featured_count,
        hidden_count=hidden_count, total_visits=total_visits,
        unique_visitors=unique_visitors,
        listings=[dict(r) for r in all_listings],
        users=[dict(u) for u in all_users])

@app.route("/admin/feature/<int:vid>", methods=["POST"])
@login_required
@admin_required
def admin_feature(vid):
    with get_db() as conn:
        row  = conn.execute("SELECT featured FROM vacancies WHERE id=?", (vid,)).fetchone()
        new_val = 0 if (row and row["featured"]) else 1
        conn.execute("UPDATE vacancies SET featured=? WHERE id=?", (new_val, vid))
        conn.commit()
    return redirect(url_for("dashboard"))

@app.route("/admin/delete/<int:vid>", methods=["POST"])
@login_required
@admin_required
def admin_delete(vid):
    with get_db() as conn:
        conn.execute("DELETE FROM vacancies WHERE id=?", (vid,))
        conn.commit()
    flash("Deleted.", "success")
    return redirect(url_for("dashboard"))

@app.route("/admin/block/<username>", methods=["POST"])
@login_required
@admin_required
def admin_block_user(username):
    action = request.form.get("action","block")
    status = "blocked" if action == "block" else "active"
    with get_db() as conn:
        conn.execute("UPDATE users SET status=? WHERE username=?", (status, username))
        conn.commit()
    flash(f"User {username} {status}.", "success")
    return redirect(url_for("dashboard"))

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
