from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import sqlite3
import os
from datetime import datetime
from functools import wraps

app = Flask(__name__)
import dotenv
dotenv.load_dotenv()
import hashlib

app.secret_key = os.getenv('SECRET_KEY')
DB = os.getenv('DB_NAME', 'database.db')
ADMIN_ACTION_PASSWORD = os.getenv('ADMIN_ACTION_PASSWORD')

# Database Initialization
def init_db():
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            email TEXT,
            coins INTEGER DEFAULT 0,
            ref_by TEXT,
            ip TEXT,
            verify_code TEXT,
            banned INTEGER DEFAULT 0,
            subscribed INTEGER DEFAULT 0,
            subscription_code TEXT
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS videos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT,
            filename TEXT,
            owner TEXT,
            approved INTEGER DEFAULT 0
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS views (
            user TEXT,
            video_id INTEGER,
            timestamp TEXT
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS redeems (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            coins_used INTEGER,
            status TEXT,
            date TEXT
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS subscription_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            code TEXT,
            status TEXT DEFAULT 'pending',
            request_date TEXT
        )''')
        conn.commit()

# Initialize DB once
init_db()

# Decorators
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            flash("Please login first.")
            return redirect(url_for('login'))
        with sqlite3.connect(DB) as conn:
            c = conn.cursor()
            c.execute("SELECT banned FROM users WHERE username=?", (session['user'],))
            banned = c.fetchone()
            if banned and banned[0] == 1:
                flash("You are banned by admin.")
                session.clear()
                return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'admin_user' not in session:
            flash("Please login as admin.")
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated

# User Routes
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        uname = request.form['username']
        pwd = request.form['password']
        email = request.form['email']
        ref = request.form.get('ref')
        ip = request.remote_addr
        with sqlite3.connect(DB) as conn:
            c = conn.cursor()
            try:
                c.execute("INSERT INTO users (username, password, email, ref_by, ip) VALUES (?, ?, ?, ?, ?)",
                          (uname, pwd, email, ref, ip))
                if ref:
                    c.execute("UPDATE users SET coins = coins + 100 WHERE username=?", (ref,))
                conn.commit()
                flash("Signup successful! Please login.")
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                flash("Username already exists")
                return redirect(url_for('signup'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        uname = request.form['username']
        pwd = request.form['password']
        with sqlite3.connect(DB) as conn:
            c = conn.cursor()
            c.execute("SELECT * FROM users WHERE username=? AND password=?", (uname, pwd))
            user = c.fetchone()
            if user:
                if user[8] == 1:  # banned
                    flash("You are banned. Contact admin.")
                    return redirect(url_for('login'))
                session['user'] = uname
                return redirect(url_for('index'))
            else:
                flash("Invalid login credentials")
                return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully.")
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM videos WHERE approved=1")
        videos = c.fetchall()
    return render_template('index.html', videos=videos, user=session['user'])

@app.route('/submit_subscription_code', methods=['GET', 'POST'])
@login_required
def submit_subscription_code():
    if request.method == 'POST':
        code = request.form['code']
        username = session['user']
        with sqlite3.connect(DB) as conn:
            c = conn.cursor()
            c.execute("INSERT INTO subscription_requests (username, code, request_date) VALUES (?, ?, ?)",
                      (username, code, datetime.now().isoformat()))
            c.execute("UPDATE users SET subscription_code=? WHERE username=?", (code, username))
            conn.commit()
        flash("Subscription code submitted. Please wait for admin approval.")
        return redirect(url_for('index'))
    return render_template('submit_subscription_code.html')

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute("SELECT subscribed FROM users WHERE username=?", (session['user'],))
        subscribed = c.fetchone()[0]
    if not subscribed:
        flash("You must be subscribed to upload videos.")
        return redirect(url_for('index'))

    if request.method == 'POST':
        if 'video' not in request.files:
            flash("No video file selected.")
            return redirect(request.url)
        f = request.files['video']
        if f.filename == '':
            flash("No selected file.")
            return redirect(request.url)

        title = request.form['title']
        fname = f.filename
        save_path = os.path.join('static', fname)
        f.save(save_path)
        with sqlite3.connect(DB) as conn:
            c = conn.cursor()
            c.execute("INSERT INTO videos (title, filename, owner) VALUES (?, ?, ?)",
                      (title, fname, session['user']))
            conn.commit()
        flash("Video uploaded, pending admin approval.")
        return redirect(url_for('upload'))
    return render_template('upload.html')

@app.route('/watch/<int:vid>')
@login_required
def watch(vid):
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute("SELECT filename, title FROM videos WHERE id=? AND approved=1", (vid,))
        video = c.fetchone()
        if not video:
            flash("Video not found or not approved.")
            return redirect(url_for('index'))
    return render_template('watch.html', video=video, vid=vid)

@app.route('/ad_click/<int:vid>', methods=['POST'])
@login_required
def ad_click(vid):
    uname = session['user']
    now = datetime.now().isoformat()
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM views WHERE user=? AND video_id=?", (uname, vid))
        already = c.fetchone()
        if not already:
            c.execute("INSERT INTO views (user, video_id, timestamp) VALUES (?, ?, ?)", (uname, vid, now))
            c.execute("SELECT owner FROM videos WHERE id=?", (vid,))
            owner = c.fetchone()[0]
            if owner == 'admin':
                c.execute("UPDATE users SET coins = coins + 50 WHERE username=?", (uname,))
            else:
                c.execute("UPDATE users SET coins = coins + 25 WHERE username=?", (owner,))
            conn.commit()
            return jsonify({"success": True, "message": "Coins added."})
        else:
            return jsonify({"success": False, "message": "Already clicked."})

@app.route('/wallet')
@login_required
def wallet():
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute("SELECT coins FROM users WHERE username=?", (session['user'],))
        coins = c.fetchone()[0]
    return render_template('wallet.html', coins=coins)

@app.route('/redeem', methods=['GET', 'POST'])
@login_required
def redeem():
    if request.method == 'POST':
        coins_to_use = int(request.form.get('coins_to_use', '1000'))
        with sqlite3.connect(DB) as conn:
            c = conn.cursor()
            c.execute("SELECT coins FROM users WHERE username=?", (session['user'],))
            coins = c.fetchone()[0]
            if coins < coins_to_use:
                flash("Not enough coins to redeem.")
                return redirect(url_for('redeem'))
            c.execute("INSERT INTO redeems (username, coins_used, status, date) VALUES (?, ?, ?, ?)",
                      (session['user'], coins_to_use, 'pending', datetime.now().isoformat()))
            c.execute("UPDATE users SET coins = coins - ? WHERE username=?", (coins_to_use, session['user']))
            conn.commit()
        flash("Redeem requested successfully!")
        return redirect(url_for('redeem'))
    return render_template('redeem.html')

# Admin Routes
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        uname = request.form['username']
        pwd = request.form['password']
        with sqlite3.connect(DB) as conn:
            c = conn.cursor()
            c.execute("SELECT * FROM admins WHERE username=? AND password=?", (uname, pwd))
            admin = c.fetchone()
            if admin:
                session['admin_user'] = uname
                flash("Admin login successful.")
                return redirect(url_for('admin_dashboard'))
            else:
                flash("Invalid admin credentials.")
                return redirect(url_for('admin_login'))
    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_user', None)
    flash("Admin logged out.")
    return redirect(url_for('admin_login'))

@app.route('/admin')
@admin_login_required
def admin_dashboard():
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM redeems")
        redeems = c.fetchall()
        c.execute("SELECT * FROM videos WHERE approved=0")
        videos = c.fetchall()
        c.execute("SELECT username, banned, subscribed FROM users")
        users = c.fetchall()
        c.execute("SELECT * FROM subscription_requests WHERE status='pending'")
        subs = c.fetchall()
    return render_template('admin.html', redeems=redeems, videos=videos, users=users, subs=subs)

def admin_action_auth():
    pw = request.form.get('admin_password')
    if pw != ADMIN_ACTION_PASSWORD:
        flash("Invalid admin action password!")
        return False
    return True

@app.route('/admin/approve_video/<int:vid>', methods=['POST'])
@admin_login_required
def approve_video(vid):
    if not admin_action_auth():
        return redirect(url_for('admin_dashboard'))
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute("UPDATE videos SET approved=1 WHERE id=?", (vid,))
        conn.commit()
    flash("Video approved.")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/reject_video/<int:vid>', methods=['POST'])
@admin_login_required
def reject_video(vid):
    if not admin_action_auth():
        return redirect(url_for('admin_dashboard'))
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute("DELETE FROM videos WHERE id=?", (vid,))
        conn.commit()
    flash("Video rejected and deleted.")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/ban_user/<username>', methods=['POST'])
@admin_login_required
def ban_user(username):
    if not admin_action_auth():
        return redirect(url_for('admin_dashboard'))
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute("UPDATE users SET banned=1 WHERE username=?", (username,))
        conn.commit()
    flash(f"User {username} banned.")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/unban_user/<username>', methods=['POST'])
@admin_login_required
def unban_user(username):
    if not admin_action_auth():
        return redirect(url_for('admin_dashboard'))
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute("UPDATE users SET banned=0 WHERE username=?", (username,))
        conn.commit()
    flash(f"User {username} unbanned.")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/approve_subscription/<int:req_id>', methods=['POST'])
@admin_login_required
def approve_subscription(req_id):
    if not admin_action_auth():
        return redirect(url_for('admin_dashboard'))
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute("UPDATE subscription_requests SET status='approved' WHERE id=?", (req_id,))
        c.execute("SELECT username FROM subscription_requests WHERE id=?", (req_id,))
        username = c.fetchone()[0]
        c.execute("UPDATE users SET subscribed=1 WHERE username=?", (username,))
        conn.commit()
    flash("Subscription approved.")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/reject_subscription/<int:req_id>', methods=['POST'])
@admin_login_required
def reject_subscription(req_id):
    if not admin_action_auth():
        return redirect(url_for('admin_dashboard'))
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute("UPDATE subscription_requests SET status='rejected' WHERE id=?", (req_id,))
        conn.commit()
    flash("Subscription rejected.")
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    app.run(debug=True)



@app.route('/api/reward', methods=['POST'])
def reward_user():
    if 'username' not in session:
        return jsonify({'status': 'unauthorized'}), 401

    video_id = request.form.get('video_id')
    if not video_id:
        return jsonify({'status': 'error', 'message': 'Missing video ID'}), 400

    username = session['username']
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        # Prevent multiple rewards for same video by same user
        c.execute("SELECT * FROM views WHERE user = ? AND video_id = ?", (username, video_id))
        if c.fetchone():
            return jsonify({'status': 'already_rewarded'})

        # Log the view
        c.execute("INSERT INTO views (user, video_id, timestamp) VALUES (?, ?, ?)", 
                  (username, video_id, datetime.utcnow().isoformat()))
        # Reward coins
        c.execute("UPDATE users SET coins = coins + 5 WHERE username = ?", (username,))
        conn.commit()
    return jsonify({'status': 'success', 'coins_added': 5})
