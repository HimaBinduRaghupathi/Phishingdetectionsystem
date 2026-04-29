from flask import Flask, render_template, request, redirect, session, url_for
import os
import sys

# FIX: Set temporary directory to D: drive due to C: drive being full
temp_dir = r"D:\PhishingTemp"
if not os.path.exists(temp_dir):
    try:
        os.makedirs(temp_dir)
    except:
        pass
os.environ['TEMP'] = temp_dir
os.environ['TMP'] = temp_dir

import sqlite3
import pandas as pd
from datetime import datetime
import joblib

# Add parent directory to path to import from model folder
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from model.feature_extraction import extract_features

app = Flask(__name__, template_folder="../frontend", static_folder="../frontend", static_url_path="")
app.secret_key = "secretkey"

# Load Model
try:
    model_path = os.path.join(os.path.dirname(__file__), '../model/phishing_model.pkl')
    print(f"Attempting to load model from: {model_path}")
    print(f"Model file exists: {os.path.exists(model_path)}")
    model = joblib.load(model_path)
    print("Model loaded successfully.")
except Exception as e:
    print(f"Error loading model: {e}")
    import traceback
    traceback.print_exc()
    model = None

# ---------------- DATABASE CREATE ----------------

def get_db_connection():
    db_path = os.path.join(os.path.dirname(__file__), "database.db")
    conn = sqlite3.connect(db_path, timeout=10.0)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # USERS TABLE
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        role TEXT NOT NULL
    )
    """)

    # LOGS TABLE
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        url TEXT NOT NULL,
        prediction TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    """)

    conn.commit()
    conn.close()

init_db()


# classification helper (can be imported from other modules/tests)
def classify_url(url):
    if model is None:
        return "Error: Model not loaded", None
    features = extract_features(url)
    if features.get('homograph', 0) or features.get('digit_in_domain', 0):
        return "Phishing (rule match)", None
    features_df = pd.DataFrame([features])
    pred = model.predict(features_df)[0]
    proba = model.predict_proba(features_df)[0]
    prediction = "Phishing" if pred == 1 else "Legitimate"
    # pred may be numpy.float64; cast to int for indexing
    probability = round(proba[int(pred)] * 100, 2)
    return prediction, probability

# ---------------- HOME ----------------

@app.route("/")
def home():
    return render_template("login.html")

# ---------------- REGISTER ----------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        role = request.form["role"]

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            cursor.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                (username, password, role)
            )
            conn.commit()
        except sqlite3.IntegrityError:
            return "Username already exists"
        finally:
            conn.close()

        return redirect("/")

    return render_template("register.html")

# ---------------- LOGIN ----------------

@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM users WHERE username=? AND password=?",
        (username, password)
    )

    user = cursor.fetchone()
    conn.close()

    if user:
        session["user_id"] = user[0]
        session["username"] = user[1]
        session["role"] = user[3]

        if user[3] == "admin":
            return redirect("/admin")
        else:
            return redirect("/dashboard")
    else:
        return "Invalid Login"

# ---------------- USER DASHBOARD ----------------

@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "user_id" not in session:
        return redirect("/")

    # helper function for classifying a single URL (model + simple rule)
    def classify_url(url):
        if model is None:
            return "Error: Model not loaded", None
        features = extract_features(url)
        # apply rule based on suspicious patterns before ML prediction
        if features.get('homograph', 0) or features.get('digit_in_domain', 0):
            return "Phishing (rule match)", None
        # otherwise use ML
        features_df = pd.DataFrame([features])
        pred = model.predict(features_df)[0]
        proba = model.predict_proba(features_df)[0]
        prediction = "Phishing" if pred == 1 else "Legitimate"
        probability = round(proba[pred] * 100, 2)
        return prediction, probability

    prediction = None
    probability = None
    if request.method == "POST":
        # Handle form submission from user_dashboard.html
        url = request.form.get("url")
        if url:
            prediction, probability = classify_url(url)

            # Log to DB
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO logs (user_id, url, prediction, timestamp) VALUES (?, ?, ?, ?)",
                (session["user_id"], url, prediction, datetime.now())
            )
            conn.commit()
            conn.close()

    # Fetch recent logs
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT url, prediction, timestamp FROM logs WHERE user_id=? ORDER BY id DESC LIMIT 5", (session["user_id"],))
    recent_logs = cursor.fetchall()
    conn.close()

    return render_template("user_dashboard.html", username=session.get("username"), result=prediction, probability=probability, recent_logs=recent_logs)

# ---------------- BULK UPLOAD ----------------

@app.route("/upload", methods=["GET", "POST"])
def upload():
    if "user_id" not in session:
        return redirect("/")
    
    if session.get("role") != "admin":
        return redirect("/dashboard")

    results = None

    if request.method == "POST":
        if "file" not in request.files:
            return redirect(request.url)
        
        file = request.files["file"]
        
        if file.filename == "":
            return redirect(request.url)

        if file:
            try:
                # Read CSV
                df = pd.read_csv(file)
                
                if "url" not in df.columns:
                    # Try to see if it has 'URL' or just take the first column
                    if "URL" in df.columns:
                        df.rename(columns={"URL": "url"}, inplace=True)
                    else:
                        df.rename(columns={df.columns[0]: "url"}, inplace=True)

                processed_results = []
                
                conn = get_db_connection()
                cursor = conn.cursor()

                for index, row in df.iterrows():
                    url = row['url']
                    try:
                        # reuse classification helper for each row
                        prediction, _ = classify_url(url)
                        
                        processed_results.append({'url': url, 'prediction': prediction})

                        # Optional: Log to DB (might be slow for large files, keeping it for now)
                        cursor.execute(
                            "INSERT INTO logs (user_id, url, prediction, timestamp) VALUES (?, ?, ?, ?)",
                            (session["user_id"], url, prediction, datetime.now())
                        )
                    except Exception as e:
                        processed_results.append({'url': url, 'prediction': f"Error: {str(e)}"})

                conn.commit()
                conn.close()
                
                results = processed_results

            except Exception as e:
                print(f"Error processing file: {e}")
                
    return render_template("upload.html", results=results)

# ... (predict route remains same if needed for API, but form uses POST to /dashboard now as per user edit) ...

# ---------------- ADMIN PANEL ----------------

@app.route("/admin", methods=["GET", "POST"])
def admin():
    if "role" not in session or session["role"] != "admin":
        return redirect("/")
        
    conn = get_db_connection()
    cursor = conn.cursor()

    prediction = None
    if request.method == "POST":
        url = request.form.get("url")
        if url:
            prediction, _ = classify_url(url)

            # Log to DB
            cursor.execute(
                "INSERT INTO logs (user_id, url, prediction, timestamp) VALUES (?, ?, ?, ?)",
                (session["user_id"], url, prediction, datetime.now())
            )
            conn.commit()
    cursor.execute("SELECT COUNT(*) FROM users")
    total_users = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM logs")
    total_logs = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM logs WHERE prediction='Phishing'")
    phishing_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM logs WHERE prediction='Legitimate'")
    legitimate_count = cursor.fetchone()[0]

    conn.close()

    return render_template("admin_dashboard.html",
                           username=session.get("username"),
                           total_users=total_users,
                           total_logs=total_logs,
                           phishing_count=phishing_count,
                           legitimate_count=legitimate_count,
                           result=prediction)

# ---------------- LOGOUT ----------------

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    app.run(debug=True)
