
import os
import sqlite3
import uuid
from datetime import datetime, timezone

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash
)
from werkzeug.utils import secure_filename

from detector import parse_pcap


# --------------------------------------------------
# APPLICATION CONFIGURATION
# --------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DATA_DIR = os.path.join(BASE_DIR, "data")
UPLOAD_DIR = os.path.join(DATA_DIR, "uploads")
DATABASE = os.path.join(DATA_DIR, "nids.db")

ALLOWED_EXTENSIONS = {"pcap", "pcapng"}
MAX_FILE_SIZE = 20 * 1024 * 1024  # 20 MB

os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY",
    "development-key-change-before-deployment"
)

app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE


# --------------------------------------------------
# DATABASE CONNECTION
# --------------------------------------------------

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


# --------------------------------------------------
# DATABASE INITIALIZATION
# --------------------------------------------------

def init_db():
    conn = get_db()

    conn.executescript("""
        CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            analyzed_at TEXT NOT NULL,
            packet_count INTEGER DEFAULT 0,
            alert_count INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id INTEGER NOT NULL,
            timestamp TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            size INTEGER,
            tcp_flags TEXT,
            FOREIGN KEY (analysis_id)
                REFERENCES analyses(id)
                ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id INTEGER NOT NULL,
            severity TEXT,
            source_ip TEXT,
            rule TEXT,
            details TEXT,
            FOREIGN KEY (analysis_id)
                REFERENCES analyses(id)
                ON DELETE CASCADE
        );
    """)

    conn.commit()
    conn.close()


# --------------------------------------------------
# FILE VALIDATION
# --------------------------------------------------

def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower()
        in ALLOWED_EXTENSIONS
    )


# --------------------------------------------------
# DASHBOARD
# --------------------------------------------------

@app.route("/")
def index():
    conn = get_db()

    total_analyses = conn.execute(
        "SELECT COUNT(*) FROM analyses"
    ).fetchone()[0]

    total_packets = conn.execute(
        "SELECT COUNT(*) FROM events"
    ).fetchone()[0]

    total_alerts = conn.execute(
        "SELECT COUNT(*) FROM alerts"
    ).fetchone()[0]

    protocol_counts = conn.execute("""
        SELECT protocol, COUNT(*) AS count
        FROM events
        GROUP BY protocol
        ORDER BY count DESC
    """).fetchall()

    recent_alerts = conn.execute("""
        SELECT alerts.*, analyses.filename
        FROM alerts
        JOIN analyses
        ON alerts.analysis_id = analyses.id
        ORDER BY alerts.id DESC
        LIMIT 10
    """).fetchall()

    analyses = conn.execute("""
        SELECT *
        FROM analyses
        ORDER BY id DESC
        LIMIT 10
    """).fetchall()

    conn.close()

    return render_template(
        "index.html",
        total_analyses=total_analyses,
        total_packets=total_packets,
        total_alerts=total_alerts,
        protocol_counts=protocol_counts,
        recent_alerts=recent_alerts,
        analyses=analyses
    )


# --------------------------------------------------
# PCAP FILE UPLOAD AND ANALYSIS
# --------------------------------------------------

@app.route("/upload", methods=["POST"])
def upload():
    uploaded_file = request.files.get("pcap_file")

    if not uploaded_file or uploaded_file.filename == "":
        flash("Please select a PCAP file.")
        return redirect(url_for("index"))

    if not allowed_file(uploaded_file.filename):
        flash("Only .pcap and .pcapng files are supported.")
        return redirect(url_for("index"))

    original_filename = secure_filename(uploaded_file.filename)

    if not original_filename:
        flash("Invalid filename.")
        return redirect(url_for("index"))

    unique_filename = f"{uuid.uuid4().hex}_{original_filename}"
    file_path = os.path.join(UPLOAD_DIR, unique_filename)

    try:
        uploaded_file.save(file_path)

        # Analyze the uploaded network capture.
        events, alerts = parse_pcap(file_path)

        conn = get_db()

        cursor = conn.execute("""
            INSERT INTO analyses (
                filename,
                analyzed_at,
                packet_count,
                alert_count
            )
            VALUES (?, ?, ?, ?)
        """, (
            original_filename,
            datetime.now(timezone.utc).isoformat(),
            len(events),
            len(alerts)
        ))

        analysis_id = cursor.lastrowid

        # Save packet events.
        for event in events:
            conn.execute("""
                INSERT INTO events (
                    analysis_id,
                    timestamp,
                    src_ip,
                    dst_ip,
                    protocol,
                    src_port,
                    dst_port,
                    size,
                    tcp_flags
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                analysis_id,
                event["timestamp"],
                event["src_ip"],
                event["dst_ip"],
                event["protocol"],
                event["src_port"],
                event["dst_port"],
                event["size"],
                event["tcp_flags"]
            ))

        # Save security alerts.
        for alert in alerts:
            conn.execute("""
                INSERT INTO alerts (
                    analysis_id,
                    severity,
                    source_ip,
                    rule,
                    details
                )
                VALUES (?, ?, ?, ?, ?)
            """, (
                analysis_id,
                alert["severity"],
                alert["source_ip"],
                alert["rule"],
                alert["details"]
            ))

        conn.commit()
        conn.close()

        flash(
            f"Analysis completed! "
            f"{len(events)} packets analyzed and "
            f"{len(alerts)} alerts detected."
        )

        return redirect(
            url_for("analysis_detail", analysis_id=analysis_id)
        )

    except Exception as error:
        flash(f"Analysis failed: {error}")
        return redirect(url_for("index"))

    finally:
        # Remove the uploaded capture after processing.
        if os.path.exists(file_path):
            os.remove(file_path)


# --------------------------------------------------
# ANALYSIS DETAILS
# --------------------------------------------------

@app.route("/analysis/<int:analysis_id>")
def analysis_detail(analysis_id):
    conn = get_db()

    analysis = conn.execute("""
        SELECT *
        FROM analyses
        WHERE id = ?
    """, (analysis_id,)).fetchone()

    if analysis is None:
        conn.close()
        flash("Analysis record not found.")
        return redirect(url_for("index"))

    events = conn.execute("""
        SELECT *
        FROM events
        WHERE analysis_id = ?
        ORDER BY id DESC
        LIMIT 200
    """, (analysis_id,)).fetchall()

    alerts = conn.execute("""
        SELECT *
        FROM alerts
        WHERE analysis_id = ?
        ORDER BY id DESC
    """, (analysis_id,)).fetchall()

    protocol_counts = conn.execute("""
        SELECT protocol, COUNT(*) AS count
        FROM events
        WHERE analysis_id = ?
        GROUP BY protocol
        ORDER BY count DESC
    """, (analysis_id,)).fetchall()

    conn.close()

    return render_template(
        "index.html",
        analysis=analysis,
        events=events,
        alerts=alerts,
        protocol_counts=protocol_counts,
        detail_view=True
    )


# --------------------------------------------------
# ERROR HANDLING
# --------------------------------------------------

@app.errorhandler(413)
def file_too_large(error):
    flash("File is too large. Maximum upload size is 20 MB.")
    return redirect(url_for("index"))


# --------------------------------------------------
# RUN APPLICATION
# --------------------------------------------------

if __name__ == "__main__":
    init_db()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
