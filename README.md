# file_integrity_checker.py
import os
import hashlib
import json
import getpass
import time
import smtplib
from datetime import datetime
from email.message import EmailMessage
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

DB_FILE = 'db.json'
FOLDER_FILE = 'folder.txt'
PASS_FILE = 'password.hash'
LOG_FILE = 'monitor.log'
ALERT_EMAIL = 'your_email@example.com'  # <-- Replace with your email
SMTP_SERVER = 'smtp.example.com'        # <-- Replace with your SMTP server
SMTP_PORT = 587
EMAIL_USER = 'your_email@example.com'   # <-- Replace with your email
EMAIL_PASS = 'your_password'            # <-- Replace with your email password (consider using environment vars)

def sha256sum(filepath):
    with open(filepath, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()

def log_event(message):
    with open(LOG_FILE, 'a') as log:
        log.write(f"[{datetime.now()}] {message}\n")

def send_email_alert(subject, body):
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = EMAIL_USER
    msg['To'] = ALERT_EMAIL
    msg.set_content(body)

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASS)
        server.send_message(msg)

def password_exists():
    return os.path.exists(PASS_FILE)

def save_password_hash(password):
    hash_val = hashlib.sha256(password.encode()).hexdigest()
    with open(PASS_FILE, 'w') as f:
        f.write(hash_val)

def verify_password(input_pass):
    if not os.path.exists(PASS_FILE):
        return False
    with open(PASS_FILE, 'r') as f:
        stored_hash = f.read().strip()
    return stored_hash == hashlib.sha256(input_pass.encode()).hexdigest()

def save_folder(folder):
    with open(FOLDER_FILE, 'w') as f:
        f.write(folder)

def load_folder():
    with open(FOLDER_FILE, 'r') as f:
        return f.read().strip()

def scan_folder(folder):
    db = {}
    for filename in os.listdir(folder):
        path = os.path.join(folder, filename)
        if os.path.isfile(path):
            db[path] = sha256sum(path)
    return db

def load_db():
    if not os.path.exists(DB_FILE):
        return {}
    with open(DB_FILE, 'r') as f:
        return json.load(f)

def save_db(db):
    with open(DB_FILE, 'w') as f:
        json.dump(db, f, indent=2)

def initialize_monitoring(folder):
    save_folder(folder)
    db = scan_folder(folder)
    save_db(db)
    print(f"Initial database created for folder: {folder}")

class FileChangeHandler(FileSystemEventHandler):
    def on_any_event(self, event):
        folder = load_folder()
        old_db = load_db()
        new_db = scan_folder(folder)

        for path, new_hash in new_db.items():
            old_hash = old_db.get(path)
            if old_hash is None:
                msg = f"New file detected: {path}"
                print(msg)
                log_event(msg)
                send_email_alert("File Added", msg)
            elif old_hash != new_hash:
                msg = f"Modified file: {path}"
                print(msg)
                log_event(msg)
                send_email_alert("File Modified", msg)

        for path in old_db:
            if path not in new_db:
                msg = f"Deleted file: {path}"
                print(msg)
                log_event(msg)
                send_email_alert("File Deleted", msg)

        save_db(new_db)

def main():
    if not password_exists():
        passwd = getpass.getpass("Set a new password: ")
        save_password_hash(passwd)
        folder = input("Enter directory to monitor: ").strip()
        initialize_monitoring(folder)
    else:
        folder = load_folder()
        print(f"Monitoring folder: {folder}")
        yn = input("Do you want to change the folder? (y/n): ").strip().lower()
        if yn == 'y':
            folder = input("Enter new folder path: ").strip()
            initialize_monitoring(folder)

    event_handler = FileChangeHandler()
    observer = Observer()
    observer.schedule(event_handler, folder, recursive=False)
    observer.start()
    print("Started real-time monitoring. Press Ctrl+C to exit.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == '__main__':
    main()

