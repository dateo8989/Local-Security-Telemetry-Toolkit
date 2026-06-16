import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
import hashlib
import uuid
import psutil
import time
import threading
from datetime import datetime
import pyautogui
import pynput
from pynput.keyboard import Key, Listener
import os
import socket

DB_NAME = "siem_core.db"


def create_connection():
    return sqlite3.connect(DB_NAME)

def init_db():
    conn = create_connection()
    cur = conn.cursor()

    
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT UNIQUE,
            password TEXT,
            salt TEXT,
            role TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS audit (
            ts TEXT,
            user TEXT,
            event TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            session TEXT,
            user TEXT,
            ts TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS keystrokes (
            ts TEXT,
            user TEXT,
            keystroke TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS screenshots (
            ts TEXT,
            user TEXT,
            screenshot BLOB
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS file_changes (
            ts TEXT,
            user TEXT,
            file_change TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS network_activity (
            ts TEXT,
            user TEXT,
            network_activity TEXT
        )
    """)

    conn.commit()
    conn.close()


def salt():
    return uuid.uuid4().hex

def hashpw(pw, s):
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), s.encode(), 120000).hex()


def register(u, p):
    conn = create_connection()
    cur = conn.cursor()

    s = salt()
    try:
        cur.execute("INSERT INTO users VALUES (?,?,?,?)", (u, hashpw(p, s), s, "operator"))
        conn.commit()
        return True
    except sqlite3.Error as e:
        print(f"Error registering user: {e}")
        return False
    finally:
        conn.close()

def login(u, p):
    conn = create_connection()
    cur = conn.cursor()

    cur.execute("SELECT password, salt FROM users WHERE username=?", (u,))
    row = cur.fetchone()

    if not row:
        return False, None

    pw, s = row

    if hashpw(p, s) != pw:
        return False, None

    session = str(uuid.uuid4())

    cur.execute("INSERT INTO sessions VALUES (?,?,?)", (session, u, str(datetime.utcnow())))

    cur.execute("INSERT INTO audit VALUES (?,?,?)", (str(datetime.utcnow()), u, "LOGIN"))

    conn.commit()
    conn.close()

    return True, session

def on_press(key):
    conn = create_connection()
    cur = conn.cursor()

    try:
        cur.execute("INSERT INTO keystrokes VALUES (?,?,?)", (str(datetime.utcnow()), STATE["user"], str(key)))
        conn.commit()
    except sqlite3.Error as e:
        print(f"Error logging keystroke: {e}")
    finally:
        conn.close()


def take_screenshot():
    screenshot = pyautogui.screenshot()
    conn = create_connection()
    cur = conn.cursor()

    try:
        cur.execute("INSERT INTO screenshots VALUES (?,?,?)", (str(datetime.utcnow()), STATE["user"], screenshot))
        conn.commit()
    except sqlite3.Error as e:
        print(f"Error capturing screenshot: {e}")
    finally:
        conn.close()

def monitor_files():
    while True:
        for root, dirs, files in os.walk("/"):
            for file in files:
                conn = create_connection()
                cur = conn.cursor()

                try:
                    cur.execute("INSERT INTO file_changes VALUES (?,?,?)", (str(datetime.utcnow()), STATE["user"], file))
                    conn.commit()
                except sqlite3.Error as e:
                    print(f"Error monitoring file: {e}")
                finally:
                    conn.close()
        time.sleep(60)

def monitor_network():
    while True:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("localhost", 12345))
        s.listen(1)
        conn, addr = s.accept()
        data = conn.recv(1024)
        conn = create_connection()
        cur = conn.cursor()

        try:
            cur.execute("INSERT INTO network_activity VALUES (?,?,?)", (str(datetime.utcnow()), STATE["user"], data))
            conn.commit()
        except sqlite3.Error as e:
            print(f"Error monitoring network: {e}")
        finally:
            conn.close()
        conn.close()
        s.close()
        time.sleep(60)

class SIEMEngine:
    def __init__(self, user):
        self.user = user
        self.running = True
        self.events = []

    def score(self, cpu, ram):
        score = 0
        if cpu > 80:
            score += 40
        if ram > 80:
            score += 30
        if len(psutil.pids()) > 200:
            score += 20
        return min(score, 100)

    def run(self):
        while self.running:
            cpu = psutil.cpu_percent()
            ram = psutil.virtual_memory().percent

            event = {
                "ts": str(datetime.utcnow()),
                "user": self.user,
                "cpu": cpu,
                "ram": ram,
                "risk": self.score(cpu, ram)
            }

            self.events.append(event)
            time.sleep(2)

    def stop(self):
        self.running = False

STATE = {
    "user": None,
    "session": None,
    "engine": None
}

class Login:
    def __init__(self, root):
        self.root = root
        root.title("SIEM Gateway")

        tk.Label(root, text="User").pack()
        self.u = tk.Entry(root)
        self.u.pack()

        tk.Label(root, text="Pass").pack()
        self.p = tk.Entry(root, show="*")
        self.p.pack()

        tk.Button(root, text="Login", command=self.do_login).pack()
        tk.Button(root, text="Register", command=self.do_reg).pack()

    def do_reg(self):
        ok = register(self.u.get(), self.p.get())
        messagebox.showinfo("Register", "OK" if ok else "Fail")

    def do_login(self):
        ok, session = login(self.u.get(), self.p.get())

        if not ok:
            messagebox.showerror("Denied", "Invalid")
            return

        STATE["user"] = self.u.get()
        STATE["session"] = session

        self.root.destroy()
        dashboard()

def dashboard():
    root = tk.Tk()
    root.title("Mini SIEM Console")
    root.geometry("600x400")

    engine = SIEMEngine(STATE["user"])
    STATE["engine"] = engine

    threading.Thread(target=engine.run, daemon=True).start()
    threading.Thread(target=start_keylogger, daemon=True).start()
    threading.Thread(target=start_screenshot, daemon=True).start()
    threading.Thread(target=monitor_files, daemon=True).start()
    threading.Thread(target=monitor_network, daemon=True).start()

    cpu_label = tk.Label(root, text="CPU: --")
    cpu_label.pack()

    ram_label = tk.Label(root, text="RAM: --")
    ram_label.pack()

    risk = tk.Label(root, text="RISK: --")
    risk.pack()

    listbox = tk.Listbox(root, width=80)
    listbox.pack()

    def update():
        while True:
            cpu = psutil.cpu_percent()
            ram = psutil.virtual_memory().percent

            cpu_label.config(text=f"CPU: {cpu}%")
            ram_label.config(text=f"RAM: {ram}%")

            if engine.events:
                e = engine.events[-1]
                risk.config(text=f"RISK: {e['risk']}")

                listbox.insert(0, f"{e['ts']} | CPU {e['cpu']} RAM {e['ram']} RISK {e['risk']}")

            time.sleep(1)

    threading.Thread(target=update, daemon=True).start()

    root.mainloop()

# Boot function
if __name__ == "__main__":
    init_db()
    root = tk.Tk()
    Login(root)
    root.mainloop()
