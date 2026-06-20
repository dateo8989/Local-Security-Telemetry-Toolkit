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
from cryptography.fernet import Fernet
import bcrypt


DB_NAME = "siem_core.db"
SALT_ROUNDS = 12

class Database:
    def __init__(self):
        self.conn = sqlite3.connect(DB_NAME)
        self.cur = self.conn.cursor()

    def create_tables(self):
        self.cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT UNIQUE,
                password TEXT,
                salt TEXT,
                role TEXT
            )
        """)

        self.cur.execute("""
            CREATE TABLE IF NOT EXISTS audit (
                ts TEXT,
                user TEXT,
                event TEXT
            )
        """)

        self.cur.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                session TEXT,
                user TEXT,
                ts TEXT
            )
        """)

        self.cur.execute("""
            CREATE TABLE IF NOT EXISTS keystrokes (
                ts TEXT,
                user TEXT,
                keystroke TEXT
            )
        """)

        self.cur.execute("""
            CREATE TABLE IF NOT EXISTS screenshots (
                ts TEXT,
                user TEXT,
                screenshot BLOB
            )
        """)

        self.cur.execute("""
            CREATE TABLE IF NOT EXISTS file_changes (
                ts TEXT,
                user TEXT,
                file_change TEXT
            )
        """)

        self.cur.execute("""
            CREATE TABLE IF NOT EXISTS network_activity (
                ts TEXT,
                user TEXT,
                network_activity TEXT
            )
        """)

        self.conn.commit()

    def register(self, username, password):
        salt = bcrypt.gensalt(SALT_ROUNDS)
        hashed_password = bcrypt.hashpw(password.encode(), salt)
        try:
            self.cur.execute("INSERT INTO users VALUES (?,?,?,?)", (username, hashed_password, salt, "operator"))
            self.conn.commit()
            return True
        except sqlite3.Error as e:
            print(f"Error registering user: {e}")
            return False

    def login(self, username, password):
        self.cur.execute("SELECT password, salt FROM users WHERE username=?", (username,))
        row = self.cur.fetchone()

        if not row:
            return False, None

        hashed_password, salt = row

        if not bcrypt.checkpw(password.encode(), hashed_password):
            return False, None

        session = str(uuid.uuid4())

        self.cur.execute("INSERT INTO sessions VALUES (?,?,?)", (session, username, str(datetime.utcnow())))

        self.cur.execute("INSERT INTO audit VALUES (?,?,?)", (str(datetime.utcnow()), username, "LOGIN"))

        self.conn.commit()

        return True, session


def salt():
    return uuid.uuid4().hex

def hashpw(pw, s):
    return bcrypt.hashpw(pw.encode(), s)

def on_press(key):
    db = Database()
    try:
        db.cur.execute("INSERT INTO keystrokes VALUES (?,?,?)", (str(datetime.utcnow()), STATE["user"], str(key)))
        db.conn.commit()
    except sqlite3.Error as e:
        print(f"Error logging keystroke: {e}")
    finally:
        db.conn.close()

def take_screenshot():
    screenshot = pyautogui.screenshot()
    db = Database()
    try:
        db.cur.execute("INSERT INTO screenshots VALUES (?,?,?)", (str(datetime.utcnow()), STATE["user"], screenshot))
        db.conn.commit()
    except sqlite3.Error as e:
        print(f"Error capturing screenshot: {e}")
    finally:
        db.conn.close()


def monitor_files():
    while True:
        for root, dirs, files in os.walk("/"):
            for file in files:
                db = Database()
                try:
                    db.cur.execute("INSERT INTO file_changes VALUES (?,?,?)", (str(datetime.utcnow()), STATE["user"], file))
                    db.conn.commit()
                except sqlite3.Error as e:
                    print(f"Error monitoring file: {e}")
                finally:
                    db.conn.close()
        time.sleep(60)


def monitor_network():
    while True:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("localhost", 12345))
        s.listen(1)
        conn, addr = s.accept()
        data = conn.recv(1024)
        db = Database()
        try:
            db.cur.execute("INSERT INTO network_activity VALUES (?,?,?)", (str(datetime.utcnow()), STATE["user"], data))
            db.conn.commit()
        except sqlite3.Error as e:
            print(f"Error monitoring network: {e}")
        finally:
            db.conn.close()
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
        db = Database()
        ok = db.register(self.u.get(), self.p.get())
        messagebox.showinfo("Register", "OK" if ok else "Fail")

    def do_login(self):
        db = Database()
        ok, session = db.login(self.u.get(), self.p.get())

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

def start_keylogger():
    listener = Listener(on_press=on_press)
    listener.start()

def start_screenshot():
    while True:
        take_screenshot()
        time.sleep(60)


if __name__ == "__main__":
    db = Database()
    db.create_tables()
    root = tk.Tk()
    Login(root)
    root.mainloop()
