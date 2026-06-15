import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
import hashlib
import uuid
import psutil
import time
import threading
from datetime import datetime



DB = "siem_core.db"

def db():
    return sqlite3.connect(DB)

def init():
    c = db()
    cur = c.cursor()

    cur.execute("""CREATE TABLE IF NOT EXISTS users(
        username TEXT UNIQUE,
        password TEXT,
        salt TEXT,
        role TEXT
    )""")

    cur.execute("""CREATE TABLE IF NOT EXISTS audit(
        ts TEXT,
        user TEXT,
        event TEXT
    )""")

    cur.execute("""CREATE TABLE IF NOT EXISTS sessions(
        session TEXT,
        user TEXT,
        ts TEXT
    )""")

    c.commit()
    c.close()



def salt():
    return uuid.uuid4().hex

def hashpw(pw, s):
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), s.encode(), 120000).hex()



def register(u, p):
    c = db()
    cur = c.cursor()

    s = salt()
    try:
        cur.execute("INSERT INTO users VALUES (?,?,?,?)",
                    (u, hashpw(p, s), s, "operator"))
        c.commit()
        return True
    except:
        return False
    finally:
        c.close()

def login(u, p):
    c = db()
    cur = c.cursor()

    cur.execute("SELECT password,salt FROM users WHERE username=?", (u,))
    row = cur.fetchone()

    if not row:
        return False, None

    pw, s = row

    if hashpw(p, s) != pw:
        return False, None

    session = str(uuid.uuid4())

    cur.execute("INSERT INTO sessions VALUES (?,?,?)",
                (session, u, str(datetime.utcnow())))

    cur.execute("INSERT INTO audit VALUES (?,?,?)",
                (str(datetime.utcnow()), u, "LOGIN"))

    c.commit()
    c.close()

    return True, session



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



if __name__ == "__main__":
    init()
    root = tk.Tk()
    Login(root)
    root.mainloop()
