"""
src/auth.py
============
Login screen shown before the main dashboard.

IMPORTANT: this is a UI placeholder, not a real authentication system —
see the "Security Notes" section in README.md. Credentials come from
config.py, which in turn reads them from environment variables so at
least the plaintext default doesn't have to live in source control.
"""

import tkinter as tk
from tkinter import messagebox

from config import DEMO_USERNAME, DEMO_PASSWORD, WINDOW_TITLE


def login_screen(on_success):
    """Show a blocking login window; call on_success() once credentials match."""
    login = tk.Tk()
    login.title(f"Login - {WINDOW_TITLE}")
    login.geometry("300x200")

    tk.Label(login, text="Username").pack()
    user_entry = tk.Entry(login)
    user_entry.pack()

    tk.Label(login, text="Password").pack()
    pwd_entry = tk.Entry(login, show="*")
    pwd_entry.pack()

    def check():
        if user_entry.get() == DEMO_USERNAME and pwd_entry.get() == DEMO_PASSWORD:
            login.destroy()
            on_success()
        else:
            messagebox.showerror("Error", "Invalid Credentials")

    tk.Button(login, text="Login", command=check).pack(pady=10)
    login.bind("<Return>", lambda _event: check())
    login.mainloop()
