from tkinter import *
from tkinter import ttk
from tkinter import filedialog
from ast import literal_eval
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

with open('password manager.pyw', encoding='utf-8') as f:
    exec(f.read())
