# vulnerable_app.py
import os
import pickle
from flask import Flask, request

app = Flask(__name__)

# 🚨 1. Command Injection
@app.route('/ping')
def ping():
    ip = request.args.get('ip')
    os.system(f"ping -c 1 {ip}")  # ⚠️ vulnérable à l'injection de commandes

# 🚨 2. Insecure Deserialization
@app.route('/load')
def load_data():
    data = request.args.get('data')
    obj = pickle.loads(bytes.fromhex(data))  # ⚠️ exécution de code arbitraire possible
    return str(obj)

# 🚨 3. Hardcoded Secret
API_KEY = "12345-SECRET-KEY"  # ⚠️ clé codée en dur

# 🚨 4. SQL Injection
import sqlite3
@app.route('/user')
def get_user():
    username = request.args.get('username')
    con = sqlite3.connect("users.db")
    cur = con.cursor()
    query = f"SELECT * FROM users WHERE username='{username}'"  # ⚠️ vulnérable à l'injection SQL
    cur.execute(query)
    return str(cur.fetchall())

if __name__ == "__main__":
    app.run(debug=True)
