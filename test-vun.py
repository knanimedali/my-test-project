import os
import subprocess
import pickle

# 1. Command Injection
user_input = input("Enter a command: ")  # User-controlled input
os.system("echo " + user_input)  # Vulnerable to command injection

# 2. Hardcoded Credentials
USERNAME = "admin"
PASSWORD = "123456"  # Weak and hardcoded password

# 3. Insecure Deserialization
class Malicious:
    def __reduce__(self):
        return (os.system, ("echo Hacked!",))

malicious_pickle = pickle.dumps(Malicious())  # Serializing a malicious object
pickle.loads(malicious_pickle)  # Insecure deserialization

# 4. SQL Injection
import sqlite3
conn = sqlite3.connect(":memory:")
cur = conn.cursor()
cur.execute("CREATE TABLE users (id INTEGER, name TEXT)")
user_input = input("Enter username: ")  # User input for SQL query
query = "SELECT * FROM users WHERE name = '" + user_input + "'"  # Vulnerable SQL query
cur.execute(query)  # SQL Injection possible

# 5. Path Traversal
filename = input("Enter filename: ")  # User-controlled filename
with open("/var/logs/" + filename, "r") as f:  # Vulnerable to path traversal
    print(f.read())

print("Vulnerable script executed!")
