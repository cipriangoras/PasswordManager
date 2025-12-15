import sqlite3
import os
import sys
import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

DB_NAME = "pwmanager.db"
CANARY_KEY_NAME = "canary_check"
CANARY_VALUE = "valid_master_key"

def get_db_connection():
    try:
        conn = sqlite3.connect(DB_NAME)
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.Error as e:
        print(f"Database Error: {e}")
        sys.exit(1)

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS passwords (
            website TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            encrypted_password BLOB NOT NULL,
            created_at TEXT,
            updated_at TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vault_config (
            key TEXT PRIMARY KEY,
            value BLOB
        )
    ''')
    conn.commit()
    conn.close()

def get_or_create_salt(conn):
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM vault_config WHERE key = 'salt'")
    row = cursor.fetchone()
    if row:
        return row['value']
    else:
        new_salt = os.urandom(16)
        cursor.execute("INSERT INTO vault_config (key, value) VALUES (?, ?)", ('salt', new_salt))
        conn.commit()
        return new_salt

def derive_key(master_password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(master_password.encode('utf-8'))

def encrypt_password(key, plaintext_password):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext_password.encode('utf-8'), None)
    return nonce + ciphertext

def decrypt_password(key, encrypted_data):
    aesgcm = AESGCM(key)
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    return aesgcm.decrypt(nonce, ciphertext, None).decode('utf-8')

def verify_master_password(conn, key):
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM vault_config WHERE key = ?", (CANARY_KEY_NAME,))
    row = cursor.fetchone()

    if row:
        try:
            decrypted = decrypt_password(key, row['value'])
            if decrypted == CANARY_VALUE:
                return True
        except InvalidTag:
            pass 
        return False
    else:
        encrypted_canary = encrypt_password(key, CANARY_VALUE)
        cursor.execute("INSERT INTO vault_config (key, value) VALUES (?, ?)", (CANARY_KEY_NAME, encrypted_canary))
        conn.commit()
        print("[+] First time setup: Vault initialized.")
        return True

def print_usage():
    print("\nPassword Manager CLI")
    print("-" * 30)
    print("Usage:")
    print("  Add/Update: python pwmanager.py <master> -add <site> <user> <pass>")
    print("  Retrieve:   python pwmanager.py <master> -get <site>")
    print("  Remove:     python pwmanager.py <master> -remove <site>")
    print("  List sites: python pwmanager.py <master> -list")
    print("-" * 30)

def handle_add(conn, key, website, username, password):
    cursor = conn.cursor()
    encrypted_pw = encrypt_password(key, password)
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    cursor.execute("SELECT website FROM passwords WHERE website = ?", (website,))
    exists = cursor.fetchone()
    
    if exists:
        cursor.execute('''
            UPDATE passwords 
            SET username=?, encrypted_password=?, updated_at=? 
            WHERE website=?
        ''', (username, encrypted_pw, now, website))
        print(f"[+] Successfully updated entry for: {website}")
    else:
        cursor.execute('''
            INSERT INTO passwords (website, username, encrypted_password, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
        ''', (website, username, encrypted_pw, now, now))
        print(f"[+] Successfully added entry for: {website}")
    conn.commit()

def handle_get(conn, key, website):
    cursor = conn.cursor()
    cursor.execute("SELECT username, encrypted_password, updated_at FROM passwords WHERE website = ?", (website,))
    row = cursor.fetchone()
    
    if row:
        try:
            decrypted_pass = decrypt_password(key, row['encrypted_password'])
            print(f"\n[+] Entry found for {website}:")
            print(f"    Username: {row['username']}")
            print(f"    Password: {decrypted_pass}")
            print(f"    Updated:  {row['updated_at']}\n")
        except InvalidTag:
            print("[!] Error: Data corruption detected or integrity check failed.")
    else:
        print(f"[-] No entry found for website: {website}")

def handle_remove(conn, website):
    cursor = conn.cursor()
    cursor.execute("DELETE FROM passwords WHERE website = ?", (website,))
    if cursor.rowcount > 0:
        conn.commit()
        print(f"[+] Successfully removed entry for: {website}")
    else:
        print(f"[-] No entry found to remove for: {website}")

def handle_list(conn):
    cursor = conn.cursor()
    cursor.execute("SELECT website, username FROM passwords ORDER BY website")
    rows = cursor.fetchall()
    
    if not rows:
        print("[-] Vault is empty.")
    else:
        print(f"\n{'WEBSITE':<25} | {'USERNAME'}")
        print("-" * 45)
        for row in rows:
            print(f"{row['website']:<25} | {row['username']}")
        print("")

def main():
    if len(sys.argv) < 3:
        print_usage()
        return

    master_password = sys.argv[1]
    command = sys.argv[2]
    
    init_db()
    
    try:
        conn = get_db_connection()
        salt = get_or_create_salt(conn)
        key = derive_key(master_password, salt)
        
        if not verify_master_password(conn, key):
            print("\n[!] ACCESS DENIED: Wrong master password.")
            sys.exit(1)
            
        if command == '-add':
            if len(sys.argv) != 6:
                print("Usage: -add <website> <username> <password>")
                return
            handle_add(conn, key, sys.argv[3], sys.argv[4], sys.argv[5])
            
        elif command == '-get':
            if len(sys.argv) != 4:
                print("Usage: -get <website>")
                return
            handle_get(conn, key, sys.argv[3])
            
        elif command == '-remove':
            if len(sys.argv) != 4:
                print("Usage: -remove <website>")
                return
            handle_remove(conn, sys.argv[3])
            
        elif command == '-list':
            handle_list(conn)
            
        else:
            print(f"[!] Unknown command: {command}")
            print_usage()
            
    except Exception as e:
        print(f"\n[!] Unexpected Error: {e}")
    finally:
        if 'conn' in locals():
            conn.close()

if __name__ == "__main__":
    main()