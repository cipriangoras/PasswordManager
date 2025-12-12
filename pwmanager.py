import sqlite3
import os
import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

DB_NAME = "pwmanager.db"

def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row  
    return conn

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
    
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode('utf-8')


def run_phase_1_test():
    print("Faza 1: Vault Setup & Crypto Check")
    

    init_db()
    print("[OK] Am intitializat db ul.")
    
    # 
    master_pass = "SecretMaster123!"
    conn = get_db_connection()
    salt = get_or_create_salt(conn)
    key = derive_key(master_pass, salt)
    print(f"[OK] Cheie derivata din master password (Salt stocat: {salt.hex()})")
    
    website = "google.com"
    username = "user@gmail.com"
    plain_pass = "MySuperSecretPassword"
    
    enc_pass = encrypt_password(key, plain_pass)
    now = datetime.datetime.now().isoformat()
    
    cursor = conn.cursor()
    cursor.execute('''
        INSERT OR REPLACE INTO passwords (website, username, encrypted_password, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?)
    ''', (website, username, enc_pass, now, now))
    conn.commit()
    print(f"[OK] Intrare salvata criptata pentru {website}.")
    
    cursor.execute("SELECT encrypted_password FROM passwords WHERE website = ?", (website,))
    row = cursor.fetchone()
    
    if row:
        stored_enc_data = row['encrypted_password']
        decrypted_pass = decrypt_password(key, stored_enc_data)
        
        print(f"\nVerificare rezultat:")
        print(f"Original:  {plain_pass}")
        print(f"Decriptat: {decrypted_pass}")
        
        if plain_pass == decrypted_pass:
            print("\n[SUCCES] Criptarea si decriptarea functioneaza perfect!")
        else:
            print("\n[EROARE] Parolele nu se potrivesc!")
    
    conn.close()

if __name__ == "__main__":
    run_phase_1_test()