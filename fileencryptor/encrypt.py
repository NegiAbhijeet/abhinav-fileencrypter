import os
import json
import tkinter as tk
from tkinter import filedialog
from tkinter import ttk
import multiprocessing
from queue import Empty
# ssahj 
from Crypto.Cipher import AES, Blowfish, DES
from Crypto.Random import get_random_bytes
from cryptography.fernet import Fernet

KEY_STORE = "encryption_keys.json"

def load_key_store():
    if os.path.exists(KEY_STORE):
        with open(KEY_STORE, "r") as f:
            return json.load(f)
    return {}

def save_key_store(keys):
    with open(KEY_STORE, "w") as f:
        json.dump(keys, f, indent=4)

def encrypt_worker(file_path, algorithm, status_queue):
    try:
        with open(file_path, "rb") as f:
            data = f.read()

        orig_name = os.path.basename(file_path)
        key = None
        encrypted = None

        if algorithm == "AES":
            key = get_random_bytes(16)
            cipher = AES.new(key, AES.MODE_EAX)
            ciphertext, tag = cipher.encrypt_and_digest(data)
            encrypted = cipher.nonce + tag + ciphertext
            ext = ".aes"

        elif algorithm == "Fernet":
            key = Fernet.generate_key()
            fernet = Fernet(key)
            encrypted = fernet.encrypt(data)
            ext = ".fernet"

        elif algorithm == "Blowfish":
            key = get_random_bytes(16)
            cipher = Blowfish.new(key, Blowfish.MODE_EAX)
            ciphertext, tag = cipher.encrypt_and_digest(data)
            encrypted = cipher.nonce + tag + ciphertext
            ext = ".blowfish"

        elif algorithm == "DES":
            key = get_random_bytes(8)
            cipher = DES.new(key, DES.MODE_EAX)
            ciphertext, tag = cipher.encrypt_and_digest(data)
            encrypted = cipher.nonce + tag + ciphertext
            ext = ".des"

        else:
            status_queue.put(f"❌ Unsupported algorithm: {algorithm}")
            return

        new_path = file_path + ext
        with open(new_path, "wb") as f:
            f.write(encrypted)

        keys = load_key_store()
        keys[orig_name] = {"algorithm": algorithm, "key": key.hex() if isinstance(key, bytes) else key.decode()}
        save_key_store(keys)

        status_queue.put(f"✅ {orig_name} encrypted → {os.path.basename(new_path)}")
    except Exception as e:
        status_queue.put(f"❌ Error encrypting {file_path}: {e}")

def decrypt_worker(file_path, status_queue):
    try:
        base_name = os.path.basename(file_path)

        # Remove extension
        for ext in ['.aes', '.fernet', '.blowfish', '.des']:
            if base_name.endswith(ext):
                orig_name = base_name[:-len(ext)]
                break
        else:
            orig_name = base_name

        keys = load_key_store()
        if orig_name not in keys:
            status_queue.put(f"❌ No key found for {orig_name}")
            return

        entry = keys[orig_name]
        algorithm = entry['algorithm']
        key = bytes.fromhex(entry['key']) if algorithm != 'Fernet' else entry['key'].encode()

        with open(file_path, 'rb') as f:
            data = f.read()

        if algorithm == 'AES':
            nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
            cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
            decrypted = cipher.decrypt_and_verify(ciphertext, tag)

        elif algorithm == 'Fernet':
    		with open("fernet.key", "rb") as key_file:
        	key = key_file.read()
    		cipher = Fernet(key)
    		decrypted = cipher.decrypt(data)


        elif algorithm == 'Blowfish':
            nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
            cipher = Blowfish.new(key, Blowfish.MODE_EAX, nonce=nonce)
            decrypted = cipher.decrypt_and_verify(ciphertext, tag)

        elif algorithm == 'DES':
            nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
            cipher = DES.new(key, DES.MODE_EAX, nonce=nonce)
            decrypted = cipher.decrypt_and_verify(ciphertext, tag)

        else:
            status_queue.put(f"❌ Unsupported algorithm: {algorithm}")
            return

        orig_root, orig_ext = os.path.splitext(orig_name)
        decrypted_name = f"{orig_root}_decrypted{orig_ext}"
        decrypted_path = os.path.join(os.path.dirname(file_path), decrypted_name)

        with open(decrypted_path, 'wb') as f:
            f.write(decrypted)

        status_queue.put(f"✅ Decrypted: {base_name} → {decrypted_name}")
    except Exception as e:
        status_queue.put(f"❌ Error decrypting {file_path}: {e}")

class EncryptorApp:
    def __init__(self, root):
        self.root = root
        root.title("🔐 File Encryptor/Decryptor")

        self.algo_label = tk.Label(root, text="Select Algorithm:")
        self.algo_label.pack()

        self.algorithm = tk.StringVar()
        self.algorithm.set("AES")
        self.algo_menu = ttk.Combobox(root, textvariable=self.algorithm)
        self.algo_menu['values'] = ["AES", "Fernet", "Blowfish", "DES"]
        self.algo_menu.pack()

        self.encrypt_button = tk.Button(root, text="Encrypt Files", command=self.start_encryption)
        self.encrypt_button.pack(pady=5)

        self.decrypt_button = tk.Button(root, text="Decrypt Files", command=self.start_decryption)
        self.decrypt_button.pack(pady=5)

        self.status_text = tk.Text(root, height=10)
        self.status_text.pack(pady=10)

        self.status_queue = multiprocessing.Queue()
        self.root.after(100, self.update_status)

    def append_status(self, msg):
        self.status_text.insert(tk.END, msg + '\n')
        self.status_text.see(tk.END)

    def update_status(self):
        try:
            while True:
                msg = self.status_queue.get_nowait()
                self.append_status(msg)
        except Empty:
            pass
        self.root.after(100, self.update_status)

    def start_encryption(self):
        files = filedialog.askopenfilenames(title="Select files to encrypt")
        if not files:
            return
        algo = self.algorithm.get()
        for file_path in files:
            p = multiprocessing.Process(target=encrypt_worker, args=(file_path, algo, self.status_queue))
            p.start()

    def start_decryption(self):
        files = filedialog.askopenfilenames(title="Select encrypted files")
        if not files:
            return
        for file_path in files:
            p = multiprocessing.Process(target=decrypt_worker, args=(file_path, self.status_queue))
            p.start()

if __name__ == "__main__":
    multiprocessing.freeze_support()
    root = tk.Tk()
    app = EncryptorApp(root)
    root.mainloop()
