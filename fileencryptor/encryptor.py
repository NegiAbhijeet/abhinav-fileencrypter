# import tkinter as tk
# from tkinter import filedialog, messagebox, ttk
# from Crypto.Cipher import AES
# from Crypto.Random import get_random_bytes
# from cryptography.fernet import Fernet
# import os
# import json
# import multiprocessing
# import subprocess
# import platform
# from datetime import datetime
# from Crypto.Cipher import ChaCha20, DES, Blowfish
# from Crypto.Util.Padding import pad, unpad
# import base64
# KEY_STORE_FILE = "encryption_keys.json"

# # AES
# def aes_encrypt(data):
#     key = get_random_bytes(16)
#     iv = get_random_bytes(16)
#     cipher = AES.new(key, AES.MODE_CBC, iv)
#     encrypted = cipher.encrypt(pad(data, AES.block_size))
#     return key + iv, iv + encrypted  # Save IV in front for decryption

# def aes_decrypt(data, key_iv):
#     key = key_iv[:16]
#     iv = data[:16]
#     cipher = AES.new(key, AES.MODE_CBC, iv)
#     return unpad(cipher.decrypt(data[16:]), AES.block_size)

# # DES
# def des_encrypt(data):
#     key = get_random_bytes(8)
#     cipher = DES.new(key, DES.MODE_ECB)
#     encrypted = cipher.encrypt(pad(data, DES.block_size))
#     return key, encrypted

# def des_decrypt(data, key):
#     cipher = DES.new(key, DES.MODE_ECB)
#     return unpad(cipher.decrypt(data), DES.block_size)

# # Blowfish
# def blowfish_encrypt(data):
#     key = get_random_bytes(16)
#     cipher = Blowfish.new(key, Blowfish.MODE_ECB)
#     encrypted = cipher.encrypt(pad(data, Blowfish.block_size))
#     return key, encrypted

# def blowfish_decrypt(data, key):
#     cipher = Blowfish.new(key, Blowfish.MODE_ECB)
#     return unpad(cipher.decrypt(data), Blowfish.block_size)

# # ChaCha20
# def chacha20_encrypt(data):
#     key = get_random_bytes(32)
#     nonce = get_random_bytes(8)
#     cipher = ChaCha20.new(key=key, nonce=nonce)
#     encrypted = cipher.encrypt(data)
#     return key + nonce, encrypted

# def chacha20_decrypt(data, key_nonce):
#     key = key_nonce[:32]
#     nonce = key_nonce[32:]
#     cipher = ChaCha20.new(key=key, nonce=nonce)
#     return cipher.decrypt(data)

# # Fernet
# def fernet_encrypt(data):
#     key = Fernet.generate_key()
#     cipher = Fernet(key)
#     encrypted = cipher.encrypt(data)
#     return key.decode(), encrypted

# def fernet_decrypt(data, key):
#     cipher = Fernet(key.encode())
#     return cipher.decrypt(data)

# # Available encryption algorithm implementations
# ALGORITHMS = {
#     'AES': {'encrypt': aes_encrypt, 'decrypt': aes_decrypt},
#     'DES': {'encrypt': des_encrypt, 'decrypt': des_decrypt},
#     'Blowfish': {'encrypt': blowfish_encrypt, 'decrypt': blowfish_decrypt},
#     'ChaCha20': {'encrypt': chacha20_encrypt, 'decrypt': chacha20_decrypt},
#     'Fernet': {'encrypt': fernet_encrypt, 'decrypt': fernet_decrypt}
# }


# def load_key_store():
#     if not os.path.exists(KEY_STORE_FILE):
#         return {}
#     with open(KEY_STORE_FILE, 'r') as f:
#         return json.load(f)


# def save_key_to_store(file_path, algorithm, key):
#     store = load_key_store()
#     base_name = os.path.basename(file_path)
#     if base_name in store:
#         return
#     store[base_name] = {
#         "algorithm": algorithm,
#         "key": key.hex() if isinstance(key, bytes) else key
#     }
#     with open(KEY_STORE_FILE, 'w') as f:
#         json.dump(store, f, indent=4)


# # ---------- ALGORITHM IMPLEMENTATIONS ----------



# # ---------- ENCRYPTION WORKER ----------

# def encrypt_worker(args):
#     file_path, algorithm = args
#     try:
#         with open(file_path, 'rb') as f:
#             data = f.read()

#         key, encrypted_data = ALGORITHMS[algorithm]['encrypt'](data)

#         ext = '.' + algorithm.lower()
#         out_file = file_path + ext
#         with open(out_file, 'wb') as f:
#             f.write(encrypted_data)

#         save_key_to_store(file_path, algorithm, key.hex() if isinstance(key, bytes) else key)
#         return f"✅ {os.path.basename(file_path)} encrypted → {os.path.basename(out_file)}"
#     except Exception as e:
#         return f"❌ {os.path.basename(file_path)} → Error: {str(e)}"

# import subprocess
# import platform

# def open_file(path):
#     if platform.system() == "Windows":
#         os.startfile(path)
#     elif platform.system() == "Darwin":  # macOS
#         subprocess.call(["open", path])
#     else:  # Linux
#         subprocess.call(["xdg-open", path])

# def decrypt_worker(file_path):
#     try:
#         base_name = os.path.basename(file_path)
#         file_root, enc_ext = os.path.splitext(base_name)
#         orig_base, orig_ext = os.path.splitext(file_root)
#         decrypted_name = f"{orig_base}_decrypted{orig_ext}"
#         decrypted_path = os.path.join(os.path.dirname(file_path), decrypted_name)

#         with open(file_path, 'rb') as f:
#             data = f.read()

#         keys = load_key_store()

#         if file_root not in keys:
#             return f"❌ No key found for {file_root}"

#         algorithm = keys[file_root]['algorithm']
#         key_hex = keys[file_root]['key']

#         key = bytes.fromhex(key_hex) if algorithm != 'Fernet' else key_hex

#         if algorithm in ['AES', 'ChaCha20']:
#             decrypted = ALGORITHMS[algorithm]['decrypt'](data, key)
#         else:
#             # Validate padding for DES/Blowfish
#             if algorithm == 'DES' and len(data) % 8 != 0:
#                 return f"❌ Data length not aligned for DES (8 bytes)"
#             if algorithm == 'Blowfish' and len(data) % 8 != 0:
#                 return f"❌ Data length not aligned for Blowfish (8 bytes)"
#             decrypted = ALGORITHMS[algorithm]['decrypt'](data, key)

#         with open(decrypted_path, 'wb') as f:
#             f.write(decrypted)

#         return f"✅ Decrypted: {base_name} → {decrypted_name}"

#     except Exception as e:
#         return f"❌ Error decrypting {file_path}: {str(e)}"
# class FileEncryptorApp:
#     def __init__(self, root):
#         self.root = root
#         self.root.title("🔐 Multi-Algorithm File Encryptor")
#         self.root.geometry("600x520")

#         self.selected_files = []

#         tk.Label(root, text="Select Encryption Algorithm:").pack(pady=5)
#         self.algo_var = tk.StringVar()
#         self.algo_dropdown = ttk.Combobox(
#             root, textvariable=self.algo_var, state='readonly')
#         self.algo_dropdown['values'] = list(ALGORITHMS.keys())
#         self.algo_dropdown.current(0)
#         self.algo_dropdown.pack(pady=5)

#         tk.Button(root, text="📁 Select Files", command=self.select_files).pack(pady=10)
#         tk.Button(root, text="🔒 Encrypt Files", command=self.start_encryption).pack(pady=10)
#         tk.Button(root, text="🔓 Decrypt Files", command=self.start_decryption).pack(pady=10)
#         tk.Button(root, text="🔑 View Saved Keys", command=self.show_keys).pack(pady=5)

#         self.status_text = tk.Text(root, height=15, width=70, state='disabled', bg="#f9f9f9")
#         self.status_text.pack(pady=10)

#     def select_files(self):
#         files = filedialog.askopenfilenames(title="Select Files to Encrypt")
#         if files:
#             self.selected_files = list(files)
#             self.append_status(f"📂 Selected {len(files)} file(s):")
#             for f in self.selected_files:
#                 try:
#                     file_info = os.stat(f)
#                     size_kb = round(file_info.st_size / 1024, 2)
#                     ext = os.path.splitext(f)[1] or "Unknown"
#                     modified = datetime.fromtimestamp(file_info.st_mtime).strftime("%Y-%m-%d %H:%M")

#                     self.append_status(f" • {os.path.basename(f)}")
#                     self.append_status(f"     ├─ Size: {size_kb} KB")
#                     self.append_status(f"     ├─ Type: {ext}")
#                     self.append_status(f"     └─ Modified: {modified}")
#                 except Exception as e:
#                     self.append_status(f" ❌ Could not get info for {f}: {str(e)}")

#     def start_encryption(self):
#         if not self.selected_files:
#             messagebox.showwarning("No Files", "Please select at least one file.")
#             return

#         algorithm = self.algo_var.get()
#         self.append_status(f"🔐 Starting encryption using {algorithm}...")

#         with multiprocessing.Pool() as pool:
#             results = pool.map(encrypt_worker, [(f, algorithm) for f in self.selected_files])
#             for r in results:
#                 self.append_status(r)

#     def start_decryption(self):
#         files = filedialog.askopenfilenames(title="Select Encrypted Files to Decrypt")
#         if not files:
#             return
#         self.append_status(f"🔓 Starting decryption for {len(files)} file(s)...")

#         with multiprocessing.Pool() as pool:
#             results = pool.map(decrypt_worker, files)
#             for r in results:
#                 self.append_status(r)

#     def show_keys(self):
#         try:
#             keys = load_key_store()
#             if not keys:
#                 self.append_status("🧾 No saved keys found.")
#                 return
#             self.append_status("🔑 Saved Keys:")
#             for fname, info in keys.items():
#                 self.append_status(f" • {fname} → {info['algorithm']}")
#         except Exception as e:
#             self.append_status(f"❌ Error reading keys: {e}")

#     def append_status(self, text):
#         self.status_text.config(state='normal')
#         self.status_text.insert(tk.END, text + '\n')
#         self.status_text.config(state='disabled')
#         self.status_text.see(tk.END)

# # ---------- RUN APP ----------
# if __name__ == "__main__":
#     multiprocessing.freeze_support()
#     root = tk.Tk()
#     app = FileEncryptorApp(root)
#     root.mainloop()

# import os
# import tkinter as tk
# from tkinter import filedialog, messagebox, ttk
# from tkinter import simpledialog

# from pathlib import Path
# import multiprocessing
# from cryptography.fernet import Fernet
# from Crypto.Cipher import AES, DES, Blowfish, ChaCha20
# from Crypto.Random import get_random_bytes
# from Crypto.Util.Padding import pad, unpad

# # === Helper Functions ===

# def save_key(filename, key):
#     with open(filename, 'wb') as f:
#         f.write(key)

# def read_key(filename):
#     with open(filename, 'rb') as f:
#         return f.read()

# def encrypt_file(algorithm, file_path):
#     print(f"[ENCRYPT] Called with: {file_path}, using algorithm: {algorithm}")
#     file_path = Path(file_path)
#     with open(file_path, 'rb') as f:
#         data = f.read()

#     ext = file_path.suffix  # e.g., .pdf, .txt
#     file_stem = file_path.stem
#     parent = file_path.parent

#     if algorithm == "AES":
#         key = get_random_bytes(16)
#         cipher = AES.new(key, AES.MODE_CBC)
#         ct_bytes = cipher.encrypt(pad(data, AES.block_size))
#         output = cipher.iv + ct_bytes
#         save_key(parent / f'{file_stem}_{algorithm.lower()}.key', key)

#     elif algorithm == "DES":
#         key = get_random_bytes(8)
#         cipher = DES.new(key, DES.MODE_CBC)
#         ct_bytes = cipher.encrypt(pad(data, DES.block_size))
#         output = cipher.iv + ct_bytes
#         save_key(parent / f'{file_stem}_{algorithm.lower()}.key', key)

#     elif algorithm == "Fernet":
#         key = Fernet.generate_key()
#         cipher = Fernet(key)
#         output = cipher.encrypt(data)
#         save_key(parent / f'{file_stem}_{algorithm.lower()}.key', key)

#     elif algorithm == "Blowfish":
#         key = get_random_bytes(16)
#         cipher = Blowfish.new(key, Blowfish.MODE_CBC)
#         ct_bytes = cipher.encrypt(pad(data, Blowfish.block_size))
#         output = cipher.iv + ct_bytes
#         save_key(parent / f'{file_stem}_{algorithm.lower()}.key', key)

#     elif algorithm == "ChaCha20":
#         key = get_random_bytes(32)
#         cipher = ChaCha20.new(key=key)
#         output = cipher.nonce + cipher.encrypt(data)
#         save_key(parent / f'{file_stem}_{algorithm.lower()}.key', key)

#     else:
#         return

#     # Make sure only ONE encrypted file is saved, with consistent naming:
#     encrypted_filename = f"encrypted_{file_stem}_{algorithm.lower()}{ext}"
#     with open(parent / encrypted_filename, 'wb') as f:
#         f.write(output)


# def decrypt_file(algorithm, encrypted_file):
#     encrypted_file = Path(encrypted_file)

#     # Check if filename is valid: it should contain at least two underscores for the format 'encrypted_filename_algorithm.extension'
#     parts = encrypted_file.stem.split("_")
    
#     if len(parts) < 3:
#         print(f"Invalid filename format for {encrypted_file.name}. Skipping file.")
#         return

#     file_stem = "_".join(parts[1:-1])  # Extract original filename without encryption info
#     full_ext = encrypted_file.suffix  # Retain original extension (.txt, .docx, etc.)
#     parent = encrypted_file.parent
#     key_file = parent / f"{file_stem}_{algorithm.lower()}.key"

#     if not key_file.exists():
#         print(f"Missing key file: {key_file}. Skipping file.")
#         return

#     key = read_key(key_file)

#     if algorithm == "AES":
#         with open(encrypted_file, 'rb') as f:
#             iv = f.read(16)
#             ct = f.read()
#         cipher = AES.new(key, AES.MODE_CBC, iv)
#         pt = unpad(cipher.decrypt(ct), AES.block_size)

#     elif algorithm == "DES":
#         with open(encrypted_file, 'rb') as f:
#             iv = f.read(8)
#             ct = f.read()
#         cipher = DES.new(key, DES.MODE_CBC, iv)
#         pt = unpad(cipher.decrypt(ct), DES.block_size)

#     elif algorithm == "Fernet":
#         with open(encrypted_file, 'rb') as f:
#             ct = f.read()
#         cipher = Fernet(key)
#         pt = cipher.decrypt(ct)

#     elif algorithm == "Blowfish":
#         with open(encrypted_file, 'rb') as f:
#             iv = f.read(8)
#             ct = f.read()
#         cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
#         pt = unpad(cipher.decrypt(ct), Blowfish.block_size)

#     elif algorithm == "ChaCha20":
#         with open(encrypted_file, 'rb') as f:
#             nonce = f.read(8)
#             ct = f.read()
#         cipher = ChaCha20.new(key=key, nonce=nonce)
#         pt = cipher.decrypt(ct)

#     else:
#         return

#     # Save decrypted file with original extension
#     output_file = parent / f'decrypted_{file_stem}_{algorithm.lower()}{full_ext}'
    
#     with open(output_file, 'wb') as f:
#         f.write(pt)

#     # Attempt to open the decrypted file with the default associated application
#     try:
#         os.startfile(output_file)  # Open with default app
#     except Exception as e:
#         print(f"Failed to open file: {e}")

# class FileEncryptorApp:
#     def __init__(self, root):
#         self.root = root
#         self.root.title("File Encryptor & Decryptor")
#         self.root.geometry("500x450")

#         self.files = []

#         tk.Label(root, text="Select Algorithm:").pack(pady=5)

#         self.algorithm = ttk.Combobox(root, values=["AES", "DES", "Fernet", "Blowfish", "ChaCha20"])
#         self.algorithm.set("AES")
#         self.algorithm.pack(pady=5)

#         self.file_listbox = tk.Listbox(root, width=60, height=10)
#         self.file_listbox.pack(pady=10)

#         tk.Button(root, text="Select Files", command=self.select_files).pack(pady=5)
#         tk.Button(root, text="Encrypt", command=self.encrypt).pack(pady=5)
#         tk.Button(root, text="Decrypt", command=self.choose_file_and_decrypt).pack(pady=5)

#     def select_files(self):
#         """Let the user select files for encryption."""
#         self.files = filedialog.askopenfilenames()
#         self.file_listbox.delete(0, tk.END)
#         for f in self.files:
#             self.file_listbox.insert(tk.END, f)

#     def encrypt(self):
#         """Encrypt the selected files using the selected algorithm."""
#         if not self.files:
#             messagebox.showerror("No files", "Please select files first.")
#             return
#         algo = self.algorithm.get()
#         jobs = []
#         for f in self.files:
#             p = multiprocessing.Process(target=encrypt_file, args=(algo, f))
#             jobs.append(p)
#             p.start()
#         for job in jobs:
#             job.join()
#         messagebox.showinfo("Done", "Encryption complete!")

#     def choose_file_and_decrypt(self):
#         print("[DEBUG] Decrypt button clicked.")
#         """Let the user select a file for decryption and decrypt it."""
#         # Let the user choose an encrypted file
#         file_path = filedialog.askopenfilename(title="Select Encrypted File")
#         if not file_path:
#             print("[DEBUG] No file selected.")
#             return
        
#         # Extract algorithm from the file name (e.g., from "encrypted_filename_aes")
#         file_name = Path(file_path).stem
#         print(f"[DEBUG] Selected file: {file_path}")
#         algorithm = self.extract_algorithm_from_filename(file_name)
#         print(f"[DEBUG] Extracted algorithm: {algorithm}")


#         if not algorithm:
#             messagebox.showerror("Invalid file", "Could not deduce algorithm from file name.")
#             return

#         # Perform the decryption
#         # Correct call to the actual decryption function
#         decrypt_file(algorithm, file_path)
#         print("[DEBUG] Called decrypt_file()")

#     def extract_algorithm_from_filename(self, file_name):
#         """Extract the encryption algorithm from the file name."""
#         parts = file_name.split('_')
#         if len(parts) > 2:
#             return parts[-1].capitalize()  # e.g., 'aes', 'des', etc.
#         return None

    
# if __name__ == "__main__":
#     multiprocessing.freeze_support()
#     root = tk.Tk()
#     app = FileEncryptorApp(root)
#     root.mainloop()

#start from here
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from Crypto.Cipher import AES, DES, Blowfish, ChaCha20
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from cryptography.fernet import Fernet
import os
import json
import subprocess
import platform

KEY_STORE_FILE = "encryption_keys.json"

# Encryption Algorithms Implementations

def _aes_encrypt(data):
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return key, cipher.nonce + tag + ciphertext

def _aes_decrypt(data, key):
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

def _fernet_encrypt(data):
    key = Fernet.generate_key()
    cipher = Fernet(key)
    return key.decode(), cipher.encrypt(data)

def _fernet_decrypt(data, key):
    cipher = Fernet(key)
    return cipher.decrypt(data)

def _chacha20_encrypt(data):
    key = get_random_bytes(32)
    cipher = ChaCha20.new(key=key)
    ciphertext = cipher.encrypt(data)
    return key + cipher.nonce, ciphertext

def _chacha20_decrypt(data, key_nonce):
    key, nonce = key_nonce[:32], key_nonce[32:]
    cipher = ChaCha20.new(key=key, nonce=nonce)
    return cipher.decrypt(data)

def _des_encrypt(data):
    key = get_random_bytes(8)
    cipher = DES.new(key, DES.MODE_ECB)
    padded_data = pad(data, DES.block_size)
    return key, cipher.encrypt(padded_data)

def _des_decrypt(data, key):
    cipher = DES.new(key, DES.MODE_ECB)
    decrypted_padded = cipher.decrypt(data)
    return unpad(decrypted_padded, DES.block_size)

def _blowfish_encrypt(data):
    key = get_random_bytes(16)
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    return key, cipher.encrypt(pad(data, Blowfish.block_size))

def _blowfish_decrypt(data, key):
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    return unpad(cipher.decrypt(data), Blowfish.block_size)

ALGORITHMS = {
    'AES': {'encrypt': _aes_encrypt, 'decrypt': _aes_decrypt},
    'Fernet': {'encrypt': _fernet_encrypt, 'decrypt': _fernet_decrypt},
    'ChaCha20': {'encrypt': _chacha20_encrypt, 'decrypt': _chacha20_decrypt},
    'DES': {'encrypt': _des_encrypt, 'decrypt': _des_decrypt},
    'Blowfish': {'encrypt': _blowfish_encrypt, 'decrypt': _blowfish_decrypt},
}

def load_key_store():
    if not os.path.exists(KEY_STORE_FILE):
        return {}
    with open(KEY_STORE_FILE, 'r') as f:
        return json.load(f)

def save_key_to_store(file_path, algorithm, key):
    store = load_key_store()
    base_name = os.path.basename(file_path).strip()
    store[base_name] = {"algorithm": algorithm, "key": key.hex() if isinstance(key, bytes) else key}
    with open(KEY_STORE_FILE, 'w') as f:
        json.dump(store, f, indent=4)

def open_file(path):
    ext = os.path.splitext(path)[1].lower()

    # Mapping common file extensions to appropriate apps
    app_map = {
        '.docx': 'libreoffice',     # Use LibreOffice for Word documents
        '.doc': 'libreoffice',
        '.xlsx': 'libreoffice',
        '.xls': 'libreoffice',
        '.pptx': 'libreoffice',
        '.ppt': 'libreoffice',
        '.pdf': 'sumatrapdf',       # Use SumatraPDF or other PDF reader
        '.txt': 'notepad',          # Notepad for text files
    }

    # Detect OS
    system = platform.system()

    if ext in app_map:
        app = app_map[ext]
        try:
            if system == "Windows":
                subprocess.Popen([app, path], shell=True)
            elif system == "Darwin":
                subprocess.call([app, path])
            else:  # Linux
                subprocess.call([app, path])
            return
        except Exception as e:
            print(f"⚠️ Could not open with {app}: {e}")

    # Fallback to default app
    try:
        if system == "Windows":
            os.startfile(path)
        elif system == "Darwin":
            subprocess.call(["open", path])
        else:
            subprocess.call(["xdg-open", path])
    except Exception as e:
        print(f"❌ Failed to open file: {e}")


class FileEncryptorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Multi-Algorithm File Encryptor")
        self.root.geometry("600x500")

        self.selected_files = []

        tk.Label(root, text="Select Encryption Algorithm:").pack(pady=5)
        self.algo_var = tk.StringVar()
        self.algo_dropdown = ttk.Combobox(root, textvariable=self.algo_var, state='readonly')
        self.algo_dropdown['values'] = list(ALGORITHMS.keys())
        self.algo_dropdown.current(0)
        self.algo_dropdown.pack(pady=5)

        tk.Button(root, text="📁 Select Files", command=self.select_files).pack(pady=5)
        tk.Button(root, text="🔒 Encrypt Files", command=self.encrypt_files).pack(pady=5)
        tk.Button(root, text="🔓 Decrypt Files", command=self.start_decryption).pack(pady=5)
        tk.Button(root, text="🔑 View Saved Keys", command=self.view_keys).pack(pady=5)

        self.status_text = tk.Text(root, height=15, width=70, state='disabled', bg="#f0f0f0")
        self.status_text.pack(pady=10)
        
    def start_decryption(self):
        self.select_encrypted_files()  # Show the file dialog for encrypted files
        if self.selected_files:  # Only proceed if files were selected
            self.decrypt_files()  # Call the decryption method

    def select_files(self):
        files = filedialog.askopenfilenames(title="Select files")
        if files:
            self.selected_files = list(files)
            self.log(f"Selected {len(files)} file(s).")
    
    def select_encrypted_files(self):
        # Create a tuple of allowed extensions based on ALGORITHMS keys
        extensions = [f"*.{algo.lower()}" for algo in ALGORITHMS]
        filetypes = [("Encrypted files", " ".join(extensions))]
        
        files = filedialog.askopenfilenames(title="Select encrypted files", filetypes=filetypes)
        if files:
            self.selected_files = list(files)
            self.log(f"Selected {len(files)} encrypted file(s).")


    def encrypt_files(self):
        algo = self.algo_var.get()
        new_selected_files = []
        for file in self.selected_files:
            try:
                with open(file, 'rb') as f:
                    data = f.read()
                key, encrypted_data = ALGORITHMS[algo]['encrypt'](data)
                out_path = file + '.' + algo.lower()
                with open(out_path, 'wb') as f:
                    f.write(encrypted_data)
                save_key_to_store(file, algo, key)
                self.log(f"✅ Encrypted: {os.path.basename(file)} → {os.path.basename(out_path)}")
                new_selected_files.append(out_path)

            except Exception as e:
                self.log(f"❌ Error encrypting {file}: {e}")
        self.selected_files = new_selected_files

    def decrypt_files(self):
        for file in self.selected_files:
            try:
                base_name = os.path.basename(file)
                orig_name = None
                for ext in ALGORITHMS.keys():
                    if base_name.endswith(f".{ext.lower()}"):
                        orig_name = base_name[:-(len(ext) + 1)]  # remove ".aes" or ".fernet" etc.
                        orig_name = orig_name.strip()

                        break
                if not orig_name:
                    self.log(f"❌ Unsupported or unknown file extension for {base_name}")
                    continue
                keys = load_key_store()
                print("Stored keys:", list(load_key_store().keys()))

                if orig_name not in keys:
                    self.log(f"❌ No key found for {base_name}")
                    continue
                algorithm = keys[orig_name]['algorithm']
                key_hex = keys[orig_name]['key']
                key = key_hex if algorithm == 'Fernet' else bytes.fromhex(key_hex)
                with open(file, 'rb') as f:
                    data = f.read()
                decrypted_data = ALGORITHMS[algorithm]['decrypt'](data, key)
                orig_extension = os.path.splitext(file.replace(f".{algorithm.lower()}", ''))[1]
                out_path = file.replace(f".{algorithm.lower()}", f"_decrypted{orig_extension}")
                with open(out_path, 'wb') as f:
                    f.write(decrypted_data)
                open_file(out_path)
                self.log(f"✅ Decrypted: {base_name} → {os.path.basename(out_path)}")
            except Exception as e:
                self.log(f"❌ Error decrypting {file}: {e}")

    def view_keys(self):
        keys = load_key_store()
        if not keys:
            self.log("No keys saved.")
        for fname, info in keys.items():
            self.log(f"{fname} → {info['algorithm']}")

    def log(self, msg):
        self.status_text.config(state='normal')
        self.status_text.insert(tk.END, msg + '\n')
        self.status_text.config(state='disabled')

if __name__ == '__main__':
    root = tk.Tk()
    app = FileEncryptorApp(root)
    root.mainloop()
    