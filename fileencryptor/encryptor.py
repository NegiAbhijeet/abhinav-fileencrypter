import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter import Entry, Button, Label
from Crypto.Cipher import AES, DES, Blowfish, ChaCha20
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from cryptography.fernet import Fernet
from Crypto.Protocol.KDF import PBKDF2, scrypt
from tkinter import simpledialog
import os
import json
import subprocess
import platform

KEY_STORE_FILE = "encryption_keys.json"


def _aes_encrypt(data,key=None):
    if key is None:
        key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return key, cipher.nonce + tag + ciphertext

def _aes_decrypt(data, key):
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

def _fernet_encrypt(data, key=None):
    if key is None:
        key = Fernet.generate_key()
    elif isinstance(key, bytes):
        try:
            Fernet(key) 
        except Exception:
            raise ValueError("❌ Invalid Fernet key format. Must be 32-byte base64-encoded.")
    fernet = Fernet(key)
    return key, fernet.encrypt(data)


def _fernet_decrypt(data, key):
    fernet  = Fernet(key)
    return fernet.decrypt(data)

def _chacha20_encrypt(data, key=None):
    if key is None:
        key = get_random_bytes(32)
    cipher = ChaCha20.new(key=key)
    nonce = cipher.nonce 
    ciphertext = cipher.encrypt(data)
    return key ,nonce + ciphertext

def _chacha20_decrypt(encrypted_data: bytes, key: bytes) -> bytes:
    nonce = encrypted_data[:8]        
    ciphertext = encrypted_data[8:]
    cipher = ChaCha20.new(key=key, nonce=nonce)
    return cipher.decrypt(ciphertext)



def _des_encrypt(data, key=None):
    if key is None:
        key = get_random_bytes(8)
    cipher = DES.new(key, DES.MODE_ECB)
    padded_data = pad(data, DES.block_size)
    return key, cipher.encrypt(padded_data)

def _des_decrypt(data, key):
    cipher = DES.new(key, DES.MODE_ECB)
    decrypted_padded = cipher.decrypt(data)
    return unpad(decrypted_padded, DES.block_size)

def _blowfish_encrypt(data, key=None):
    if key is None:
        key = get_random_bytes(16)
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    padded_data = pad(data, Blowfish.block_size)
    return key, cipher.encrypt(padded_data)

def _blowfish_decrypt(data, key):
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    decrypted_padded = cipher.decrypt(data)
    return unpad(decrypted_padded, Blowfish.block_size)

def custom_xor_encrypt(data: bytes, key: bytes=None) -> tuple[bytes, bytes]:
    """Encrypts data using XOR with a repeating key. Returns (key, encrypted_data)."""
    if key is None:
        key = get_random_bytes(16)
    encrypted = bytearray()
    key_len = len(key)
    for i in range(len(data)):
        encrypted.append(data[i] ^ key[i % key_len])
    return key, bytes(encrypted)

def custom_xor_decrypt(data: bytes, key: bytes) -> bytes:
    decrypted = bytearray()
    key_len = len(key)
    for i in range(len(data)):
        decrypted.append(data[i] ^ key[i % key_len])
    return bytes(decrypted)


ALGORITHMS = {
    'AES': {'encrypt': _aes_encrypt, 'decrypt': _aes_decrypt},
    'Fernet': {'encrypt': _fernet_encrypt, 'decrypt': _fernet_decrypt},
    'ChaCha20': {'encrypt': _chacha20_encrypt, 'decrypt': _chacha20_decrypt},
    'DES': {'encrypt': _des_encrypt, 'decrypt': _des_decrypt},
    'Blowfish': {'encrypt': _blowfish_encrypt, 'decrypt': _blowfish_decrypt},
    'XOR': {
    'encrypt': custom_xor_encrypt,
    'decrypt': custom_xor_decrypt,
    },

}

def load_key_store():
    if not os.path.exists(KEY_STORE_FILE):
        return {}
    with open(KEY_STORE_FILE, 'r') as f:
        return json.load(f)

def save_key_to_store(file_path, algorithm, key, salt=None, extra_data=None):
    store = load_key_store()
    base_name = os.path.basename(file_path).strip()
    store[base_name] = {
        "algorithm": algorithm,
        "key": key.hex() if isinstance(key, bytes) else key
    }
    if salt:
        store[base_name]["salt"] = salt
    if extra_data:
        store[base_name].update(extra_data)  
    with open(KEY_STORE_FILE, 'w') as f:
        json.dump(store, f, indent=4)

def open_file(path):
    ext = os.path.splitext(path)[1].lower()

    app_map = {
        '.docx': 'libreoffice',    
        '.doc': 'libreoffice',
        '.xlsx': 'libreoffice',
        '.xls': 'libreoffice',
        '.pptx': 'libreoffice',
        '.ppt': 'libreoffice',
        '.pdf': 'sumatrapdf',     
        '.txt': 'notepad',          
    }

    system = platform.system()

    if ext in app_map:
        app = app_map[ext]
        try:
            if system == "Windows":
                subprocess.Popen([app, path], shell=True)
            elif system == "Darwin":
                subprocess.call([app, path])
            else:  
                subprocess.call([app, path])
            return
        except Exception as e:
            print(f"⚠️ Could not open with {app}: {e}")

    try:
        if system == "Windows":
            os.startfile(path)
        elif system == "Darwin":
            subprocess.call(["open", path])
        else:
            subprocess.call(["xdg-open", path])
    except Exception as e:
        print(f"❌ Failed to open file: {e}")

def derive_key_from_password(password: str, method='pbkdf2', salt=None, key_len=16):
    if not salt:
        salt = get_random_bytes(16)
    if method == 'pbkdf2':
        key = PBKDF2(password, salt, dkLen=key_len, count=100000)
    elif method == 'scrypt':
        key = scrypt(password, salt, key_len, N=2**14, r=8, p=1)
    return key, salt

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

        tk.Label(root, text="Optional: Enter custom key or password").pack(pady=5)
        self.custom_key_entry = tk.Entry(root, width=50, show="*")
        self.custom_key_entry.pack(pady=5)

        tk.Label(root, text="Key Type").pack()
        self.key_type = tk.StringVar(value="random")
        tk.Radiobutton(root, text="Random Key", variable=self.key_type, value="random").pack(anchor='w')
        tk.Radiobutton(root, text="Custom Hex Key", variable=self.key_type, value="custom_hex").pack(anchor='w')
        tk.Radiobutton(root, text="Password (PBKDF2)", variable=self.key_type, value="password_pbkdf2").pack(anchor='w')
        tk.Radiobutton(root, text="Password (Scrypt)", variable=self.key_type, value="password_scrypt").pack(anchor='w')


        tk.Button(root, text="📁 Select Files", command=self.select_files).pack(pady=5)
        tk.Button(root, text="🔒 Encrypt Files", command=self.encrypt_files).pack(pady=5)
        tk.Button(root, text="🔓 Decrypt Files", command=self.start_decryption).pack(pady=5)
        tk.Button(root, text="🔑 View Saved Keys", command=self.view_keys).pack(pady=5)

        self.status_text = tk.Text(root, height=15, width=70, state='disabled', bg="#f0f0f0")
        self.status_text.pack(pady=10)


        self.generate_key_button = tk.Button(self.root, text="Generate 256-bit Hex Key", command=self.generate_custom_key)
        self.generate_key_button.pack(pady=5)

        tk.Label(self.root, text="(Paste or use generated key for custom hex encryption)").pack(pady=5)



    def prompt_password(self, filename):
        return simpledialog.askstring("Password Required", f"Enter password to decrypt '{filename}':", show="*")
            
    def start_decryption(self):
        self.select_encrypted_files()  
        if self.selected_files:  
            self.decrypt_files()  
    def select_files(self):
        files = filedialog.askopenfilenames(title="Select files")
        if files:
            self.selected_files = list(files)
            self.log(f"Selected {len(files)} file(s).")
    
    def select_encrypted_files(self):
        extensions = [f"*.{algo.lower()}" for algo in ALGORITHMS]
        filetypes = [("Encrypted files", " ".join(extensions))]
        
        files = filedialog.askopenfilenames(title="Select encrypted files", filetypes=filetypes)
        if files:
            self.selected_files = list(files)
            self.log(f"Selected {len(files)} encrypted file(s).")
    def prompt_password(self, filename, purpose="Decryption"):
        return simpledialog.askstring(f"{purpose} Password", f"Enter password for {purpose.lower()} of {filename}:", show='*')
    def generate_custom_key(self):
        hex_key = os.urandom(32).hex()  
        self.custom_key_entry.delete(0, 'end')
        self.custom_key_entry.insert(0, hex_key)
        self.log("✅ Generated 256-bit custom hex key.")

    def encrypt_files(self):
        algo = self.algo_var.get()
        new_selected_files = []

        if algo == 'Fernet' and key_type.startswith('password'):
            self.log("❌ Fernet does not support password-based encryption. Please choose a different algorithm or key type.")
            return
        key_type = self.key_type.get()

        for file in self.selected_files:
            try:
                with open(file, 'rb') as f:
                    data = f.read()

                salt = None
                if key_type.startswith('password'):
                    if algo == 'Fernet':
                        self.log(f"❌ Fernet does not support password-based encryption. Skipping {os.path.basename(file)}.")
                        continue
                    method = 'pbkdf2' if 'pbkdf2' in key_type.lower() else 'scrypt'
                    password = self.prompt_password(os.path.basename(file), purpose="Encryption")
                    if not password:
                        self.log(f"❌ Password is required for password-based encryption of {os.path.basename(file)}.")
                        continue
                    try:
                        if algo == 'DES':
                            key_len = 8
                        elif algo == 'ChaCha20':
                            key_len = 32
                        else:
                            key_len = 16
                        key, salt = derive_key_from_password(password, method=method, key_len=key_len)
                        key = key[:key_len]  

                    except Exception as e:
                        self.log(f"❌ Key derivation failed for {file}: {e}")
                        continue
                
                elif key_type == 'custom_hex':
                    if algo == 'Fernet':
                        self.log(f"❌ Fernet does not support custom hex keys. Skipping {os.path.basename(file)}.")
                        continue

                    expected_key_len = {
                        'ChaCha20': 32,
                        'DES': 8,
                    }.get(algo, 16) 
                    hex_key_input = self.custom_key_entry.get().strip()

                    if not hex_key_input:
                        key = get_random_bytes(expected_key_len)
                        hex_key_input = key.hex()
                        self.custom_key_entry.delete(0, tk.END)
                        self.custom_key_entry.insert(0, hex_key_input)
                        self.log(f"✅ Auto-generated {expected_key_len}-byte hex key for {os.path.basename(file)}.")

                    try:
                        key = bytes.fromhex(hex_key_input)

                        if len(key) != expected_key_len:
                            self.log(f"❌ {algo} requires a {expected_key_len}-byte key. Provided key is {len(key)} bytes.")
                            continue

                        self.log(f"✅ Using {expected_key_len}-byte custom hex key for {os.path.basename(file)}.")

                    except ValueError:
                        self.log(f"❌ Invalid hex key format for {os.path.basename(file)}.")
                        continue


                elif key_type == 'random':
                    if algo == 'Fernet':
                        key = Fernet.generate_key()
                        self.log(f"✅ Auto-generated Fernet key for {os.path.basename(file)}.")
                    else:
                        key = None  

                else:
                    self.log("❌ Unknown key option.")
                    continue
                
                file_root, file_ext = os.path.splitext(file)
                out_path = f"{file_root}.{algo.lower()}"
                if key is not None:
                    result = ALGORITHMS[algo]['encrypt'](data, key)
                    key = result[0] if isinstance(result, tuple) else key
                    encrypted_data = result[1] if isinstance(result, tuple) else result
                else:
                    key, encrypted_data = ALGORITHMS[algo]['encrypt'](data)

                with open(out_path, 'wb') as f:
                    f.write(encrypted_data)

                orig_ext = os.path.splitext(file)[1]
                
                if key_type.startswith('password'):
                    save_key_to_store(
                        os.path.basename(out_path),
                        f"{method}-{algo}",
                        key,
                        salt.hex(),
                        extra_data={"orig_ext": orig_ext}
                    )
                else:
                    save_key_to_store(
                        os.path.basename(out_path),
                        f"{'Hex-' if key_type == 'custom_hex' else ''}{algo}",
                        key.hex() if isinstance(key, bytes) else key,
                        extra_data={"orig_ext": orig_ext}
                    )

                self.log(f"✅ Encrypted: {os.path.basename(file)} → {os.path.basename(out_path)}")
                new_selected_files.append(out_path)

            except Exception as e:
                self.log(f"❌ Error encrypting {file}: {e}")

        self.selected_files = new_selected_files
    def decrypt_files(self):
        for file in self.selected_files:
            try:
                base_name = os.path.basename(file)
                keys = load_key_store()
                if base_name not in keys:
                    self.log(f"❌ No key found for {base_name}")
                    continue

                key_info = keys[base_name]

                algorithm = key_info['algorithm']

                key = None  
                salt = None

                if 'salt' in key_info:
                    salt = bytes.fromhex(key_info['salt'])
                    password = self.prompt_password(base_name)
                    if not password:
                        self.log(f"❌ Password required to decrypt {base_name}")
                        continue

                    method = 'pbkdf2' if 'pbkdf2' in algorithm.lower() else 'scrypt'
                    base_algo = algorithm.split('-')[-1].lower()

                    if base_algo == 'chacha20':
                        key_len = 32
                    elif base_algo == 'des':
                        key_len = 8
                    else:
                        key_len = 16

                    try:
                        key, _ = derive_key_from_password(password, method=method, salt=salt, key_len=key_len)
                        key = key[:key_len]
                    except Exception as e:
                        self.log(f"❌ Key derivation failed: {e}")
                        continue


                elif 'hex' in algorithm.lower():
                    try:
                        key = bytes.fromhex(key_info['key'])
                    except ValueError:
                        self.log(f"❌ Invalid hex key format stored for {base_name}")
                        continue

                else:
                    key = key_info['key'] if 'fernet' in algorithm.lower() else bytes.fromhex(key_info['key'])

                with open(file, 'rb') as f:
                    data = f.read()
                base_algo = algorithm.split('-')[-1] 
                decrypted_data = ALGORITHMS[base_algo]['decrypt'](data, key)
                encrypted_ext = os.path.splitext(file)[1]
                if file.endswith(encrypted_ext):
                    decrypted_path  = file[:-len(encrypted_ext)]  
                else:
                    decrypted_path  = file

                orig_ext = key_info.get("orig_ext", "")
                file_base = os.path.splitext(file)[0]  
                out_path = f"{file_base}_decrypted{orig_ext}"


                with open(out_path, 'wb') as f:
                    f.write(decrypted_data)
                
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
    