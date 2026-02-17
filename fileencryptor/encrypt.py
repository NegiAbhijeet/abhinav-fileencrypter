import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
# Removed unused drag and drop imports that may cause issues
import threading
from Crypto.Cipher import AES, DES, Blowfish, ChaCha20
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from cryptography.fernet import Fernet
from Crypto.Protocol.KDF import PBKDF2, scrypt
import os
import json
import subprocess
import platform
import multiprocessing
<<<<<<< HEAD
import time
import concurrent.futures
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import base64  # Add this import at the top of the file

KEY_STORE_FILE = "encryption_keys.json"
=======
from queue import Empty
# ssahj 
from Crypto.Cipher import AES, Blowfish, DES
from Crypto.Random import get_random_bytes
from cryptography.fernet import Fernet
>>>>>>> dc3d1a6dcc5c1dd52f755ce4f4a0e856149dd7e6

# Encryption algorithm implementations
def _aes_encrypt(data, key=None):
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
        # Convert raw bytes to URL-safe base64 if needed
        try:
            # Check if it's already a valid Fernet key
            Fernet(key)
        except Exception:
            # If not valid, encode as base64
            key = base64.urlsafe_b64encode(key)
    
    # Ensure key is properly formatted for Fernet
    try:
        if isinstance(key, str):
            # If it's a string, encode it
            key = key.encode()
        
        # Validate the key format
        Fernet(key)
    except Exception as e:
        print(f"Fernet key error: {e}")
        # Generate a new key if the provided one is invalid
        key = Fernet.generate_key()
        print(f"Generated new Fernet key: {key}")
    
    fernet = Fernet(key)
    return key, fernet.encrypt(data)

def _fernet_decrypt(data, key):
    # Ensure key is properly formatted for Fernet
    if isinstance(key, str):
        # If it's a string, encode it
        key = key.encode()
    
    # Check if key is hex encoded and needs conversion
    if len(key) != 44 and not key.endswith(b'='):
        try:
            # Try to convert from hex to base64
            binary_key = bytes.fromhex(key.decode() if isinstance(key, bytes) else key)
            key = base64.urlsafe_b64encode(binary_key)
        except Exception as e:
            print(f"Error converting key: {e}")
            raise ValueError("Invalid Fernet key format")
    
    fernet = Fernet(key)
    return fernet.decrypt(data)

def _chacha20_encrypt(data, key=None):
    if key is None:
        key = get_random_bytes(32)
    cipher = ChaCha20.new(key=key)
    nonce = cipher.nonce 
    ciphertext = cipher.encrypt(data)
    return key, nonce + ciphertext

def _chacha20_decrypt(encrypted_data, key):
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

def _xor_encrypt(data, key=None):
    """Simple XOR encryption"""
    if key is None:
        key = get_random_bytes(16)
    encrypted = bytearray()
    key_len = len(key)
    for i in range(len(data)):
        encrypted.append(data[i] ^ key[i % key_len])
    return key, bytes(encrypted)

def _xor_decrypt(data, key):
    """Simple XOR decryption"""
    decrypted = bytearray()
    key_len = len(key)
    for i in range(len(data)):
        decrypted.append(data[i] ^ key[i % key_len])
    return bytes(decrypted)

# Dictionary of supported algorithms
ALGORITHMS = {
    'AES': {'encrypt': _aes_encrypt, 'decrypt': _aes_decrypt},
    'Fernet': {'encrypt': _fernet_encrypt, 'decrypt': _fernet_decrypt},
    'ChaCha20': {'encrypt': _chacha20_encrypt, 'decrypt': _chacha20_decrypt},
    'DES': {'encrypt': _des_encrypt, 'decrypt': _des_decrypt},
    'Blowfish': {'encrypt': _blowfish_encrypt, 'decrypt': _blowfish_decrypt},
    'XOR': {'encrypt': _xor_encrypt, 'decrypt': _xor_decrypt},
}

# Helper functions
def load_key_store():
    """Load the key store from disk"""
    if not os.path.exists(KEY_STORE_FILE):
        return {}
    with open(KEY_STORE_FILE, 'r') as f:
        return json.load(f)

def save_key_to_store(filename, algorithm, key, salt=None, extra_data=None):
    """Save encryption key to the key store"""
    keys = load_key_store()
    
    # Create key entry
    key_entry = {
        'algorithm': algorithm,
        'key': key
    }
    
    # Add salt if provided
    if salt:
        key_entry['salt'] = salt
    
    # Add any extra data
    if extra_data and isinstance(extra_data, dict):
        key_entry.update(extra_data)
    
    # Save to key store
    keys[filename] = key_entry
    
    with open(KEY_STORE_FILE, 'w') as f:
        json.dump(keys, f, indent=4)

def open_file(path):
    """Open a file with the default application"""
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

def derive_key_from_password(password, method='pbkdf2', salt=None, key_len=16):
    """Derive encryption key from password using PBKDF2 or scrypt"""
    if not salt:
        salt = get_random_bytes(16)
        
    if method == 'pbkdf2':
        key = PBKDF2(password.encode(), salt, dkLen=key_len, count=100000)
        return key, salt
    elif method == 'scrypt':
        key = scrypt(password.encode(), salt, key_len, N=2**14, r=8, p=1)
        return key, salt
    else:
        raise ValueError(f"Unsupported key derivation method: {method}")

def generate_test_file(size_mb, path):
    """Generate a test file of specified size in MB"""
    size_bytes = size_mb * 1024 * 1024
    with open(path, 'wb') as f:
        f.write(os.urandom(size_bytes))
    return path

def encrypt_worker(args):
    """Worker function for encryption in thread pool"""
    file_path, algo, key_type, custom_key, password = args
    start_time = time.time()
    
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        key = None
        salt = None
        method = None
        
        # Handle different key types
        if key_type == "random":
            key = None  # Will be generated by the encryption function
        
        elif key_type == "custom_hex":
            if custom_key:
                try:
                    # Try to parse as hex first
                    try:
                        key = bytes.fromhex(custom_key)
                    except ValueError:
                        # If not hex, treat as string and encode
                        key = custom_key.encode('utf-8')

                    # Adjust key length for algorithm if needed
                    if algo == 'ChaCha20':
                        # ChaCha20 requires 32-byte key
                        if len(key) != 32:
                            key = key[:32] if len(key) > 32 else key.ljust(32, b'\0')
                    elif algo == 'DES':
                        # DES requires 8-byte key
                        if len(key) != 8:
                            key = key[:8] if len(key) > 8 else key.ljust(8, b'\0')
                    elif algo == 'Fernet':
                        # For Fernet, convert to URL-safe base64 (32 bytes -> base64)
                        raw_key = key[:32] if len(key) > 32 else key.ljust(32, b'\0')
                        key = base64.urlsafe_b64encode(raw_key)
                    else:
                        # AES, Blowfish, XOR use 16-byte keys
                        if len(key) != 16:
                            key = key[:16] if len(key) > 16 else key.ljust(16, b'\0')
                except Exception as e:
                    return {"status": "error", "file": os.path.basename(file_path), "error": f"Invalid key format: {e}"}
        
        elif key_type.startswith("password"):
            if password:
                method = 'pbkdf2' if key_type == 'password_pbkdf2' else 'scrypt'
                
                if algo == 'Fernet':
                    # For Fernet, we need to derive a URL-safe base64 encoded key
                    salt = get_random_bytes(16)
                    raw_key = PBKDF2(password.encode(), salt, dkLen=32, count=100000)
                    key = base64.urlsafe_b64encode(raw_key)
                    print(f"Derived Fernet key from password: {key}")
                else:
                    # For other algorithms, derive the appropriate key length
                    if algo == 'ChaCha20':
                        key_len = 32
                    elif algo == 'DES':
                        key_len = 8
                    else:
                        key_len = 16  # AES, Blowfish, XOR
                    key, salt = derive_key_from_password(password, method, key_len=key_len)
            else:
                return {"status": "error", "file": os.path.basename(file_path), "error": "No password provided"}
        
        # Encrypt the file
        file_root, file_ext = os.path.splitext(file_path)
        out_path = f"{file_root}.{algo.lower()}"
        
        if key is not None:
            result = ALGORITHMS[algo]['encrypt'](data, key)
            key = result[0] if isinstance(result, tuple) else key
            encrypted_data = result[1] if isinstance(result, tuple) else result
        else:
            key, encrypted_data = ALGORITHMS[algo]['encrypt'](data)
        
        with open(out_path, 'wb') as f:
            f.write(encrypted_data)
        
        # Store key information
        base_name = os.path.basename(out_path)
        
        if key_type.startswith("password"):
            # For password-based encryption, store the method and salt
            extra_data = {"orig_ext": file_ext}
            save_key_to_store(base_name, f"{method}-{algo}", None, salt.hex(), extra_data)
        else:
            # For other encryption types, store the key directly
            key_str = key.decode() if isinstance(key, bytes) and algo == 'Fernet' else key.hex() if isinstance(key, bytes) else key
            extra_data = {"orig_ext": file_ext}
            save_key_to_store(base_name, algo, key_str, None, extra_data)
        
        end_time = time.time()
        file_size = os.path.getsize(file_path) / (1024 * 1024)  # Size in MB
        speed = file_size / (end_time - start_time) if (end_time - start_time) > 0 else 0  # MB/s
        
        return {
            "status": "success",
            "file": os.path.basename(file_path),
            "output": os.path.basename(out_path),
            "time": end_time - start_time,
            "size": file_size,
            "speed": speed
        }
    
    except Exception as e:
        import traceback
        traceback.print_exc()
        return {
            "status": "error",
            "file": os.path.basename(file_path),
            "error": str(e)
        }

def decrypt_worker(args):
    """Worker function for decryption in thread pool"""
    file_path, password, custom_key = args if len(args) == 3 else (args[0], args[1], None)
    start_time = time.time()
    
    try:
        base_name = os.path.basename(file_path)
        
        # Find the algorithm from the file extension
        algo_ext = None
        for algo in ALGORITHMS.keys():
            if file_path.lower().endswith(f".{algo.lower()}"):
                algo_ext = algo.lower()
                break
        
        if not algo_ext:
            return {"status": "error", "file": base_name, 
                    "error": f"Unknown file format. Expected one of: {', '.join([f'.{a.lower()}' for a in ALGORITHMS.keys()])}"}
        
        # Load key information
        keys = load_key_store()
        if base_name not in keys:
            return {"status": "error", "file": base_name, 
                    "error": "No key found in key store. Make sure the file was encrypted with this application."}
        
        key_info = keys[base_name]
        algorithm = key_info['algorithm']
        
        # Handle different key types
        key = None

        # If custom_key is provided, use it instead of stored key
        if custom_key:
            try:
                # Try to parse as hex first
                try:
                    key = bytes.fromhex(custom_key)
                except ValueError:
                    # If not hex, treat as string and encode
                    key = custom_key.encode('utf-8')

                # Adjust key length for algorithm if needed
                if 'chacha20' in algorithm.lower():
                    # ChaCha20 requires 32-byte key
                    if len(key) != 32:
                        key = key[:32] if len(key) > 32 else key.ljust(32, b'\0')
                elif 'des' in algorithm.lower():
                    # DES requires 8-byte key
                    if len(key) != 8:
                        key = key[:8] if len(key) > 8 else key.ljust(8, b'\0')
                elif 'fernet' in algorithm.lower():
                    # For Fernet, convert to URL-safe base64 (32 bytes -> base64)
                    raw_key = key[:32] if len(key) > 32 else key.ljust(32, b'\0')
                    key = base64.urlsafe_b64encode(raw_key)
                else:
                    # AES, Blowfish, XOR use 16-byte keys
                    if len(key) != 16:
                        key = key[:16] if len(key) > 16 else key.ljust(16, b'\0')
            except Exception as e:
                return {"status": "error", "file": base_name, "error": f"Invalid custom key format: {e}"}

        elif 'pbkdf2' in algorithm.lower() or 'scrypt' in algorithm.lower():
            # Password-based key
            if not password:
                return {"status": "error", "file": base_name, "error": "No password provided"}

            method = 'pbkdf2' if 'pbkdf2' in algorithm.lower() else 'scrypt'
            if 'salt' not in key_info:
                return {"status": "error", "file": base_name, "error": "Missing salt for password-based decryption"}

            salt = bytes.fromhex(key_info['salt'])

            if 'fernet' in algorithm.lower():
                # For Fernet, derive a URL-safe base64 encoded key
                raw_key = PBKDF2(password.encode(), salt, dkLen=32, count=100000)
                key = base64.urlsafe_b64encode(raw_key)
                print(f"Derived Fernet key from password for decryption: {key}")
            else:
                # For other algorithms, derive the appropriate key length
                if 'chacha20' in algorithm.lower():
                    key_len = 32
                elif 'des' in algorithm.lower():
                    key_len = 8
                else:
                    key_len = 16  # AES, Blowfish, XOR
                key, _ = derive_key_from_password(password, method, salt, key_len)

        elif 'hex' in algorithm.lower():
            # Hex key
            try:
                key = bytes.fromhex(key_info['key'])

                # For Fernet, convert hex to URL-safe base64
                if 'fernet' in algorithm.lower():
                    key = base64.urlsafe_b64encode(key)
            except ValueError:
                return {"status": "error", "file": base_name, "error": "Invalid hex key format in key store"}

        else:
            # Standard key
            try:
                if 'fernet' in algorithm.lower():
                    # For Fernet, ensure the key is properly formatted
                    key = key_info['key']
                    if isinstance(key, str):
                        key = key.encode()
                else:
                    key = bytes.fromhex(key_info['key'])
            except ValueError:
                return {"status": "error", "file": base_name, "error": "Invalid key format in key store"}
        
        # Read the encrypted data
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
        
        # Determine which algorithm to use for decryption
        algo_name = None
        for name in ALGORITHMS.keys():
            if name.lower() in algorithm.lower():
                algo_name = name
                break
        
        if not algo_name:
            return {"status": "error", "file": base_name, 
                    "error": f"Unknown algorithm: {algorithm}. Supported algorithms: {', '.join(ALGORITHMS.keys())}"}
        
        # Decrypt the data
        try:
            print(f"Decrypting with algorithm: {algo_name}")
            print(f"Key type: {type(key)}")
            if isinstance(key, bytes):
                print(f"Key length: {len(key)}")
            
            decrypted_data = ALGORITHMS[algo_name]['decrypt'](encrypted_data, key)
        except Exception as e:
            return {"status": "error", "file": base_name, 
                    "error": f"Decryption failed: {e}. This may be due to an incorrect password or corrupted file."}
        
        # Determine output path
        orig_ext = key_info.get('orig_ext', '')
        file_dir = os.path.dirname(file_path)
        file_name = os.path.splitext(base_name)[0]
        out_path = os.path.join(file_dir, f"decrypted_{file_name}{orig_ext}")
        
        # Save decrypted data
        with open(out_path, 'wb') as f:
            f.write(decrypted_data)
        
        end_time = time.time()
        file_size = os.path.getsize(file_path) / (1024 * 1024)  # Size in MB
        speed = file_size / (end_time - start_time) if (end_time - start_time) > 0 else 0  # MB/s
        
        return {
            "status": "success",
            "file": base_name,
            "output": os.path.basename(out_path),
            "time": end_time - start_time,
            "size": file_size,
            "speed": speed
        }
    
    except Exception as e:
        import traceback
        traceback.print_exc()
        return {
            "status": "error",
            "file": os.path.basename(file_path),
            "error": str(e)
        }

class FileEncryptorApp:
    def __init__(self, root):
        # Just use the provided root window
        self.root = root
        self.root.title("🔐 Multi-Algorithm File Encryptor")
        self.root.geometry("900x700")
        
        # Create a frame for file drop (without TkinterDnD for now)
        self.drop_frame = tk.LabelFrame(self.root, text="Select Files", height=100)
        self.drop_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Add label to drop zone
        self.drop_label = tk.Label(self.drop_frame, text="Use the 'Select Files' button to choose files")
        self.drop_label.pack(expand=True, fill=tk.BOTH, padx=20, pady=20)
        
        # Progress bar
        self.progress_frame = tk.Frame(self.root)
        self.progress_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.progress_label = tk.Label(self.progress_frame, text="Progress:")
        self.progress_label.pack(side=tk.LEFT, padx=5)
        
        self.progress_bar = ttk.Progressbar(self.progress_frame, length=400, mode='determinate')
        self.progress_bar.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        self.progress_text = tk.Label(self.progress_frame, text="0%")
        self.progress_text.pack(side=tk.LEFT, padx=5)
        
        # Selected files
        self.selected_files = []
        
        # Performance metrics
        self.performance_results = []
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create tabs
        self.main_tab = ttk.Frame(self.notebook)
        self.performance_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.main_tab, text="Main")
        self.notebook.add(self.performance_tab, text="Performance")
        
        # Create UI elements for main tab
        self._create_main_ui()
        
        # Create UI elements for performance tab
        self._create_performance_ui()
    
    def _create_main_ui(self):
        """Create the main UI elements"""
        # Algorithm selection
        tk.Label(self.main_tab, text="Select Encryption Algorithm:").pack(pady=5)
        self.algo_var = tk.StringVar()
        self.algo_dropdown = ttk.Combobox(self.main_tab, textvariable=self.algo_var, state='readonly')
        self.algo_dropdown['values'] = list(ALGORITHMS.keys())
        self.algo_dropdown.current(0)
        self.algo_dropdown.pack(pady=5)
        
        # Key type selection
        tk.Label(self.main_tab, text="Key Type:").pack(pady=5)
        self.key_type = tk.StringVar()
        self.key_type.set("random")
        
        key_frame = ttk.Frame(self.main_tab)
        key_frame.pack(pady=5)
        
        ttk.Radiobutton(key_frame, text="Random Key", variable=self.key_type, 
                       value="random").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(key_frame, text="Custom Hex Key", variable=self.key_type, 
                       value="custom_hex").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(key_frame, text="Password (PBKDF2)", variable=self.key_type, 
                       value="password_pbkdf2").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(key_frame, text="Password (Scrypt)", variable=self.key_type, 
                       value="password_scrypt").pack(side=tk.LEFT, padx=5)
        
        # Custom key entry
        tk.Label(self.main_tab, text="Enter custom key/password (can be text or hex)").pack(pady=5)
        self.custom_key_entry = tk.Entry(self.main_tab, width=50, show="*")
        self.custom_key_entry.pack(pady=5)
        
        # Show/hide password checkbox
        self.show_password = tk.BooleanVar()
        ttk.Checkbutton(self.main_tab, text="Show password", variable=self.show_password, 
                       command=self._toggle_password_visibility).pack(pady=5)
        
        # Generate key buttons
        key_button_frame = tk.Frame(self.main_tab)
        key_button_frame.pack(pady=5)

        self.generate_key_button = tk.Button(key_button_frame, text="Generate Algorithm-Specific Key",
                                           command=self.generate_custom_key)
        self.generate_key_button.pack(side=tk.LEFT, padx=5)

        self.generate_simple_key_button = tk.Button(key_button_frame, text="Generate Simple Key",
                                                  command=self.generate_simple_key)
        self.generate_simple_key_button.pack(side=tk.LEFT, padx=5)
        
        # Threading options
        threading_frame = ttk.LabelFrame(self.main_tab, text="Performance Options")
        threading_frame.pack(pady=10, fill=tk.X, padx=10)
        
        # Threading mode
        self.threading_mode = tk.StringVar()
        self.threading_mode.set("multi")
        
        ttk.Radiobutton(threading_frame, text="Single-threaded", variable=self.threading_mode, 
                       value="single").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(threading_frame, text="Multi-threaded", variable=self.threading_mode, 
                       value="multi").pack(side=tk.LEFT, padx=5)
        
        # Number of threads slider
              
        thread_frame = ttk.Frame(threading_frame)
        thread_frame.pack(side=tk.RIGHT, padx=10)
        
        tk.Label(thread_frame, text="Number of threads:").pack(side=tk.LEFT)
        self.max_threads = multiprocessing.cpu_count()
        self.thread_count = tk.IntVar()
        self.thread_count.set(max(1, self.max_threads - 1))  # Default to max-1
        
        self.thread_slider = tk.Scale(thread_frame, from_=1, to=self.max_threads,
                                     orient=tk.HORIZONTAL, variable=self.thread_count)
        self.thread_slider.pack(side=tk.LEFT, padx=5)
        
        # File operations buttons
        button_frame = ttk.Frame(self.main_tab)
        button_frame.pack(pady=10)

        select_button = ttk.Button(button_frame, text="📁 Select Files", command=self.select_files)
        select_button.pack(side=tk.LEFT, padx=5)
        print("Created Select Files button with command:", self.select_files)

        ttk.Button(button_frame, text="🔒 Encrypt Files", 
                  command=self.encrypt_files).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="🔓 Decrypt Files", 
                  command=self.start_decryption).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="🔑 View Saved Keys", 
                  command=self.view_keys).pack(side=tk.LEFT, padx=5)
        
        # Status text area
        self.status_text = tk.Text(self.main_tab, height=15, width=70, state='disabled', bg="#f0f0f0")
        self.status_text.pack(pady=10, fill=tk.BOTH, expand=True)
        
        # Add scrollbar to status text
        scrollbar = ttk.Scrollbar(self.status_text, command=self.status_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.status_text.config(yscrollcommand=scrollbar.set)
        
        # Performance metrics frame
        metrics_frame = ttk.LabelFrame(self.main_tab, text="Performance Metrics")
        metrics_frame.pack(pady=5, fill=tk.X, padx=10)
        
        self.metrics_label = tk.Label(metrics_frame, text="No operations performed yet")
        self.metrics_label.pack(pady=5)
    
    def _create_performance_ui(self):
        """Create the performance testing UI"""
        # Test configuration frame
        config_frame = ttk.LabelFrame(self.performance_tab, text="Test Configuration")
        config_frame.pack(pady=10, fill=tk.X, padx=10)
        
        # Algorithm selection
        algo_frame = ttk.Frame(config_frame)
        algo_frame.pack(pady=5, fill=tk.X)
        
        tk.Label(algo_frame, text="Algorithm:").pack(side=tk.LEFT, padx=5)
        self.test_algo_var = tk.StringVar()
        self.test_algo_dropdown = ttk.Combobox(algo_frame, textvariable=self.test_algo_var, state='readonly')
        self.test_algo_dropdown['values'] = list(ALGORITHMS.keys())
        self.test_algo_dropdown.current(0)
        self.test_algo_dropdown.pack(side=tk.LEFT, padx=5)
        
        # Test data source
        data_frame = ttk.LabelFrame(config_frame, text="Test Data")
        data_frame.pack(pady=5, fill=tk.X)
        
        self.data_source = tk.StringVar()
        self.data_source.set("generate")
        
        ttk.Radiobutton(data_frame, text="Generate test files", variable=self.data_source, 
                       value="generate", command=self._toggle_data_source).pack(anchor=tk.W, padx=5)
        
        # Test file size
        size_frame = ttk.Frame(data_frame)
        size_frame.pack(pady=5, fill=tk.X, padx=20)
        
        tk.Label(size_frame, text="File size (MB):").pack(side=tk.LEFT)
        self.test_file_size = tk.IntVar()
        self.test_file_size.set(100)  # Default 100MB
        
        size_entry = ttk.Entry(size_frame, textvariable=self.test_file_size, width=5)
        size_entry.pack(side=tk.LEFT, padx=5)
        
        tk.Label(size_frame, text="Number of files:").pack(side=tk.LEFT, padx=10)
        self.test_file_count = tk.IntVar()
        self.test_file_count.set(3)  # Default 3 files
        
        count_entry = ttk.Entry(size_frame, textvariable=self.test_file_count, width=5)
        count_entry.pack(side=tk.LEFT, padx=5)
        
        ttk.Radiobutton(data_frame, text="Use selected files", variable=self.data_source, 
                       value="selected", command=self._toggle_data_source).pack(anchor=tk.W, padx=5)
        
        ttk.Button(data_frame, text="Select Files", command=self.select_test_files).pack(pady=5)
        
        self.selected_files_label = tk.Label(data_frame, text="No files selected")
        self.selected_files_label.pack(pady=5)
        
        # Threading configurations to test
        thread_frame = ttk.LabelFrame(config_frame, text="Threading Configurations to Test")
        thread_frame.pack(pady=5, fill=tk.X)
        
        self.test_single = tk.BooleanVar(value=True)
        ttk.Checkbutton(thread_frame, text="Single-threaded", variable=self.test_single).pack(anchor=tk.W, padx=5)
        
        self.test_multi = tk.BooleanVar(value=True)
        ttk.Checkbutton(thread_frame, text="Multi-threaded (all cores)", variable=self.test_multi).pack(anchor=tk.W, padx=5)
        
        self.test_custom = tk.BooleanVar(value=False)
        custom_check = ttk.Checkbutton(thread_frame, text="Custom thread count:", variable=self.test_custom)
        custom_check.pack(side=tk.LEFT, padx=5)
        
        self.custom_thread_count = tk.IntVar()
        self.custom_thread_count.set(max(2, self.max_threads // 2))  # Default to half cores
        
        custom_entry = ttk.Entry(thread_frame, textvariable=self.custom_thread_count, width=5)
        custom_entry.pack(side=tk.LEFT)
        
        # Run test button
        ttk.Button(config_frame, text="Run Performance Test", command=self.run_performance_test).pack(pady=10)
        
        # Results frame
        results_frame = ttk.LabelFrame(self.performance_tab, text="Test Results")
        results_frame.pack(pady=10, fill=tk.BOTH, expand=True, padx=10)
        
        # Results text area
        self.results_text = tk.Text(results_frame, height=10, width=70, state='disabled', bg="#f0f0f0")
        self.results_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, pady=5, padx=5)
        
        # Add scrollbar to results text
        results_scrollbar = ttk.Scrollbar(results_frame, command=self.results_text.yview)
        results_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.results_text.config(yscrollcommand=results_scrollbar.set)
        
        # Graph frame
        self.graph_frame = ttk.Frame(self.performance_tab)
        self.graph_frame.pack(pady=10, fill=tk.BOTH, expand=True, padx=10)
    
    def _toggle_data_source(self):
        """Toggle between generated and selected test files"""
        # This method can be expanded to enable/disable relevant UI elements
        pass
    
    def _toggle_password_visibility(self):
        """Toggle password visibility in the custom key entry"""
        if self.show_password.get():
            self.custom_key_entry.config(show="")
        else:
            self.custom_key_entry.config(show="*")
    
    def generate_custom_key(self):
        """Generate a random hex key for the selected algorithm"""
        algo = self.algo_var.get()

        # Generate appropriate key length for the algorithm
        if algo == 'ChaCha20':
            key_bytes = os.urandom(32)  # 32 bytes for ChaCha20
        elif algo == 'DES':
            key_bytes = os.urandom(8)   # 8 bytes for DES
        elif algo == 'Fernet':
            key_bytes = os.urandom(32)  # 32 bytes for Fernet
        else:
            key_bytes = os.urandom(16)  # 16 bytes for AES, Blowfish, XOR

        hex_key = key_bytes.hex()
        self.custom_key_entry.delete(0, 'end')
        self.custom_key_entry.insert(0, hex_key)
        self.log(f"✅ Generated {len(key_bytes)*8}-bit hex key for {algo}.")

    def generate_simple_key(self):
        """Generate a simple, memorable key"""
        # Generate a simple 8-character alphanumeric key
        import string
        import random

        # Use only letters and numbers for easier typing
        chars = string.ascii_letters + string.digits
        simple_key = ''.join(random.choice(chars) for _ in range(8))

        self.custom_key_entry.delete(0, 'end')
        self.custom_key_entry.insert(0, simple_key)
        self.log(f"✅ Generated simple 8-character key: {simple_key}")
    
    def select_files(self):
        """Open file dialog to select files for encryption"""
        print("Opening file dialog...")
        from tkinter import filedialog  # Make sure this import is available
        
        files = filedialog.askopenfilenames(title="Select Files to Encrypt")
        print(f"Selected files: {files}")
        
        if files:
            self.selected_files = list(files)
            self.log(f"Selected {len(files)} file(s) for encryption.")
            return True
        return False
    
    def select_test_files(self):
        """Select files for performance testing"""
        files = filedialog.askopenfilenames(title="Select Files for Performance Testing")
        if files:
            self.test_files = list(files)
            self.selected_files_label.config(text=f"{len(files)} files selected")
        else:
            self.test_files = []
            self.selected_files_label.config(text="No files selected")
    
    def select_encrypted_files(self):
        """Open file dialog to select encrypted files for decryption"""
        # Create file filter based on supported algorithms
        extensions = [f"*.{algo.lower()}" for algo in ALGORITHMS.keys()]
        filetypes = [("Encrypted files", " ".join(extensions))]
        
        files = filedialog.askopenfilenames(
            title="Select Encrypted Files", 
            filetypes=filetypes
        )
        
        if files:
            self.selected_files = list(files)
            self.log(f"Selected {len(files)} encrypted file(s) for decryption.")
    
    def get_password_for_file(self, filename, purpose="encryption"):
        """Get password for a file using a blocking approach"""
        # This is a blocking call that will pause the thread until the user responds
        return simpledialog.askstring(
            f"Password Required", 
            f"Enter password for {purpose} of {filename}:", 
            show='*',
            parent=self.root
        )

    def get_custom_key_for_file(self, filename):
        """Get custom key for a file using a blocking approach"""
        # This is a blocking call that will pause the thread until the user responds
        return simpledialog.askstring(
            "Custom Key Required", 
            f"Enter custom hex key for encryption of {filename}:", 
            parent=self.root
        )

    def encrypt_files(self):
        """Encrypt the selected files with progress updates"""
        if not self.selected_files:
            messagebox.showwarning("No Files", "Please select files to encrypt first.")
            return
        
        # Get encryption parameters
        algo = self.algo_var.get()
        key_type = self.key_type.get()
        threading_mode = self.threading_mode.get()
        thread_count = self.thread_count.get()
        
        # If using password-based encryption, get passwords for all files first
        passwords = {}
        custom_keys = {}
        
        if key_type.startswith('password') or key_type == 'custom_hex':
            threading_mode = 'single'
            self.log("Using single-threaded mode for password/custom key encryption.")
            
            # Get passwords/keys for all files before starting encryption
            for file_path in self.selected_files:
                file_name = os.path.basename(file_path)
                
                if key_type.startswith('password'):
                    password = simpledialog.askstring(
                        "Password Required", 
                        f"Enter password for encryption of {file_name}:", 
                        show='*',
                        parent=self.root
                    )
                    
                    if not password:
                        self.log(f"❌ Encryption skipped for {file_name}: No password provided.")
                        continue
                    
                    passwords[file_path] = password
                
                elif key_type == 'custom_hex':
                    # Always ask for custom key for each file (don't use entry field)
                    custom_key = simpledialog.askstring(
                        "Custom Key Required",
                        f"Enter custom key for encryption of {file_name}:\n(Can be text or hex)",
                        parent=self.root
                    )

                    if not custom_key:
                        self.log(f"❌ Encryption skipped for {file_name}: No custom key provided.")
                        continue

                    custom_keys[file_path] = custom_key
        
        # Create a thread to handle encryption
        encryption_thread = threading.Thread(
            target=self._encrypt_files_thread, 
            args=(algo, key_type, threading_mode, thread_count, passwords, custom_keys),
            daemon=True
        )
        encryption_thread.start()

    def _encrypt_files_thread(self, algo, key_type, threading_mode, thread_count, passwords, custom_keys):
        """Background thread for encryption with progress updates"""
        # Filter out files that don't have passwords/keys if needed
        if key_type.startswith('password'):
            files_to_process = [f for f in self.selected_files if f in passwords]
        elif key_type == 'custom_hex':
            files_to_process = [f for f in self.selected_files if f in custom_keys]
        else:
            files_to_process = self.selected_files
        
        total_files = len(files_to_process)
        processed_files = 0
        
        # Reset progress bar
        self.update_progress(0, total_files, "Preparing encryption...")
        
        # Start timing
        start_time = time.time()
        results = []  # Initialize the results list
        
        # Process files one by one
        for i, file_path in enumerate(files_to_process):
            file_name = os.path.basename(file_path)
            self.update_progress(i, total_files, f"Encrypting {file_name}...")
            
            # Get password/key for this file
            password = passwords.get(file_path) if key_type.startswith('password') else None
            custom_key = custom_keys.get(file_path) if key_type == 'custom_hex' else None
            
            try:
                # Print debug info
                print(f"Encrypting file: {file_path}")
                print(f"Algorithm: {algo}, Key type: {key_type}")
                print(f"Password provided: {'Yes' if password else 'No'}")
                print(f"Custom key provided: {'Yes' if custom_key else 'No'}")
                
                result = encrypt_worker((file_path, algo, key_type, custom_key, password))
                results.append(result)
                processed_files += 1
                
                if result['status'] == 'success':
                    self.log(f"✅ Encrypted {result['file']} → {result['output']} ({result['speed']:.2f} MB/s)")
                else:
                    self.log(f"❌ Failed to encrypt {result['file']}: {result.get('error', 'Unknown error')}")
            except Exception as e:
                import traceback
                traceback.print_exc()
                self.log(f"❌ Error processing {file_name}: {e}")
                processed_files += 1
        
        # Final progress update
        self.update_progress(total_files, total_files, "Encryption complete!")
        
        # End timing
        end_time = time.time()
        total_time = end_time - start_time
        
        # Update metrics
        total_size = sum(result.get('size', 0) for result in results if result.get('status') == 'success')
        avg_speed = total_size / total_time if total_time > 0 else 0
        
        self.log(f"Encryption completed in {total_time:.2f}s. Average speed: {avg_speed:.2f} MB/s")
        self.metrics_label.config(text=f"Last operation: Encrypted {processed_files} files in {total_time:.2f}s. Avg speed: {avg_speed:.2f} MB/s")
    
    def start_decryption(self):
        """Start the decryption process"""
        self.select_encrypted_files()
        if self.selected_files:
            self.decrypt_files()
    
    def decrypt_files(self):
        """Decrypt the selected files with progress updates"""
        if not self.selected_files:
            messagebox.showwarning("No Files", "Please select files to decrypt first.")
            return
        
        # Reset progress bar
        self.update_progress(0, 1, "Preparing decryption...")
        
        # Check which files need passwords or custom keys
        passwords = {}
        custom_keys = {}
        keys = load_key_store()

        for file_path in self.selected_files:
            base_name = os.path.basename(file_path)

            if base_name in keys:
                key_info = keys[base_name]
                algorithm = key_info.get('algorithm', '').lower()

                if 'pbkdf2' in algorithm or 'scrypt' in algorithm:
                    # This file needs a password
                    password = simpledialog.askstring(
                        "Password Required",
                        f"Enter password for decryption of {base_name}:",
                        show='*',
                        parent=self.root
                    )

                    if not password:
                        self.log(f"❌ Decryption skipped for {base_name}: No password provided.")
                        continue

                    passwords[file_path] = password

                elif algorithm in ['aes', 'des', 'blowfish', 'chacha20', 'xor', 'fernet']:
                    # This file was encrypted with a custom key, ask for it
                    custom_key = simpledialog.askstring(
                        "Custom Key Required",
                        f"Enter custom key for decryption of {base_name}:\n(Can be text or hex)",
                        parent=self.root
                    )

                    if not custom_key:
                        self.log(f"❌ Decryption skipped for {base_name}: No custom key provided.")
                        continue

                    custom_keys[file_path] = custom_key
        
        # Create a thread to handle decryption
        decryption_thread = threading.Thread(
            target=self._decrypt_files_thread,
            args=(passwords, custom_keys),
            daemon=True
        )
        decryption_thread.start()

    def _decrypt_files_thread(self, passwords, custom_keys):
        """Background thread for decryption with progress updates"""
        # Filter out files that need passwords/keys but don't have them
        files_to_process = []
        keys = load_key_store()

        for file_path in self.selected_files:
            base_name = os.path.basename(file_path)

            if base_name in keys:
                key_info = keys[base_name]
                algorithm = key_info.get('algorithm', '').lower()

                if ('pbkdf2' in algorithm or 'scrypt' in algorithm) and file_path not in passwords:
                    # Skip this file - needs password but doesn't have one
                    continue
                elif algorithm in ['aes', 'des', 'blowfish', 'chacha20', 'xor', 'fernet'] and file_path not in custom_keys:
                    # Skip this file - needs custom key but doesn't have one
                    continue

            files_to_process.append(file_path)
        
        total_files = len(files_to_process)
        processed_files = 0
        
        # Reset progress bar
        self.update_progress(0, total_files, "Preparing decryption...")
        
        # Start timing
        start_time = time.time()
        results = []  # Initialize the results list
        
        # Process files one by one
        for i, file_path in enumerate(files_to_process):
            base_name = os.path.basename(file_path)
            self.update_progress(i, total_files, f"Decrypting {base_name}...")
            
            # Get password or custom key for this file if needed
            password = passwords.get(file_path)
            custom_key = custom_keys.get(file_path)

            try:
                # Print debug info
                print(f"Decrypting file: {file_path}")
                print(f"Password provided: {'Yes' if password else 'No'}")
                print(f"Custom key provided: {'Yes' if custom_key else 'No'}")

                result = decrypt_worker((file_path, password, custom_key))
                results.append(result)
                processed_files += 1
                
                if result['status'] == 'success':
                    self.log(f"✅ Decrypted {result['file']} → {result['output']} ({result['speed']:.2f} MB/s)")
                else:
                    self.log(f"❌ Failed to decrypt {result['file']}: {result.get('error', 'Unknown error')}")
            except Exception as e:
                import traceback
                traceback.print_exc()
                self.log(f"❌ Error processing {base_name}: {e}")
                processed_files += 1
        
        # Final progress update
        self.update_progress(total_files, total_files, "Decryption complete!")
        
        # End timing
        end_time = time.time()
        total_time = end_time - start_time
        
        # Update metrics
        total_size = sum(result.get('size', 0) for result in results if result.get('status') == 'success')
        avg_speed = total_size / total_time if total_time > 0 else 0
        
        self.log(f"Decryption completed in {total_time:.2f}s. Average speed: {avg_speed:.2f} MB/s")
        self.metrics_label.config(text=f"Last operation: Decrypted {processed_files} files in {total_time:.2f}s. Avg speed: {avg_speed:.2f} MB/s")
    
    def run_performance_test(self):
        """Run performance tests with different threading configurations"""
        # Clear previous results
        self.log_results("Starting performance test...")
        
        # Get test configuration
        algo = self.test_algo_var.get()
        data_source = self.data_source.get()
        
        # Determine which files to use
        test_files = []
        
        if data_source == "generate":
            # Generate test files
            file_size = self.test_file_size.get()
            file_count = self.test_file_count.get()
            
            self.log_results(f"Generating {file_count} test files of {file_size}MB each...")
            
            for i in range(file_count):
                test_path = os.path.join(os.getcwd(), f"test_file_{i+1}_{file_size}MB.dat")
                generate_test_file(file_size, test_path)
                test_files.append(test_path)
            
            self.log_results(f"Generated {len(test_files)} test files.")
        
        elif data_source == "selected":
            # Use selected files
            if hasattr(self, 'test_files') and self.test_files:
                test_files = self.test_files
            else:
                self.log_results("❌ No test files selected. Please select files first.")
                return
        
        # Determine which threading configurations to test
        configs = []
        
        if self.test_single.get():
            configs.append(("Single-threaded", 1))
        
        if self.test_multi.get():
            configs.append((f"Multi-threaded (all {self.max_threads} cores)", self.max_threads))
        
        if self.test_custom.get():
            custom_threads = self.custom_thread_count.get()
            configs.append((f"Multi-threaded ({custom_threads} threads)", custom_threads))
        
        if not configs:
            self.log_results("❌ No threading configurations selected for testing.")
            return
        
        # Run tests for each configuration
        results = []
        
        for config_name, thread_count in configs:
            self.log_results(f"Testing {config_name}...")
            
            # Prepare arguments for workers
            args = [(file, algo, "random", None, None) for file in test_files]
            
            # Start timing
            start_time = time.time()
            
            # Process files
            if thread_count == 1:
                # Single-threaded
                for arg in args:
                    encrypt_worker(arg)
            else:
                # Multi-threaded
                with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
                    list(executor.map(encrypt_worker, args))
            
            # End timing
            end_time = time.time()
            total_time = end_time - start_time
            
            # Calculate total size
            total_size = sum(os.path.getsize(file) / (1024 * 1024) for file in test_files)
            
            # Calculate speed
            speed = total_size / total_time
            
            results.append({
                "config": config_name,
                "threads": thread_count,
                "time": total_time,
                "size": total_size,
                "speed": speed
            })
            
            self.log_results(f"{config_name}: {total_time:.2f}s, {speed:.2f} MB/s")
        
        # Calculate speedup factors
        if len(results) > 1 and self.test_single.get():
            single_result = next(r for r in results if r["threads"] == 1)
            single_time = single_result["time"]
            
            for result in results:
                if result["threads"] > 1:
                    speedup = single_time / result["time"]
                    result["speedup"] = speedup
                    self.log_results(f"Speedup with {result['config']}: {speedup:.2f}x")
        
        # Store results for graphing
        self.performance_results = results
        
        # Create graph
        self._create_performance_graph(results)

        # Clean up test files if they were generated
        if data_source == "generate":
            self.log_results("Cleaning up generated test files...")
            for file in test_files:
                try:
                    os.remove(file)
                    # Also remove encrypted versions
                    encrypted_file = f"{os.path.splitext(file)[0]}.{algo.lower()}"
                    if os.path.exists(encrypted_file):
                        os.remove(encrypted_file)
                except Exception:
                    pass
    
    def _create_performance_graph(self, results):
        """Create a performance comparison graph"""
        # Clear previous graph
        for widget in self.graph_frame.winfo_children():
            widget.destroy()
        
        if not results:
            return
        
        # Create figure and axis
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4))
        
        # Extract data
        configs = [r["config"] for r in results]
        times = [r["time"] for r in results]
        speeds = [r["speed"] for r in results]
        
        # Create time bar chart
        ax1.bar(configs, times, color='skyblue')
        ax1.set_title('Execution Time (lower is better)')
        ax1.set_ylabel('Time (seconds)')
        ax1.set_xticklabels(configs, rotation=45, ha='right')
        
        # Create speed bar chart
        ax2.bar(configs, speeds, color='lightgreen')
        ax2.set_title('Processing Speed (higher is better)')
        ax2.set_ylabel('Speed (MB/s)')
        ax2.set_xticklabels(configs, rotation=45, ha='right')
        
        # Add speedup annotations if available
        for i, result in enumerate(results):
            if "speedup" in result:
                ax2.annotate(f"{result['speedup']:.2f}x",
                            xy=(i, result["speed"]),
                            xytext=(0, 5),
                            textcoords="offset points",
                            ha='center')
        
        plt.tight_layout()
        
        # Embed in tkinter
        canvas = FigureCanvasTkAgg(fig, master=self.graph_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def view_keys(self):
        """View saved encryption keys"""
        keys = load_key_store()
        
        if not keys:
            messagebox.showinfo("No Keys", "No encryption keys found.")
            return
        
        # Create a new window to display keys
        key_window = tk.Toplevel(self.root)
        key_window.title("Saved Encryption Keys")
        key_window.geometry("800x600")
        
        # Create a frame for the keys
        frame = ttk.Frame(key_window)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create a treeview to display the keys
        columns = ("File", "Algorithm", "Key")
        tree = ttk.Treeview(frame, columns=columns, show="headings")
        
        # Set column headings
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=100)
        
        # Set column widths
        tree.column("File", width=200)
        tree.column("Algorithm", width=100)
        tree.column("Key", width=400)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Add keys to the treeview
        for filename, key_info in keys.items():
            algorithm = key_info.get("algorithm", "Unknown")
            key_value = key_info.get("key", "N/A")

            # Handle None key values
            if key_value is None:
                display_key = "Password-based (no key stored)"
            elif isinstance(key_value, str) and len(key_value) > 40:
                display_key = key_value[:37] + "..."
            else:
                display_key = str(key_value) if key_value is not None else "N/A"

            tree.insert("", tk.END, values=(filename, algorithm, display_key))
        
        # Add buttons
        button_frame = ttk.Frame(key_window)
        button_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(button_frame, text="Close", command=key_window.destroy).pack(side=tk.RIGHT, padx=10)
        ttk.Button(button_frame, text="Export Keys", command=lambda: self.export_keys(keys)).pack(side=tk.RIGHT, padx=10)
    
    def log(self, message):
        """Add a message to the status text area"""
        print(f"Log: {message}")  # Debug print
        try:
            self.status_text.config(state='normal')
            self.status_text.insert(tk.END, message + "\n")
            self.status_text.see(tk.END)
            self.status_text.config(state='disabled')
            self.root.update_idletasks()
        except Exception as e:
            print(f"Error logging message: {e}")
    
    def log_results(self, message):
        """Add a message to the results text area"""
        self.results_text.config(state='normal')
        self.results_text.insert(tk.END, message + "\n")
        self.results_text.see(tk.END)
        self.results_text.config(state='disabled')
        self.root.update_idletasks()
    
    def handle_drop(self, event):
        """Handle files dropped onto the application"""
        files = self.parse_drop_data(event.data)
        if files:
            self.selected_files = files
            self.log(f"Dropped {len(files)} file(s).")
            
            # Determine if files are encrypted or not
            encrypted_count = sum(1 for f in files if any(f.lower().endswith(f".{algo.lower()}") 
                                                         for algo in ALGORITHMS.keys()))
            
            if encrypted_count == len(files):
                # All files appear to be encrypted
                self.log("All files appear to be encrypted. Preparing for decryption...")
                self.decrypt_files()
            else:
                # Some or all files are not encrypted
                self.log("Files ready for encryption.")
    
    def parse_drop_data(self, data):
        """Parse the data from a drop event"""
        if not data:
            return []
            
        files = []
        # Handle different formats of drop data
        if isinstance(data, str):
            if os.name == 'nt':  # Windows
                for filename in data.split(' '):
                    # Remove curly braces and quotes that Windows might add
                    filename = filename.strip('{}')
                    if os.path.exists(filename):
                        files.append(filename)
            else:  # Unix-like
                for filename in data.split('\n'):
                    if filename.startswith('file://'):
                        filename = filename[7:]  # Remove 'file://'
                    if os.path.exists(filename):
                        files.append(filename)
        return files
    
    def update_progress(self, current, total, message=""):
        """Update the progress bar and message"""
        try:
            progress = int(100 * current / total) if total > 0 else 0
            self.progress_bar["value"] = progress
            self.progress_text.config(text=f"{progress}%")
            if message:
                self.progress_label.config(text=message)
            self.root.update_idletasks()
        except Exception as e:
            print(f"Error updating progress: {e}")

    def export_keys(self, keys=None):
        """Export encryption keys to a file"""
        if keys is None:
            keys = load_key_store()
        
        if not keys:
            messagebox.showinfo("No Keys", "No encryption keys to export.")
            return
        
        # Ask for a file to save to
        file_path = filedialog.asksaveasfilename(
            title="Export Keys",
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")]
        )
        
        if not file_path:
            return
        
        try:
            with open(file_path, 'w') as f:
                json.dump(keys, f, indent=4)
            
            self.log(f"✅ Exported {len(keys)} keys to {file_path}")
            messagebox.showinfo("Export Successful", f"Exported {len(keys)} keys to {file_path}")
        except Exception as e:
            self.log(f"❌ Failed to export keys: {e}")
            messagebox.showerror("Export Failed", f"Failed to export keys: {e}")

if __name__ == '__main__':
    print("Starting File Encryptor application...")
    multiprocessing.freeze_support()
    
    # Create a basic Tkinter window
    root = tk.Tk()
    root.title("File Encryptor")
    print("Created root window")
    
    # Create the application
    app = FileEncryptorApp(root)
    print("Created application")
    
    # Start the main event loop
    print("Starting main loop")
    root.mainloop()
    print("Application closed")
