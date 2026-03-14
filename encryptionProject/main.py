import tkinter as tk
from tkinter import messagebox, filedialog, scrolledtext, ttk
import base64
import rsa
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from hashlib import sha256
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import numpy as np
import string
import math
import random
import os

# Modern color scheme - Dark Professional Theme
COLORS = {
    'bg': '#0f172a',  # Slate 900 - Main background
    'card': '#1e293b',  # Slate 800 - Card backgrounds
    'accent': '#3b82f6',  # Blue 500 - Primary buttons
    'accent_hover': '#2563eb',  # Blue 600 - Button hover
    'success': '#10b981',  # Emerald 500 - Success states
    'warning': '#f59e0b',  # Amber 500 - Warnings
    'danger': '#ef4444',  # Red 500 - Errors/Danger
    'purple': '#8b5cf6',  # Violet 500 - Secondary accent
    'text': '#f8fafc',  # Slate 50 - Primary text
    'text_muted': '#94a3b8',  # Slate 400 - Secondary text
    'border': '#334155',  # Slate 700 - Borders
    'input_bg': '#1e293b'  # Input background
}


# ==================== CRYPTOGRAPHY CLASSES ====================

class AESCipher:
    """AES-256 Encryption/Decryption with CBC mode"""

    @staticmethod
    def encrypt(plaintext: str, key: bytes) -> str:
        cipher = AES.new(key, AES.MODE_CBC)
        ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
        iv = base64.b64encode(cipher.iv).decode('utf-8')
        cipher_text = base64.b64encode(ciphertext).decode('utf-8')
        return iv + ":" + cipher_text

    @staticmethod
    def decrypt(ciphertext: str, key: bytes) -> str:
        try:
            iv, cipher_text = ciphertext.split(":")
            iv = base64.b64decode(iv)
            cipher_text = base64.b64decode(cipher_text)
            cipher = AES.new(key, AES.MODE_CBC, iv=iv)
            plaintext = unpad(cipher.decrypt(cipher_text), AES.block_size)
            return plaintext.decode('utf-8')
        except Exception as e:
            raise ValueError(f"AES Decryption failed: {str(e)}")


class DESCipher:
    """DES Encryption/Decryption with CBC mode (Legacy - for educational purposes)"""

    @staticmethod
    def encrypt(plaintext: str, key: bytes) -> str:
        cipher = DES.new(key, DES.MODE_CBC)
        ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), DES.block_size))
        iv = base64.b64encode(cipher.iv).decode('utf-8')
        cipher_text = base64.b64encode(ciphertext).decode('utf-8')
        return iv + ":" + cipher_text

    @staticmethod
    def decrypt(ciphertext: str, key: bytes) -> str:
        try:
            iv, cipher_text = ciphertext.split(":")
            iv = base64.b64decode(iv)
            cipher_text = base64.b64decode(cipher_text)
            cipher = DES.new(key, DES.MODE_CBC, iv=iv)
            plaintext = unpad(cipher.decrypt(cipher_text), DES.block_size)
            return plaintext.decode('utf-8')
        except Exception as e:
            raise ValueError(f"DES Decryption failed: {str(e)}")


class RSACipher:
    """RSA Encryption/Decryption with 2048-bit keys and chunking support"""

    @staticmethod
    def generate_keys(bits=2048):
        return rsa.newkeys(bits)

    @staticmethod
    def encrypt(plaintext: str, public_key) -> str:
        # RSA has size limits (245 bytes for 2048-bit key with PKCS#1 v1.5 padding)
        max_length = 245
        chunks = [plaintext[i:i + max_length] for i in range(0, len(plaintext), max_length)]
        encrypted_chunks = [rsa.encrypt(chunk.encode('utf-8'), public_key) for chunk in chunks]
        return base64.b64encode(b'|'.join(encrypted_chunks)).decode('utf-8')

    @staticmethod
    def decrypt(ciphertext: str, private_key) -> str:
        try:
            encrypted_chunks = base64.b64decode(ciphertext).split(b'|')
            decrypted_chunks = [rsa.decrypt(chunk, private_key).decode('utf-8') for chunk in encrypted_chunks]
            return ''.join(decrypted_chunks)
        except Exception as e:
            raise ValueError(f"RSA Decryption failed: {str(e)}")


class Hasher:
    """SHA-256 Hashing"""

    @staticmethod
    def hash(plaintext: str) -> str:
        return sha256(plaintext.encode('utf-8')).hexdigest()


# ==================== MACHINE LEARNING ====================

class FeatureExtractor:
    """Extract statistical features from ciphertext for ML classification"""

    @staticmethod
    def extract_features(ciphertext: str) -> np.ndarray:
        try:
            decoded = base64.b64decode(ciphertext)
            length = len(decoded)
            is_base64 = 1
        except Exception:
            decoded = ciphertext.encode('utf-8')
            length = len(decoded)
            is_base64 = 0

        entropy = FeatureExtractor.calculate_entropy(decoded)
        byte_freq = FeatureExtractor.byte_frequency(decoded)
        hash_detected = 1 if len(ciphertext) == 64 and all(c in "0123456789abcdef" for c in ciphertext) else 0

        return np.array([length, is_base64, entropy, hash_detected] + byte_freq)

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        total = len(data)
        entropy = -sum((f / total) * math.log2(f / total) for f in freq if f > 0)
        return entropy

    @staticmethod
    def byte_frequency(data: bytes) -> list:
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        total = len(data)
        return [f / total for f in freq]


class TrainingDataGenerator:
    """Generate synthetic training data for the classifier"""

    @staticmethod
    def generate():
        aes_key = get_random_bytes(16)
        des_key = get_random_bytes(8)
        public_key, _ = RSACipher.generate_keys()

        features = []
        labels = []

        for _ in range(500):
            plaintext = ''.join(random.choices(string.ascii_letters + string.digits, k=50))

            # AES
            aes_cipher = AESCipher.encrypt(plaintext, aes_key)
            features.append(FeatureExtractor.extract_features(aes_cipher))
            labels.append(0)  # AES

            # DES
            des_cipher = DESCipher.encrypt(plaintext, des_key)
            features.append(FeatureExtractor.extract_features(des_cipher))
            labels.append(1)  # DES

            # RSA
            rsa_cipher = RSACipher.encrypt(plaintext, public_key)
            features.append(FeatureExtractor.extract_features(rsa_cipher))
            labels.append(2)  # RSA

            # SHA-256 Hash
            hash_value = Hasher.hash(plaintext)
            features.append(FeatureExtractor.extract_features(hash_value))
            labels.append(3)  # SHA-256

        return np.array(features), np.array(labels)


class ClassifierTrainer:
    """Train Random Forest classifier"""

    @staticmethod
    def train():
        features, labels = TrainingDataGenerator.generate()
        X_train, X_test, y_train, y_test = train_test_split(
            features, labels, test_size=0.2, random_state=42
        )
        clf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
        clf.fit(X_train, y_train)
        accuracy = clf.score(X_test, y_test) * 100
        return clf, accuracy


# ==================== MODERN UI COMPONENTS ====================

class ModernButton(tk.Canvas):
    """Custom rounded button with hover effects"""

    def __init__(self, parent, text, command, bg_color=COLORS['accent'],
                 fg_color=COLORS['text'], width=200, height=40, font_size=11):
        super().__init__(parent, width=width, height=height, bg=COLORS['bg'],
                         highlightthickness=0, cursor="hand2")
        self.command = command
        self.bg_color = bg_color
        self.hover_color = COLORS['accent_hover'] if bg_color == COLORS['accent'] else bg_color
        self.current_color = bg_color

        # Draw rounded rectangle
        self.round_rect = self.create_rounded_rect(5, 5, width - 5, height - 5, 20, fill=bg_color, outline="")
        self.text_item = self.create_text(width // 2, height // 2, text=text,
                                          fill=fg_color, font=("Segoe UI", font_size, "bold"))

        self.bind("<Enter>", self.on_enter)
        self.bind("<Leave>", self.on_leave)
        self.bind("<Button-1>", self.on_click)
        self.bind("<ButtonRelease-1>", self.on_release)

    def create_rounded_rect(self, x1, y1, x2, y2, radius, **kwargs):
        points = [x1 + radius, y1, x2 - radius, y1, x2, y1, x2, y1 + radius,
                  x2, y2 - radius, x2, y2, x2 - radius, y2, x1 + radius, y2,
                  x1, y2, x1, y2 - radius, x1, y1 + radius, x1, y1]
        return self.create_polygon(points, smooth=True, **kwargs)

    def on_enter(self, event):
        self.current_color = self.hover_color
        self.itemconfig(self.round_rect, fill=self.hover_color)

    def on_leave(self, event):
        self.current_color = self.bg_color
        self.itemconfig(self.round_rect, fill=self.bg_color)

    def on_click(self, event):
        self.itemconfig(self.round_rect, fill=self._darken_color(self.current_color))

    def on_release(self, event):
        self.itemconfig(self.round_rect, fill=self.current_color)
        self.command()

    def _darken_color(self, hex_color):
        # Simple darken effect
        return hex_color


class ModernTextArea(tk.Frame):
    """Custom styled text area with label"""

    def __init__(self, parent, label_text, height=8, read_only=False):
        super().__init__(parent, bg=COLORS['bg'])

        # Label
        self.label = tk.Label(self, text=label_text, bg=COLORS['bg'],
                              fg=COLORS['text'], font=("Segoe UI", 10, "bold"),
                              anchor="w")
        self.label.pack(fill="x", pady=(0, 5))

        # Container for text and scrollbar
        self.container = tk.Frame(self, bg=COLORS['border'], bd=1)
        self.container.pack(fill="both", expand=True)

        # Text widget
        self.text = tk.Text(self.container, height=height, bg=COLORS['input_bg'],
                            fg=COLORS['text'], font=("Consolas", 10),
                            relief="flat", padx=10, pady=10,
                            insertbackground=COLORS['text'],
                            selectbackground=COLORS['accent'],
                            selectforeground=COLORS['text'],
                            wrap="word")
        self.text.pack(side="left", fill="both", expand=True)

        if read_only:
            self.text.config(state="disabled")

        # Scrollbar
        self.scrollbar = tk.Scrollbar(self.container, bg=COLORS['card'],
                                      troughcolor=COLORS['bg'],
                                      activebackground=COLORS['accent'],
                                      highlightbackground=COLORS['border'])
        self.scrollbar.pack(side="right", fill="y")

        self.text.config(yscrollcommand=self.scrollbar.set)
        self.scrollbar.config(command=self.text.yview)


class CryptoApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("🔐 AI Crypto Analysis Tool")
        self.geometry("1200x800")
        self.configure(bg=COLORS['bg'])
        self.minsize(1000, 700)

        # Initialize keys
        self.aes_key = get_random_bytes(16)
        self.des_key = get_random_bytes(8)
        self.rsa_public, self.rsa_private = RSACipher.generate_keys()

        # Status bar
        self.status_var = tk.StringVar(value="Initializing AI Classifier...")

        # Train classifier in background
        self.classifier, self.accuracy = ClassifierTrainer.train()
        self.status_var.set(f"AI Classifier Ready | Accuracy: {self.accuracy:.1f}%")

        self.setup_styles()
        self.create_widgets()

    def setup_styles(self):
        """Configure ttk styles for modern look"""
        self.style = ttk.Style()
        self.style.theme_use('clam')

        # Configure styles
        self.style.configure("Custom.TNotebook", background=COLORS['bg'],
                             tabmargins=[2, 5, 2, 0])
        self.style.configure("Custom.TNotebook.Tab", background=COLORS['card'],
                             foreground=COLORS['text'], padding=[15, 5],
                             font=("Segoe UI", 9))
        self.style.map("Custom.TNotebook.Tab",
                       background=[("selected", COLORS['accent']), ("active", COLORS['border'])],
                       foreground=[("selected", COLORS['text']), ("active", COLORS['text'])])

        # Combobox style
        self.style.configure("Custom.TCombobox", fieldbackground=COLORS['input_bg'],
                             background=COLORS['accent'], foreground=COLORS['text'])

    def create_widgets(self):
        # Main container with padding
        self.main_container = tk.Frame(self, bg=COLORS['bg'])
        self.main_container.pack(fill="both", expand=True, padx=20, pady=20)

        # Header
        self.create_header()

        # Notebook (Tabs)
        self.notebook = ttk.Notebook(self.main_container, style="Custom.TNotebook")
        self.notebook.pack(fill="both", expand=True, pady=20)

        # Tab 1: Encryption/Decryption
        self.encrypt_tab = tk.Frame(self.notebook, bg=COLORS['bg'])
        self.notebook.add(self.encrypt_tab, text="  🔒 Encrypt/Decrypt  ")
        self.create_encrypt_tab()

        # Tab 2: Hashing
        self.hash_tab = tk.Frame(self.notebook, bg=COLORS['bg'])
        self.notebook.add(self.hash_tab, text="  #️⃣ Hashing  ")
        self.create_hash_tab()

        # Tab 3: AI Analysis
        self.analysis_tab = tk.Frame(self.notebook, bg=COLORS['bg'])
        self.notebook.add(self.analysis_tab, text="  🤖 AI Analysis  ")
        self.create_analysis_tab()

        # Tab 4: Key Management
        self.keys_tab = tk.Frame(self.notebook, bg=COLORS['bg'])
        self.notebook.add(self.keys_tab, text="  🔑 Keys & Info  ")
        self.create_keys_tab()

        # Status bar
        self.status_bar = tk.Label(self, textvariable=self.status_var,
                                   bg=COLORS['card'], fg=COLORS['text_muted'],
                                   font=("Segoe UI", 9), anchor="w", padx=10)
        self.status_bar.pack(fill="x", side="bottom")

    def create_header(self):
        header = tk.Frame(self.main_container, bg=COLORS['bg'])
        header.pack(fill="x")

        title = tk.Label(header, text="🔐 AI Crypto Analysis Tool",
                         bg=COLORS['bg'], fg=COLORS['text'],
                         font=("Segoe UI", 24, "bold"))
        title.pack(side="left")

        subtitle = tk.Label(header, text="Advanced Encryption & Machine Learning Classification",
                            bg=COLORS['bg'], fg=COLORS['text_muted'],
                            font=("Segoe UI", 11))
        subtitle.pack(side="left", padx=15, pady=10)

    def create_encrypt_tab(self):
        # Left panel - Input
        left_panel = tk.Frame(self.encrypt_tab, bg=COLORS['bg'])
        left_panel.pack(side="left", fill="both", expand=True, padx=(0, 10))

        # Algorithm selection
        algo_frame = tk.Frame(left_panel, bg=COLORS['bg'])
        algo_frame.pack(fill="x", pady=(0, 10))

        tk.Label(algo_frame, text="Algorithm:", bg=COLORS['bg'],
                 fg=COLORS['text'], font=("Segoe UI", 10, "bold")).pack(side="left")

        self.algo_var = tk.StringVar(value="AES")
        algo_combo = ttk.Combobox(algo_frame, textvariable=self.algo_var,
                                  values=["AES", "DES", "RSA"],
                                  state="readonly", width=15, font=("Segoe UI", 10))
        algo_combo.pack(side="left", padx=10)

        # Mode selection
        self.mode_var = tk.StringVar(value="Encrypt")
        modes = [("Encrypt", "Encrypt"), ("Decrypt", "Decrypt")]
        for text, mode in modes:
            tk.Radiobutton(algo_frame, text=text, variable=self.mode_var, value=mode,
                           bg=COLORS['bg'], fg=COLORS['text'], selectcolor=COLORS['card'],
                           activebackground=COLORS['bg'], font=("Segoe UI", 10)).pack(side="left", padx=5)

        # Input area
        self.input_area = ModernTextArea(left_panel, "Input Text:", height=12)
        self.input_area.pack(fill="both", expand=True, pady=10)

        # Action buttons
        btn_frame = tk.Frame(left_panel, bg=COLORS['bg'])
        btn_frame.pack(fill="x", pady=10)

        self.process_btn = ModernButton(btn_frame, "Process", self.process_crypto,
                                        width=150, height=40)
        self.process_btn.pack(side="left", padx=5)

        self.clear_btn = ModernButton(btn_frame, "Clear", self.clear_all,
                                      bg_color=COLORS['danger'], width=100, height=40)
        self.clear_btn.pack(side="left", padx=5)

        self.copy_btn = ModernButton(btn_frame, "Copy Result", self.copy_result,
                                     bg_color=COLORS['purple'], width=120, height=40)
        self.copy_btn.pack(side="left", padx=5)

        # Right panel - Output
        right_panel = tk.Frame(self.encrypt_tab, bg=COLORS['bg'])
        right_panel.pack(side="right", fill="both", expand=True, padx=(10, 0))

        self.output_area = ModernTextArea(right_panel, "Output:", height=20, read_only=False)
        self.output_area.pack(fill="both", expand=True)

    def create_hash_tab(self):
        # Input
        self.hash_input = ModernTextArea(self.hash_tab, "Text to Hash:", height=10)
        self.hash_input.pack(fill="both", expand=True, padx=100, pady=10)

        # Buttons
        btn_frame = tk.Frame(self.hash_tab, bg=COLORS['bg'])
        btn_frame.pack(pady=20)

        hash_btn = ModernButton(btn_frame, "Generate SHA-256 Hash", self.generate_hash,
                                width=250, height=45, bg_color=COLORS['success'])
        hash_btn.pack()

        # Result
        self.hash_result = ModernTextArea(self.hash_tab, "Hash Result:", height=3, read_only=False)
        self.hash_result.pack(fill="x", padx=100, pady=10)

        # Verify section
        verify_frame = tk.Frame(self.hash_tab, bg=COLORS['bg'])
        verify_frame.pack(fill="x", padx=100, pady=10)

        tk.Label(verify_frame, text="Verify Hash:", bg=COLORS['bg'],
                 fg=COLORS['text'], font=("Segoe UI", 10, "bold")).pack(anchor="w")

        self.verify_entry = tk.Entry(verify_frame, bg=COLORS['input_bg'], fg=COLORS['text'],
                                     font=("Consolas", 10), relief="flat",
                                     highlightthickness=1, highlightcolor=COLORS['accent'],
                                     highlightbackground=COLORS['border'])
        self.verify_entry.pack(fill="x", pady=5, ipady=8)

        verify_btn = ModernButton(verify_frame, "Verify", self.verify_hash,
                                  width=120, height=35, bg_color=COLORS['warning'])
        verify_btn.pack(pady=5)

        self.verify_result = tk.Label(verify_frame, text="", bg=COLORS['bg'],
                                      font=("Segoe UI", 10, "bold"))
        self.verify_result.pack()

    def create_analysis_tab(self):
        # Description
        desc = tk.Label(self.analysis_tab,
                        text="Paste any ciphertext or hash to identify the encryption algorithm using AI",
                        bg=COLORS['bg'], fg=COLORS['text_muted'], font=("Segoe UI", 11))
        desc.pack(pady=10)

        # Input
        self.analysis_input = ModernTextArea(self.analysis_tab, "Ciphertext to Analyze:", height=10)
        self.analysis_input.pack(fill="x", padx=50, pady=10)

        # Analyze button
        analyze_btn = ModernButton(self.analysis_tab, "🔍 Analyze with AI", self.analyze_text,
                                   width=250, height=50, bg_color=COLORS['purple'], font_size=12)
        analyze_btn.pack(pady=20)

        # Results frame
        self.result_frame = tk.Frame(self.analysis_tab, bg=COLORS['card'], bd=2, relief="flat")
        self.result_frame.pack(fill="both", expand=True, padx=50, pady=10)

        # Result labels
        self.result_title = tk.Label(self.result_frame, text="Analysis Results",
                                     bg=COLORS['card'], fg=COLORS['text'],
                                     font=("Segoe UI", 16, "bold"))
        self.result_title.pack(pady=20)

        self.prediction_label = tk.Label(self.result_frame, text="Algorithm: -",
                                         bg=COLORS['card'], fg=COLORS['text_muted'],
                                         font=("Segoe UI", 14))
        self.prediction_label.pack(pady=10)

        self.confidence_label = tk.Label(self.result_frame, text="Confidence: -",
                                         bg=COLORS['card'], fg=COLORS['text_muted'],
                                         font=("Segoe UI", 12))
        self.confidence_label.pack(pady=5)

        self.features_label = tk.Label(self.result_frame, text="", bg=COLORS['card'],
                                       fg=COLORS['text_muted'], font=("Consolas", 10),
                                       wraplength=800, justify="left")
        self.features_label.pack(pady=20)

    def create_keys_tab(self):
        # Info cards
        info_frame = tk.Frame(self.keys_tab, bg=COLORS['bg'])
        info_frame.pack(fill="both", expand=True, padx=50, pady=20)

        # AES Card
        aes_card = self.create_info_card(info_frame, "AES-256 Key",
                                         base64.b64encode(self.aes_key).decode(),
                                         COLORS['success'])
        aes_card.pack(fill="x", pady=10)

        # DES Card
        des_card = self.create_info_card(info_frame, "DES Key",
                                         base64.b64encode(self.des_key).decode(),
                                         COLORS['warning'])
        des_card.pack(fill="x", pady=10)

        # RSA Info
        rsa_frame = tk.Frame(info_frame, bg=COLORS['card'], padx=20, pady=20)
        rsa_frame.pack(fill="x", pady=10)

        tk.Label(rsa_frame, text="RSA Key Pair (2048-bit)", bg=COLORS['card'],
                 fg=COLORS['text'], font=("Segoe UI", 12, "bold")).pack(anchor="w")

        tk.Label(rsa_frame, text=f"Public Key: {str(self.rsa_public)[:50]}...",
                 bg=COLORS['card'], fg=COLORS['text_muted'],
                 font=("Consolas", 9)).pack(anchor="w", pady=5)

        # Regenerate button
        regen_btn = ModernButton(self.keys_tab, "Regenerate All Keys", self.regenerate_keys,
                                 width=250, height=45, bg_color=COLORS['danger'])
        regen_btn.pack(pady=20)

        # Algorithm info
        info_text = """
Algorithm Information:

• AES-256 (Advanced Encryption Standard)
  - Block size: 128 bits | Key size: 256 bits
  - Mode: CBC (Cipher Block Chaining)
  - Industry standard for symmetric encryption

• DES (Data Encryption Standard) - Legacy
  - Block size: 64 bits | Key size: 56 bits
  - Mode: CBC
  - ⚠️ Considered insecure for modern use

• RSA (Rivest–Shamir–Adleman)
  - Key size: 2048 bits
  - Asymmetric encryption with public/private key pair
  - Used for secure key exchange and digital signatures

• SHA-256 (Secure Hash Algorithm)
  - Produces 256-bit (64 hex character) hash
  - One-way function - cannot be decrypted
  - Used for data integrity verification
        """

        info_label = tk.Label(self.keys_tab, text=info_text, bg=COLORS['bg'],
                              fg=COLORS['text_muted'], font=("Consolas", 10),
                              justify="left", anchor="w")
        info_label.pack(pady=20)

    def create_info_card(self, parent, title, content, color):
        card = tk.Frame(parent, bg=COLORS['card'], padx=20, pady=15)

        tk.Label(card, text=title, bg=COLORS['card'], fg=color,
                 font=("Segoe UI", 12, "bold")).pack(anchor="w")

        content_label = tk.Label(card, text=content, bg=COLORS['card'],
                                 fg=COLORS['text_muted'], font=("Consolas", 10),
                                 wraplength=800)
        content_label.pack(anchor="w", pady=5)

        # Copy button
        copy_btn = tk.Button(card, text="Copy", command=lambda: self.copy_to_clipboard(content),
                             bg=COLORS['border'], fg=COLORS['text'], relief="flat",
                             font=("Segoe UI", 9), cursor="hand2")
        copy_btn.pack(anchor="e")

        return card

    # ==================== ACTIONS ====================

    def process_crypto(self):
        text = self.input_area.text.get("1.0", "end-1c").strip()
        if not text:
            messagebox.showwarning("Warning", "Please enter text to process")
            return

        algo = self.algo_var.get()
        mode = self.mode_var.get()

        try:
            if algo == "AES":
                if mode == "Encrypt":
                    result = AESCipher.encrypt(text, self.aes_key)
                else:
                    result = AESCipher.decrypt(text, self.aes_key)
            elif algo == "DES":
                if mode == "Encrypt":
                    result = DESCipher.encrypt(text, self.des_key)
                else:
                    result = DESCipher.decrypt(text, self.des_key)
            elif algo == "RSA":
                if mode == "Encrypt":
                    result = RSACipher.encrypt(text, self.rsa_public)
                else:
                    result = RSACipher.decrypt(text, self.rsa_private)

            self.output_area.text.delete("1.0", "end")
            self.output_area.text.insert("1.0", result)
            self.status_var.set(f"Processed with {algo} - {mode}")

        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.status_var.set("Error occurred during processing")

    def generate_hash(self):
        text = self.hash_input.text.get("1.0", "end-1c").strip()
        if not text:
            messagebox.showwarning("Warning", "Please enter text to hash")
            return

        hash_val = Hasher.hash(text)
        self.hash_result.text.delete("1.0", "end")
        self.hash_result.text.insert("1.0", hash_val)
        self.status_var.set("SHA-256 hash generated")

    def verify_hash(self):
        text = self.hash_input.text.get("1.0", "end-1c").strip()
        hash_to_verify = self.verify_entry.get().strip()

        if not text or not hash_to_verify:
            messagebox.showwarning("Warning", "Please enter both text and hash to verify")
            return

        generated = Hasher.hash(text)
        if generated == hash_to_verify:
            self.verify_result.config(text="✅ Hash Verified Successfully!", fg=COLORS['success'])
        else:
            self.verify_result.config(text="❌ Hash Does Not Match!", fg=COLORS['danger'])

    def analyze_text(self):
        ciphertext = self.analysis_input.text.get("1.0", "end-1c").strip()
        if not ciphertext:
            messagebox.showwarning("Warning", "Please enter ciphertext to analyze")
            return

        try:
            features = FeatureExtractor.extract_features(ciphertext).reshape(1, -1)
            prediction = self.classifier.predict(features)[0]
            probabilities = self.classifier.predict_proba(features)[0]

            labels = ["AES", "DES", "RSA", "SHA-256 Hash"]
            confidence = probabilities[prediction] * 100

            self.prediction_label.config(
                text=f"Detected Algorithm: {labels[prediction]}",
                fg=COLORS['success'] if confidence > 80 else COLORS['warning']
            )
            self.confidence_label.config(text=f"Confidence: {confidence:.1f}%")

            # Feature details
            entropy = features[0][2]
            is_base64 = "Yes" if features[0][1] == 1 else "No"
            length = int(features[0][0])

            details = f"""Features Detected:
• Length: {length} bytes
• Base64 Encoded: {is_base64}
• Entropy: {entropy:.2f} (High randomness indicates strong encryption)
• Hash Pattern: {"Yes" if features[0][3] == 1 else "No"}"""

            self.features_label.config(text=details)
            self.status_var.set(f"Analysis complete: {labels[prediction]} detected")

        except Exception as e:
            messagebox.showerror("Error", f"Analysis failed: {str(e)}")
            self.status_var.set("Analysis failed")

    def regenerate_keys(self):
        if messagebox.askyesno("Confirm", "Regenerate all keys? This will invalidate previous encryptions."):
            self.aes_key = get_random_bytes(16)
            self.des_key = get_random_bytes(8)
            self.rsa_public, self.rsa_private = RSACipher.generate_keys()

            # Refresh keys tab
            for widget in self.keys_tab.winfo_children():
                widget.destroy()
            self.create_keys_tab()

            self.status_var.set("All keys regenerated successfully")
            messagebox.showinfo("Success", "New keys generated successfully!")

    def clear_all(self):
        self.input_area.text.delete("1.0", "end")
        self.output_area.text.delete("1.0", "end")
        self.status_var.set("Cleared")

    def copy_result(self):
        result = self.output_area.text.get("1.0", "end-1c")
        if result:
            self.copy_to_clipboard(result)
            self.status_var.set("Result copied to clipboard")

    def copy_to_clipboard(self, text):
        self.clipboard_clear()
        self.clipboard_append(text)


if __name__ == "__main__":
    app = CryptoApp()
    app.mainloop()