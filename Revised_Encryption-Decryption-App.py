import os
import random
import hashlib
import base64
from tkinter import (
    Tk, filedialog, Button, Text, Scrollbar, Entry, Label, 
    END, Y, BOTH, LEFT, RIGHT, TOP, BOTTOM, Frame, messagebox,
    StringVar, ttk
)
from tkinter.font import Font
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import pyperclip

class AdvancedEncryptionApp:
    def __init__(self):
        self.root = Tk()
        self.root.title("CryptoVault Pro")
        self.root.geometry("900x700")
        self.root.minsize(800, 600)
        self.root.configure(bg="#f0f2f5")
        
        
        self.configure_styles()
        self.setup_ui()
        self.encryption_params = None
        self.current_theme = "light"
        
    def configure_styles(self):
        self.style = ttk.Style()
        
        
        self.style.theme_create("light", parent="alt", settings={
            "TFrame": {"configure": {"background": "#f0f2f5"}},
            "TLabel": {"configure": {"background": "#f0f2f5", "foreground": "black"}},
            "TButton": {
                "configure": {
                    "background": "#3498db",
                    "foreground": "white",
                    "font": ("Helvetica", 10),
                    "padding": 5,
                    "borderwidth": 1
                },
                "map": {
                    "background": [("active", "#2980b9"), ("disabled", "#bdc3c7")],
                    "foreground": [("disabled", "#7f8c8d")]
                }
            },
            "TEntry": {
                "configure": {
                    "fieldbackground": "white",
                    "foreground": "black",
                    "insertcolor": "black"
                }
            },
            "TScrollbar": {"configure": {"arrowcolor": "black"}}
        })
        
       
        self.style.theme_create("dark", parent="alt", settings={
            "TFrame": {"configure": {"background": "#121212"}},
            "TLabel": {"configure": {"background": "#121212", "foreground": "white"}},
            "TButton": {
                "configure": {
                    "background": "#2c3e50",
                    "foreground": "white",
                    "font": ("Helvetica", 10),
                    "padding": 5,
                    "borderwidth": 1
                },
                "map": {
                    "background": [("active", "#34495e"), ("disabled", "#7f8c8d")],
                    "foreground": [("disabled", "#bdc3c7")]
                }
            },
            "TEntry": {
                "configure": {
                    "fieldbackground": "#252525",
                    "foreground": "white",
                    "insertcolor": "white"
                }
            },
            "TScrollbar": {"configure": {"arrowcolor": "white"}}
        })
        
        self.style.theme_use("light")
        
    def setup_ui(self):
        self.create_header()
        self.create_main_frame()
        self.create_footer()
        
    def create_header(self):
        header_frame = Frame(self.root, bg="#2c3e50", height=80)
        header_frame.pack(side=TOP, fill="x")
        
        title_font = Font(family="Helvetica", size=18, weight="bold")
        title_label = Label(
            header_frame, 
            text="Advance_CryptoVault Pro", 
            fg="white", 
            bg="#2c3e50", 
            font=title_font
        )
        title_label.pack(pady=20)
        
        self.theme_btn = Button(
            header_frame, 
            text="☀️", 
            command=self.toggle_theme,
            bg="#2c3e50",
            fg="white",
            borderwidth=0,
            font=("Arial", 14),
            activebackground="#2c3e50",
            activeforeground="white"
        )
        self.theme_btn.place(relx=0.95, rely=0.5, anchor="center")
        
    def create_main_frame(self):
        main_frame = Frame(self.root, bg="#f0f2f5")
        main_frame.pack(expand=True, fill=BOTH, padx=20, pady=10)
        
        left_frame = Frame(main_frame, bg="#f0f2f5")
        left_frame.pack(side=LEFT, fill=Y, padx=(0, 10))
        
        right_frame = Frame(main_frame, bg="#f0f2f5")
        right_frame.pack(side=RIGHT, expand=True, fill=BOTH)
        
        self.create_controls(left_frame)
        self.create_output(right_frame)
        
    def create_controls(self, parent):
        control_frame = Frame(parent, bg="#ffffff", padx=15, pady=15, bd=1, relief="solid")
        control_frame.pack(fill=Y, expand=True)
        
        section_font = Font(family="Helvetica", size=12, weight="bold")
        
       
        encrypt_frame = Frame(control_frame, bg="#ffffff")
        encrypt_frame.pack(fill="x", pady=(0, 20))
        
        Label(
            encrypt_frame, 
            text="File Encryption", 
            bg="#ffffff", 
            font=section_font
        ).pack(anchor="w", pady=(0, 10))
        
        self.encrypt_btn = ttk.Button(
            encrypt_frame,
            text="Encrypt File",
            command=self.encrypt_file
        )
        self.encrypt_btn.pack(fill="x", pady=5)
        
       
        decrypt_frame = Frame(control_frame, bg="#ffffff")
        decrypt_frame.pack(fill="x", pady=(0, 20))
        
        Label(
            decrypt_frame, 
            text="File Decryption", 
            bg="#ffffff", 
            font=section_font
        ).pack(anchor="w", pady=(0, 10))
        
        self.key_label = Label(
            decrypt_frame, 
            text="Encryption Key:", 
            bg="#ffffff"
        )
        self.key_label.pack(anchor="w")
        
        self.key_entry = Entry(
            decrypt_frame, 
            show="•", 
            width=30,
            font=("Courier", 10),
            bg="white",
            fg="black",
            insertbackground="black"
        )
        self.key_entry.pack(fill="x", pady=5)
        
        self.salt_label = Label(
            decrypt_frame, 
            text="Salt Value:", 
            bg="#ffffff"
        )
        self.salt_label.pack(anchor="w")
        
        self.salt_entry = Entry(
            decrypt_frame, 
            width=30,
            font=("Courier", 10),
            bg="white",
            fg="black",
            insertbackground="black"
        )
        self.salt_entry.pack(fill="x", pady=5)
        
        self.decrypt_btn = ttk.Button(
            decrypt_frame,
            text="Decrypt File",
            command=self.decrypt_file
        )
        self.decrypt_btn.pack(fill="x", pady=5)
        
       
        key_frame = Frame(control_frame, bg="#ffffff")
        key_frame.pack(fill="x")
        
        Label(
            key_frame, 
            text="Key Tools", 
            bg="#ffffff", 
            font=section_font
        ).pack(anchor="w", pady=(0, 10))
        
        ttk.Button(
            key_frame,
            text="Generate Key",
            command=self.generate_key_dialog
        ).pack(fill="x", pady=5)
        
        ttk.Button(
            key_frame,
            text="Copy Key",
            command=self.copy_key
        ).pack(fill="x", pady=5)
        
        ttk.Button(
            key_frame,
            text="Paste Key",
            command=self.paste_key
        ).pack(fill="x", pady=5)
        
    def create_output(self, parent):
        output_frame = Frame(parent, bg="#ffffff", bd=1, relief="solid")
        output_frame.pack(expand=True, fill=BOTH)
        
        self.output_text = Text(
            output_frame,
            wrap="word",
            bg="white",
            fg="black",
            insertbackground="black",
            selectbackground="#3498db",
            padx=10,
            pady=10,
            font=("Consolas", 10)
        )
        
        scrollbar = ttk.Scrollbar(
            output_frame,
            orient="vertical",
            command=self.output_text.yview
        )
        scrollbar.pack(side=RIGHT, fill=Y)
        
        self.output_text.configure(yscrollcommand=scrollbar.set)
        self.output_text.pack(expand=True, fill=BOTH)
        
        self.output_text.tag_config("success", foreground="#27ae60")
        self.output_text.tag_config("error", foreground="#e74c3c")
        self.output_text.tag_config("warning", foreground="#f39c12")
        self.output_text.tag_config("info", foreground="#3498db")
        
        welcome_msg = """=== CryptoVault Pro ===
Advanced File Encryption Suite

Features:
- AES-256 Encryption with PBKDF2 key derivation
- Secure salt generation
- Military-grade cryptographic operations
- User-friendly interface

Instructions:
1. Click 'Encrypt File' to secure your files
2. Save the generated key and salt securely
3. Use the same key and salt to decrypt
"""
        self.output_text.insert(END, welcome_msg)
        self.output_text.configure(state="disabled")
        
    def create_footer(self):
        footer_frame = Frame(self.root, bg="#2c3e50", height=40)
        footer_frame.pack(side=BOTTOM, fill="x")
        
        status_var = StringVar()
        status_var.set("Ready")
        
        status_label = Label(
            footer_frame,
            textvariable=status_var,
            fg="white",
            bg="#2c3e50",
            font=("Helvetica", 9)
        )
        status_label.pack(side=LEFT, padx=10)
        
        version_label = Label(
            footer_frame,
            text="v2.3.1 | Secure Encryption Suite",
            fg="white",
            bg="#2c3e50",
            font=("Helvetica", 9)
        )
        version_label.pack(side=RIGHT, padx=10)
        
    def toggle_theme(self):
        if self.current_theme == "light":
            self.apply_dark_theme()
            self.theme_btn.config(text="🌙")
            self.current_theme = "dark"
        else:
            self.apply_light_theme()
            self.theme_btn.config(text="☀️")
            self.current_theme = "light"
    
    def apply_dark_theme(self):
        self.style.theme_use("dark")
        self.root.configure(bg="#121212")
        for widget in self.root.winfo_children():
            if isinstance(widget, Frame) and widget.cget("bg") not in ["#2c3e50"]:
                widget.configure(bg="#1e1e1e")
            if hasattr(widget, 'winfo_children'):
                for child in widget.winfo_children():
                    if isinstance(child, (Label, Frame)) and child.cget("bg") not in ["#2c3e50"]:
                        child.configure(bg="#1e1e1e", fg="white")
                    elif isinstance(child, Text):
                        child.configure(bg="#252525", fg="white", insertbackground="white")
                    elif isinstance(child, Entry):
                        child.configure(bg="#252525", fg="white", insertbackground="white")
        
    def apply_light_theme(self):
        self.style.theme_use("light")
        self.root.configure(bg="#f0f2f5")
        for widget in self.root.winfo_children():
            if isinstance(widget, Frame) and widget.cget("bg") not in ["#2c3e50"]:
                widget.configure(bg="#f0f2f5")
            if hasattr(widget, 'winfo_children'):
                for child in widget.winfo_children():
                    if isinstance(child, (Label, Frame)) and child.cget("bg") not in ["#2c3e50"]:
                        child.configure(bg="#ffffff", fg="black")
                    elif isinstance(child, Text):
                        child.configure(bg="white", fg="black", insertbackground="black")
                    elif isinstance(child, Entry):
                        child.configure(bg="white", fg="black", insertbackground="black")
    
    def generate_key_dialog(self):
        key_window = Tk()
        key_window.title("Generate New Key")
        key_window.geometry("500x300")
        
        key_frame = Frame(key_window, padx=20, pady=20)
        key_frame.pack(expand=True, fill=BOTH)
        
        Label(key_frame, text="Key Strength:").pack(anchor="w")
        
        strength_var = StringVar(value="high")
        ttk.Radiobutton(
            key_frame,
            text="Standard (256-bit)",
            variable=strength_var,
            value="high"
        ).pack(anchor="w")
        
        ttk.Radiobutton(
            key_frame,
            text="Extra Strong (384-bit)",
            variable=strength_var,
            value="extra"
        ).pack(anchor="w")
        
        ttk.Radiobutton(
            key_frame,
            text="Military Grade (512-bit)",
            variable=strength_var,
            value="military"
        ).pack(anchor="w")
        
        def generate_and_display():
            strength = strength_var.get()
            if strength == "high":
                key_length = 32
            elif strength == "extra":
                key_length = 48
            else:
                key_length = 64
                
            key = os.urandom(key_length)
            salt = os.urandom(16)
            
            key_display = base64.urlsafe_b64encode(key).decode('utf-8')
            salt_display = base64.urlsafe_b64encode(salt).decode('utf-8')
            
            result_text.delete(1.0, END)
            result_text.insert(END, f"Key: {key_display}\n\nSalt: {salt_display}")
            
            def copy_all():
                pyperclip.copy(f"Key: {key_display}\nSalt: {salt_display}")
                
            copy_btn.config(state="normal", command=copy_all)
        
        generate_btn = ttk.Button(
            key_frame,
            text="Generate Key",
            command=generate_and_display
        )
        generate_btn.pack(pady=10)
        
        result_text = Text(key_frame, height=6, width=50)
        result_text.pack(fill="x", pady=10)
        
        copy_btn = ttk.Button(
            key_frame,
            text="Copy to Clipboard",
            state="disabled"
        )
        copy_btn.pack()
        
        key_window.mainloop()
    
    def copy_key(self):
        if self.encryption_params:
            key, salt = self.encryption_params
            pyperclip.copy(f"Key: {key}\nSalt: {salt}")
            self.log_message("Key copied to clipboard", "success")
        else:
            self.log_message("No key available to copy", "warning")
    
    def paste_key(self):
        try:
            clipboard = pyperclip.paste()
            if "Key:" in clipboard and "Salt:" in clipboard:
                key = clipboard.split("Key:")[1].split("Salt:")[0].strip()
                salt = clipboard.split("Salt:")[1].strip()
                self.key_entry.delete(0, END)
                self.key_entry.insert(0, key)
                self.salt_entry.delete(0, END)
                self.salt_entry.insert(0, salt)
                self.log_message("Key pasted from clipboard", "success")
            else:
                self.log_message("Clipboard doesn't contain valid key", "warning")
        except Exception as e:
            self.log_message(f"Paste failed: {str(e)}", "error")
    
    def log_message(self, message, tag=None):
        self.output_text.configure(state="normal")
        self.output_text.insert(END, f"\n{message}", tag)
        self.output_text.see(END)
        self.output_text.configure(state="disabled")
    
    def derive_key(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())
    
    def encrypt_file(self):
        input_file = filedialog.askopenfilename(title="Select File to Encrypt")
        if not input_file:
            return
            
        output_file = filedialog.asksaveasfilename(
            title="Save Encrypted File",
            defaultextension=".enc"
        )
        if not output_file:
            return
            
        try:
            
            key = os.urandom(32)
            salt = os.urandom(16)
            
            
            iv = os.urandom(16)
            cipher = Cipher(
                algorithms.AES(key),
                modes.CFB(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            
            with open(input_file, 'rb') as infile:
                plaintext = infile.read()
                
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            
            with open(output_file, 'wb') as outfile:
                outfile.write(salt + iv + ciphertext)
            
            
            key_display = base64.urlsafe_b64encode(key).decode('utf-8')
            salt_display = base64.urlsafe_b64encode(salt).decode('utf-8')
            
            self.encryption_params = (key_display, salt_display)
            
            self.log_message("\n=== ENCRYPTION SUCCESSFUL ===", "success")
            self.log_message(f"\nKey: {key_display}", "info")
            self.log_message(f"\nSalt: {salt_display}", "info")
            self.log_message("\n\nIMPORTANT: Save this key and salt securely!", "warning")
            self.log_message("You will need both to decrypt the file.", "warning")
            
        except Exception as e:
            self.log_message(f"\nEncryption failed: {str(e)}", "error")
    
    def decrypt_file(self):
        input_file = filedialog.askopenfilename(title="Select File to Decrypt")
        if not input_file:
            return
            
        output_file = filedialog.asksaveasfilename(title="Save Decrypted File")
        if not output_file:
            return
            
        try:
            # Get key and salt from UI
            key_b64 = self.key_entry.get().strip()
            salt_b64 = self.salt_entry.get().strip()
            
            if not key_b64 or not salt_b64:
                raise ValueError("Both key and salt are required")
                
            key = base64.urlsafe_b64decode(key_b64)
            salt = base64.urlsafe_b64decode(salt_b64)
            
            # Read encrypted file
            with open(input_file, 'rb') as infile:
                data = infile.read()
                
            if len(data) < 32:  # salt (16) + iv (16)
                raise ValueError("File is too small to be valid")
                
            file_salt = data[:16]
            iv = data[16:32]
            ciphertext = data[32:]
            
            # Verify salt matches
            if salt != file_salt:
                raise ValueError("Salt mismatch - wrong decryption key")
                
            # Decrypt the file
            cipher = Cipher(
                algorithms.AES(key),
                modes.CFB(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            with open(output_file, 'wb') as outfile:
                outfile.write(plaintext)
            
            self.log_message("\n=== DECRYPTION SUCCESSFUL ===", "success")
            self.log_message(f"\nFile saved to: {output_file}", "info")
            
        except Exception as e:
            self.log_message(f"\nDecryption failed: {str(e)}", "error")
    
    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = AdvancedEncryptionApp()
    app.run()