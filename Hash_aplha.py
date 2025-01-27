import os
import sys
import datetime
import hashlib
import signature
import customtkinter as ctk
from tkinter import filedialog, messagebox
from PIL import Image

class HashToolkit:
    def __init__(self):
        # Configure the main window
        self.root = ctk.CTk()
        self.root.title("Hash Toolkit")
        
        # Set window icon
        try:
            # Try to use .ico file
            icon_path = os.path.join(os.path.dirname(__file__), 'icon.ico')
            if os.path.exists(icon_path):
                self.root.iconbitmap(icon_path)
            else:
                # Fallback to PNG if .ico not found
                img = ctk.CTkImage(Image.open(os.path.join(os.path.dirname(__file__), 'icon.png')))
                self.root.iconphoto(False, img)
        except Exception as e:
            print(f"Could not set icon: {e}")

        self.root.geometry("1200x800")
        self.root.minsize(1000, 600)
        
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        self._create_ui()
        
    def _create_ui(self):
        # Main frame
        main_frame = ctk.CTkFrame(self.root, corner_radius=10)
        main_frame.pack(padx=20, pady=20, fill="both", expand=True)
        
        # Text Hashing Section
        text_frame = ctk.CTkFrame(main_frame, corner_radius=10)
        text_frame.pack(padx=10, pady=10, fill="x")
        
        ctk.CTkLabel(text_frame, text="Text Hashing", font=("Helvetica", 16, "bold")).pack(pady=10)
        
        # Algorithm Selection
        algo_label = ctk.CTkLabel(text_frame, text="Select Hash Algorithm:")
        algo_label.pack(pady=(10, 5))
        
        self.text_algo_var = ctk.StringVar(value="MD5")
        algo_dropdown = ctk.CTkOptionMenu(text_frame, values=["MD5", "SHA1", "SHA512"], 
                                          variable=self.text_algo_var)
        algo_dropdown.pack(pady=10)
        
        # Input field
        self.text_input = ctk.CTkEntry(text_frame, placeholder_text="Enter text to hash", 
                                       width=500, height=40)
        self.text_input.pack(pady=10)
        
        # Hash button
        text_hash_btn = ctk.CTkButton(text_frame, text="Hash Text", 
                                      command=self._hash_text, 
                                      fg_color="#60AB25", hover_color="green")
        text_hash_btn.pack(pady=10)
        
        # Result display
        self.text_result = ctk.CTkEntry(text_frame, placeholder_text="Hashed result", 
                                        width=600, state="readonly")
        self.text_result.pack(pady=10)
        
        # File Hashing Section
        file_frame = ctk.CTkFrame(main_frame, corner_radius=10)
        file_frame.pack(padx=10, pady=10, fill="x")
        
        ctk.CTkLabel(file_frame, text="File Hashing", font=("Helvetica", 16, "bold")).pack(pady=10)
        
        # Algorithm Selection for File
        file_algo_label = ctk.CTkLabel(file_frame, text="Select Hash Algorithm:")
        file_algo_label.pack(pady=(10, 5))
        
        self.file_algo_var = ctk.StringVar(value="MD5")
        file_algo_dropdown = ctk.CTkOptionMenu(file_frame, values=["MD5", "SHA1", "SHA512"], 
                                               variable=self.file_algo_var)
        file_algo_dropdown.pack(pady=10)
        
        # File selection button
        file_select_btn = ctk.CTkButton(file_frame, text="Select File", 
                                        command=self._hash_file, 
                                        fg_color="#3A7CA5")
        file_select_btn.pack(pady=10)
        file_select_btn = ctk.CTkButton(file_frame, text="Verify Signature", 
                                        command=self.verify, hover_color="red",
                                        fg_color="orange",)
        file_select_btn.pack(pady=10)
        
        # Result display for file
        self.file_result = ctk.CTkEntry(file_frame, placeholder_text="Hashed file result", 
                                        width=600, state="readonly")
        self.file_result.pack(pady=10)
        
        # Theme switcher
        theme_frame = ctk.CTkFrame(main_frame, corner_radius=10)
        theme_frame.pack(padx=10, pady=10, fill="x")
        
        self.theme_var = ctk.StringVar(value="on")
        theme_switch = ctk.CTkSwitch(theme_frame, text="Dark/Light Mode", 
                                     variable=self.theme_var, 
                                     command=self._toggle_theme,
                                     onvalue="on", offvalue="off")
        theme_switch.pack(pady=10)
        
        # Footer
        ctk.CTkLabel(main_frame, text="HashToolKit by @ekoraj", 
                     font=("Helvetica", 10)).pack(pady=10)
    def verify(self):
       
     import subprocess
     subprocess.run(["python", "signature.py"])
    def _hash_text(self):
        text = self.text_input.get()
        algo = self.text_algo_var.get().lower()
        
        try:
            hash_result = self._compute_hash(text.encode(), algo)
            self._log_hash("text", text, algo, hash_result)
            
            self.text_result.configure(state="normal")
            self.text_result.delete(0, 'end')
            self.text_result.insert(0, hash_result)
            self.text_result.configure(state="readonly")
            
            self._show_success_message("Text hashed successfully!")
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def _hash_file(self):
        file_path = filedialog.askopenfilename(title="Select a File")
        if not file_path:
            return
        
        algo = self.file_algo_var.get().lower()
        
        try:
            with open(file_path, "rb") as f:
                hash_result = self._compute_hash(f.read(), algo)
                
                self._log_hash("file", file_path, algo, hash_result)
                
                self.file_result.configure(state="normal")
                self.file_result.delete(0, 'end')
                self.file_result.insert(0, hash_result)
                self.file_result.configure(state="readonly")
                
                self._show_success_message("File hashed successfully!")
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def _compute_hash(self, data, algo):
        hash_functions = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha512': hashlib.sha512
        }
        hash_func = hash_functions.get(algo)
        if not hash_func:
            raise ValueError(f"Unsupported hash algorithm: {algo}")
        return hash_func(data).hexdigest()
    
    def _log_hash(self, hash_type, input_data, algo, result):
        now = datetime.datetime.now()
        log_file = f"hash_{algo.upper()}.txt"
        
        with open(log_file, "a") as log:
            log.write(f"Timestamp: {now.strftime('%Y-%m-%d %H:%M:%S')}\n")
            log.write(f"Type: {hash_type.capitalize()} Hashing\n")
            log.write(f"Input: {input_data}\n")
            log.write(f"Algorithm: {algo.upper()}\n")
            log.write(f"Result: {result}\n")
            log.write("#" * 50 + "\n")
            messagebox.showinfo("Done", "Hash saved in log file !✅  ")
    
    def _show_success_message(self, message):
        success_label = ctk.CTkLabel(self.root, text=message, text_color="green")
        success_label.pack(pady=10)
        self.root.after(3000, success_label.destroy)
    
    def _toggle_theme(self):
        if self.theme_var.get() == "on":
            ctk.set_appearance_mode("dark")
        else:
            ctk.set_appearance_mode("light")
    
    def run(self):
        self.root.mainloop()

def main():
    toolkit = HashToolkit()
    toolkit.run()

if __name__ == "__main__":
    main()
