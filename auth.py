import tkinter as tk
import customtkinter as ctk
import os
import datetime
import sys
import hashlib
from tkinter import messagebox, ttk
class LoginPage(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        # Window Configuration
        self.title("Hash Toolkit - Login")
        self.geometry("800x500")
        self.resizable(False, False)
        
        # Configure Grid
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        # Main Frame
        main_frame = ctk.CTkFrame(self, corner_radius=15)
        main_frame.grid(row=0, column=0, padx=60, pady=60, sticky="nsew")
        main_frame.grid_columnconfigure(0, weight=1)
        main_frame.grid_columnconfigure(1, weight=1)
        
        # Left Side (Logo/Info)
        logo_frame = ctk.CTkFrame(main_frame, corner_radius=10, fg_color="transparent")
        logo_frame.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")
        
        logo_label = ctk.CTkLabel(logo_frame, 
                                  text="HashToolKit", 
                                  font=("Helvetica", 36, "bold"))
        logo_label.pack(expand=True)
        
        subtitle = ctk.CTkLabel(logo_frame, 
                                text="Secure Hash Management", 
                                font=("Helvetica", 18))
        subtitle.pack(expand=True)
        
        # Right Side (Login Form)
        login_frame = ctk.CTkFrame(main_frame, corner_radius=10)
        login_frame.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        
        login_title = ctk.CTkLabel(login_frame, 
                                   text="Login", 
                                   font=("Helvetica", 24, "bold"))
        login_title.pack(pady=(20, 10))
        
        # Username Entry
        self.username_entry = ctk.CTkEntry(login_frame, 
                                           placeholder_text="Username", 
                                           width=300, 
                                           height=40)
        self.username_entry.pack(pady=10)
        
        # Password Entry
        self.password_entry = ctk.CTkEntry(login_frame, 
                                           placeholder_text="Password", 
                                           show="*", 
                                           width=300, 
                                           height=40)
        self.password_entry.pack(pady=10)
        
        # Login Button
        login_button = ctk.CTkButton(login_frame, 
                                     text="Login", 
                                     command=self.login,
                                     width=300,
                                     height=40,
                                     fg_color="#4CAF50",
                                     hover_color="#45a049")
        login_button.pack(pady=10)
        
        # Signup Button
        signup_button = ctk.CTkButton(login_frame, 
                                      text="Sign Up", 
                                      command=self.open_signup,  # Correction ici
                                      width=300,
                                      height=40,
                                      fg_color="#2196F3",
                                      hover_color="#1E88E5")
        signup_button.pack(pady=10)
    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if username == "root" and password == "ekoraj":
            messagebox.showinfo("Admin Login", "Privileged session opened")
            import subprocess
            LoginPage.destroy(self)
# Run Hash_aplha.py as a separate process
            subprocess.run(["python", "Hash_aplha.py"])


            
        
        elif self.check_credentials(username, password):
            self.log_login(username, password)
            messagebox.showinfo("Login", f"Welcome {username}")
            import subprocess
            LoginPage.destroy(self)
# Run Hash_aplha.py as a separate process
            subprocess.run(["python", "Hash_aplha.py"])
        else:
            messagebox.showerror("Error", "Invalid username or password")
    
    def check_credentials(self, username, password):
        try:
            with open("ID.txt", "r") as ID:
                for line in ID:
                    line = line.split(",")
                    if line[1] == username and line[3] == password:
                        return True
            return False
        except FileNotFoundError:
            open("ID.txt", "w")
            return False
    
    def log_login(self, username, password):
        now = datetime.datetime.now()
        with open("logs.txt", "a") as logs:
            logs.write("***SESSION OPENED***\n")
            logs.write(f"Current date and time: {now.strftime('%Y-%m-%d %H:%M:%S')}\n")
            hash_password = hashlib.md5(password.encode()).hexdigest()
            logs.write(f"Username: {username}\nPassword Hash: {hash_password} <md5>\n")
    
    def open_signup(self):
       
     signup_page = SignupPage()
     signup_page.mainloop()
     


class SignupPage(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        self.title("Hash Toolkit - Sign Up")
        self.geometry("800x500")
        self.resizable(False, False)
        
        # Configure Grid
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        # Main Frame
        main_frame = ctk.CTkFrame(self, corner_radius=15)
        main_frame.grid(row=0, column=0, padx=60, pady=60, sticky="nsew")
        main_frame.grid_columnconfigure(0, weight=1)
        
        signup_frame = ctk.CTkFrame(main_frame, corner_radius=10)
        signup_frame.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")
        
        signup_title = ctk.CTkLabel(signup_frame, 
                                    text="Create Account", 
                                    font=("Helvetica", 24, "bold"))
        signup_title.pack(pady=(20, 10))
        
        # Username Entry
        self.username_entry = ctk.CTkEntry(signup_frame, 
                                           placeholder_text="Username", 
                                           width=300, 
                                           height=40)
        self.username_entry.pack(pady=10)
        
        # Password Entry
        self.password_entry = ctk.CTkEntry(signup_frame, 
                                           placeholder_text="Password", 
                                           show="*", 
                                           width=300, 
                                           height=40)
        self.password_entry.pack(pady=10)
        
        # Signup Button
        signup_button = ctk.CTkButton(signup_frame, 
                                      text="Sign Up", 
                                      command=self.signup,
                                      width=300,
                                      height=40,
                                      fg_color="#4CAF50",
                                      hover_color="#45a049")
        signup_button.pack(pady=10)
    
    def signup(self):
        user = self.username_entry.get()
        pw = hashlib(self.password_entry.get()).hexdigest()
        
        if not user:
            messagebox.showerror("Warning", "Invalid username")
            return
        
        if not self.check_username(user):
            messagebox.showerror("Warning", "Username already exists")
            return
        
        if len(pw) < 8:
            messagebox.showerror("Error", "Password must be at least 8 characters")
            return
        
        with open('ID.txt', "a", encoding="utf-8") as ID:
            os.system("attrib +h ID.txt")
            ID.write(f"Username,{user},Password,{pw},\n")
        
        messagebox.showinfo("Information", "Your credentials have been saved!\nPlease log in.")
        
        self.destroy()
    
    def check_username(self, username):
        try:
            with open("ID.txt", "r") as ID:
                for line in ID:
                    line = line.split(",")
                    if line[1] == username:
                        return False
            return True
        except FileNotFoundError:
            return True

def main():
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")
    LoginPage().mainloop()

if __name__ == "__main__":
    main()