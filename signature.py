import sys
import os
import datetime
import hashlib
import customtkinter as ctk
from tkinter import filedialog, messagebox, simpledialog
from PIL import Image  # Importing Image from PIL to handle icon if needed

class HashToolkit:
    def __init__(self):
        # Initialisation de la fenêtre
        self.root = ctk.CTk()
        self.root.title("Hash Toolkit")
        self.root.geometry("1200x900")
        self.root.minsize(1000, 700)
        
        # Set window icon
        try:
            # Essayer d'utiliser un fichier .ico
            icon_path = os.path.join(os.path.dirname(__file__), 'icon.ico')
            if os.path.exists(icon_path):
                self.root.iconbitmap(icon_path)
            else:
                # Si .ico non trouvé, utiliser une image PNG
                img = ctk.CTkImage(Image.open(os.path.join(os.path.dirname(__file__), 'icon.png')))
                self.root.iconphoto(False, img)
        except Exception as e:
            print(f"Could not set icon: {e}")
        
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        self._create_ui()
    
    def _create_ui(self):
        # Création de l'interface utilisateur
        main_frame = ctk.CTkFrame(self.root, corner_radius=10)
        main_frame.pack(padx=20, pady=20, fill="both", expand=True)
        
        # Section de vérification de la signature
        sig_frame = ctk.CTkFrame(main_frame, corner_radius=10)
        sig_frame.pack(padx=10, pady=10, fill="x")
        
        ctk.CTkLabel(sig_frame, text="File Signature Verification", 
                     font=("Helvetica", 16, "bold")).pack(pady=10)
        
        # Bouton pour sélectionner un fichier
        file_select_btn = ctk.CTkButton(sig_frame, text="Select File to Verify", 
                                        command=self._verify_file_signature, 
                                        fg_color="#C83A3A")
        file_select_btn.pack(pady=10)
        
        # Affichage du résultat de la vérification de la signature
        self.sig_result = ctk.CTkEntry(sig_frame, placeholder_text="Verification Result", 
                                       width=600, state="readonly")
        self.sig_result.pack(pady=10)
    
    def _verify_file_signature(self):
        # Sélectionner le fichier à vérifier
        file_path = filedialog.askopenfilename(title="Select File to Verify")
        if not file_path:
            return

        # Demander à l'utilisateur de saisir la valeur de hachage attendue
        expected_hash = simpledialog.askstring("Input", 
                                               "Enter the expected hash value:", 
                                               parent=self.root)
        if not expected_hash:
            return
        
        # Demander à l'utilisateur de sélectionner l'algorithme de hachage
        algo = simpledialog.askstring("Input", 
                                      "Enter the hash algorithm (md5, sha1, sha512):", 
                                      parent=self.root)
        if algo not in ['md5', 'sha1', 'sha512']:
            messagebox.showerror("Error", "Invalid algorithm selected. Please choose 'md5', 'sha1', or 'sha512'.")
            return
        
        # Calculer le hachage du fichier avec l'algorithme sélectionné
        try:
            with open(file_path, "rb") as f:
                # Lire le contenu du fichier
                file_content = f.read()

                # Appliquer l'algorithme choisi
                if algo == 'md5':
                    file_hash = hashlib.md5(file_content).hexdigest()
                elif algo == 'sha1':
                    file_hash = hashlib.sha1(file_content).hexdigest()
                elif algo == 'sha512':
                    file_hash = hashlib.sha512(file_content).hexdigest()

            # Comparer le hachage calculé avec le hachage attendu
            verification_result = (file_hash == expected_hash.lower())
            
            # Mettre à jour l'affichage du résultat
            self.sig_result.configure(state="normal")
            self.sig_result.delete(0, 'end')
            
            if verification_result:
                self.sig_result.insert(0, "✅ Signature Verified: File is Authentic")
                self.sig_result.configure(foreground="green")
            else:
                self.sig_result.insert(0, "❌ Signature Verification Failed: File May Be Tampered")
                self.sig_result.configure(foreground="red")
            
            self.sig_result.configure(state="readonly")
            
            # Enregistrer la tentative de vérification
            self._log_signature_verification(file_path, expected_hash, file_hash, verification_result)

        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def _log_signature_verification(self, file_path, expected_hash, computed_hash, is_verified):
        now = datetime.datetime.now()
        log_file = "signature_verification.log"
        
        with open(log_file, "a") as log:
            log.write(f"Timestamp: {now.strftime('%Y-%m-%d %H:%M:%S')}\n")
            log.write(f"File: {file_path}\n")
            log.write(f"Expected Hash: {expected_hash}\n")
            log.write(f"Computed Hash: {computed_hash}\n")
            log.write(f"Verification Result: {'Passed' if is_verified else 'Failed'}\n")
            log.write("#" * 50 + "\n")
    
    # Méthode principale pour lancer l'application
    def run(self):
        self.root.mainloop()

def main():
    toolkit = HashToolkit()
    toolkit.run()

if __name__ == "__main__":
    main()
