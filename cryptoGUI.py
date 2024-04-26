import tkinter as tk
from tkinter import filedialog
from tkinter import simpledialog
from tkinter import messagebox
import subprocess
import hashlib
import os


def browse_file():
    filename = filedialog.askopenfilename()
    file_entry.delete(0, tk.END)
    file_entry.insert(0, filename)

    return filename
   
def aescrypt():
    root = tk.Tk()
    root.withdraw()  # Hide the main window
 
    # Choose the file that needs to be encrypted
    filename = file_entry.get()
    name_file = os.path.basename(filename)

    #Asking for password, to be used with AEScrypt tool
    password = simpledialog.askstring("Password", "Please enter the password:", show='*')

    try:
        subprocess.run(['aescrypt', '-e', '-p', password, filename], check=True)
        # Display message indicating encryption is done
        status_label.config(text=f"First encryption done. File saved as {name_file}.aes")
    except subprocess.CalledProcessError as e:
        # Display error message if encryption fails
        status_label.config(text=f"Error: {e}")

def derive_shared_secret():
    root = tk.Tk()
    root.withdraw()  # Hide the main window

    public_key = filedialog.askopenfilename(title="Choose Doctor's Public Key", filetypes=[("PEM files", "*.pem")])

    # Choose the name and location for the output file
    output_file = filedialog.asksaveasfilename(title="Save Shared Secret Key As", defaultextension=".pem", filetypes=[("PEM files", "*.pem")])
    
    # Perform ECDH key agreement protocol using openssl
    try:
        subprocess.run(['openssl', 'pkeyutl', '-derive', '-inkey', 'privKey.pem', '-peerkey', public_key, '-out', output_file], check=True)
        messagebox.showinfo("Shared Secret Generation", "SSK is generated successfully.")
        #print("Shared secret key is generated successfully")
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
    
    return output_file

def hash_shared_secret():

    ssk = filedialog.askopenfilename(title="Select the Shared Secret Key", filetypes=[("PEM files", "*.pem")])

    # Choose the name and location for the output file
    hash_file = filedialog.asksaveasfilename(title="Save Hashed Shared Secret Key As", defaultextension=".hash", filetypes=[("Binary files", "*.hash")])

    # Compute SHA256 hash of the shared sec key
    subprocess.run(['openssl', 'dgst', '-sha256', '-out', hash_file, ssk], check = True)

    with open(hash_file, 'r') as f:
        hashed_secret = f.read().split('=')[1].strip()
        status_label.config(text = f"The shared secret: {hashed_secret}")

def sign_message():
        #root = tk.Tk()
        #root.withdraw()  # Hide the main window
 
    encrypted_file = browse_file()
    # Prompt the user for the output filename
    output_filename = filedialog.asksaveasfilename(defaultextension=".sign", filetypes=[("Signature Files", "*.sign")])
    if not output_filename:
        return  # User canceled the save dialog, exit the function

    try:
        # Sign the file and saved it as Signed_DCT_from_patient.sign
        subprocess.run(['openssl', 'dgst', '-sha256', '-sign', 'privKey.pem', '-out', output_filename, encrypted_file], check=True)

        status_label.config(text="File signed successfully.")
    except subprocess.CalledProcessError as e:
        status_label.config(text=f"Error: {e}")

def decrypt_iv():
    try:
        # Decrypt IV using patient's private key
        subprocess.run(['openssl', 'pkeyutl', '-decrypt', '-in', 'CipherIV_patient.bin', '-inkey', 'privKey_A.pem', '-out', 'iv_decrypted.txt'], check=True)
        with open('iv_decrypted.txt', 'r') as f:
            iv = f.read().strip()
        return iv
    except subprocess.CalledProcessError as e:
        print(f"Error decrypting IV: {e}")
        return None

def second_encryption():
    # Select the previously-encrypted file, to be encrypted second round
    Double_CP = file_entry.get()
    hashed_SSK_input = simpledialog.askstring("hashed_SSK_input", "Please enter the Shared Secret Key:", show='*')

    # Choose the name and location for the output file
    output_file = filedialog.asksaveasfilename(title="Save the Encrypted File As", defaultextension=".enc", filetypes=[("Encrypted files", "*.enc")])   

    try:
        # Use of IV and SSK for second layer encryption (AES256)
        subprocess.run(['openssl', 'enc', '-aes-256-cbc', '-iv', 'c220c0d3949a37bdfa12ff83089e3e52', '-K',
        hashed_SSK_input, '-in', Double_CP, '-out', output_file], check=True)
        #print("Second layer encryption completed.")
        messagebox.showinfo("Encryption", "Second layer of encryption completed.")
    except subprocess.CalledProcessError as e:
        print(f"Error performing second layer encryption: {e}")

    
# Create main window
root = tk.Tk()
root.title("Encryption  Process" )

# File selection button and entry
file_button = tk.Button(root, text="Browse", command=browse_file)
file_button.pack(pady=5)

file_entry = tk.Entry(root)
file_entry.pack(pady=5)

# Encrypt with AES butto (AESCrypt)
encrypt_aes_button = tk.Button(root, text="Encrypt File", command=aescrypt)
encrypt_aes_button.pack(pady = 5)

# Derive shared secret button
derive_shared_secret_button = tk.Button(root, text="Generate the  Shared Secret Key", command=derive_shared_secret)
derive_shared_secret_button.pack(pady=5)

# Hash shared secret button
hash_shared_secret_button = tk.Button(root, text="Hash Shared Secret", command=hash_shared_secret)
hash_shared_secret_button.pack(pady=5)

# Second encryption button (disabled initially)
second_encryption_button = tk.Button(root, text="Perform  Second Encryption", command=second_encryption)
second_encryption_button.pack(pady=5)

# Sign message button
sign_message_button = tk.Button(root, text="Sign Encrypted File", command=sign_message)
sign_message_button.pack(pady=5)

# Status label
status_label = tk.Label(root, text="")
status_label.pack(pady=5)


root.mainloop()

