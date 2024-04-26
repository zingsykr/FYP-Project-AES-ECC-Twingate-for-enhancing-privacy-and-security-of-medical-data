import tkinter as tk
import subprocess
from tkinter import filedialog
from tkinter import simpledialog
from tkinter import messagebox

def browse_file():
    filename = filedialog.askopenfilename()
    file_entry.delete(0, tk.END)
    file_entry.insert(0, filename)


def derive_shared_secret():    
    root = tk.Tk()
    root.withdraw()  # Hide the main window

    public_key = filedialog.askopenfilename(title="Choose a patient's Public Key File", filetypes=[("PEM files", "*.pem")])

    try:

        # Perform ECDH key agreement protocol using openssl
        subprocess.run(['openssl', 'pkeyutl', '-derive', '-inkey', 'privKey_doctor30.pem', 
        '-peerkey', public_key, '-out', 'SSK_Doctor.pem'], check=True)
        status_label.config(text="Shared secret derived successfully.")


    except subprocess.CalledProcessError as e:
        status_label.config(text=f"Error: {e}")

def hash_shared_secret():
    ssk = filedialog.askopenfilename(title="Select the shared secret key", filetypes=[("PEM files", "*.pem")])

    # Compute SHA256 hash of the shared secret
    subprocess.run(['openssl', 'dgst', '-sha256', '-out', 'hashed_SSK_doctor.hash', ssk], check=True)

    with open('hashed_SSK_doctor.hash', 'r') as f:
        hashed_secret = f.read().split('=')[1].strip()
        status_label.config(text=f"Shared Secret Key is successfully hashed and saved")
   # except subprocess.CalledProcessError as e:
        #status_label.config(text=f"Error: {e}")

def decrypt_iv():
    # Ask the user to select the encrypted IV file
    iv_file_path = filedialog.askopenfilename(
        title="Select Encrypted IV File",
        filetypes=(("Binary Files", "*.bin"), ("All Files", "*.*"))
    )
    if not iv_file_path:
        return  # User canceled, so exit the function

    try:
        # Decrypt IV using healthcare user's private key
        subprocess.run(['openssl', 'pkeyutl', '-decrypt', '-in', iv_file_path, '-inkey', 'privKey.pem', '-out', 'iv_decrypted.txt'], check=True)
        with open('iv_decrypted.txt', 'r') as f:
            iv = f.read().strip()
            print("IV decrypted successfully:", iv)
        return iv
    except subprocess.CalledProcessError as e:
        print(f"Error decrypting IV: {e}")
        return None

def verify_signature():

    root = tk.Tk()
    root.withdraw()  # Hide the main window    

    # Ask user the name of the .sign file to be saved to. 
    signature_file = filedialog.askopenfilename(title="Choose Signature File", filetypes=[("Signature Files", "*.sign")])
    if not signature_file:
        print("No signature file selected.")
        return False  

    # Prompt user to choose public key of the sender
    public_key_file = filedialog.askopenfilename(title="Choose Public Key File", filetypes=[("Public Key Files", "*.pem")])
    if not public_key_file:
        print("No public key file selected.")
        return False

    # Prompt user to choose the encrypted-file to be verified (ECDSA)
    data_file = filedialog.askopenfilename(title="Choose the Ciphertext", filetypes=[("All Files", "*.*")])
    if not data_file:
        print("None selected.")
        return False

    try:
        # Include the .sign file, public key of patient (sender) and the doubleciphertext in the algorithm
        subprocess.run(['openssl', 'dgst', '-sha256', '-verify', public_key_file, '-signature', signature_file, data_file], check=True)

        messagebox.showinfo("Verification","Signature is checked. Sender verified.")
    except subprocess.CalledProcessError as e:
        #print(f"Error verifying signature: {e}")
        message.showinfo("Verification", "Sender unverified.")


def first_layer_decryption():

    iv = "c220c0d3949a37bdfa12ff83089e3e52" #same IV value used by the sender (patient)
    try:
        #Select the double ciphertext
        filename = filedialog.askopenfilename(title="Select file", filetypes=(("All files", "*.*"),))
        if not filename:
            return

        # Prompted to enter the Shared secret key
        hashed_SSK_input = simpledialog.askstring("hashed_SSK_Input", "Please enter the shared secret key", 
        show="*")

        # Use IV and the previously entered shared secret key to perform first layer of decryption
        subprocess.run(['openssl', 'enc', '-d', '-aes-256-cbc', '-iv', iv, '-in', filename, '-out', 
        'Ciphertext.txt.dec', '-K', hashed_SSK_input], check=True)

        status_label.config(text="First layer decryption is successful.")
    except subprocess.CalledProcessError as e:
        status_label.config(text=f"Error: First layer decryption failed.")
    

def decrypt_with_aes():
    root = tk.Tk()
    root.withdraw()
    
    password = simpledialog.askstring("Password", "Please enter the  password:", show='*')

    try:
        filename = filedialog.askopenfilename(title="Select file", filetypes=(("All files", "*.*"),))
        if not filename:
            return

        # Decrypt data using AES
        subprocess.run(['aescrypt', '-d', '-p', password, filename], check=True)
        status_label.config(text="File decrypted successfully. Patient's data can be accessed.")

    except subprocess.CalledProcessError as e:
        status_label.config(text=f"Error: {e}")


root = tk.Tk()
root.title("Key Generation and Decryption")

derive_shared_secret_button = tk.Button(root, text="Derive Shared Secret", command=derive_shared_secret)
derive_shared_secret_button.pack()

hash_shared_secret_button = tk.Button(root, text="Hash Shared Secret", command=hash_shared_secret)
hash_shared_secret_button.pack()

verify_signature_button = tk.Button(root, text="Verify the signature", command=verify_signature)
verify_signature_button.pack()

first_layer_decryption_button = tk.Button(root, text="Perform first layer of decryption", command=first_layer_decryption)
first_layer_decryption_button.pack()

decrypt_with_aes_button = tk.Button(root, text="Perform final decryption", command=decrypt_with_aes)
decrypt_with_aes_button.pack()

status_label = tk.Label(root, text="")
status_label.pack()

root.mainloop()

