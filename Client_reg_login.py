import tkinter as tk
from tkinter import messagebox
import sqlite3
import hashlib
import subprocess

import sensors


# Connect to the SQLite database
conn = sqlite3.connect("/home/kali/3_parties/CSP/patient_database.db")
cursor = conn.cursor()


def hash_password(password):
    salt = "salt_value"
    hashed_password = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
    return hashed_password

# Define the registration function
def register():
    # Get the user input
    patient_id  = entry_id.get()
    password = entry_password.get()
    hashed_password = hash_password(password)

    # Insert the user into the database
    cursor.execute("INSERT INTO patients (patient_id, hashed_password) VALUES (?, ?)", (patient_id, hashed_password))
    conn.commit()

    # Clear the input fields
    entry_id.delete(0, tk.END)
    entry_password.delete(0, tk.END)

    # Show a success message
    messagebox.showinfo("Registration successful", f"Registered successfully. Keys generated for {patient_id}")
    generate_keys()
    upload_public_key(patient_id)


def generate_keys():

        # Generate ECC key pair using openssl
        subprocess.run(['openssl', 'ecparam', '-genkey', '-name',
        'secp256k1', '-out', 'privKey.pem'], check=True)
        subprocess.run(['openssl', 'ec', '-in', 'privKey.pem', 
        '-pubout', '-out', 'pubKey.pem'], check=True)
       
  
def upload_public_key(patient_id):
        subprocess.run(['cp', 'pubKey.pem', f'/home/kali/3_parties/Healthcare/PubKey_{patient_id}.pem'], check=True)
        messagebox.showinfo("Share Public Key", "Public key is shared to the Cloud")
        
# Define the login function
def login():

    # Get the user input
    patient_id = entry_id.get()
    password = entry_password.get()

    hashed_input_password = hash_password(password)
    
    # Check if the hashed password exists in the database for the given patient ID
    cursor.execute("SELECT COUNT(*) FROM patients WHERE patient_id = ? AND hashed_password = ?", (patient_id, hashed_input_password))
    count = cursor.fetchone()[0]

    # Check if the password is correct
    if count > 0:
        messagebox.showinfo("Login successful."," Data generating...")
        sensors.collect_and_save_data(patient_id)
        subprocess.run(['python', '/home/kali/3_parties/CSP/cryptoGUI.py'])
        check = True 
    else:
        check = False
        messagebox.showinfo("Login failed", "Incorrect password!")
        return check

# Create the main window
window = tk.Tk()
window.title("Patient Registration and Login")


# Create the input fields
label_id = tk.Label(window, text="Patient ID")
label_id.grid(row=0, column=0)
entry_id = tk.Entry(window)
entry_id.grid(row=0, column=1)

label_password = tk.Label(window, text="Password")
label_password.grid(row=1, column=0)
entry_password = tk.Entry(window, show="*")
entry_password.grid(row=1, column=1)

# Create the registration button
button_register = tk.Button(window, text="Register", command=register)
button_register.grid(row=2, column=0)

# Create the login button
button_login = tk.Button(window, text="Login", command=login)
button_login.grid(row=2, column=1)

# Run the Tkinter event loop
window.mainloop()

# Close the database connection
conn.close()
