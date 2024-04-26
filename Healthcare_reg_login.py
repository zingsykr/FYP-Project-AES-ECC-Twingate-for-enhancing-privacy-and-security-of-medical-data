import tkinter as tk
from tkinter import messagebox
import subprocess
import sqlite3
import hashlib

# Connect to the SQLite database
conn = sqlite3.connect('/home/kali/3_parties/CSP/patient_database.db')
cursor = conn.cursor()

# Create doctors table if not exists
cursor.execute('''CREATE TABLE IF NOT EXISTS doctors (
                    id INTEGER PRIMARY KEY,
                    username TEXT UNIQUE,
                    password TEXT
                )''')
conn.commit()
def generate_keys():

        # Generate ECC key pair using openssl
        subprocess.run(['openssl', 'ecparam', '-genkey', '-name',
        'secp256k1', '-out', 'privKey.pem'], check=True)
        subprocess.run(['openssl', 'ec', '-in', 'privKey.pem', 
        '-pubout', '-out', 'pubKey.pem'], check=True)
        

def upload_public_key(doctor_id):
        subprocess.run(['cp', f'pubKey_{doctor_id}.pem', f'/home/kali/3_parties/CSP/PubKey_{doctor_id}.pem'], check=True)

        messagebox.showinfo("Share Public Key","Public key is shared to the Cloud")
        
        #status_label.config(text="Public key uploaded successfully.")


def generate_keys(username):
        # Generate ECC key pair using openssl
        subprocess.run(['openssl', 'ecparam', '-genkey', '-name', 'secp256k1', '-out', f'privKey_{username}.pem'], check=True)
        subprocess.run(['openssl', 'ec', '-in', f'privKey_{username}.pem', '-pubout', '-out', f'pubKey_{username}.pem'], check=True)
       # status_label.config(text="Keys generated successfully.")

       # return f'pubKey_Doctor_{username}.pem'

def register():
    username = username_entry.get()
    password = password_entry.get()

    # Hash the password before storing it
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    # Insert doctor's credentials into the database
    try:
        cursor.execute("INSERT INTO doctors (username, password) VALUES (?, ?)", (username, hashed_password))
        conn.commit()

        generate_keys(username)
        upload_public_key(username)
        messagebox.showinfo("Registration successful", "User registered successfully") 

    except sqlite3.IntegrityError:
        print("Username already exists. Please choose another username.")

def login():
    username = username_entry.get()
    password = password_entry.get()

    # Hash the password (to be matched with the hashed passwords in the database)
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    # Check if the username and password matc
    cursor.execute("SELECT * FROM doctors WHERE username = ? AND password = ?", (username, hashed_password))
    doctor = cursor.fetchone()

    if doctor:
        messagebox.showinfo("Login successful!"," Connecting to Twingate Client..")
        subprocess.run(['twingate', 'start'], check=True) #Twingate will start and ask for authentication
        subprocess.run(['python', '/home/kali/3_parties/CSP/Healthcare_GUI.py'])

        #option to logout
        choice = messagebox.askquestion("Logout", "Do you want to logout?")
        if choice == 'yes':
            logout(username)

    else:
        messagebox.showerror("Login Failed", "Invalid username or password.")
   
# Function to log out a doctor and disconnect from Twingate
def logout(username):
    print(f"Logging out {username}...")
    subprocess.run(['twingate', 'stop'], check= True)

    print("Logged out")

# Create the main window
window = tk.Tk()
window.title("Doctor Registration and Login")

# Create the input fields
label_id = tk.Label(window, text="username")
label_id.grid(row=0, column=0)
username_entry = tk.Entry(window)
username_entry.grid(row=0, column=1)

label_password = tk.Label(window, text="password")
label_password.grid(row=1, column=0)
password_entry = tk.Entry(window, show="*")
password_entry.grid(row=1, column=1)

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

# Example usage
#while True:
#    print("\n1. Register")
#    print("2. Login")
#    print("3. Exit")
#    choice = input("Enter your choice: ")

#    if choice == '1':
#        register()
#    elif choice == '2':
#        current_user = login()
#    elif choice == '3':
#        break
#    else:
#    print("Invalid choice. Please try again.")

 
