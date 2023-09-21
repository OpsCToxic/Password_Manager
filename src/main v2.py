import sqlite3, hashlib
from tkinter import *
from tkinter import NS, Canvas, Scrollbar, ttk
from tkinter import simpledialog
from functools import partial
# This is for the recovery key
import uuid
# Copy the recovery key
import pyperclip
# Encrypt the data
import base64
import os
# Encryption packages
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

# Initialize sqlite database (by creating cursor object)
with sqlite3.connect("password_manager.db") as db:
    # We query database using the cursor object
    cursor = db.cursor()

backend = default_backend()
salt = b'2447'

kdf = PBKDF2HMAC(
    # This creates a random SHA 256 hash
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=200000,
    backend=backend
)

encryptionKey = 0

# This will be used to encrypt
def encrypt(message: bytes, key: bytes) -> bytes:
    return Fernet(key).encrypt(message)
# This will be used to decrypt
def decrypt(message: bytes, token: bytes) -> bytes:
    return Fernet(token).decrypt(message)

# Creates datatable called masterpasswords in the password_manager database
cursor.execute("""
CREATE TABLE IF NOT EXISTS masterpasswords(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL,
recoveryKey TEXT NOT NULL);
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS password_vault(
id INTEGER PRIMARY KEY,
website TEXT NOT NULL,
username TEXT NOT NULL,
password TEXT NOT NULL);
""")

# Create popup
def popup(text):
    # Will create a popup and ask for a string, and text is what we give it to ask
    answer = simpledialog.askstring("input string", text)
    # This will return what the user enters in the popup.
    # This will be useful for storing the entered website, username, password, etc
    return answer

def hash_password(password):
    # hashlib is the library that hashes passwords
    # This will turn the text into an SHA256 hash
    hash = hashlib.sha256(password)
    # This will turn the md5 back into text so it is readable
    hash = hash.hexdigest()

    return hash

def start_screen():
    def save_password():
        # If the master passwords that are entered by the user match
        if text_input.get() == text_input1.get():
            # Create SQL command to delete previous master password frm datatable
            sql = "DELETE FROM masterpasswords WHERE id = 1"
            # Executes the above sql command
            cursor.execute(sql)
            # We hash the password but hashing method needs string to be encoded. So encode the input from user
            # We are giving it a string but the actual hashing method needs to string to be encoded
            hashed_mp = hash_password(text_input.get().encode("utf-8"))
            # This generates a random key
            key = str(uuid.uuid4().hex)
            # We want to encrypt the recovery key so we first encode it in utf-8, then we pass that as an
            # argument to the hash_password() function
            recovery_key = hash_password(key.encode("utf-8"))
            global encryptionKey
            encryptionKey = base64.urlsafe_b64encode(kdf.derive(text_input.get().encode()))
            # This will insert the hashed master password into the masterpasswords datatable in the sqlite db
            insert_password = """INSERT INTO masterpasswords(password, recoveryKey) VALUES(?, ?)"""
            # This wil execute the sql command above with the hashed_mp varaible replacing the ? in the SQL command
            cursor.execute(insert_password, ((hashed_mp), (recovery_key)))
            # Saves our changes in our database
            db.commit()

            recovery_key_screen(key)
        else:
            error_label.config(text="Passwords do not match")

    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("250x150")

    master_label = Label(window, text="Create Master Password: ")
    master_label.config(anchor=CENTER)
    master_label.pack()

    # Master password input
    text_input = Entry(window, width=20, show="*")
    text_input.pack()
    text_input.focus()

    # Re-enter Master password label
    master_label1 = Label(window, text="Re-enter Password: ")
    master_label1.pack()

    # Renter master password input
    text_input1 = Entry(window, width=20, show="*")
    text_input1.pack()
    text_input1.focus()

    error_label = Label(window)
    error_label.pack()

    save_btn = Button(window, text="Save", command=save_password)
    save_btn.pack(pady=10)

def recovery_key_screen(key):
    def copy_recovery_key():
        pyperclip.copy(label1.cget("text"))

    def done():
        password_vault_screen()

    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("250x150")

    label = Label(window, text="Save this key to be able to recover account")
    label.config(anchor=CENTER)
    label.pack()

    # Re-enter Master password label
    label1 = Label(window, text=key)
    label1.pack()

    error_label = Label(window)
    error_label.pack()

    # This button will copy the recovery key from the label into the clipboard
    copy_btn = Button(window, text="Copy Key", command=copy_recovery_key)
    copy_btn.pack(pady=10)
    # This will return the user back to the vault screen
    done_btn = Button(window, text="Done", command=done)
    done_btn.pack(pady=10)

def reset_screen():
    def copy_recovery_key():
        pyperclip.copy(label1.cget("text"))

    def get_recovery_key():
        # This will give the recovery key that user entered and will check it with the
        # recovery key stored in the database
        recoveryKeyCheck = hash_password(str(text_in.get()).encode("utf-8"))
        # This will check for the recovery key is the one we stored in our database
        cursor.execute("SELECT * FROM masterpasswords WHERE id = 1 AND recoveryKey = ?",[(recoveryKeyCheck)])
        return cursor.fetchall()

    def check_recovery_key():
        checked = get_recovery_key()

        if checked:
            start_screen()
        else:
            text_in.delete(0, 'end')
            label1.config(text="Wrong key")


    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("250x150")

    label = Label(window, text="Enter Recovery Key")
    label.config(anchor=CENTER)
    label.pack()

    text_in = Entry(window, width=20)
    text_in.pack()
    text_in.focus()

    label1 = Label(window)
    label1.config(anchor=CENTER)
    label1.pack()

    # This will return the user back to the vault screen
    done_btn = Button(window, text="Check Recovery Key", command=check_recovery_key)
    done_btn.pack(pady=10)
def login_screen():
    def get_master_password():
        check_hashed_password = hash_password(text_in.get().encode("utf-8"))
        # Selects everything from table and checks the passwords where id = 1, and the password placeholder
        # is relaced by the variable after, which is check_hashed_password
        global encryptionKey
        encryptionKey = base64.urlsafe_b64encode(kdf.derive(text_in.get().encode()))
        cursor.execute("SELECT * FROM masterpasswords WHERE id = 1 AND password = ?", [(check_hashed_password)])
        return cursor.fetchall()

    def validate_password():
        # password_match returns a tuple list which returns the master password that matches the user input
        password_match = get_master_password()
        if password_match:
            password_vault_screen()
        else:
            text_in.delete(0, 'end')
            master_label1.config(text="WRONG PASSWORD")

    def reset_password():
        reset_screen()


    for widget in window.winfo_children():
        widget.destroy()
    # Screen size is 250 x 150
    window.geometry("250x150")

    # Creates Master Password label
    master_label = Label(window, text="Enter Master Password: ")
    # Centers master password label
    master_label.config(anchor=CENTER)
    # Places master password label on the window so that it is visible
    master_label.pack()

    # Text input for master password
    text_in = Entry(window, width=20, show="*")
    # Makes text input visible
    text_in.pack()
    # Cursor automatically focuses on master password input
    text_in.focus()

    master_label1 = Label(window)
    master_label1.pack()

    # Button to submit master password. When clicked, it will execute the "validate_password" function.
    # comamnd function must be defined above the button
    login_btn = Button(window, text="Submit", command=validate_password)
    login_btn.pack(pady=10)

    reset_btn = Button(window, text="Reset Password", command=reset_password)
    reset_btn.pack(pady=10)
def password_vault_screen():
    def initialize_canvas(container):
        canvas = Canvas(container)
        return canvas

    def create_treeview_layout(canvas):
        yscrollbar = Scrollbar(canvas, orient='vertical')
        tree = ttk.Treeview(canvas, yscrollcommand=yscrollbar.set, columns=("c0", "c1", "c2"))

        tree.column("#0", width=50, anchor=W, stretch=NO)
        tree.column("#1", anchor=W, stretch=NO)
        tree.column("#2", anchor=W, stretch=NO)

        tree.heading("#0", text="Website")
        tree.heading("#1", text="User Name")
        tree.heading("#2", text="Password")

        yscrollbar.configure(command=tree.yview)
        yscrollbar.grid(row=0, column=3, rowspan=10, sticky=NS)
        return tree

    def add_entry():
        text_1 = "Website"
        text_2 = "Username"
        text_3 = "Password"

        # Each of thee popups will store the values in a variable, which is encrypted
        website = encrypt(popup(text_1).encode(), encryptionKey)
        username = encrypt(popup(text_2).encode(), encryptionKey)
        password = encrypt(popup(text_3).encode(), encryptionKey)

        insert_fields = """INSERT INTO password_vault(website,username,password)
        VALUES(?,?,?)"""
        cursor.execute(insert_fields, (website, username, password))
        db.commit()

        password_vault_screen()

    def remove_entry(selected_entry):
        cursor.execute("SELECT id, website FROM password_vault")
        rows = cursor.fetchall()

        selected_website = tree_view_layout.item(selected_entry, "text")

        for row in rows:
            primary_id = row[0]
            encrypted_website = row[1]

            decrypted_website = decrypt(encrypted_website, encryptionKey).decode().strip().lower()
            selected_website_cleaned = selected_website.strip().lower()

            if decrypted_website == selected_website_cleaned:
                # Delete the corresponding entry from the database using the selected ID
                cursor.execute("DELETE FROM password_vault WHERE id = ?", (primary_id,))
                db.commit()
                break

        password_vault_screen()


    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("700x350")
    new_canvas = initialize_canvas(window)
    tree_view_layout = create_treeview_layout(new_canvas)
    tree_view_layout.grid(row=1, column=1, rowspan=10, columnspan=3)

    new_canvas.grid(row=1, column=1, columnspan=3)

    home_label = Label(window, text="Password Vault")
    home_label.grid(column=2)

    add_button = Button(window, text="Add Entry", command=add_entry)
    add_button.grid(row=0, column=1, pady=10)

    delete_button = Button(window, text="Delete", command=lambda: remove_entry(tree_view_layout.selection()))
    delete_button.grid(row=0, column=2, pady=10)

    # label = Label(window, text="Website")
    # label.grid(row=2, column=0, padx=80)
    # label = Label(window, text="Username")
    # label.grid(row=2, column=1, padx=80)
    # label = Label(window, text="Password")
    # label.grid(row=2, column=2, padx=80)

    cursor.execute("SELECT * FROM password_vault")
    if (cursor.fetchall() != None):
        cursor.execute("SELECT * FROM password_vault")
        rows = cursor.fetchall()
        for i, row in enumerate(rows):

            # Database stored as an array, where each item is website, username, password
            # We are storing all of the entries in an array, then we access each of the entries using index i
            # index 1 will access the website

            website_data = decrypt(rows[i][1], encryptionKey).decode()
            username_data = decrypt(rows[i][2], encryptionKey).decode()
            password_data = decrypt(rows[i][3], encryptionKey).decode()

            tree_view_layout.insert('', 'end', text=website_data, values=(username_data, password_data))
            # The delete button will delete the corresponding entry by passing the current record's id
            # (using array[i][0]) and passing that to the remove_entry function. This is done by passing this
            # into the partial function

            # delete_btn.grid(column=3, row=i+3, pady=10)

# Creates an instance of a TK window
window = Tk()

# Intiialize window title
window.title("Password Manager")
window.eval("tk::PlaceWindow . center")
window.resizable()

cursor.execute("SELECT * FROM masterpasswords")
# If a master password has already been entered, then the login screen will be shown
if cursor.fetchall():
    login_screen()
# If the user did not enter a master password before (none stored in the database) then app proceeds to start_screen
# Where they create a master password
else:
    start_screen()

# Ensures application window remains running
window.mainloop()