from tkinter import *
from tkinter import messagebox
from base64 import b64decode
import hashlib
from Cryptodome.Cipher import AES

window = Tk()
window.title('Password Manager')
window.config(padx=60, pady=120)

# labels
cypher_text = Label(text='cypher Text', font=('Helvetica', 15, 'normal'), fg='grey')
cypher_text.grid(row=1, column=0)

salt = Label(text='salt', font=('Helvetica', 15, 'normal'), fg='grey')
salt.grid(row=3, column=0)

nonce = Label(text='nonce', font=('Helvetica', 15, 'normal'), fg='grey')
nonce.grid(row=5, column=0)

tag = Label(text='tag', font=('Helvetica', 15, 'normal'), fg='grey')
tag.grid(row=7, column=0)

key = Label(text='key', font=('Helvetica', 15, 'normal'), fg='grey')
key.grid(row=9, column=0)
# text boxes
cypher_text_value = Entry(width=35, foreground='Blue', font=('Calibri', 11, 'bold'), borderwidth=1, show='*')
cypher_text_value.grid(row=1, column=1, pady=10, ipady=5)

salt_value = Entry(width=35, foreground='Blue', font=('Calibri', 11, 'bold'), borderwidth=1, show='*')
salt_value.grid(row=3, column=1, pady=10, ipady=5)

nonce_value = Entry(width=35, foreground='Blue', font=('Calibri', 11, 'bold'), borderwidth=1, show='*')
nonce_value.grid(row=5, column=1, pady=10, ipady=5)

tag_value = Entry(width=35, foreground='Blue', font=('Calibri', 11, 'bold'), borderwidth=1, show='*')
tag_value.grid(row=7, column=1, pady=10, ipady=5)

key_value = Entry(width=35, foreground='Blue', font=('Calibri', 11, 'bold'), borderwidth=1, show='*')
key_value.grid(row=9, column=1, pady=10, ipady=5)

# brypting password
def bcryptPassword():
    cypher_text = cypher_text_value.get()
    salt_key = salt_value.get()
    nonce_key = nonce_value.get()
    tag_key = tag_value.get()
    key = key_value.get()

    if cypher_text == '' or salt_key == '' or nonce_key == "" or tag_key == "" or key == "":
        messagebox.showerror(title='Empty', message='Required fields are empty: ')

    else:
        salt = b64decode(salt_key)
        cipher_text = b64decode(cypher_text)
        nonce = b64decode(nonce_key)
        tag = b64decode(tag_key)

            # generate the private key from the password and salt
        private_key = hashlib.scrypt(key.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)

        # create the cipher config
        cipher = AES.new(private_key, AES.MODE_GCM, nonce=nonce)

        # decrypt the cipher text
        decrypted = cipher.decrypt_and_verify(cipher_text, tag)

        original_password = bytes.decode(decrypted)
        messagebox.askokcancel(title="password", message=f'Password:{original_password}')

#buttons
button_img = PhotoImage(file='images/show_pass.png')
add_button = Button(text='Save', image=button_img, height=40, width=120, borderwidth=0, command=bcryptPassword)
add_button.grid(row=12, column=0, pady=10, columnspan=2)

window.mainloop()