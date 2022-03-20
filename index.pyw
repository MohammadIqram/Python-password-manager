from tkinter import *
from tkinter import messagebox
from base64 import b64encode, b64decode
import hashlib
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
import os

window = Tk()
window.title('Password Manager')
window.config(padx=50, pady=20)

canvas = Canvas(width=300, height=300)
logo_img = PhotoImage(file='images/password-m.png')
canvas.create_image(150, 130, image=logo_img)
canvas.grid(row=0, column=1)

web_label = Label(text='Website', font=('Helvetica', 15, 'normal'), fg='grey')
web_label.grid(row=1, column=0)
email_label = Label(text='Email/Name', font=('Helvetica', 15, 'normal'), fg='grey')
email_label.grid(row=2, column=0)
pass_label = Label(text='Password:', font=('Helvetica', 15, 'normal'), fg='grey')
pass_label.grid(row=3, column=0)

# text boxes
web_entry = Entry(width=35, foreground='Blue', font=('Helvetica', 11, 'normal'), borderwidth=1)
web_entry.grid(row=1, column=1, ipady=5)
email_entry = Entry(width=35, foreground='Blue', font=('Helvetica', 11, 'normal'), borderwidth=1)
email_entry.grid(row=2, column=1, pady=10, ipady=5)
pass_entry = Entry(width=35, foreground='Blue', font=('Helvetica', 11, 'normal'), borderwidth=1, show='*')
pass_entry.grid(row=3, column=1, pady=10, ipady=5)

def encrypt(plain_text, password):
    # generate a random salt
    salt = get_random_bytes(AES.block_size)

    # use the Scrypt KDF to get a private key from the password
    private_key = hashlib.scrypt(
        password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)

    # create cipher config
    cipher_config = AES.new(private_key, AES.MODE_GCM)

    # return a dictionary with the encrypted text
    cipher_text, tag = cipher_config.encrypt_and_digest(bytes(plain_text, 'utf-8'))
    return {
        'cipher_text': b64encode(cipher_text).decode('utf-8'),
        'salt': b64encode(salt).decode('utf-8'),
        'nonce': b64encode(cipher_config.nonce).decode('utf-8'),
        'tag': b64encode(tag).decode('utf-8')
    }

# saving the data
def data_save():
    website_name = web_entry.get()
    email = email_entry.get()
    password = pass_entry.get()

    encrypted = encrypt(password, "dlafmks45345$%$#D35")

    if website_name == '' or password == '':
        messagebox.showerror(title='Empty', message='Required fields are empty: ')

    if len(website_name) < 4:
        messagebox.showerror(title='invalid length', message='website length too short')

    else:
        is_confirm = messagebox.askokcancel(title=website_name,
                                            message=f'Details:\n email: {email} \npassword: {password}')

        if is_confirm:
            try:
                with open('data_file.txt', 'a') as dataFile:
                   dataFile.write(f"WEBSITE :: {website_name} || email :: {email} || hash :: {encrypted}\n")

            except FileNotFoundError:
                with open('data_file.txt', 'w') as dataFile:
                    dataFile.write(f"WEBSITE :: {website_name} || email :: {email} || hash :: {encrypted}\n")

            finally:
                    web_entry.delete(0, END)
                    email_entry.delete(0, END)
                    pass_entry.delete(0, END)
                    dataFile.close()


def find_data():
    data_search = web_entry.get()
    data_found = False
    line_number = 1

    if len(data_search) != 4:
        messagebox.showerror(title="value Error", message="write only first 4 letters of your website")

    elif len(data_search) == "":
        messagebox.showerror(title="Empty field", message="website field cannot be empty")

    else:
        try:
            with open('data_file.txt') as data_file:
                lines = data_file.readlines()

                for item in lines:
                    word = item.strip('\n')

                    if word[11] == data_search[0] and word[12] == data_search[1] and word[13] == data_search[2] and word[14] == data_search[3]:
                        messagebox.showinfo(title="found", message="data found")
                        data_found = True
                        break
                    line_number += 1

                if data_found == True:
                    messagebox.showinfo(title="found", message=f"data found at line number {line_number}")

                else:
                    messagebox.showerror(title="Not found", message="data not present")

        except FileNotFoundError:
            messagebox.showerror(title="file not found", message="file not created yet")

        finally:
            data_file.close()


def decrypt_file():
    if checkbox.get():
        os.system('start decrypt.pyw')

        try:
            os.system('start data_file.txt')

        except FileNotFoundError:
            raise

    else:
        os.system('start decrypt.pyw')

#buttons
button_img = PhotoImage(file='images/button_img1.png')
add_button = Button(text='Save', image=button_img, height=40, width=120, borderwidth=0, command=data_save)
add_button.grid(row=4, column=1, pady=8)
button_img_decrypt = PhotoImage(file='images/decrypt_button.png')
add_button3 = Button(text='Decrypt', image=button_img_decrypt, height=40, width=120, borderwidth=0, command=decrypt_file)
add_button3.grid(row=4, column=2, pady=8)
button_search_img = PhotoImage(file='images/search_img.png')
add_button2 = Button(text='Save', image=button_search_img, height=50, width=40, borderwidth=0, command=find_data)
add_button2.grid(row=1, column=2)

checkbox = IntVar()
cb1 = Checkbutton(window, text="open datafile", onvalue=1, offvalue=0, variable=checkbox, height=2, width=12, relief=GROOVE,
                  font=('Helvetica', 10, 'normal'), fg='red')
cb1.grid(row=5, column=2)


window.mainloop()
