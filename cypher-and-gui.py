# Caesar Cipher
import pyperclip
try:
    import tkinter as tk        # python v3
except:
    import Tkinter as tk        # python v2


def print_translated(translated):
    # OUTPUTS
    lbl = tk.Label(
        root, text = "Translated:", 
        font=("Fira Code", 9), bg='#444444', fg='#F04F5A'
        )
    lbl.grid(row=4, column=0, columnspan=1)

    #inp = inputtxt.get(1.0, "end-1c")
    #lbl.config(text="Provided Input: "+inp)
    
    # Output via Textbox 
    text_box = tk.Text(
        root,
        height=8,
        width=20,
        highlightthickness=0
        # bg="white", highlightthickness=1, 
        # foreground="black",
        # insertbackground="black", wrap="word"
        )
    text_scroll = tk.Scrollbar(orient=tk.VERTICAL,)

    text_scroll.config(command=text_box.yview, )
    text_box["yscrollcommand"] = text_scroll.set
    
    text_box.insert('end', translated)
    text_box.config(state='disabled')
    
    text_box.grid(row=4, column=1, columnspan=2, sticky="w")
    text_scroll.grid(row=4, column=2, sticky="nse")


def get_mode(input_mode):
    # set mode - encrypt / decrypt:
    mode = 'encrypt'
    mode = input_mode
    #mode = input("Enter 'e' for encrypt, 'd' for decrypt: ")
    if (mode == 'd'):
        mode = 'decrypt'
    else:
        mode = 'encrypt'
    return mode


# encryption/decryption-key:
def get_key(input_key):
    key = 0
    #key = int(input('\nEnter encryption-key [1 - 26]: '))
    key = int(input_key)
    if key == 0:
        key = 13
    return key


def caesar(input_mode):
    print(input_mode)
    #message = input('Enter: ')
    message = input_entry.get()
    key = get_key(key_entry.get())
    mode = get_mode(input_mode)

    SYMBOLS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890 !?.'
    #SYMBOLS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz123456789 \
    #    !?.`~@#$%^&*()_+-=[]{}|;:<>,/'

    translated = ''
    for symbol in message:
        if symbol in SYMBOLS:
            symbol_index = SYMBOLS.find(symbol)
            if mode == 'encrypt':
                translated_index = symbol_index + key
            elif mode == 'decrypt':
                translated_index = symbol_index - key

            if translated_index >= len(SYMBOLS):
                translated_index = translated_index - len(SYMBOLS)
            elif translated_index < 0:
                translated_index = translated_index + len(SYMBOLS)

            translated = translated + SYMBOLS[translated_index]
        else:
            translated = translated + symbol

    print('\n' + message) 
    #print('\n[ MESSAGE: ' + message + ' ]') 
    print('\n[ KEY: ' + str(key) + ' ] [ MODE: ' + mode + ' ]: ')
    print('\n' + translated + '\n')
    #print('\n' + message + '  -->  ' + translated + '\n')
    print_translated(translated)
    pyperclip.copy(translated)
    
    #return translated


# This function is called when the submit button is clicked
def submit_callback(input_entry):
    print("User entered : " + input_entry.get())
    return None


#######################  GUI ###########################
root = tk.Tk()
root.title("Cypher - Decypher")
root.geometry('300x250')       #Set window size
root.config(bg='#444444')

# HEADING
heading = tk.Label(
    root, text="Caesar-Cypher", 
    font=("Fira Code", 9), bg='#444444', fg='#F04F5A'
    )
heading.grid(row=0, column=1, columnspan=3)


# INPUTS
input_label = tk.Label(
    root, text="Enter message:", 
    font=("Fira Code", 9), bg='#444444', fg='#F04F5A'
    )
input_label.grid(row=1, column=0, columnspan=1)

input_entry = tk.Entry(root)
input_entry.grid(row=1, column=1, columnspan=2)


key_label = tk.Label(
    root, text="Enter key:", 
    font=("Fira Code", 9), bg='#444444', fg='#F04F5A'
    )
key_label.grid(row=2, column=0, columnspan=1)

key_entry = tk.Entry(root)
key_entry.grid(row=2, column=1, columnspan=2)


# # BUTTONS
# encrypt_btn = tk.Button(
#     root, 
#     text="Encrypt", 
#     command=lambda: caesar('e'),
#     font=("Fira Code", 9), bg='#444444', fg='#F04F5A'
#     )
# encrypt_btn.grid(row=3, column=1)

# decrypt_btn = tk.Button(
#     root, 
#     text="Decrypt", 
#     command=lambda: caesar('d'), 
#     font=("Fira Code", 9), bg='#444444', fg='#F04F5A'
#     )
# decrypt_btn.grid(row=3, column=2)


#####################  FAKE-BUTTONS #########################
# FAKE-BUTTONS
def OnPressed_encrypt(event):
    caesar('e')
def OnHover(event):
    encrypt_But.config(bg='#F04F5A', fg='#444444')
def OnLeave(event):
    encrypt_But.config(bg='white', fg='black')

encrypt_But = tk.Label(root, text='Encrypt', bg='white', relief='groove')
#encrypt_But.place(x=10, y=10, width=100)
encrypt_But.grid(row=3, column=1)
encrypt_But.bind('<Button-1>', OnPressed_encrypt)
encrypt_But.bind('<Enter>', OnHover)
encrypt_But.bind('<Leave>', OnLeave)


def OnPressed_decrypt(event):
    caesar('d')
def OnHover(event):
    decrypt_But.config(bg='#F04F5A', fg='#444444')
def OnLeave(event):
    decrypt_But.config(bg='white', fg='black')

decrypt_But = tk.Label(root, text='Encrypt', bg='white', relief='groove')
#decrypt_But.place(x=10, y=10, width=100)
decrypt_But.grid(row=3, column=2)
decrypt_But.bind('<Button-1>', OnPressed_decrypt)
decrypt_But.bind('<Enter>', OnHover)
decrypt_But.bind('<Leave>', OnLeave)
#############################################################


# MAIN
root.mainloop()
#############################################################
