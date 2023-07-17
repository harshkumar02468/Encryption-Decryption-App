import random
from tkinter import Tk, filedialog, Button, Text, Scrollbar, Entry, Label, END, Y, BOTH

class FileEncryptionApp:
    def __init__(self):
        self.root = Tk()
        self.root.withdraw()

        # Create the main application window
        self.app_window = Tk()
        self.app_window.title("File Encryption/Decryption")

        # Create a text widget for output and add initial instructions
        self.output_text = Text(self.app_window)
        self.output_text.pack(side='left', fill=BOTH, expand=True)

        initial_instructions = (
            "Welcome to File Encryption/Decryption App!\n\n"
            "Instructions:\n"
            "1. To encrypt a file, click 'Click to Encrypt File' button.\n"
            "2. To decrypt a file, click 'Click to Decrypt File' button and enter the key.\n"
            "3. For decryption, you will need the key that was generated during encryption.\n\n"
        )

        self.output_text.insert(END, initial_instructions)

        
        scrollbar = Scrollbar(self.app_window, command=self.output_text.yview)
        scrollbar.pack(side='right', fill=Y)
        self.output_text.config(yscrollcommand=scrollbar.set)

     
        encrypt_button = Button(self.app_window, text="Click to Encrypt File", command=self.encrypt_file)
        encrypt_button.pack()

        self.decrypt_button = Button(self.app_window, text="Click to Decrypt File", command=self.show_key_entry)
        self.decrypt_button.pack()

        self.key_entry = Entry(self.app_window)
        self.key_label = Label(self.app_window, text="Enter the key:")
        self.decrypt_file_button = Button(self.app_window, text="Decrypt File", command=self.decrypt_file)
        self.decrypt_key = None 

    def generate_key(self):
        e = random.randint(10, 99)
        f = random.randint(10, 99)
        g = random.randint(10, 99)
        p = random.randint(10, 99)
        ck = random.randint(10, 99)
        pk = random.randint(10, 99)
        gk = random.randint(10, 99)

        key = e * 1000000000000 + f * 10000000000 + g * 100000000 + p * 1000000 + ck * 10000 + pk * 100 + gk
        self.output_text.insert(END, "Generated key: {}\n".format(key))
        
        return e, f, g, p, ck, pk, gk

    def encrypt(self, input_path, output_path, e, f, g, p, ck, pk, gk):
        with open(input_path, "r", encoding="utf-8") as input_file, open(output_path, "w") as output_file:
            for line in input_file:
                i = 0
                flag = 0
                while 1:
                    if flag == 1:
                        output_file.write("\n")
                        break
                    for j in range(7):
                        if i < len(line) - 1:
                            if line[i] == " ":
                                output_file.write(" ")
                                i = i + 1
                            elif j == 0:
                                k = e + ord(line[i])
                                while k > 126 or k < 33:
                                    if k > 126:
                                        k = k - 126
                                    elif k < 33:
                                        k = k + 33
                                output_file.write(chr(k))
                                i = i + 1
                            elif j == 1:
                                k = f + ord(line[i])
                                while k > 126 or k < 33:
                                    if k > 126:
                                        k = k - 126
                                    elif k < 33:
                                        k = k + 33
                                output_file.write(chr(k))
                                i = i + 1
                            elif j == 2:
                                k = g + ord(line[i])
                                while k > 126 or k < 33:
                                    if k > 126:
                                        k = k - 126
                                    elif k < 33:
                                        k = k + 33
                                output_file.write(chr(k))
                                i = i + 1
                            elif j == 3:
                                k = p + ord(line[i])
                                while k > 126 or k < 33:
                                    if k > 126:
                                        k = k - 126
                                    elif k < 33:
                                        k = k + 33
                                output_file.write(chr(k))
                                i = i + 1
                            elif j == 4:
                                k = ck + ord(line[i])
                                while k > 126 or k < 33:
                                    if k > 126:
                                        k = k - 126
                                    elif k < 33:
                                        k = k + 33
                                output_file.write(chr(k))
                                i = i + 1 
                            elif j == 5:
                                k = pk + ord(line[i])
                                while k > 126 or k < 33:
                                    if k > 126:
                                        k = k - 126
                                    elif k < 33:
                                        k = k + 33
                                output_file.write(chr(k))
                                i = i + 1 
                            elif j == 6:
                                k = gk + ord(line[i])
                                while k > 126 or k < 33:
                                    if k > 126:
                                        k = k - 126
                                    elif k < 33:
                                        k = k + 33
                                output_file.write(chr(k))
                                i = i + 1  
                        else:
                            flag = 1
                            break

    def decrypt(self, input_path, output_path, key2):
        h = int(key2 / 1000000000000)
        k = int((key2/ 10000000000) - (h * 100))
        s = int((key2/ 100000000) - ((h * 10000) + (k * 100)))
        p = int((key2 / 1000000) - ((h * 1000000) + (k * 10000) + (s * 100)))
        ck = int((key2 / 10000) - ((h * 100000000) + (k * 1000000) + (s * 10000) + (p * 100)))
        pk = int((key2/ 100) - ((h * 10000000000) + (k * 100000000) + (s * 1000000) + (p * 10000) + (ck * 100)))
        gk = key2 - (int(key2 / 100) * 100)
        y = open(input_path, "r", encoding="utf-8")
        x = open(output_path, "w")
        for ab in y:
            flag = 0
            i = 0
            while 1:
                if flag == 1:
                    break
                for j in range(7):
                    if i < len(ab) - 1:
                        if ab[i] == " ":
                            x.write(" ")
                            i = i + 1
                        elif j == 0:
                            z = ord(ab[i]) - h
                            while z < 33:
                                if z < 33 and z >= 0:
                                    z = 126 - (33 - z)
                                elif z < 0:
                                    z = 126 + z
                            x.write(chr(z))
                            i = i + 1
                        elif j == 1:
                            z = ord(ab[i]) - k
                            while z < 33:
                                if z < 33 and z >= 0:
                                    z = 126 - (33 - z)
                                elif z < 0:
                                    z = 126 + z
                            x.write(chr(z))
                            i = i + 1
                        elif j == 2:
                            z = ord(ab[i]) - s
                            while z < 33:
                                if z < 33 and z >= 0:
                                    z = 126 - (33 - z)
                                elif z < 0:
                                    z = 126 + z
                            x.write(chr(z))
                            i = i + 1
                        elif j == 3:
                            z = ord(ab[i]) - p
                            while z < 33:
                                if z < 33 and z >= 0:
                                    z = 126 - (33 - z)
                                elif z < 0:
                                    z = 126 + z
                            x.write(chr(z))
                            i = i + 1
                        elif j == 4:
                            z = ord(ab[i]) - ck
                            while z < 33:
                                if z < 33 and z >= 0:
                                    z = 126 - (33 - z)
                                elif z < 0:
                                    z = 126 + z
                            x.write(chr(z))
                            i = i + 1
                        elif j == 5:
                            z = ord(ab[i]) - pk
                            while z < 33:
                                if z < 33 and z >= 0:
                                    z = 126 - (33 - z)
                                elif z < 0:
                                    z = 126 + z
                            x.write(chr(z))
                            i = i + 1
                        elif j == 6:
                            z = ord(ab[i]) - gk
                            while z < 33:
                                if z < 33 and z >= 0:
                                    z = 126 - (33 - z)
                                elif z < 0:
                                    z = 126 + z
                            x.write(chr(z))
                            i = i + 1
                    else:
                        flag = 1
                        break
        x.close()

    def display_contents(self, text_widget, file_path):
        with open(file_path, 'r', encoding="utf-8") as file:
            contents = file.read()
            text_widget.insert(END, contents)

    def show_key_entry(self):
        self.key_entry.pack()
        self.key_label.pack()
        self.decrypt_file_button.pack()
        self.decrypt_button.configure(state="disabled")

    def encrypt_file(self):
        inputFileName = filedialog.askopenfilename(title="Select File to Encrypt")
        if inputFileName:
            outputFileName = filedialog.asksaveasfilename(title="Save Encrypted File As")
            if outputFileName:
                fu = self.generate_key()
                self.encrypt(inputFileName, outputFileName, fu[0], fu[1], fu[2], fu[3], fu[4], fu[5], fu[6])
                self.output_text.insert(END, "File encrypted successfully.\n\n")
                self.output_text.insert(END, "/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/")
                self.output_text.insert(END, "\n\n")

    def decrypt_file(self):
        inputFileName = filedialog.askopenfilename(title="Select File to Decrypt")
        if inputFileName:
            outputFileName = filedialog.asksaveasfilename(title="Save Decrypted File As")
            if outputFileName:
                self.decrypt_key = self.key_entry.get()
                if self.decrypt_key.isdigit():
                    self.decrypt(inputFileName, outputFileName, int(self.decrypt_key))
                    self.output_text.insert(END, "File decrypted successfully.\n\n")
                    self.output_text.insert(END, "/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/")
                    self.output_text.insert(END, "\n\n")
                else:
                    self.output_text.insert(END, "Invalid key. Please enter a valid key.\n")

    def run(self):
        self.app_window.mainloop()

app = FileEncryptionApp()
app.run()
