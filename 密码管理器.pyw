from tkinter import *
from tkinter import ttk
from tkinter import filedialog
from ast import literal_eval
import math
import random
from matrix import *

with open('encrypt_config.py', encoding='utf-8-sig') as f:
    exec(f.read())


class Root(Tk):
    def __init__(self):
        super(Root, self).__init__()
        self.title("密码管理器")
        self.minsize(800, 600)
        self.password_text = None
        self.choose_password_file = ttk.Button(
            self, text='请选择密码文件', command=self.choose_password_text_filename)
        self.choose_password_file.place(x=200, y=150)
        self.enter_password_file = ttk.Button(
            self, text='请选择密钥文件', command=self.choose_password_filename)
        self.enter_password_file.place(x=200, y=200)
        self.current_msg = ttk.Label(self, text='当前暂无动作')
        self.current_msg.place(x=200, y=250)
        self.encrypt_file = ttk.Button(self,
                                       text='加密文件',
                                       command=self.choose_encrypt_file)
        self.encrypt_file.place(x=50, y=150)
        self.password_text_filename = None

    def choose_password_text_filename(self):
        filename = filedialog.askopenfilename(initialdir='.',
                                              title="请选择密码文件",
                                              filetype=(("all files",
                                                         "*.*"), ))
        if filename:
            self.password_text_filename = filename
            with open(filename, encoding='utf-8-sig') as f:
                self.password_text = f.read()
            self.current_msg.configure(text='已成功读取密码文件，请选择密钥文件')

    def choose_password_filename(self):
        if not self.password_text:
            self.current_msg.configure(text='请先选择密码文件')
            return
        filename = filedialog.askopenfilename(initialdir='.',
                                              title="请选择密钥文件",
                                              filetype=(("all files",
                                                         "*.*"), ))
        if filename:
            with open(filename, encoding='utf-8-sig') as f:
                self.password = f.read()
            self.decrypt()

    def choose_encrypt_file(self):
        filename = filedialog.askopenfilename(initialdir='.',
                                              title="请选择想要加密的文件",
                                              filetype=(("all files",
                                                         "*.*"), ))
        if filename:
            try:
                with open(filename, encoding='utf-8-sig') as f:
                    data = f.read()
            except:
                self.current_msg.configure(
                    text='请把你想要加密的文件的编码格式改成UTF-8，否则无法打开')
                return
            self.encrypt(data)

    def encrypt(self, text):
        text_length = len(text)
        num = math.ceil(text_length**0.5)
        overflow = num**2 - text_length
        size = [num, num]
        length = size[0] * size[1]
        encrypt_mat = build(*size)
        encrypt_mat.fillin(
            [random.randint(*number_range) for i in range(length)])
        while encrypt_mat.det() == 0:
            encrypt_mat.fillin(
                [random.randint(*number_range) for i in range(length)])
        try:
            encrypted_text = self.encrypt2(text, encrypt_mat, size)
        except:
            pass
        while True:
            while not self.test_validity(encrypted_text, encrypt_mat, size,
                                         overflow, text):
                encrypt_mat = build(*size)
                encrypt_mat.fillin(
                    [random.randint(*number_range) for i in range(length)])
                while encrypt_mat.det() == 0:
                    encrypt_mat.fillin(
                        [random.randint(*number_range) for i in range(length)])
                try:
                    encrypted_text = self.encrypt2(text, encrypt_mat, size)
                except:
                    pass
            try:
                with open('matrix_password.txt', 'w',
                          encoding='utf-8-sig') as f:
                    f.write(str((encrypt_mat.element(), num, overflow)))
                with open('password.txt', 'w', encoding='utf-8-sig') as f:
                    f.write(encrypted_text)
                break
            except:
                encrypt_mat = build(*size)
                encrypt_mat.fillin(
                    [random.randint(*number_range) for i in range(length)])
                while encrypt_mat.det() == 0:
                    encrypt_mat.fillin(
                        [random.randint(*number_range) for i in range(length)])
                try:
                    encrypted_text = self.encrypt2(text, encrypt_mat, size)
                except:
                    pass

        self.current_msg.configure(
            text='加密成功，matrix_password.txt是密钥文件，password.txt是密文')

    def encrypt2(self, text, mat, sizes):
        text_num = [ord(i) for i in text]
        text_mat = form(text_num, *sizes)
        new_mat = text_mat * mat
        new_mat_element = new_mat.element()
        return ''.join([chr(j) for j in new_mat_element])

    def test_validity(self, text, mat, sizes, overflow, original_text):
        try:
            decrypt_text = self.decrypt2(text, mat, sizes)
            if overflow != 0:
                decrypt_text = decrypt_text[:-overflow]
            return decrypt_text == original_text
        except:
            return False

    def decrypt(self):
        data = self.password
        if not (data[0] == '(' and data[-1] == ')'):
            self.current_msg.configure(text='密钥文件格式不正确或者密钥错误')
            return
        try:
            text = self.password_text
            mat_list, mat_size_num, overflow = eval(data)
            mat_size = [mat_size_num, mat_size_num]
            mat_decrypt = form(mat_list, *mat_size)
            decrypted_text = self.decrypt2(text, mat_decrypt, mat_size)
            if overflow != 0:
                decrypted_text = decrypted_text[:-overflow]
            self.results = decrypted_text
            exec(self.results, globals(), globals())
            self.reset_init()
        except:
            self.current_msg.configure(text='密钥文件格式不正确或者密钥错误')
            return

    def decrypt2(self, text, mat, sizes):
        text_list = [ord(i) for i in text]
        text_mat = form(text_list, *sizes)
        decrypt_mat = (text_mat * mat.inv_lu()).formated()
        decrypt_mat_element = decrypt_mat.element()
        return ''.join([chr(x) for x in decrypt_mat_element])

    def reset_init(self):
        self.current_msg.place_forget()
        self.choose_password_file.place_forget()
        self.enter_password_file.place_forget()
        self.encrypt_file.place_forget()
        self.config_options_bar = Scrollbar(self)
        self.config_options_bar.place(x=235, y=120, height=170, anchor=CENTER)
        self.choose_config_options = Listbox(
            self, yscrollcommand=self.config_options_bar.set)
        self.choose_config_options.bind('<<ListboxSelect>>',
                                        self.show_current_config_options)
        self.all_config_options = self.get_all_config_options(self.results)
        self.options_num = len(self.all_config_options)
        for k in self.all_config_options:
            self.choose_config_options.insert(END, k)
        self.choose_config_options.place(x=0, y=30, width=220)
        self.config_options_bar.config(
            command=self.choose_config_options.yview)
        self.config_name = ttk.Label(self, text='')
        self.config_name.place(x=300, y=20)
        self.config_contents = Text(self,
                                    undo=True,
                                    autoseparators=True,
                                    maxundo=-1)
        self.config_contents.bind('<KeyRelease>', self.config_change)
        self.config_contents.place(x=350, y=50, width=400, height=400)
        self.choose_filename_button = ttk.Button(self,
                                                 text='choose filename',
                                                 command=self.choose_filename)
        self.choose_directory_button = ttk.Button(
            self, text='choose directory', command=self.choose_directory)
        self.choose_filename_button.place(x=0, y=250)
        self.choose_directory_button.place(x=0, y=320)
        self.save = ttk.Button(self, text="save", command=self.save_current)
        self.save.place(x=0, y=400)
        self.saved_text = ttk.Label(text='saved')
        self.search_text = ttk.Label(self, text='search for password')
        self.search_text.place(x=0, y=450)
        self.search_contents = StringVar()
        self.search_contents.trace_add('write', self.search)
        self.search_entry = Entry(self, textvariable=self.search_contents)
        self.search_entry.place(x=0, y=480)
        self.search_inds = 0
        self.up_button = ttk.Button(
            self,
            text='up',
            command=lambda: self.change_search_inds(-1),
            width=8)
        self.down_button = ttk.Button(
            self,
            text='down',
            command=lambda: self.change_search_inds(1),
            width=8)
        self.up_button.place(x=170, y=480)
        self.down_button.place(x=250, y=480)
        self.search_inds_list = []
        self.value_dict = {i: str(eval(i)) for i in self.all_config_options}
        self.choose_bool1 = ttk.Button(
            self, text='True', command=lambda: self.insert_bool('True'))
        self.choose_bool2 = ttk.Button(
            self, text='False', command=lambda: self.insert_bool('False'))
        self.choose_bool1.place(x=120, y=270)
        self.choose_bool2.place(x=220, y=270)
        self.re_encrypt_button = ttk.Button(self,
                                            text='重新加密',
                                            command=self.re_encrypt)
        self.re_encrypt_button.place(x=0, y=530)

    def re_encrypt(self):
        with open(self.password_text_filename, encoding='utf-8-sig') as f:
            data = f.read()
        self.encrypt(data)
        self.current_msg.place(x=110, y=530)

    def get_all_config_options(self, text):
        result = []
        N = len(text)
        for i in range(N):
            current = text[i]
            if current == '\n':
                if i + 1 < N:
                    next_character = text[i + 1]
                    if next_character.isalpha():
                        inds = text[i + 1:].index('=') - 1
                        current_config_options = text[i + 1:i + 1 + inds]
                        result.append(current_config_options)
        return result

    def change(self, text, var, new, is_str=True):
        text_ls = list(text)
        var_len = len(var) + 1
        var_ind = text.index('\n' + var + ' ') + var_len
        current_var_ind = self.all_config_options.index(var)
        if current_var_ind < len(self.all_config_options) - 1:
            next_var = self.all_config_options[current_var_ind + 1]
            next_var_ind = text.index('\n' + next_var + ' ')
        else:
            next_var_ind = -1
        if is_str:
            text_ls[var_ind:next_var_ind] = f" = '{new}'"
        else:
            text_ls[var_ind:next_var_ind] = f" = {new}"
        new_password = ''.join(text_ls)
        with open(self.password_text_filename, 'w', encoding='utf-8-sig') as f:
            f.write(new_password)
        self.results = new_password

    def insert_bool(self, content):
        self.config_contents.delete('1.0', END)
        self.config_contents.insert(END, content)
        self.config_change(0)

    def config_change(self, e):
        try:
            current = self.config_contents.get('1.0', 'end-1c')
            current = literal_eval(current)
            if type(current) == str:
                current = f"'{current}'"
            current_config = self.choose_config_options.get(ANCHOR)
            exec(f'{current_config} = {current}', globals(), globals())
        except:
            pass

    def change_search_inds(self, num):
        self.search_inds += num
        if self.search_inds < 0:
            self.search_inds = 0
        if self.search_inds_list:
            search_num = len(self.search_inds_list)
            if self.search_inds >= search_num:
                self.search_inds = search_num - 1
            first = self.search_inds_list[self.search_inds]
            self.choose_config_options.selection_clear(0, END)
            self.choose_config_options.selection_set(first)
            self.choose_config_options.selection_anchor(first)
            self.choose_config_options.see(first)
            self.show_current_config_options(0)

    def search(self, *args):
        current = self.search_contents.get()
        self.search_inds_list = [
            i for i in range(self.options_num)
            if current in self.all_config_options[i]
        ]
        if self.search_inds_list:
            self.search_inds = 0
            first = self.search_inds_list[self.search_inds]
            self.choose_config_options.selection_clear(0, END)
            self.choose_config_options.selection_set(first)
            self.choose_config_options.selection_anchor(first)
            self.choose_config_options.see(first)
            self.show_current_config_options(0)
        else:
            self.choose_config_options.selection_clear(0, END)

    def show_current_config_options(self, e):
        current_config = self.choose_config_options.get(ANCHOR)
        self.config_name.configure(text=current_config)
        self.config_contents.delete('1.0', END)
        current_config_value = eval(current_config)
        if type(current_config_value) == str:
            current_config_value = f"'{current_config_value}'"
        else:
            current_config_value = str(current_config_value)
        self.config_contents.insert(END, current_config_value)

    def choose_filename(self):
        filename = filedialog.askopenfilename(initialdir='.',
                                              title="choose filename",
                                              filetype=(("all files",
                                                         "*.*"), ))
        self.config_contents.delete('1.0', END)
        self.config_contents.insert(END, f"'{filename}'")
        self.config_change(0)

    def choose_directory(self):
        directory = filedialog.askdirectory(
            initialdir='.',
            title="choose directory",
        )
        self.config_contents.delete('1.0', END)
        self.config_contents.insert(END, f"'{directory}'")
        self.config_change(0)

    def show_saved(self):
        self.saved_text.place(x=140, y=400)
        self.after(1000, self.saved_text.place_forget)

    def save_current(self):
        changed = False
        for each in self.all_config_options:
            current_value = eval(each, globals())
            current_value_str = str(current_value)
            before_value = self.value_dict[each]
            if current_value_str != before_value:
                self.change(self.results, each, current_value_str,
                            type(current_value) == str)
                self.value_dict[each] = current_value_str
                changed = True
        if changed:
            self.show_saved()


root = Root()
root.mainloop()
