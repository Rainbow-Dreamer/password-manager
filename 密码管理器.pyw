from tkinter import *
from tkinter import ttk
from tkinter import filedialog
from ast import literal_eval
import math
import random
from matrix import *

with open('encrypt_config.py', encoding='utf-8') as f:
    exec(f.read())
counter = 0


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
        self.current_msg.place(x=200, y=530)
        self.encrypt_file = ttk.Button(self,
                                       text='加密文件',
                                       command=self.choose_encrypt_file)
        self.encrypt_file.place(x=50, y=150)
        self.password_text_filename = None
        self.make_password_file = ttk.Button(self,
                                             text='创建全新的密码文件',
                                             command=self.write_password_file)
        self.make_password_file.place(x=50, y=200)
        self.write_password = False

    def write_password_file(self):
        if not self.write_password:
            self.write_password = True
            self.password_bar = Scrollbar(self)
            self.password_bar.place(x=235, y=400, height=170, anchor=CENTER)
            self.choose_password_options = Listbox(
                self, yscrollcommand=self.password_bar.set)
            self.choose_password_options.bind('<<ListboxSelect>>',
                                              self.show_current_passwords)
            self.password_dict = {}
            self.choose_password_options.place(x=0, y=310, width=220)
            self.password_bar.config(
                command=self.choose_password_options.yview)
            self.password_name = ttk.Label(self, text='')
            self.password_name.place(x=300, y=300)
            self.password_name_contents = Text(self,
                                               undo=True,
                                               autoseparators=True,
                                               maxundo=-1)
            self.password_contents = Text(self,
                                          undo=True,
                                          autoseparators=True,
                                          maxundo=-1)
            self.password_contents.place(x=350, y=200, width=400, height=200)
            self.password_name_contents.place(x=350,
                                              y=50,
                                              width=400,
                                              height=100)
            self.password_name_contents_label = ttk.Label(self, text='当前密码名')
            self.password_contents_label = ttk.Label(self, text='当前密码内容')
            self.password_name_contents_label.place(x=350, y=20)
            self.password_contents_label.place(x=350, y=170)
            self.add_new_password = ttk.Button(self,
                                               text='添加新的密码',
                                               command=self.add_password)
            self.add_new_password.place(x=50, y=250)
            self.change_password_button = ttk.Button(
                self, text='修改密码', command=self.change_password)
            self.change_password_button.place(x=350, y=420)
            self.delete_password_button = ttk.Button(
                self, text='删除密码', command=self.delete_password)
            self.delete_password_button.place(x=450, y=420)
            self.output_password_button = ttk.Button(
                self, text='加密输出', command=self.convert_password)
            self.output_password_button.place(x=550, y=420)
            self.go_back_button = ttk.Button(self,
                                             text='返回',
                                             command=self.go_back_func)
            self.go_back_button.place(x=650, y=420)

    def add_password(self):
        password_name = self.password_name_contents.get('1.0', 'end-1c')
        password_contents = self.password_contents.get('1.0', 'end-1c')
        if password_name and password_contents:
            self.password_dict[password_name] = password_contents
            self.choose_password_options.delete(0, END)
            for k in self.password_dict:
                self.choose_password_options.insert(END, k)

    def delete_password(self):
        password_name = self.password_name_contents.get('1.0', 'end-1c')
        password_contents = self.password_contents.get('1.0', 'end-1c')
        if password_name in self.password_dict and password_contents:
            del self.password_dict[password_name]
            self.choose_password_options.delete(0, END)
            for k in self.password_dict:
                self.choose_password_options.insert(END, k)

    def change_password(self):
        password_name = self.choose_password_options.get(ANCHOR)
        new_password_name = self.password_name_contents.get('1.0', 'end-1c')
        password_contents = self.password_contents.get('1.0', 'end-1c')
        if password_name and password_contents:
            keys = list(self.password_dict.keys())
            values = list(self.password_dict.values())
            inds = keys.index(password_name)
            keys[inds] = new_password_name
            values[inds] = password_contents
            self.password_dict = dict(zip(keys, values))
            self.choose_password_options.delete(0, END)
            for k in self.password_dict:
                self.choose_password_options.insert(END, k)

    def convert_password(self):
        if self.password_dict:
            current_text = {}
            for each in self.password_dict:
                current_text[each] = self.password_dict[each]
            self.encrypt(str(current_text))

    def choose_password_text_filename(self):
        filename = filedialog.askopenfilename(title="请选择密码文件",
                                              filetypes=(("all files", "*"), ))
        if filename:
            self.password_text_filename = filename
            with open(filename, encoding='utf-8') as f:
                self.password_text = f.read()
            self.current_msg.configure(text='已成功读取密码文件，请选择密钥文件')

    def choose_password_filename(self):
        if not self.password_text:
            self.current_msg.configure(text='请先选择密码文件')
            return
        filename = filedialog.askopenfilename(title="请选择密钥文件",
                                              filetypes=(("all files", "*"), ))
        if filename:
            with open(filename, encoding='utf-8') as f:
                self.password = f.read()
            self.current_msg.configure(text='已成功读取密钥文件，正在尝试解密中，请稍候')
            self.update()
            self.decrypt()

    def choose_encrypt_file(self):
        filename = filedialog.askopenfilename(title="请选择想要加密的文件",
                                              filetypes=(("all files", "*"), ))
        if filename:
            try:
                with open(filename, encoding='utf-8') as f:
                    data = f.read()
            except:
                self.current_msg.configure(
                    text='请把你想要加密的文件的编码格式改成UTF-8，否则无法打开')
                return
            self.current_msg.configure(text='已成功读取要加密的文件，正在加密中，请稍候')
            self.update()
            self.encrypt(data)

    def encrypt(self, text):
        global counter
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
            encrypted_text = ''
        while True:
            while not self.test_validity(encrypted_text, encrypt_mat, size,
                                         overflow, text):
                counter += 1
                self.current_msg.configure(
                    text=f'当前随机矩阵无法加密，正在重新加密，第{counter}次')
                self.update()
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
                with open('matrix_password.txt', 'w', encoding='utf-8') as f:
                    f.write(str((encrypt_mat.element(), num, overflow)))
                with open('password.txt', 'w', encoding='utf-8') as f:
                    f.write(encrypted_text)
                break
            except:
                counter += 1
                self.current_msg.configure(
                    text=f'当前随机矩阵无法加密，正在重新加密，第{counter}次')
                self.update()
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
        if not text:
            return False
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
            self.results = eval(decrypted_text)
            self.reset_init()
        except Exception as e:
            print(str(e))
            self.current_msg.configure(text='密钥文件格式不正确或者密钥错误')
        return

    def decrypt2(self, text, mat, sizes):
        text_list = [ord(i) for i in text]
        text_mat = form(text_list, *sizes)
        decrypt_mat = (text_mat * mat.inv_lu()).formated()
        decrypt_mat_element = decrypt_mat.element()
        return ''.join([chr(x) for x in decrypt_mat_element])

    def reset_init(self):
        if self.write_password:
            self.password_bar.place_forget()
            self.choose_password_options.place_forget()
            self.password_name.place_forget()
            self.password_contents.place_forget()
            self.password_name_contents.place_forget()
            self.password_name_contents_label.place_forget()
            self.add_new_password.place_forget()
            self.change_password_button.place_forget()
            self.output_password_button.place_forget()
        self.make_password_file.place_forget()
        self.current_msg.place_forget()
        self.choose_password_file.place_forget()
        self.enter_password_file.place_forget()
        self.encrypt_file.place_forget()
        self.current_msg.configure(text='')
        self.current_msg.place(x=20, y=570)
        self.password_dict = self.results
        self.password_bar = Scrollbar(self)
        self.password_bar.place(x=235, y=140, height=170, anchor=CENTER)
        self.choose_password_options = Listbox(
            self, yscrollcommand=self.password_bar.set)
        self.choose_password_options.bind('<<ListboxSelect>>',
                                          self.show_current_passwords)
        self.choose_password_options.place(x=0, y=50, width=220)
        self.password_bar.config(command=self.choose_password_options.yview)
        self.password_name = ttk.Label(self, text='')
        self.password_name.place(x=300, y=300)
        self.password_name_contents = Text(self,
                                           undo=True,
                                           autoseparators=True,
                                           maxundo=-1)
        self.password_contents = Text(self,
                                      undo=True,
                                      autoseparators=True,
                                      maxundo=-1)
        self.password_contents.place(x=350, y=200, width=400, height=200)
        self.password_name_contents.place(x=350, y=50, width=400, height=100)
        self.password_name_contents_label = ttk.Label(self, text='当前密码名')
        self.password_contents_label = ttk.Label(self, text='当前密码内容')
        self.password_name_contents_label.place(x=350, y=20)
        self.password_contents_label.place(x=350, y=170)
        self.add_new_password = ttk.Button(self,
                                           text='添加新的密码',
                                           command=self.add_password)
        self.add_new_password.place(x=50, y=250)
        self.change_password_button = ttk.Button(self,
                                                 text='修改密码',
                                                 command=self.change_password)
        self.change_password_button.place(x=350, y=420)
        self.delete_password_button = ttk.Button(self,
                                                 text='删除密码',
                                                 command=self.delete_password)
        self.delete_password_button.place(x=450, y=420)
        self.output_password_button = ttk.Button(self,
                                                 text='加密输出',
                                                 command=self.convert_password)
        self.output_password_button.place(x=550, y=420)
        self.choose_password_options.delete(0, END)
        for k in self.password_dict:
            self.choose_password_options.insert(END, k)

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
        self.go_back = ttk.Button(self, text='返回', command=self.go_back_func)
        self.go_back.place(x=170, y=530)

    def go_back_func(self):
        self.destroy()
        self.__init__()

    def re_encrypt(self):
        self.current_msg.configure(text='')
        self.current_msg.place(x=20, y=570)
        with open(self.password_text_filename, encoding='utf-8') as f:
            data = f.read()
        if data == self.password_text:
            self.current_msg.configure(text='当前并无任何改动，无需重新加密')
            self.update()
            return
        self.current_msg.configure(text='正在重新加密中，请稍候')
        self.update()
        self.encrypt(data)

    def insert_bool(self, content):
        self.config_contents.delete('1.0', END)
        self.config_contents.insert(END, content)
        self.config_change(0)

    def config_change(self, e):
        try:
            current = self.config_contents.get('1.0', 'end-1c')
            current_config = self.choose_config_options.get(ANCHOR)
            exec(f'{current_config} = "{current}"', globals(), globals())
        except:
            pass

    def password_change(self):
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
            self.choose_password_options.selection_clear(0, END)
            self.choose_password_options.selection_set(first)
            self.choose_password_options.selection_anchor(first)
            self.choose_password_options.see(first)
            self.show_current_config_options(0)

    def search(self, *args):
        current = self.search_contents.get()
        keys = list(self.password_dict.keys())
        self.search_inds_list = [
            i for i in range(len(keys)) if current in keys[i]
        ]
        if self.search_inds_list:
            self.search_inds = 0
            first = self.search_inds_list[self.search_inds]
            self.choose_password_options.selection_clear(0, END)
            self.choose_password_options.selection_set(first)
            self.choose_password_options.selection_anchor(first)
            self.choose_password_options.see(first)
            self.show_current_config_options(0)
        else:
            self.choose_password_options.selection_clear(0, END)

    def show_current_config_options(self, e):
        current_config = self.choose_password_options.get(ANCHOR)
        self.password_name_contents.delete('1.0', END)
        self.password_name_contents.insert(END, current_config)
        self.password_contents.delete('1.0', END)
        current_config_value = self.password_dict[current_config]
        #if type(current_config_value) == str:
        #current_config_value = f"'{current_config_value}'"
        #else:
        #current_config_value = str(current_config_value)
        self.password_contents.insert(END, current_config_value)

    def show_current_passwords(self, e):
        current_password = self.choose_password_options.get(ANCHOR)
        if current_password in self.password_dict:

            self.password_name_contents.delete('1.0', END)
            self.password_name_contents.insert(END, current_password)
            self.password_contents.delete('1.0', END)
            current_password_value = self.password_dict[current_password]
            self.password_contents.insert(END, current_password_value)

    def choose_filename(self):
        filename = filedialog.askopenfilename(title="choose filename",
                                              filetypes=(("all files", "*"), ))
        self.config_contents.delete('1.0', END)
        self.config_contents.insert(END, f"'{filename}'")
        self.config_change(0)

    def choose_directory(self):
        directory = filedialog.askdirectory(title="choose directory", )
        self.config_contents.delete('1.0', END)
        self.config_contents.insert(END, f"'{directory}'")
        self.config_change(0)


root = Root()
root.mainloop()
