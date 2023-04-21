from tkinter import *
from tkinter import ttk
from tkinter import filedialog
from ast import literal_eval
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class Root(Tk):

    def __init__(self):
        super(Root, self).__init__()
        self.title("密码管理器")
        self.minsize(800, 600)
        self.choose_password_file = ttk.Button(
            self, text='打开密码文件', command=self.choose_password_text_filename)
        self.choose_password_file.place(x=0, y=170, width=300)
        self.current_msg = ttk.Label(self, text='当前暂无动作')
        self.current_msg.place(x=0, y=530)
        self.password_text_filename = None
        self.make_password_file = ttk.Button(self,
                                             text='创建全新的密码文件',
                                             command=self.reset_init)
        self.make_password_file.place(x=0, y=100, width=300)
        self.current_ask_password_window = None
        self.current_ask_save_password_window = None
        self.password_dict = {}

    def show(self, text):
        self.current_msg.configure(text=text)
        self.current_msg.update()

    def add_password(self):
        self.show('')
        password_name = self.password_name_contents.get('1.0', 'end-1c')
        password_contents = self.password_contents.get('1.0', 'end-1c')
        if password_name and password_contents:
            if password_name in self.password_dict:
                self.show('密码名称已经存在')
                return
            self.password_dict[password_name] = password_contents
            self.choose_password_options.delete(0, END)
            for k in self.password_dict:
                self.choose_password_options.insert(END, k)
            self.choose_password_options.see(END)
            self.choose_password_options.selection_set(END)
            self.choose_password_options.selection_anchor(END)

    def delete_password(self):
        password_name = self.password_name_contents.get('1.0', 'end-1c')
        password_contents = self.password_contents.get('1.0', 'end-1c')
        if password_name in self.password_dict and password_contents:
            del self.password_dict[password_name]
            current_ind = self.choose_password_options.index(ANCHOR)
            self.choose_password_options.delete(current_ind)

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
            current_ind = self.choose_password_options.index(ANCHOR)
            self.choose_password_options.delete(current_ind)
            self.choose_password_options.insert(current_ind, new_password_name)
            self.choose_password_options.selection_set(current_ind)
            self.choose_password_options.selection_anchor(current_ind)
            self.choose_password_options.see(current_ind)

    def ask_save_password(self):
        if self.current_ask_save_password_window is not None and self.current_ask_save_password_window.winfo_exists(
        ):
            self.current_ask_save_password_window.lift()
            return
        if self.password_dict:
            self.current_ask_save_password_window = Toplevel(self)
            self.current_ask_save_password_window.minsize(500, 300)
            self.current_ask_save_password_window.title('请输入密码')
            self.ask_save_password_label = ttk.Label(
                self.current_ask_save_password_window, text='请输入密码本的加密密码:')
            self.ask_save_password_label.place(x=0, y=100)
            self.ask_save_password_entry = ttk.Entry(
                self.current_ask_save_password_window, width=30)
            self.ask_save_password_entry.place(x=150, y=100)
            self.ask_save_password_button = ttk.Button(
                self.current_ask_save_password_window,
                text='确定',
                command=self.start_encrypt)
            self.ask_save_password_button.place(x=380, y=100)

    def start_encrypt(self):
        password = self.ask_save_password_entry.get()
        if password:
            self.current_ask_save_password_window.destroy()
            password = password.encode('utf-8')
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=390000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password))
            f = Fernet(key)
            current_text = str(self.password_dict).encode('utf-8')
            encrypt_text = f.encrypt(current_text)
            self.show('加密成功，请保存密文文件')
            filename = filedialog.asksaveasfilename(title="保存密文文件",
                                                    initialfile='Untitled.txt')
            if filename:
                with open(filename, 'w') as f:
                    f.write(str((salt, encrypt_text)))
                    self.show(f'密文文件已保存在 {filename}')

    def choose_password_text_filename(self):
        filename = filedialog.askopenfilename(title="请选择密码文件",
                                              filetypes=(("all files", "*"), ))
        if filename:
            self.password_text_filename = filename
            self.ask_password()

    def ask_password(self):
        if self.current_ask_password_window is not None and self.current_ask_password_window.winfo_exists(
        ):
            self.current_ask_password_window.lift()
            return
        self.current_ask_password_window = Toplevel(self)
        self.current_ask_password_window.minsize(500, 300)
        self.current_ask_password_window.title('请输入密码')
        self.ask_password_label = ttk.Label(self.current_ask_password_window,
                                            text='请输入密码本的解锁密码:')
        self.ask_password_label.place(x=0, y=100)
        self.ask_password_entry = ttk.Entry(self.current_ask_password_window,
                                            width=30)
        self.ask_password_entry.place(x=150, y=100)
        self.ask_password_button = ttk.Button(self.current_ask_password_window,
                                              text='确定',
                                              command=self.start_decrypt)
        self.ask_password_button.place(x=380, y=100)

    def start_decrypt(self):
        password = self.ask_password_entry.get()
        if password:
            try:
                with open(self.password_text_filename, encoding='utf-8') as f:
                    salt, password_text = literal_eval(f.read())
            except:
                self.show('密文文件格式错误')
                return
            try:
                password = password.encode('utf-8')
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=390000,
                )
                key = base64.urlsafe_b64encode(kdf.derive(password))
                f = Fernet(key)
                decrypt_text = f.decrypt(password_text).decode('utf-8')
            except:
                self.show('密码错误')
                return
            self.password_dict = literal_eval(decrypt_text)
            self.current_ask_password_window.destroy()
            self.reset_init()

    def reset_init(self):
        self.make_password_file.place_forget()
        self.current_msg.place_forget()
        self.choose_password_file.place_forget()
        self.show('')
        self.current_msg.place(x=0, y=530)
        self.password_bar = Scrollbar(self)
        self.password_bar.place(x=226, y=140, height=170, anchor=CENTER)
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
        self.add_new_password.place(x=350, y=470)
        self.change_password_button = ttk.Button(self,
                                                 text='修改密码',
                                                 command=self.change_password)
        self.change_password_button.place(x=350, y=420)
        self.delete_password_button = ttk.Button(self,
                                                 text='删除密码',
                                                 command=self.delete_password)
        self.delete_password_button.place(x=450, y=420)
        self.output_password_button = ttk.Button(
            self, text='加密输出', command=self.ask_save_password)
        self.output_password_button.place(x=450, y=470)
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
        self.go_back.place(x=550, y=420)

    def go_back_func(self):
        self.destroy()
        self.__init__()

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
