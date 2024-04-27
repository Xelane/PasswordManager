import json
import hashlib
import string
import random
import os
import pyperclip
import wx
from cryptography.fernet import Fernet

def hash_pass(password):
    sha = hashlib.sha256()
    sha.update(password.encode())
    return sha.hexdigest()

def keygen():
    return Fernet.generate_key()

def initialize_cipher(key):
    return Fernet(key)

def encrypt(cipher, password):
    return cipher.encrypt(password.encode()).decode()

def decrypt(cipher, en_password):
    return cipher.decrypt(en_password.encode()).decode()

def reg(username, master_pass):
    hased_master_pass = hash_pass(master_pass)
    userdata = {'username': username, 'master_password': hased_master_pass}
    filename = 'userdata.json'
    
    try:
        with open(filename, 'r') as file:
            data = json.load(file)
            if data['username'] == username:
                print("\nUser already exists")
                return
    except FileNotFoundError:
        pass

    with open(filename, 'w') as file:
        json.dump(userdata, file)
        print("\nRegistration successful\n")

def login(username, entered_pass):
    try:
        with open('userdata.json', 'r') as file:
            userdata = json.load(file)
        stored_password_hash = userdata.get('master_password')
        entered_pass_hash = hash_pass(entered_pass)
        if entered_pass_hash == stored_password_hash and username == userdata.get('username'):
            print("\nLogin successful\n")
            return True
        else:
            print("\nInvalid Login credentials\n")
            return False
    except Exception:
        print("\nPlease register before logging in.\n")
        return False

def websites():
    try:
        with open('password.json', 'r') as data:
            view = json.load(data)
            print("\n Saved websites:\n")
            for x in view:
                print(x['website'])
            print('\n')
    except FileNotFoundError:
        print("\nNo saved passwords found!\n")

key_filename = 'encryption_key.key'
if os.path.exists(key_filename):
    with open(key_filename, 'rb') as key_file:
        key = key_file.read()
else:
    key = keygen()
    with open(key_filename, 'wb') as key_file:
        key_file.write(key)

cipher = initialize_cipher(key)

def add_pass(website, password):
    if not os.path.exists('password.json'):
        data = []
    else:
        try:
            with open('password.json', 'r') as file:
                data = json.load(file)
        except json.JSONDecodeError:
            data = []
    en_password = encrypt(cipher, password)
    pass_entry = {'website': website, 'password': en_password}
    data.append(pass_entry)
    with open('password.json', 'w') as file:
        json.dump(data, file, indent=4)

def get_pass(website):
    if not os.path.exists('password.json'):
        return None
    try:
        with open('password.json', 'r') as file:
            data = json.load(file)
    except json.JSONDecodeError:
        data = []
    for entry in data:
        if entry['website'] == website:
            decrypted_pass = decrypt(cipher, entry['password'])
            return decrypted_pass
    return None

class MainFrame(wx.Frame):
    def __init__(self):
        super(MainFrame, self).__init__(parent=None, title='Password Manager', size=(400, 300))
        
        self.panel = wx.Panel(self)
        self.sizer = wx.BoxSizer(wx.VERTICAL)
        
        self.choice_label = wx.StaticText(self.panel, label="Please login/register your Master account:")
        self.register_btn = wx.Button(self.panel, label="Register")
        self.login_btn = wx.Button(self.panel, label="Login")
        self.quit_btn = wx.Button(self.panel, label="Quit")
        self.message_label = wx.StaticText(self.panel, label="")
        
        self.sizer.AddSpacer(40)
        self.sizer.Add(self.choice_label, 0, wx.ALIGN_CENTER_HORIZONTAL, 10)
        self.sizer.AddSpacer(10)
        self.sizer.Add(self.register_btn, 0, wx.ALIGN_CENTER_HORIZONTAL | wx.ALL, 5)
        self.sizer.Add(self.login_btn, 0, wx.ALIGN_CENTER_HORIZONTAL | wx.ALL, 5)
        self.sizer.Add(self.quit_btn, 0, wx.ALIGN_CENTER_HORIZONTAL | wx.ALL, 5)
        self.sizer.AddSpacer(10)
        self.sizer.Add(self.message_label, 0, wx.ALIGN_CENTER, 5)
        self.panel.SetSizer(self.sizer)
        
        self.register_btn.Bind(wx.EVT_BUTTON, self.on_register)
        self.login_btn.Bind(wx.EVT_BUTTON, self.on_login)
        self.quit_btn.Bind(wx.EVT_BUTTON, self.on_quit)

    def on_register(self, event):
        reg_frame = RegisterFrame(self)
        reg_frame.Show()

    def on_login(self, event):
        login_frame = LoginFrame(self)
        login_frame.Show()

    def on_quit(self, event):
        self.Close()

    def switch_to_post_login_frame(self, username):
        post_login_frame = PostLoginFrame(self, username)
        post_login_frame.Show()

    def set_message(self, message):
        self.message_label.SetLabel(message)
        self.sizer.Layout() 
        self.message_label.Wrap(350)
        self.message_label.SetSize(self.message_label.GetBestSize())
        self.message_label.SetPosition((self.panel.GetSize().width / 2 - self.message_label.GetSize().width / 2, -1))

class RegisterFrame(wx.Frame):
    def __init__(self, parent):
        super(RegisterFrame, self).__init__(parent=parent, title="Register", size=(400, 200))
        
        self.panel = wx.Panel(self)
        
        self.username_label = wx.StaticText(self.panel, label="Username:")
        self.username_text = wx.TextCtrl(self.panel)
        
        self.masterpass_label = wx.StaticText(self.panel, label="Master Password:")
        self.masterpass_text = wx.TextCtrl(self.panel, style=wx.TE_PASSWORD)
        
        self.register_btn = wx.Button(self.panel, label="Register")
        self.cancel_btn = wx.Button(self.panel, label="Cancel")
        
        self.sizer = wx.BoxSizer(wx.VERTICAL)
        self.sizer.Add(self.username_label, 0, wx.ALL, 5)
        self.sizer.Add(self.username_text, 0, wx.ALL | wx.EXPAND, 5)
        self.sizer.Add(self.masterpass_label, 0, wx.ALL, 5)
        self.sizer.Add(self.masterpass_text, 0, wx.ALL | wx.EXPAND, 5)
        self.sizer.Add(self.register_btn, 0, wx.ALIGN_CENTER_HORIZONTAL | wx.ALL, 5)
        self.sizer.Add(self.cancel_btn, 0, wx.ALIGN_CENTER_HORIZONTAL | wx.ALL, 5)
        
        self.panel.SetSizer(self.sizer)
        
        self.register_btn.Bind(wx.EVT_BUTTON, self.on_register)
        self.cancel_btn.Bind(wx.EVT_BUTTON, self.on_cancel)

    def on_register(self, event):
        username = self.username_text.GetValue()
        master_pass = self.masterpass_text.GetValue()
        reg(username, master_pass)
        self.Parent.set_message("Registration successful")
        self.Close()

    def on_cancel(self, event):
        self.Close()

class LoginFrame(wx.Frame):
    def __init__(self, parent):
        super(LoginFrame, self).__init__(parent=parent, title="Login", size=(400, 200))
        
        self.panel = wx.Panel(self)
        
        self.username_label = wx.StaticText(self.panel, label="Username:")
        self.username_text = wx.TextCtrl(self.panel)
        
        self.masterpass_label = wx.StaticText(self.panel, label="Master Password:")
        self.masterpass_text = wx.TextCtrl(self.panel, style=wx.TE_PASSWORD)
        
        self.login_btn = wx.Button(self.panel, label="Login")
        self.cancel_btn = wx.Button(self.panel, label="Cancel")
        
        self.sizer = wx.BoxSizer(wx.VERTICAL)
        self.sizer.Add(self.username_label, 0, wx.ALL, 5)
        self.sizer.Add(self.username_text, 0, wx.ALL | wx.EXPAND, 5)
        self.sizer.Add(self.masterpass_label, 0, wx.ALL, 5)
        self.sizer.Add(self.masterpass_text, 0, wx.ALL | wx.EXPAND, 5)
        self.sizer.Add(self.login_btn, 0, wx.ALIGN_CENTER_HORIZONTAL | wx.ALL, 5)
        self.sizer.Add(self.cancel_btn, 0, wx.ALIGN_CENTER_HORIZONTAL | wx.ALL, 5)
        
        self.panel.SetSizer(self.sizer)
        
        self.login_btn.Bind(wx.EVT_BUTTON, self.on_login)
        self.cancel_btn.Bind(wx.EVT_BUTTON, self.on_cancel)

    def on_login(self, event):
        username = self.username_text.GetValue()
        master_pass = self.masterpass_text.GetValue()
        if login(username, master_pass):
            self.Parent.switch_to_post_login_frame(username)
            self.Parent.set_message("Login successful")
            self.Close()
        else:
            self.Parent.set_message("Invalid Login credentials")

    def on_cancel(self, event):
        self.Close()


class PostLoginFrame(wx.Frame):
    def __init__(self, parent, username):
        super(PostLoginFrame, self).__init__(parent=parent, title=f"Logged in as {username}", size=(500, 300))
        
        self.panel = wx.Panel(self)
        
        self.add_pass_btn = wx.Button(self.panel, label="Add Password")
        self.get_pass_btn = wx.Button(self.panel, label="Get Password")
        self.delete_pass_btn = wx.Button(self.panel, label="Delete Password")
        self.view_websites_btn = wx.Button(self.panel, label="View Saved Websites")
        self.exit_btn = wx.Button(self.panel, label="Exit")
        self.message_label = wx.StaticText(self.panel, label="", style=wx.ALIGN_CENTER)
        
        self.sizer = wx.BoxSizer(wx.VERTICAL)
        self.sizer.AddSpacer(40)
        self.sizer.Add(self.add_pass_btn, 0, wx.ALIGN_CENTER_HORIZONTAL | wx.ALL, 5)
        self.sizer.Add(self.get_pass_btn, 0, wx.ALIGN_CENTER_HORIZONTAL | wx.ALL, 5)
        self.sizer.Add(self.delete_pass_btn, 0, wx.ALIGN_CENTER_HORIZONTAL | wx.ALL, 5)
        self.sizer.Add(self.view_websites_btn, 0, wx.ALIGN_CENTER_HORIZONTAL | wx.ALL, 5)
        self.sizer.Add(self.exit_btn, 0, wx.ALIGN_CENTER_HORIZONTAL | wx.ALL, 5)
        self.sizer.Add(self.message_label, 0, wx.ALIGN_CENTER_HORIZONTAL | wx.ALL, 5)
        
        self.panel.SetSizer(self.sizer)
        
        self.add_pass_btn.Bind(wx.EVT_BUTTON, self.on_add_pass)
        self.get_pass_btn.Bind(wx.EVT_BUTTON, self.on_get_pass)
        self.delete_pass_btn.Bind(wx.EVT_BUTTON, self.on_delete_pass)
        self.view_websites_btn.Bind(wx.EVT_BUTTON, self.on_view_websites)
        self.exit_btn.Bind(wx.EVT_BUTTON, self.on_exit)

    def on_add_pass(self, event):
        add_pass_frame = AddPasswordFrame(self)
        add_pass_frame.Show()

    def on_get_pass(self, event):
        get_pass_frame = GetPasswordFrame(self)
        get_pass_frame.Show()

    def on_view_websites(self, event):
        view_websites_frame = ViewWebsitesFrame(self)
        view_websites_frame.Show()

    def on_exit(self, event):
        self.Close()

    def set_message(self, message):
        self.message_label.SetLabel(message)
        self.sizer.Layout() 
        self.message_label.Wrap(350) 
        self.message_label.SetSize(self.message_label.GetBestSize())
        self.message_label.SetPosition((self.panel.GetSize().width / 2 - self.message_label.GetSize().width / 2, -1))

    def on_delete_pass(self, event):
        delete_pass_frame = DeletePasswordFrame(self)
        delete_pass_frame.Show()

class AddPasswordFrame(wx.Frame):
    def __init__(self, parent):
        super(AddPasswordFrame, self).__init__(parent=parent, title="Add New Password", size=(400, 250))
        
        self.panel = wx.Panel(self)
        
        self.website_label = wx.StaticText(self.panel, label="Website:")
        self.website_text = wx.TextCtrl(self.panel)
        
        self.password_label = wx.StaticText(self.panel, label="Password:")
        self.password_text = wx.TextCtrl(self.panel, style=wx.TE_PASSWORD)
        
        self.generate_checkbox = wx.CheckBox(self.panel, label="Generate Password")
        
        self.add_btn = wx.Button(self.panel, label="Add")
        self.cancel_btn = wx.Button(self.panel, label="Cancel")
        
        self.sizer = wx.BoxSizer(wx.VERTICAL)
        self.sizer.Add(self.website_label, 0, wx.ALL, 5)
        self.sizer.Add(self.website_text, 0, wx.ALL | wx.EXPAND, 5)
        self.sizer.Add(self.password_label, 0, wx.ALL, 5)
        self.sizer.Add(self.password_text, 0, wx.ALL | wx.EXPAND, 5)
        self.sizer.Add(self.generate_checkbox, 0, wx.ALL, 5)
        self.sizer.Add(self.add_btn, 0, wx.ALIGN_CENTER_HORIZONTAL | wx.ALL, 5)
        self.sizer.Add(self.cancel_btn, 0, wx.ALIGN_CENTER_HORIZONTAL | wx.ALL, 5)
        
        self.panel.SetSizer(self.sizer)
        
        self.add_btn.Bind(wx.EVT_BUTTON, self.on_add)
        self.cancel_btn.Bind(wx.EVT_BUTTON, self.on_cancel)
        self.generate_checkbox.Bind(wx.EVT_CHECKBOX, self.on_generate_password)

    def on_add(self, event):
        website = self.website_text.GetValue()
        password = self.password_text.GetValue()
        if not password:
            wx.MessageBox("Please enter a password or generate one.", "Error", wx.OK | wx.ICON_ERROR)
            return
        add_pass(website, password)
        self.Parent.set_message("Password added!")
        self.Close()

    def on_cancel(self, event):
        self.Close()

    def on_generate_password(self, event):
        if self.generate_checkbox.IsChecked():
            password = self.generate_random_password()
            self.password_text.SetValue(password)
            self.password_text.Disable() 
        else:
            self.password_text.SetValue("")
            self.password_text.Enable()

    def generate_random_password(self):
        characters = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(random.choice(characters) for i in range(12))
        return password

class GetPasswordFrame(wx.Frame):
    def __init__(self, parent):
        super(GetPasswordFrame, self).__init__(parent=parent, title="Get Old Password", size=(400, 200))
        
        self.panel = wx.Panel(self)
        
        self.website_label = wx.StaticText(self.panel, label="Website:")
        self.website_text = wx.TextCtrl(self.panel)
        
        self.get_btn = wx.Button(self.panel, label="Get Password")
        self.cancel_btn = wx.Button(self.panel, label="Cancel")
        
        self.sizer = wx.BoxSizer(wx.VERTICAL)
        self.sizer.Add(self.website_label, 0, wx.ALL, 5)
        self.sizer.Add(self.website_text, 0, wx.ALL | wx.EXPAND, 5)
        self.sizer.Add(self.get_btn, 0, wx.ALIGN_CENTER_HORIZONTAL | wx.ALL, 5)
        self.sizer.Add(self.cancel_btn, 0, wx.ALIGN_CENTER_HORIZONTAL | wx.ALL, 5)
        
        self.panel.SetSizer(self.sizer)
        
        self.get_btn.Bind(wx.EVT_BUTTON, self.on_get)
        self.cancel_btn.Bind(wx.EVT_BUTTON, self.on_cancel)

    def on_get(self, event):
        website = self.website_text.GetValue()
        decrypted_pass = get_pass(website)
        if website and decrypted_pass:
            pyperclip.copy(decrypted_pass)
            self.Parent.set_message(f"Password for {website} copied to clipboard.")
            self.Close()
        else:
            self.Parent.set_message("No saved passwords found!")

    def on_cancel(self, event):
        self.Close()

class ViewWebsitesFrame(wx.Frame):
    def __init__(self, parent):
        super(ViewWebsitesFrame, self).__init__(parent=parent, title="View Saved Websites", size=(400, 300))
        
        self.panel = wx.Panel(self)
        
        self.websites_text = wx.TextCtrl(self.panel, style=wx.TE_MULTILINE | wx.TE_READONLY, size=(350, 200))
        self.close_btn = wx.Button(self.panel, label="Close")
        
        self.sizer = wx.BoxSizer(wx.VERTICAL)
        self.sizer.Add(self.websites_text, 0, wx.ALL, 5)
        self.sizer.Add(self.close_btn, 0, wx.ALIGN_CENTER_HORIZONTAL | wx.ALL, 5)
        
        self.panel.SetSizer(self.sizer)
        
        self.load_websites()
        self.close_btn.Bind(wx.EVT_BUTTON, self.on_close)

    def load_websites(self):
        try:
            with open('password.json', 'r') as data:
                view = json.load(data)
                websites = [x['website'] for x in view]
                self.websites_text.SetValue("\n".join(websites))
        except FileNotFoundError:
            self.websites_text.SetValue("\nNo saved passwords found!")

    def on_close(self, event):
        self.Close()

class DeletePasswordFrame(wx.Frame):
    def __init__(self, parent):
        super(DeletePasswordFrame, self).__init__(parent=parent, title="Delete Password", size=(400, 200))
        
        self.panel = wx.Panel(self)
        
        self.website_label = wx.StaticText(self.panel, label="Website:")
        self.website_text = wx.TextCtrl(self.panel)
        
        self.delete_btn = wx.Button(self.panel, label="Delete")
        self.cancel_btn = wx.Button(self.panel, label="Cancel")
        
        self.sizer = wx.BoxSizer(wx.VERTICAL)
        self.sizer.Add(self.website_label, 0, wx.ALL, 5)
        self.sizer.Add(self.website_text, 0, wx.ALL | wx.EXPAND, 5)
        self.sizer.Add(self.delete_btn, 0, wx.ALIGN_CENTER_HORIZONTAL | wx.ALL, 5)
        self.sizer.Add(self.cancel_btn, 0, wx.ALIGN_CENTER_HORIZONTAL | wx.ALL, 5)
        
        self.panel.SetSizer(self.sizer)
        
        self.delete_btn.Bind(wx.EVT_BUTTON, self.on_delete)
        self.cancel_btn.Bind(wx.EVT_BUTTON, self.on_cancel)

    def on_delete(self, event):
        website = self.website_text.GetValue()
        if website:
            self.delete_password(website)
            self.Parent.set_message(f"Password for {website} deleted successfully.")
            self.Close()
        else:
            self.Parent.set_message("Please enter a website to delete the password.")
    
    def delete_password(self, website):
        try:
            with open('password.json', 'r') as file:
                data = json.load(file)
        except FileNotFoundError:
            data = []
        
        updated_data = [entry for entry in data if entry['website'] != website]
        
        with open('password.json', 'w') as file:
            json.dump(updated_data, file, indent=4)

    def on_cancel(self, event):
        self.Close()

if __name__ == '__main__':
    app = wx.App(False)
    frame = MainFrame()
    frame.Show()
    app.MainLoop()
