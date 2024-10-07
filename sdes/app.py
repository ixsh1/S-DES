import tkinter as tk
from tkinter import messagebox, Toplevel, Label
from S_DES import encrypt_string, decrypt_string, key_crack

def show_custom_message(title, message):
    popup = Toplevel(root)
    popup.title(title)
    popup.geometry("400x200")
    Label(popup, text=message, font=("Arial", 14), wraplength=350).pack(expand=True, pady=20)
    tk.Button(popup, text="关闭", command=popup.destroy).pack(pady=10)

def encrypt():
    plain_text = plain_text_entry.get("1.0", tk.END).strip()
    key = key_text_entry.get("1.0", tk.END).strip()
    if not key or not (len(key) == 10 and all(char in '01' for char in key)):
        messagebox.showerror("错误", "密钥必须是10位的二进制字符串。")
        return
    cipher_text = encrypt_string(plain_text, key)
    show_custom_message("加密结果", f"加密得到密文: {cipher_text}")

def decrypt():
    cipher_text = cipher_text_entry.get("1.0", tk.END).strip()
    key = key_text_entry.get("1.0", tk.END).strip()
    if not key or not (len(key) == 10 and all(char in '01' for char in key)):
        messagebox.showerror("错误", "密钥必须是10位的二进制字符串。")
        return
    plain_text = decrypt_string(cipher_text, key)
    show_custom_message("解密结果", f"解密得到明文: {plain_text}")

def brute_force_crack():
    plain_text = plain_text_entry.get("1.0", tk.END).strip()
    cipher_text = cipher_text_entry.get("1.0", tk.END).strip()
    keys, time = key_crack(plain_text, cipher_text)
    show_custom_message("暴力破解结果", f"破解得到密钥: {keys};\n耗时 {time} 秒")

def show_encrypt_ui():
    clear_ui()
    global plain_text_entry, key_text_entry
    tk.Label(frame, text="请输入明文", font=("Arial", 12)).pack(pady=10)
    plain_text_entry = tk.Text(frame, height=1, width=20, font=("Arial", 20))
    plain_text_entry.pack(pady=10)
    tk.Label(frame, text="请输入密钥 (10位二进制)", font=("Arial", 12)).pack(pady=10)
    key_text_entry = tk.Text(frame, height=1, width=20, font=("Arial", 20))
    key_text_entry.pack(pady=10)
    tk.Button(frame, text="加密", command=encrypt, height=1, width=10, font=("Arial", 20)).pack(pady=20)

def show_decrypt_ui():
    clear_ui()
    global cipher_text_entry, key_text_entry
    tk.Label(frame, text="请输入密文", font=("Arial", 12)).pack(pady=10)
    cipher_text_entry = tk.Text(frame, height=1, width=20, font=("Arial", 20))
    cipher_text_entry.pack(pady=10)
    tk.Label(frame, text="请输入密钥 (10位二进制)", font=("Arial", 12)).pack(pady=10)
    key_text_entry = tk.Text(frame, height=1, width=20, font=("Arial", 20))
    key_text_entry.pack(pady=10)
    tk.Button(frame, text="解密", command=decrypt, height=1, width=10, font=("Arial", 20)).pack(pady=20)

def show_brute_force_ui():
    clear_ui()
    global plain_text_entry, cipher_text_entry
    tk.Label(frame, text="请输入明文", font=("Arial", 12)).pack(pady=10)
    plain_text_entry = tk.Text(frame, height=1, width=20, font=("Arial", 20))
    plain_text_entry.pack(pady=10)
    tk.Label(frame, text="请输入密文", font=("Arial", 12)).pack(pady=10)
    cipher_text_entry = tk.Text(frame, height=1, width=20, font=("Arial", 20))
    cipher_text_entry.pack(pady=10)
    tk.Button(frame, text="暴力破解", command=brute_force_crack, height=1, width=10, font=("Arial", 20)).pack(pady=20)

def clear_ui():
    for widget in frame.winfo_children():
        widget.destroy()

# 创建主窗口
root = tk.Tk()
root.title("S-DES 加密解密工具")
root.geometry("600x400")

# 创建左侧菜单
menu_frame = tk.Frame(root)
menu_frame.pack(side=tk.LEFT, fill=tk.Y)

tk.Button(menu_frame, text="加密", command=show_encrypt_ui, height=1, width=10, font=("Arial", 20)).pack(pady=20)
tk.Button(menu_frame, text="解密", command=show_decrypt_ui, height=1, width=10, font=("Arial", 20)).pack(pady=20)
tk.Button(menu_frame, text="暴力破解", command=show_brute_force_ui, height=1, width=10, font=("Arial", 20)).pack(pady=20)

# 创建主内容区域
frame = tk.Frame(root)
frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

# 启动主循环
root.mainloop()
