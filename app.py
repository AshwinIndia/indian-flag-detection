import tkinter as tk
from tkinter import messagebox, filedialog
import sqlite3
from PIL import Image, ImageTk
import numpy as np
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing import image

conn = sqlite3.connect('users.db')
c = conn.cursor()

c.execute('''CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                security_question TEXT NOT NULL,
                security_answer TEXT NOT NULL
            )''')
conn.commit()

security_questions = [
    "What is your favorite color?",
    "What is your pet's name?",
    "What is your mother's maiden name?",
    "What was your first car?",
    "Where did you grow up?"
]

model = load_model('1.keras')
categories = ['Indian Flag', 'Other', 'Similar to Indian Flag']

def bring_to_front(window):
    window.lift()
    window.attributes('-topmost', True)
    window.after_idle(window.attributes, '-topmost', False)

def load_image(img_path):
    img = image.load_img(img_path, target_size=(150, 150))
    img_tensor = image.img_to_array(img)
    img_tensor = np.expand_dims(img_tensor, axis=0)
    img_tensor /= 255.
    return img_tensor

def main_window():
    root = tk.Tk()
    root.title("Flag Detection App")
    root.geometry("400x300")

    def open_register_window():
        root.withdraw()
        register_window()

    def open_login_window():
        root.withdraw()
        login_window()

    tk.Label(root, text="Welcome to Flag Detection", font=("Arial", 16)).pack(pady=20)
    tk.Button(root, text="Register", command=open_register_window).pack(pady=10)
    tk.Button(root, text="Login", command=open_login_window).pack(pady=10)

    root.mainloop()

def register_window():
    register = tk.Toplevel()
    register.title("Register")
    register.geometry("400x400")
    bring_to_front(register)

    def register_user():
        username = username_entry.get()
        password = password_entry.get()
        question = security_question_var.get()
        answer = answer_entry.get()

        if username and password and question and answer:
            try:
                c.execute("INSERT INTO users (username, password, security_question, security_answer) VALUES (?, ?, ?, ?)",
                          (username, password, question, answer))
                conn.commit()
                messagebox.showinfo("Success", "Registration successful!")
                register.destroy()
                main_window()  
            except sqlite3.IntegrityError:
                messagebox.showerror("Error", "Username already exists")
        else:
            messagebox.showerror("Error", "All fields are required")

    tk.Label(register, text="Register", font=("Arial", 16)).pack(pady=10)
    tk.Label(register, text="Username").pack()
    username_entry = tk.Entry(register)
    username_entry.pack()

    tk.Label(register, text="Password").pack()
    password_entry = tk.Entry(register, show="*")
    password_entry.pack()

    tk.Label(register, text="Select Security Question").pack()
    security_question_var = tk.StringVar(register)
    security_question_var.set(security_questions[0])  
    tk.OptionMenu(register, security_question_var, *security_questions).pack()

    tk.Label(register, text="Answer").pack()
    answer_entry = tk.Entry(register)
    answer_entry.pack()

    tk.Button(register, text="Register", command=register_user).pack(pady=10)


def login_window():
    login = tk.Toplevel()
    login.title("Login")
    login.geometry("400x400")
    bring_to_front(login)

    def verify_login():
        username = username_entry.get()
        password = password_entry.get()

        c.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
        user = c.fetchone()

        if user:
            messagebox.showinfo("Success", "Login successful!")
            login.destroy()
            upload_window()  
        else:
            messagebox.showerror("Error", "Invalid username or password")

    def open_forgot_password_window():
        login.withdraw()  
        forgot_password_window()

    tk.Label(login, text="Login", font=("Arial", 16)).pack(pady=10)
    tk.Label(login, text="Username").pack()
    username_entry = tk.Entry(login)
    username_entry.pack()

    tk.Label(login, text="Password").pack()
    password_entry = tk.Entry(login, show="*")
    password_entry.pack()

    tk.Button(login, text="Login", command=verify_login).pack(pady=10)
    tk.Button(login, text="Forgot Password", command=open_forgot_password_window).pack(pady=10)

def forgot_password_window():
    forgot_password = tk.Toplevel()
    forgot_password.title("Forgot Password")
    forgot_password.geometry("400x400")
    bring_to_front(forgot_password)

    def reset_password():
        username = username_entry.get()
        question = security_question_var.get()
        answer = answer_entry.get()
        new_password = new_password_entry.get()

        c.execute("SELECT * FROM users WHERE username = ? AND security_question = ? AND security_answer = ?",
                  (username, question, answer))
        user = c.fetchone()

        if user:
            c.execute("UPDATE users SET password = ? WHERE username = ?", (new_password, username))
            conn.commit()
            messagebox.showinfo("Success", "Password reset successful!")
            forgot_password.destroy()
            main_window()  
        else:
            messagebox.showerror("Error", "Security question or answer is incorrect")

    tk.Label(forgot_password, text="Forgot Password", font=("Arial", 16)).pack(pady=10)
    tk.Label(forgot_password, text="Username").pack()
    username_entry = tk.Entry(forgot_password)
    username_entry.pack()

    tk.Label(forgot_password, text="Select Security Question").pack()
    security_question_var = tk.StringVar(forgot_password)
    security_question_var.set(security_questions[0]) 
    tk.OptionMenu(forgot_password, security_question_var, *security_questions).pack()

    tk.Label(forgot_password, text="Answer").pack()
    answer_entry = tk.Entry(forgot_password)
    answer_entry.pack()

    tk.Label(forgot_password, text="New Password").pack()
    new_password_entry = tk.Entry(forgot_password, show="*")
    new_password_entry.pack()

    tk.Button(forgot_password, text="Reset Password", command=reset_password).pack(pady=10)

def upload_window():
    upload = tk.Toplevel()
    upload.title("Upload Image for Flag Detection")
    upload.geometry("400x500")
    bring_to_front(upload)

    def upload_image():
        file_path = filedialog.askopenfilename(filetypes=[("Image files", "*.jpg;*.png")])
        if file_path:
            img = Image.open(file_path)
            img = img.resize((150, 150))
            img = ImageTk.PhotoImage(img)
            img_label.config(image=img)
            img_label.image = img 

            new_image = load_image(file_path)
            pred = model.predict(new_image)
            predicted_class = categories[np.argmax(pred)]
            result_label.config(text=f"Predicted class: {predicted_class}")

    tk.Label(upload, text="Upload Image for Flag Detection", font=("Arial", 16)).pack(pady=10)
    tk.Button(upload, text="Upload Image", command=upload_image).pack(pady=10)

    img_label = tk.Label(upload)
    img_label.pack()

    result_label = tk.Label(upload, text="", font=("Arial", 14))
    result_label.pack(pady=20)

if __name__ == "__main__":
    main_window()