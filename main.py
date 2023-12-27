#!/usr/bin/env python3

import os
import hashlib
import argparse
import tkinter as tk
from tkinter import filedialog, ttk
import subprocess

#hash the file using the haslib library
#only sha256 is supported for now - will consider adding more
def hash_file(filepath):
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as f:
        buf = f.read()
        hasher.update(buf)
    return hasher.hexdigest()

#this method handles the file system logic, iterating
#recursively through the directory specified and
#writing to the output file
def hash_directory():
    output_file_path = output_file.get()
    input_dir = input_directory.get()
    total_files = count_files(input_dir)
    progress['maximum'] = total_files
    hashed_files = 0
    with (open(output_file_path, 'w') as outFile):
        for rootDir, dirs, files in os.walk(input_dir):
            for name in files:
                filepath = os.path.join(rootDir, name)
                try:
                    file_hash = hash_file(filepath)
                    outFile.write(f"{filepath}: {file_hash}\n")
                    hashed_files += 1
                    progress['value'] = hashed_files
                    progress_label.config(text=f"{progress['value']} of {total_files}")
                    root.update_idletasks()  # Update the progress bar
                except IOError as e:
                    print(f"Error reading {filepath}: {e}")
    progress_label.config(text="Done!")
    open_file_button.config(state="normal")

def select_input_directory():
    input_dir = filedialog.askdirectory()
    if input_dir:
        input_directory.set(input_dir)
        output_file.set(input_dir + "/hashes.txt")  # Set default output file

def select_output_file():
    file = filedialog.asksaveasfilename(initialdir=input_directory.get(), title="Select file", filetypes=(("text files", "*.txt"), ("all files", "*.*")))
    if file:
        output_file.set(file)

def count_files(directory):
    return sum([len(files) for _, _, files in os.walk(directory)])

def open_hash_file():
    output_file_path = output_file.get()
    try:
        os.startfile(output_file_path)
    except AttributeError:
        subprocess.call(['xdg-open', output_file_path])

root = tk.Tk()
root.title("Hash It All")
style = ttk.Style()
style.theme_use('clam')
style.configure('TButton', background='#E1E1E1', font=('Arial', 10))
style.configure('TEntry', padding=5, font=('Arial', 10))
style.configure("Horizontal.TProgressbar", background='blue', troughcolor='#E1E1E1')

main_frame = ttk.Frame(root, padding="10")
main_frame.pack(fill='both', expand=True)
main_frame.columnconfigure(1, weight=1)

input_directory = tk.StringVar()
output_file = tk.StringVar()

input_dir_button = ttk.Button(main_frame, text="Select Input Directory", command=select_input_directory)
input_dir_button.grid(row=0, column=0, sticky='ew', padx=5, pady=5)

input_dir_entry = ttk.Entry(main_frame, textvariable=input_directory, width=50)
input_dir_entry.grid(row=0, column=1, sticky='ew', padx=5, pady=5)

output_file_button = ttk.Button(main_frame, text="Select Output File", command=select_output_file)
output_file_button.grid(row=1, column=0, sticky='ew', padx=5, pady=5)

output_file_entry = ttk.Entry(main_frame, textvariable=output_file, width=50)
output_file_entry.grid(row=1, column=1, sticky='ew', padx=5, pady=5)

start_button = ttk.Button(main_frame, text="Start Hashing", command=hash_directory)
start_button.grid(row=2, column=0, columnspan=2, sticky='ew', padx=5, pady=5)

progress = ttk.Progressbar(main_frame, orient="horizontal", length=100, mode="determinate")
progress.grid(row=3, column=1, sticky='ew', padx=5, pady=5)

progress_label = ttk.Label(main_frame, text="Progress:")
progress_label.grid(row=3, column=0, sticky=tk.E, padx=5, pady=5)

open_file_button = ttk.Button(main_frame, text="Open Hash File", command=open_hash_file, state='disabled')
open_file_button.grid(row=5, column=0, columnspan=2, sticky='ew', padx=5, pady=5)

root.mainloop()
