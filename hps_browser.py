# hps_browser.py (versão corrigida e otimizada)
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import asyncio
import aiohttp
import socketio
import json
import os
import hashlib
import base64
import time
import threading
import uuid
from pathlib import Path
import mimetypes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import tempfile
import webbrowser
from PIL import Image, ImageTk
import io
import logging
import qrcode
from io import BytesIO
import socket
import random
import secrets
from datetime import datetime, timedelta
import math
import struct
import sqlite3
import ssl
import subprocess
import platform

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("HPS-Browser")

class ContentSecurityDialog:
    def __init__(self, parent, content_info, browser_instance):
        self.window = tk.Toplevel(parent)
        self.window.title("Verificação de Segurança")
        self.window.geometry("700x600")
        self.window.transient(parent)
        self.window.grab_set()
        self.browser = browser_instance
        
        main_frame = ttk.Frame(self.window, padding="15")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(main_frame, text="Verificação de Segurança do Conteúdo", font=("Arial", 14, "bold")).pack(pady=10)
        
        status_frame = ttk.Frame(main_frame)
        status_frame.pack(fill=tk.X, pady=10)
        
        verified = content_info.get('verified', False)
        integrity_ok = content_info.get('integrity_ok', True)
        
        if not integrity_ok:
            status_text = "CONTEÚDO ADULTERADO"
            status_color = "red"
        elif verified:
            status_text = "CONTEÚDO VERIFICADO"
            status_color = "green"
        else:
            status_text = "CONTEÚDO NÃO VERIFICADO"
            status_color = "orange"
            
        ttk.Label(status_frame, text=status_text, foreground=status_color, font=("Arial", 12, "bold")).pack()
        
        details_frame = ttk.LabelFrame(main_frame, text="Detalhes do Conteúdo", padding="10")
        details_frame.pack(fill=tk.X, pady=10)
        
        info_grid = ttk.Frame(details_frame)
        info_grid.pack(fill=tk.X)
        
        details = [
            ("Título:", content_info.get('title', 'N/A')),
            ("Autor:", content_info.get('username', 'N/A')),
            ("Hash:", content_info.get('content_hash', 'N/A')),
            ("Tipo MIME:", content_info.get('mime_type', 'N/A')),
            ("Reputação do Autor:", str(content_info.get('reputation', 100))),
            ("Origem:", "Rede P2P"),
        ]
        
        for i, (label, value) in enumerate(details):
            ttk.Label(info_grid, text=label, font=("Arial", 9, "bold")).grid(row=i, column=0, sticky=tk.W, pady=2, padx=5)
            ttk.Label(info_grid, text=value, font=("Arial", 9)).grid(row=i, column=1, sticky=tk.W, pady=2, padx=5)
            
        sig_frame = ttk.LabelFrame(main_frame, text="Assinatura Digital", padding="10")
        sig_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        ttk.Label(sig_frame, text="Chave Pública do Autor:").pack(anchor=tk.W)
        pub_key_text = scrolledtext.ScrolledText(sig_frame, height=4)
        pub_key_text.pack(fill=tk.X, pady=5)
        pub_key_text.insert(tk.END, content_info.get('public_key', 'N/A'))
        pub_key_text.config(state=tk.DISABLED)
        
        ttk.Label(sig_frame, text="Assinatura:").pack(anchor=tk.W)
        sig_text = scrolledtext.ScrolledText(sig_frame, height=3)
        sig_text.pack(fill=tk.X, pady=5)
        sig_text.insert(tk.END, content_info.get('signature', 'N/A'))
        sig_text.config(state=tk.DISABLED)
        
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=10)
        
        ttk.Button(button_frame, text="Copiar Hash", command=lambda: self.copy_hash(content_info.get('content_hash', ''))).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Reportar Conteúdo", command=lambda: self.report_content(content_info)).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Abrir com Aplicativo", command=lambda: self.open_with_app(content_info)).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Fechar", command=self.window.destroy).pack(side=tk.LEFT, padx=5)

    def copy_hash(self, hash_value):
        self.window.clipboard_clear()
        self.window.clipboard_append(hash_value)
        messagebox.showinfo("Copiado", "Hash copiado para área de transferência")

    def report_content(self, content_info):
        if not self.browser.current_user:
            messagebox.showwarning("Aviso", "Você precisa estar logado para reportar conteúdo.")
            return
            
        if self.browser.reputation < 20:
            messagebox.showwarning("Aviso", "Sua reputação é muito baixa para reportar conteúdo.")
            return
            
        if content_info.get('username') == self.browser.current_user:
            messagebox.showwarning("Aviso", "Você não pode reportar seu próprio conteúdo.")
            return
            
        if messagebox.askyesno("Confirmar Reporte", f"Tem certeza que deseja reportar o conteúdo '{content_info.get('title')}' de '{content_info.get('username')}'?"):
            self.browser.report_content_action(content_info.get('content_hash'), content_info.get('username'))
            self.window.destroy()

    def open_with_app(self, content_info):
        try:
            temp_dir = tempfile.gettempdir()
            extension = mimetypes.guess_extension(content_info.get('mime_type', 'application/octet-stream')) or '.dat'
            temp_path = os.path.join(temp_dir, f"{content_info.get('content_hash', 'content')}{extension}")
            
            with open(temp_path, 'wb') as f:
                f.write(content_info['content'])
                
            if platform.system() == "Windows":
                os.startfile(temp_path)
            elif platform.system() == "Darwin":
                subprocess.run(["open", temp_path])
            else:
                subprocess.run(["xdg-open", temp_path])
                
            messagebox.showinfo("Sucesso", f"Arquivo aberto com aplicativo padrão")
        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao abrir arquivo: {e}")

class SearchDialog:
    def __init__(self, parent, browser):
        self.browser = browser
        self.window = tk.Toplevel(parent)
        self.window.title("Busca Avançada")
        self.window.geometry("600x500")
        self.window.transient(parent)
        self.window.grab_set()
        self.setup_ui()

    def setup_ui(self):
        main_frame = ttk.Frame(self.window, padding="15")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(main_frame, text="Busca Avançada", font=("Arial", 14, "bold")).pack(pady=10)
        
        search_frame = ttk.Frame(main_frame)
        search_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(search_frame, text="Termo de busca:").pack(anchor=tk.W)
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var, font=("Arial", 11))
        search_entry.pack(fill=tk.X, pady=5)
        search_entry.bind('<Return>', lambda e: self.do_search())
        
        filter_frame = ttk.Frame(main_frame)
        filter_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(filter_frame, text="Tipo de conteúdo:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.type_var = tk.StringVar(value="all")
        type_combo = ttk.Combobox(filter_frame, textvariable=self.type_var, values=["all", "image", "video", "audio", "document", "text"])
        type_combo.grid(row=0, column=1, sticky=tk.W, pady=5, padx=10)
        
        ttk.Label(filter_frame, text="Ordenar por:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.sort_var = tk.StringVar(value="reputation")
        sort_combo = ttk.Combobox(filter_frame, textvariable=self.sort_var, values=["reputation", "recent", "popular"])
        sort_combo.grid(row=1, column=1, sticky=tk.W, pady=5, padx=10)
        
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=10)
        
        ttk.Button(button_frame, text="Buscar", command=self.do_search).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Limpar", command=self.clear_search).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Copiar Hash", command=self.copy_selected_hash).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Fechar", command=self.window.destroy).pack(side=tk.LEFT, padx=5)
        
        self.results_frame = ttk.LabelFrame(main_frame, text="Resultados", padding="10")
        self.results_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        self.results_text = scrolledtext.ScrolledText(self.results_frame, height=15)
        self.results_text.pack(fill=tk.BOTH, expand=True)
        self.results_text.config(state=tk.DISABLED)
        
        self.results_text.tag_configure("title", font=("Arial", 11, "bold"))
        self.results_text.tag_configure("verified", foreground="green")
        self.results_text.tag_configure("unverified", foreground="orange")
        self.results_text.tag_configure("link", foreground="blue", underline=True)
        self.results_text.bind("<Button-1>", self.handle_result_click)

    def do_search(self):
        query = self.search_var.get().strip()
        if not query:
            messagebox.showwarning("Aviso", "Digite um termo para buscar")
            return
            
        asyncio.run_coroutine_threadsafe(self.browser._search_content(query, self.type_var.get(), self.sort_var.get()), self.browser.loop)
        
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, f"Buscando por: '{query}'")
        self.results_text.config(state=tk.DISABLED)

    def clear_search(self):
        self.search_var.set("")
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results_text.config(state=tk.DISABLED)

    def handle_result_click(self, event):
        index = self.results_text.index(f"@{event.x},{event.y}")
        for tag in self.results_text.tag_names(index):
            if tag == "link":
                line_start = self.results_text.index(f"{index} linestart")
                line_end = self.results_text.index(f"{index} lineend")
                line_text = self.results_text.get(line_start, line_end)
                import re
                match = re.search(r'hps://(\S+)', line_text)
                if match:
                    url = f"hps://{match.group(1)}"
                    self.browser.browser_url_var.set(url)
                    self.browser.browser_navigate()
                    self.window.destroy()
                break

    def copy_selected_hash(self):
        try:
            index = self.results_text.index(tk.SEL_FIRST)
            line_start = self.results_text.index(f"{index} linestart")
            line_end = self.results_text.index(f"{index} lineend")
            line_text = self.results_text.get(line_start, line_end)
            import re
            match = re.search(r'Hash: (\S+)', line_text)
            if match:
                hash_value = match.group(1)
                self.window.clipboard_clear()
                self.window.clipboard_append(hash_value)
                messagebox.showinfo("Copiado", "Hash copiado para área de transferência")
        except tk.TclError:
            messagebox.showwarning("Aviso", "Selecione um hash para copiar")

class PowPopupWindow:
    def __init__(self, parent, action_type="login"):
        self.window = tk.Toplevel(parent)
        self.window.title(f"Prova de Trabalho - {action_type.title()}")
        self.window.geometry("500x400")
        self.window.transient(parent)
        self.window.grab_set()
        self.window.protocol("WM_DELETE_WINDOW", self.cancel)
        
        self.action_type = action_type
        self.cancelled = False
        self.start_time = time.time()
        self.setup_ui()

    def setup_ui(self):
        main_frame = ttk.Frame(self.window, padding="15")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(main_frame, text=f"Resolvendo Prova de Trabalho", font=("Arial", 14, "bold")).pack(pady=10)
        ttk.Label(main_frame, text=f"Ação: {self.action_type.title()}").pack(pady=5)
        
        info_frame = ttk.Frame(main_frame)
        info_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(info_frame, text="Status:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.status_var = tk.StringVar(value="Iniciando...")
        ttk.Label(info_frame, textvariable=self.status_var).grid(row=0, column=1, sticky=tk.W, pady=2)
        
        ttk.Label(info_frame, text="Bits Alvo:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.bits_var = tk.StringVar(value="0")
        ttk.Label(info_frame, textvariable=self.bits_var).grid(row=1, column=1, sticky=tk.W, pady=2)
        
        ttk.Label(info_frame, text="Tempo Decorrido:").grid(row=2, column=0, sticky=tk.W, pady=2)
        self.time_var = tk.StringVar(value="0.0s")
        ttk.Label(info_frame, textvariable=self.time_var).grid(row=2, column=1, sticky=tk.W, pady=2)
        
        ttk.Label(info_frame, text="Hashrate:").grid(row=3, column=0, sticky=tk.W, pady=2)
        self.hashrate_var = tk.StringVar(value="0 H/s")
        ttk.Label(info_frame, textvariable=self.hashrate_var).grid(row=3, column=1, sticky=tk.W, pady=2)
        
        ttk.Label(info_frame, text="Tentativas:").grid(row=4, column=0, sticky=tk.W, pady=2)
        self.attempts_var = tk.StringVar(value="0")
        ttk.Label(info_frame, textvariable=self.attempts_var).grid(row=4, column=1, sticky=tk.W, pady=2)
        
        info_frame.columnconfigure(1, weight=1)
        
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate', length=400)
        self.progress.pack(pady=15)
        self.progress.start()
        
        ttk.Label(main_frame, text="Detalhes:", font=("Arial", 10, "bold")).pack(anchor=tk.W, pady=(10,5))
        
        self.details_text = scrolledtext.ScrolledText(main_frame, height=8, width=50)
        self.details_text.pack(fill=tk.BOTH, expand=True, pady=5)
        self.details_text.config(state=tk.DISABLED)
        
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=10)
        
        self.cancel_button = ttk.Button(button_frame, text="Cancelar", command=self.cancel)
        self.cancel_button.pack(side=tk.LEFT, padx=5)

    def log_message(self, message):
        self.details_text.config(state=tk.NORMAL)
        self.details_text.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {message}")
        self.details_text.see(tk.END)
        self.details_text.config(state=tk.DISABLED)

    def update_status(self, status, bits=None, elapsed_time=None, hashrate=None, attempts=None):
        self.status_var.set(status)
        if bits is not None:
            self.bits_var.set(str(bits))
        if elapsed_time is not None:
            self.time_var.set(f"{elapsed_time:.2f}s")
        if hashrate is not None:
            self.hashrate_var.set(f"{hashrate:.0f} H/s")
        if attempts is not None:
            self.attempts_var.set(str(attempts))
        self.window.update_idletasks()

    def cancel(self):
        self.cancelled = True
        self.window.destroy()

    def destroy(self):
        if self.window.winfo_exists():
            self.window.destroy()

class UploadProgressWindow:
    def __init__(self, parent):
        self.window = tk.Toplevel(parent)
        self.window.title("Upload em Progresso")
        self.window.geometry("450x300")
        self.window.transient(parent)
        self.window.grab_set()
        self.window.protocol("WM_DELETE_WINDOW", self.cancel)
        
        self.progress_var = tk.DoubleVar()
        self.status_var = tk.StringVar(value="Preparando upload...")
        self.cancelled = False
        self.setup_ui()

    def setup_ui(self):
        main_frame = ttk.Frame(self.window, padding="15")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(main_frame, text="Upload de Arquivo", font=("Arial", 14, "bold")).pack(pady=10)
        
        ttk.Label(main_frame, textvariable=self.status_var).pack(pady=10)
        
        self.progress_bar = ttk.Progressbar(main_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X, pady=10)
        
        info_frame = ttk.Frame(main_frame)
        info_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(info_frame, text="Hash:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.hash_var = tk.StringVar(value="Calculando...")
        ttk.Label(info_frame, textvariable=self.hash_var).grid(row=0, column=1, sticky=tk.W, pady=2)
        
        ttk.Label(info_frame, text="Tamanho:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.size_var = tk.StringVar(value="0 bytes")
        ttk.Label(info_frame, textvariable=self.size_var).grid(row=1, column=1, sticky=tk.W, pady=2)
        
        info_frame.columnconfigure(1, weight=1)
        
        self.details_text = scrolledtext.ScrolledText(main_frame, height=6, width=50)
        self.details_text.pack(fill=tk.BOTH, expand=True, pady=10)
        self.details_text.config(state=tk.DISABLED)
        
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=10)
        
        self.cancel_button = ttk.Button(button_frame, text="Cancelar Upload", command=self.cancel)
        self.cancel_button.pack(side=tk.LEFT, padx=5)

    def log_message(self, message):
        self.details_text.config(state=tk.NORMAL)
        self.details_text.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {message}")
        self.details_text.see(tk.END)
        self.details_text.config(state=tk.DISABLED)

    def update_progress(self, value, status, hash_value=None, size=None):
        self.progress_var.set(value)
        self.status_var.set(status)
        if hash_value:
            self.hash_var.set(f"{hash_value[:20]}...")
        if size:
            self.size_var.set(self.format_size(size))
        self.window.update_idletasks()

    def format_size(self, size):
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"

    def cancel(self):
        self.cancelled = True
        self.window.destroy()

    def destroy(self):
        if self.window.winfo_exists():
            self.window.destroy()

class DDNSProgressWindow:
    def __init__(self, parent):
        self.window = tk.Toplevel(parent)
        self.window.title("Processando DNS")
        self.window.geometry("450x300")
        self.window.transient(parent)
        self.window.grab_set()
        
        self.progress_var = tk.DoubleVar()
        self.status_var = tk.StringVar(value="Preparando DNS...")
        self.setup_ui()

    def setup_ui(self):
        main_frame = ttk.Frame(self.window, padding="15")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(main_frame, text="Registro de DNS", font=("Arial", 14, "bold")).pack(pady=10)
        
        ttk.Label(main_frame, textvariable=self.status_var).pack(pady=10)
        
        self.progress_bar = ttk.Progressbar(main_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X, pady=10)
        
        info_frame = ttk.Frame(main_frame)
        info_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(info_frame, text="Domínio:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.domain_var = tk.StringVar(value="")
        ttk.Label(info_frame, textvariable=self.domain_var).grid(row=0, column=1, sticky=tk.W, pady=2)
        
        ttk.Label(info_frame, text="Hash do Conteúdo:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.hash_var = tk.StringVar(value="")
        ttk.Label(info_frame, textvariable=self.hash_var).grid(row=1, column=1, sticky=tk.W, pady=2)
        
        info_frame.columnconfigure(1, weight=1)
        
        self.details_text = scrolledtext.ScrolledText(main_frame, height=6, width=50)
        self.details_text.pack(fill=tk.BOTH, expand=True, pady=10)
        self.details_text.config(state=tk.DISABLED)

    def log_message(self, message):
        self.details_text.config(state=tk.NORMAL)
        self.details_text.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {message}")
        self.details_text.see(tk.END)
        self.details_text.config(state=tk.DISABLED)

    def update_progress(self, value, status, domain=None, hash_value=None):
        self.progress_var.set(value)
        self.status_var.set(status)
        if domain:
            self.domain_var.set(domain)
        if hash_value:
            self.hash_var.set(f"{hash_value[:20]}...")
        self.window.update_idletasks()

    def destroy(self):
        if self.window.winfo_exists():
            self.window.destroy()

class ReportProgressWindow:
    def __init__(self, parent):
        self.window = tk.Toplevel(parent)
        self.window.title("Reportando Conteúdo")
        self.window.geometry("500x350")
        self.window.transient(parent)
        self.window.grab_set()
        self.window.protocol("WM_DELETE_WINDOW", self.cancel)
        
        self.progress_var = tk.DoubleVar()
        self.status_var = tk.StringVar(value="Preparando reporte...")
        self.cancelled = False
        self.setup_ui()

    def setup_ui(self):
        main_frame = ttk.Frame(self.window, padding="15")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(main_frame, text="Reporte de Conteúdo", font=("Arial", 14, "bold")).pack(pady=10)
        
        ttk.Label(main_frame, textvariable=self.status_var).pack(pady=10)
        
        self.progress_bar = ttk.Progressbar(main_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X, pady=10)
        
        info_frame = ttk.Frame(main_frame)
        info_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(info_frame, text="Hash do Conteúdo:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.hash_var = tk.StringVar(value="")
        ttk.Label(info_frame, textvariable=self.hash_var).grid(row=0, column=1, sticky=tk.W, pady=2)
        
        ttk.Label(info_frame, text="Autor Reportado:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.author_var = tk.StringVar(value="")
        ttk.Label(info_frame, textvariable=self.author_var).grid(row=1, column=1, sticky=tk.W, pady=2)
        
        ttk.Label(info_frame, text="Sua Reputação:").grid(row=2, column=0, sticky=tk.W, pady=2)
        self.reputation_var = tk.StringVar(value="")
        ttk.Label(info_frame, textvariable=self.reputation_var).grid(row=2, column=1, sticky=tk.W, pady=2)
        
        info_frame.columnconfigure(1, weight=1)
        
        self.details_text = scrolledtext.ScrolledText(main_frame, height=8, width=50)
        self.details_text.pack(fill=tk.BOTH, expand=True, pady=10)
        self.details_text.config(state=tk.DISABLED)
        
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=10)
        
        self.cancel_button = ttk.Button(button_frame, text="Cancelar Reporte", command=self.cancel)
        self.cancel_button.pack(side=tk.LEFT, padx=5)

    def log_message(self, message):
        self.details_text.config(state=tk.NORMAL)
        self.details_text.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {message}")
        self.details_text.see(tk.END)
        self.details_text.config(state=tk.DISABLED)

    def update_progress(self, value, status, content_hash=None, author=None, reputation=None):
        self.progress_var.set(value)
        self.status_var.set(status)
        if content_hash:
            self.hash_var.set(f"{content_hash[:20]}...")
        if author:
            self.author_var.set(author)
        if reputation is not None:
            self.reputation_var.set(str(reputation))
        self.window.update_idletasks()

    def cancel(self):
        self.cancelled = True
        self.window.destroy()

    def destroy(self):
        if self.window.winfo_exists():
            self.window.destroy()

class PowSolver:
    def __init__(self, browser):
        self.browser = browser
        self.is_solving = False
        self.current_challenge = None
        self.current_target_bits = 0
        self.solution_found = threading.Event()
        self.nonce_solution = None
        self.hashrate_observed = 0.0
        self.current_popup = None

    def leading_zero_bits(self, h: bytes) -> int:
        count = 0
        for byte in h:
            if byte == 0:
                count += 8
            else:
                count += bin(byte)[2:].zfill(8).index('1')
                break
        return count

    def calibrate_hashrate(self, seconds: float = 1.0) -> float:
        message = secrets.token_bytes(16)
        end = time.time() + seconds
        count = 0
        nonce = 0
        
        while time.time() < end:
            data = message + struct.pack(">Q", nonce)
            _ = hashlib.sha256(data).digest()
            nonce += 1
            count += 1
            
        elapsed = seconds
        return count / elapsed if elapsed > 0 else 0.0

    def solve_challenge(self, challenge: str, target_bits: int, target_seconds: float, action_type: str = "login"):
        if self.is_solving:
            return
            
        self.is_solving = True
        self.solution_found.clear()
        self.nonce_solution = None
        self.current_challenge = challenge
        self.current_target_bits = target_bits
        
        def show_popup():
            self.current_popup = PowPopupWindow(self.browser.root, action_type)
            self.current_popup.log_message(f"Desafio recebido: {target_bits} bits")
            self.current_popup.log_message(f"Tempo alvo: {target_seconds:.1f}s")
            
        self.browser.root.after(0, show_popup)
        
        def solve_thread():
            try:
                challenge_bytes = base64.b64decode(challenge)
                start_time = time.time()
                nonce = 0
                hash_count = 0
                last_update = start_time
                
                hashrate = self.calibrate_hashrate(0.5)
                self.hashrate_observed = hashrate
                
                if self.current_popup and self.current_popup.window.winfo_exists():
                    self.browser.root.after(0, lambda: self.current_popup.update_status(f"Resolvendo PoW - {target_bits} bits", bits=target_bits, hashrate=hashrate))
                    self.browser.root.after(0, lambda: self.current_popup.log_message(f"Iniciando mineração: {target_bits} bits alvo, hashrate estimado: {hashrate:.0f} H/s"))
                
                current_hashrate = 0.0
                
                while self.is_solving and time.time() - start_time < 300:
                    if self.current_popup and self.current_popup.cancelled:
                        self.is_solving = False
                        break
                        
                    data = challenge_bytes + struct.pack(">Q", nonce)
                    hash_result = hashlib.sha256(data).digest()
                    hash_count += 1
                    
                    lzb = self.leading_zero_bits(hash_result)
                    
                    current_time = time.time()
                    elapsed = current_time - start_time
                    
                    if current_time - last_update >= 1.0:
                        current_hashrate = hash_count / (current_time - last_update)
                        if self.current_popup and self.current_popup.window.winfo_exists():
                            self.browser.root.after(0, lambda: self.current_popup.update_status(f"Resolvendo... {nonce:,} tentativas", elapsed_time=elapsed, hashrate=current_hashrate, attempts=nonce))
                        last_update = current_time
                        hash_count = 0
                    
                    if lzb >= target_bits:
                        solve_time = current_time - start_time
                        self.nonce_solution = str(nonce)
                        self.hashrate_observed = current_hashrate
                        
                        if self.current_popup and self.current_popup.window.winfo_exists():
                            self.browser.root.after(0, lambda: self.current_popup.log_message(f"Solução encontrada! Nonce: {nonce}, tempo: {solve_time:.2f}s"))
                            self.browser.root.after(0, lambda: self.current_popup.update_status("Solução encontrada! Feche esta janela.", elapsed_time=solve_time, hashrate=current_hashrate, attempts=nonce))
                            self.browser.root.after(0, lambda: self.current_popup.log_message("Solução encontrada! Você pode fechar esta janela."))
                            
                        self.browser.root.after(0, lambda: self.browser.pow_solution_found(nonce, solve_time, current_hashrate))
                        self.solution_found.set()
                        break
                    
                    nonce += 1
                    
                    if nonce % 10000 == 0:
                        time.sleep(0.001)
                    
                    if nonce % 1000 == 0 and not self.is_solving:
                        break
                        
                if not self.nonce_solution and self.is_solving:
                    if self.current_popup and self.current_popup.window.winfo_exists():
                        self.browser.root.after(0, lambda: self.current_popup.log_message("Tempo limite excedido"))
                        self.browser.root.after(0, lambda: self.current_popup.update_status("Tempo limite excedido"))
                    self.browser.root.after(0, lambda: self.browser.pow_solution_failed())
                    
            except Exception as e:
                logger.error(f"Erro na mineração PoW: {e}")
                if self.current_popup and self.current_popup.window.winfo_exists():
                    self.current_popup.log_message(f"Erro: {e}")
                self.browser.root.after(0, lambda: self.browser.pow_solution_failed())
            finally:
                self.is_solving = False
                
        threading.Thread(target=solve_thread, daemon=True).start()

    def stop_solving(self):
        self.is_solving = False
        if self.current_popup and self.current_popup.window.winfo_exists():
            self.current_popup.cancelled = True
            self.current_popup.destroy()
            self.current_popup = None

class NetworkSyncDialog:
    def __init__(self, parent, browser):
        self.browser = browser
        self.window = tk.Toplevel(parent)
        self.window.title("Sincronização de Rede")
        self.window.geometry("500x300")
        self.window.transient(parent)
        self.window.grab_set()
        self.cancelled = False
        self.window.protocol("WM_DELETE_WINDOW", self.cancel)
        self.setup_ui()

    def setup_ui(self):
        main_frame = ttk.Frame(self.window, padding="15")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(main_frame, text="Sincronização de Rede P2P", font=("Arial", 14, "bold")).pack(pady=10)
        
        ttk.Label(main_frame, text="Status da Sincronização:").pack(anchor=tk.W, pady=5)
        self.status_var = tk.StringVar(value="Preparando para sincronizar...")
        status_label = ttk.Label(main_frame, textvariable=self.status_var)
        status_label.pack(anchor=tk.W, pady=5)
        
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate', length=400)
        self.progress.pack(pady=15)
        self.progress.start()
        
        self.details_text = scrolledtext.ScrolledText(main_frame, height=8, width=50)
        self.details_text.pack(fill=tk.BOTH, expand=True, pady=10)
        self.details_text.config(state=tk.DISABLED)
        
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=10)
        
        ttk.Button(button_frame, text="Fechar", command=self.window.destroy).pack(side=tk.LEFT, padx=5)

    def log_message(self, message):
        self.details_text.config(state=tk.NORMAL)
        self.details_text.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {message}")
        self.details_text.see(tk.END)
        self.details_text.config(state=tk.DISABLED)

    def update_status(self, status):
        self.status_var.set(status)
        self.window.update_idletasks()

    def cancel(self):
        self.cancelled = True
        self.window.destroy()

    def destroy(self):
        if self.window.winfo_exists():
            self.window.destroy()

class HPSBrowser:
    def __init__(self, root):
        self.root = root
        self.root.title("Navegador P2P Hsyst")
        self.root.geometry("1400x900")
        self.root.minsize(1200, 800)
        
        self.current_user = None
        self.private_key = None
        self.public_key_pem = None
        self.session_id = str(uuid.uuid4())
        self.node_id = hashlib.sha256(self.session_id.encode()).hexdigest()[:32]
        self.connected = False
        self.peers = []
        self.content_cache = {}
        self.dns_cache = {}
        self.local_files = {}
        self.history = []
        self.history_index = -1
        self.current_content_hash = None
        self.current_content_info = None
        self.known_servers = []
        self.current_server = None
        self.server_nodes = []
        self.content_verification_cache = {}
        self.node_type = "client"
        self.connection_attempts = 0
        self.max_connection_attempts = 3
        self.reputation = 100
        self.rate_limits = {}
        self.banned_until = None
        self.client_identifier = self.generate_client_identifier()
        self.upload_blocked_until = 0
        self.login_blocked_until = 0
        self.dns_blocked_until = 0
        self.report_blocked_until = 0
        self.ban_duration = 0
        self.ban_reason = ""
        self.pow_solver = PowSolver(self)
        self.max_upload_size = 100 * 1024 * 1024
        self.disk_quota = 500 * 1024 * 1024
        self.used_disk_space = 0
        self.private_key_passphrase = None
        self.server_public_keys = {}
        self.session_key = None
        self.server_auth_challenge = None
        self.client_auth_challenge = None
        self.upload_window = None
        self.ddns_window = None
        self.report_window = None
        self.upload_callback = None
        self.dns_callback = None
        self.report_callback = None
        self.search_dialog = None
        self.sync_dialog = None
        self.ssl_verify = False
        self.use_ssl = False
        self.backup_server = None
        self.auto_reconnect = True
        
        self.stats_data = {
            'session_start': time.time(),
            'data_sent': 0,
            'data_received': 0,
            'content_downloaded': 0,
            'content_uploaded': 0,
            'dns_registered': 0,
            'pow_solved': 0,
            'pow_time': 0,
            'content_reported': 0
        }
        
        self.loop = None
        self.sio = None
        self.network_thread = None
        
        self.crypto_dir = os.path.join(os.path.expanduser("~"), ".hps_browser")
        os.makedirs(self.crypto_dir, exist_ok=True)
        self.db_path = os.path.join(self.crypto_dir, "hps_browser.db")
        
        self.init_database()
        self.load_known_servers()
        self.setup_ui()
        self.setup_cryptography()
        self.start_network_thread()
        self.calculate_disk_usage()

    def init_database(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS browser_network_nodes (
                    node_id TEXT PRIMARY KEY,
                    address TEXT NOT NULL,
                    node_type TEXT NOT NULL,
                    reputation INTEGER DEFAULT 100,
                    status TEXT NOT NULL,
                    last_seen REAL NOT NULL
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS browser_dns_records (
                    domain TEXT PRIMARY KEY,
                    content_hash TEXT NOT NULL,
                    username TEXT NOT NULL,
                    verified INTEGER DEFAULT 0,
                    timestamp REAL NOT NULL,
                    ddns_hash TEXT NOT NULL DEFAULT ''
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS browser_known_servers (
                    server_address TEXT PRIMARY KEY,
                    reputation INTEGER DEFAULT 100,
                    last_connected REAL NOT NULL,
                    is_active INTEGER DEFAULT 1,
                    use_ssl INTEGER DEFAULT 0
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS browser_content_cache (
                    content_hash TEXT PRIMARY KEY,
                    file_path TEXT NOT NULL,
                    file_name TEXT NOT NULL,
                    mime_type TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    last_accessed REAL NOT NULL,
                    title TEXT,
                    description TEXT,
                    username TEXT,
                    signature TEXT,
                    public_key TEXT,
                    verified INTEGER DEFAULT 0
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS browser_ddns_cache (
                    domain TEXT PRIMARY KEY,
                    ddns_hash TEXT NOT NULL,
                    content_hash TEXT NOT NULL,
                    username TEXT NOT NULL,
                    verified INTEGER DEFAULT 0,
                    timestamp REAL NOT NULL
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS browser_settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS browser_reports (
                    report_id TEXT PRIMARY KEY,
                    content_hash TEXT NOT NULL,
                    reported_user TEXT NOT NULL,
                    reporter_user TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    status TEXT NOT NULL,
                    reason TEXT
                )
            ''')
            
            try:
                cursor.execute("PRAGMA table_info(browser_dns_records)")
                columns = [column[1] for column in cursor.fetchall()]
                if 'ddns_hash' not in columns:
                    cursor.execute('ALTER TABLE browser_dns_records ADD COLUMN ddns_hash TEXT NOT NULL DEFAULT ""')
            except Exception as e:
                logger.error(f"Error checking/adding ddns_hash column: {e}")
                
            conn.commit()

    def load_known_servers(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT server_address, use_ssl FROM browser_known_servers WHERE is_active = 1')
            for row in cursor.fetchall():
                self.known_servers.append(row[0])
                if row[1]:
                    self.use_ssl = True
                    
        logger.info(f"Loaded known servers: {len(self.known_servers)}")

    def save_known_servers(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            for server_address in self.known_servers:
                use_ssl = 1 if server_address.startswith('https://') else 0
                cursor.execute(
                    '''INSERT OR REPLACE INTO browser_known_servers 
                    (server_address, last_connected, is_active, use_ssl) 
                    VALUES (?, ?, ?, ?)''',
                    (server_address, time.time(), 1, use_ssl)
                )
            conn.commit()

    def calculate_disk_usage(self):
        if os.path.exists(self.crypto_dir):
            total_size = 0
            for dirpath, dirnames, filenames in os.walk(self.crypto_dir):
                for f in filenames:
                    fp = os.path.join(dirpath, f)
                    total_size += os.path.getsize(fp)
            self.used_disk_space = total_size
            
        self.disk_usage_var.set(f"Disco: {self.used_disk_space // (1024*1024)}MB/{self.disk_quota // (1024*1024)}MB")

    def generate_client_identifier(self):
        machine_id = hashlib.sha256(str(uuid.getnode()).encode()).hexdigest()
        return hashlib.sha256((machine_id + self.session_id).encode()).hexdigest()

    def setup_ui(self):
        self.setup_main_frames()
        self.setup_login_ui()
        self.setup_browser_ui()
        self.setup_dns_ui()
        self.setup_upload_ui()
        self.setup_network_ui()
        self.setup_settings_ui()
        self.setup_servers_ui()
        self.setup_stats_ui()
        self.show_login()

    def setup_main_frames(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(1, weight=1)
        
        ttk.Label(main_frame, text="Navegador P2P Hsyst", font=("Arial", 16, "bold")).grid(row=0, column=0, columnspan=3, pady=10)
        
        nav_frame = ttk.Frame(main_frame)
        nav_frame.grid(row=1, column=0, sticky=(tk.N, tk.S, tk.W), padx=(0, 10))
        
        self.nav_buttons = {
            "login": ttk.Button(nav_frame, text="Login", command=self.show_login, width=15),
            "browser": ttk.Button(nav_frame, text="Navegador", command=self.show_browser, width=15),
            "dns": ttk.Button(nav_frame, text="DNS", command=self.show_dns, width=15),
            "upload": ttk.Button(nav_frame, text="Upload", command=self.show_upload, width=15),
            "network": ttk.Button(nav_frame, text="Rede", command=self.show_network, width=15),
            "settings": ttk.Button(nav_frame, text="Config", command=self.show_settings, width=15),
            "servers": ttk.Button(nav_frame, text="Servidores", command=self.show_servers, width=15),
            "stats": ttk.Button(nav_frame, text="Stats", command=self.show_stats, width=15),
        }
        
        for button in self.nav_buttons.values():
            button.pack(fill=tk.X, pady=2)
            
        self.main_area = ttk.Frame(main_frame)
        self.main_area.grid(row=1, column=1, sticky=(tk.N, tk.E, tk.S, tk.W))
        self.main_area.columnconfigure(0, weight=1)
        self.main_area.rowconfigure(0, weight=1)
        
        status_frame = ttk.Frame(main_frame)
        status_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        self.status_var = tk.StringVar(value="Desconectado")
        status_label = ttk.Label(status_frame, textvariable=self.status_var)
        status_label.pack(side=tk.LEFT)
        
        self.user_var = tk.StringVar(value="Não logado")
        ttk.Label(status_frame, textvariable=self.user_var).pack(side=tk.RIGHT)
        
        self.reputation_var = tk.StringVar(value="100")
        ttk.Label(status_frame, textvariable=self.reputation_var).pack(side=tk.RIGHT, padx=20)
        
        self.ban_status_var = tk.StringVar(value="")
        ban_label = ttk.Label(status_frame, textvariable=self.ban_status_var, foreground="red")
        ban_label.pack(side=tk.RIGHT, padx=20)
        
        self.disk_usage_var = tk.StringVar(value=f"0MB/500MB")
        ttk.Label(status_frame, textvariable=self.disk_usage_var).pack(side=tk.RIGHT, padx=20)

    def setup_login_ui(self):
        self.login_frame = ttk.Frame(self.main_area)
        
        ttk.Label(self.login_frame, text="Entrar na Rede P2P", font=("Arial", 14, "bold")).grid(row=0, column=0, columnspan=2, pady=10)
        
        ttk.Label(self.login_frame, text="Servidor:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.server_var = tk.StringVar(value="localhost:8080")
        self.server_combo = ttk.Combobox(self.login_frame, textvariable=self.server_var, values=self.known_servers)
        self.server_combo.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5)
        self.server_combo['state'] = 'readonly'
        
        ttk.Label(self.login_frame, text="Usuário:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.username_var = tk.StringVar()
        ttk.Entry(self.login_frame, textvariable=self.username_var).grid(row=2, column=1, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(self.login_frame, text="Senha:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.password_var = tk.StringVar()
        ttk.Entry(self.login_frame, textvariable=self.password_var, show="*").grid(row=3, column=1, sticky=(tk.W, tk.E), pady=5)
        
        self.auto_login_var = tk.BooleanVar()
        ttk.Checkbutton(self.login_frame, text="Login automático", variable=self.auto_login_var).grid(row=4, column=0, columnspan=2, pady=5)
        
        self.save_keys_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(self.login_frame, text="Salvar chaves criptográficas", variable=self.save_keys_var).grid(row=5, column=0, columnspan=2, pady=5)
        
        self.use_ssl_var = tk.BooleanVar(value=self.use_ssl)
        ttk.Checkbutton(self.login_frame, text="Usar SSL/TLS", variable=self.use_ssl_var).grid(row=6, column=0, columnspan=2, pady=5)
        
        self.auto_reconnect_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(self.login_frame, text="Reconexão automática", variable=self.auto_reconnect_var).grid(row=7, column=0, columnspan=2, pady=5)
        
        button_frame = ttk.Frame(self.login_frame)
        button_frame.grid(row=8, column=0, columnspan=2, pady=20)
        
        self.enter_button = ttk.Button(button_frame, text="Entrar na Rede", command=self.enter_network)
        self.enter_button.pack(side=tk.LEFT, padx=5)
        
        self.exit_button = ttk.Button(button_frame, text="Sair da Rede", command=self.exit_network)
        self.exit_button.pack(side=tk.LEFT, padx=5)
        
        self.login_status = ttk.Label(self.login_frame, text="", foreground="red")
        self.login_status.grid(row=9, column=0, columnspan=2, pady=5)
        
        self.login_frame.columnconfigure(1, weight=1)

    def setup_browser_ui(self):
        self.browser_frame = ttk.Frame(self.main_area)
        
        top_frame = ttk.Frame(self.browser_frame)
        top_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(top_frame, text="Voltar", command=self.browser_back, width=8).pack(side=tk.LEFT, padx=2)
        ttk.Button(top_frame, text="Avançar", command=self.browser_forward, width=8).pack(side=tk.LEFT, padx=2)
        ttk.Button(top_frame, text="Recarregar", command=self.browser_reload, width=8).pack(side=tk.LEFT, padx=2)
        ttk.Button(top_frame, text="Início", command=self.browser_home, width=8).pack(side=tk.LEFT, padx=2)
        
        self.browser_url_var = tk.StringVar(value="hps://rede")
        self.browser_url_entry = ttk.Entry(top_frame, textvariable=self.browser_url_var, font=("Arial", 10))
        self.browser_url_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.browser_url_entry.bind('<Return>', lambda e: self.browser_navigate())
        
        ttk.Button(top_frame, text="Segurança", command=self.show_security_dialog, width=10).pack(side=tk.LEFT, padx=2)
        ttk.Button(top_frame, text="Buscar", command=self.show_search_dialog, width=8).pack(side=tk.LEFT, padx=2)
        ttk.Button(top_frame, text="Ir", command=self.browser_navigate).pack(side=tk.LEFT, padx=2)
        
        self.browser_content = scrolledtext.ScrolledText(self.browser_frame, wrap=tk.WORD, font=("Arial", 11))
        self.browser_content.pack(fill=tk.BOTH, expand=True, pady=10)
        self.browser_content.config(state=tk.DISABLED)
        
        self.browser_content.tag_configure("title", font=("Arial", 14, "bold"))
        self.browser_content.tag_configure("verified", foreground="green")
        self.browser_content.tag_configure("unverified", foreground="orange")
        self.browser_content.tag_configure("link", foreground="blue", underline=True)
        self.browser_content.bind("<Button-1>", self.handle_content_click)

    def setup_dns_ui(self):
        self.dns_frame = ttk.Frame(self.main_area)
        
        ttk.Label(self.dns_frame, text="Sistema de Nomes Descentralizado", font=("Arial", 14, "bold")).pack(pady=10)
        
        dns_top_frame = ttk.Frame(self.dns_frame)
        dns_top_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(dns_top_frame, text="Domínio:").pack(side=tk.LEFT, padx=5)
        self.dns_domain_var = tk.StringVar()
        ttk.Entry(dns_top_frame, textvariable=self.dns_domain_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        ttk.Button(dns_top_frame, text="Registrar", command=self.register_dns).pack(side=tk.LEFT, padx=5)
        ttk.Button(dns_top_frame, text="Resolver", command=self.resolve_dns).pack(side=tk.LEFT, padx=5)
        
        ttk.Label(self.dns_frame, text="Hash do conteúdo:").pack(anchor=tk.W, pady=5)
        
        dns_content_frame = ttk.Frame(self.dns_frame)
        dns_content_frame.pack(fill=tk.X, pady=5)
        
        self.dns_content_hash_var = tk.StringVar()
        ttk.Entry(dns_content_frame, textvariable=self.dns_content_hash_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Button(dns_content_frame, text="Selecionar Arquivo", command=self.select_dns_content_file).pack(side=tk.LEFT, padx=5)
        
        self.dns_status = ttk.Label(self.dns_frame, text="", foreground="red")
        self.dns_status.pack(pady=5)
        
        self.dns_tree = ttk.Treeview(self.dns_frame, columns=("domain", "content_hash", "verified"), show="headings")
        self.dns_tree.heading("domain", text="Domínio")
        self.dns_tree.heading("content_hash", text="Hash do Conteúdo")
        self.dns_tree.heading("verified", text="Verificado")
        self.dns_tree.column("domain", width=200)
        self.dns_tree.column("content_hash", width=300)
        self.dns_tree.column("verified", width=100)
        self.dns_tree.pack(fill=tk.BOTH, expand=True, pady=10)
        self.dns_tree.bind("<Double-1>", self.open_dns_content)

    def setup_upload_ui(self):
        self.upload_frame = ttk.Frame(self.main_area)
        
        ttk.Label(self.upload_frame, text="Upload de Conteúdo", font=("Arial", 14, "bold")).pack(pady=10)
        
        upload_form_frame = ttk.Frame(self.upload_frame)
        upload_form_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(upload_form_frame, text="Arquivo:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.upload_file_var = tk.StringVar()
        ttk.Entry(upload_form_frame, textvariable=self.upload_file_var).grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)
        ttk.Button(upload_form_frame, text="Selecionar", command=self.select_upload_file).grid(row=0, column=2, pady=5, padx=5)
        
        ttk.Label(upload_form_frame, text="Título:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.upload_title_var = tk.StringVar()
        ttk.Entry(upload_form_frame, textvariable=self.upload_title_var).grid(row=1, column=1, columnspan=2, sticky=(tk.W, tk.E), pady=5, padx=5)
        
        ttk.Label(upload_form_frame, text="Descrição:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.upload_description_var = tk.StringVar()
        ttk.Entry(upload_form_frame, textvariable=self.upload_description_var).grid(row=2, column=1, columnspan=2, sticky=(tk.W, tk.E), pady=5, padx=5)
        
        ttk.Label(upload_form_frame, text="Tipo MIME:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.upload_mime_var = tk.StringVar()
        ttk.Entry(upload_form_frame, textvariable=self.upload_mime_var).grid(row=3, column=1, columnspan=2, sticky=(tk.W, tk.E), pady=5, padx=5)
        
        ttk.Button(upload_form_frame, text="Upload", command=self.upload_file).grid(row=4, column=0, columnspan=3, pady=10)
        
        self.upload_status = ttk.Label(self.upload_frame, text="", foreground="red")
        self.upload_status.pack(pady=5)
        
        upload_form_frame.columnconfigure(1, weight=1)

    def setup_network_ui(self):
        self.network_frame = ttk.Frame(self.main_area)
        
        ttk.Label(self.network_frame, text="Rede P2P", font=("Arial", 14, "bold")).pack(pady=10)
        
        network_top_frame = ttk.Frame(self.network_frame)
        network_top_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(network_top_frame, text="Atualizar", command=self.refresh_network).pack(side=tk.LEFT, padx=5)
        ttk.Button(network_top_frame, text="Sincronizar", command=self.sync_network).pack(side=tk.LEFT, padx=5)
        ttk.Button(network_top_frame, text="Meu Nó", command=self.show_my_node).pack(side=tk.LEFT, padx=5)
        
        self.network_tree = ttk.Treeview(self.network_frame, columns=("node_id", "address", "type", "reputation", "status"), show="headings")
        self.network_tree.heading("node_id", text="ID do Nó")
        self.network_tree.heading("address", text="Endereço")
        self.network_tree.heading("type", text="Tipo")
        self.network_tree.heading("reputation", text="Reputação")
        self.network_tree.heading("status", text="Status")
        self.network_tree.column("node_id", width=150)
        self.network_tree.column("address", width=150)
        self.network_tree.column("type", width=100)
        self.network_tree.column("reputation", width=80)
        self.network_tree.column("status", width=80)
        self.network_tree.pack(fill=tk.BOTH, expand=True, pady=10)
        
        network_stats_frame = ttk.Frame(self.network_frame)
        network_stats_frame.pack(fill=tk.X, pady=10)
        
        self.network_stats_var = tk.StringVar(value="Nós: 0 | Conteúdo: 0 | DNS: 0")
        ttk.Label(network_stats_frame, textvariable=self.network_stats_var).pack()

    def setup_settings_ui(self):
        self.settings_frame = ttk.Frame(self.main_area)
        
        ttk.Label(self.settings_frame, text="Configurações", font=("Arial", 14, "bold")).pack(pady=10)
        
        settings_form_frame = ttk.Frame(self.settings_frame)
        settings_form_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(settings_form_frame, text="ID do Cliente:").grid(row=0, column=0, sticky=tk.W, pady=5)
        ttk.Label(settings_form_frame, text=self.client_identifier).grid(row=0, column=1, sticky=tk.W, pady=5)
        
        ttk.Label(settings_form_frame, text="ID da Sessão:").grid(row=1, column=0, sticky=tk.W, pady=5)
        ttk.Label(settings_form_frame, text=self.session_id).grid(row=1, column=1, sticky=tk.W, pady=5)
        
        ttk.Label(settings_form_frame, text="ID do Nó:").grid(row=2, column=0, sticky=tk.W, pady=5)
        ttk.Label(settings_form_frame, text=self.node_id).grid(row=2, column=1, sticky=tk.W, pady=5)
        
        ttk.Label(settings_form_frame, text="Chave Pública:").grid(row=4, column=0, sticky=tk.W, pady=5)
        pub_key_text = scrolledtext.ScrolledText(settings_form_frame, height=4, width=50)
        pub_key_text.grid(row=4, column=1, pady=5, padx=5, sticky=(tk.W, tk.E))
        if self.public_key_pem:
            pub_key_text.insert(tk.END, self.public_key_pem.decode('utf-8'))
        pub_key_text.config(state=tk.DISABLED)
        
        ttk.Button(settings_form_frame, text="Gerar Chaves", command=self.generate_new_keys).grid(row=5, column=0, columnspan=2, pady=10)
        ttk.Button(settings_form_frame, text="Exportar Chaves", command=self.export_keys).grid(row=6, column=0, columnspan=2, pady=5)
        ttk.Button(settings_form_frame, text="Importar Chaves", command=self.import_keys).grid(row=7, column=0, columnspan=2, pady=5)
        
        settings_form_frame.columnconfigure(1, weight=1)

    def setup_servers_ui(self):
        self.servers_frame = ttk.Frame(self.main_area)
        
        ttk.Label(self.servers_frame, text="Servidores Conhecidos", font=("Arial", 14, "bold")).pack(pady=10)
        
        servers_top_frame = ttk.Frame(self.servers_frame)
        servers_top_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(servers_top_frame, text="Novo Servidor:").pack(side=tk.LEFT, padx=5)
        self.new_server_var = tk.StringVar()
        ttk.Entry(servers_top_frame, textvariable=self.new_server_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Button(servers_top_frame, text="Adicionar", command=self.add_server).pack(side=tk.LEFT, padx=5)
        
        self.servers_tree = ttk.Treeview(self.servers_frame, columns=("address", "status", "reputation"), show="headings")
        self.servers_tree.heading("address", text="Endereço")
        self.servers_tree.heading("status", text="Status")
        self.servers_tree.heading("reputation", text="Reputação")
        self.servers_tree.column("address", width=200)
        self.servers_tree.column("status", width=100)
        self.servers_tree.column("reputation", width=100)
        self.servers_tree.pack(fill=tk.BOTH, expand=True, pady=10)
        
        servers_button_frame = ttk.Frame(self.servers_frame)
        servers_button_frame.pack(pady=10)
        
        ttk.Button(servers_button_frame, text="Remover", command=self.remove_server).pack(side=tk.LEFT, padx=5)
        ttk.Button(servers_button_frame, text="Conectar", command=self.connect_selected_server).pack(side=tk.LEFT, padx=5)
        ttk.Button(servers_button_frame, text="Atualizar", command=self.refresh_servers).pack(side=tk.LEFT, padx=5)

    def setup_stats_ui(self):
        self.stats_frame = ttk.Frame(self.main_area)
        
        ttk.Label(self.stats_frame, text="Estatísticas", font=("Arial", 14, "bold")).pack(pady=10)
        
        stats_grid = ttk.Frame(self.stats_frame)
        stats_grid.pack(fill=tk.BOTH, expand=True, pady=10)
        
        self.stats_vars = {}
        stats_data = [
            ("Tempo de Sessão:", "0h 0m 0s"),
            ("Dados Enviados:", "0 MB"),
            ("Dados Recebidos:", "0 MB"),
            ("Conteúdo Baixado:", "0 arquivos"),
            ("Conteúdo Publicado:", "0 arquivos"),
            ("DNS Registrados:", "0 domínios"),
            ("PoW Resolvidos:", "0"),
            ("Tempo Total PoW:", "0s"),
            ("Conteúdos Reportados:", "0"),
        ]
        
        for i, (label, value) in enumerate(stats_data):
            ttk.Label(stats_grid, text=label, font=("Arial", 10, "bold")).grid(row=i, column=0, sticky=tk.W, pady=5, padx=10)
            var = tk.StringVar(value=value)
            ttk.Label(stats_grid, textvariable=var, font=("Arial", 10)).grid(row=i, column=1, sticky=tk.W, pady=5, padx=10)
            self.stats_vars[label] = var
            
        ttk.Button(self.stats_frame, text="Atualizar", command=self.update_stats).pack(pady=10)

    def show_login(self):
        self.show_frame(self.login_frame)
        self.update_nav_buttons("login")

    def show_browser(self):
        if not self.current_user:
            messagebox.showwarning("Aviso", "Você precisa estar conectado à rede para acessar o navegador.")
            return
        self.show_frame(self.browser_frame)
        self.update_nav_buttons("browser")

    def show_dns(self):
        if not self.current_user:
            messagebox.showwarning("Aviso", "Você precisa estar conectado à rede para acessar o DNS.")
            return
        self.show_frame(self.dns_frame)
        self.update_nav_buttons("dns")
        self.refresh_dns_records()

    def show_upload(self):
        if not self.current_user:
            messagebox.showwarning("Aviso", "Você precisa estar conectado à rede para fazer upload.")
            return
        self.show_frame(self.upload_frame)
        self.update_nav_buttons("upload")

    def show_network(self):
        if not self.current_user:
            messagebox.showwarning("Aviso", "Você precisa estar conectado à rede para ver a rede.")
            return
        self.show_frame(self.network_frame)
        self.update_nav_buttons("network")
        self.refresh_network()

    def show_settings(self):
        self.show_frame(self.settings_frame)
        self.update_nav_buttons("settings")

    def show_servers(self):
        self.show_frame(self.servers_frame)
        self.update_nav_buttons("servers")
        self.refresh_servers()

    def show_stats(self):
        self.show_frame(self.stats_frame)
        self.update_nav_buttons("stats")
        self.update_stats()

    def show_frame(self, frame):
        for widget in self.main_area.winfo_children():
            widget.pack_forget()
        frame.pack(fill=tk.BOTH, expand=True)

    def update_nav_buttons(self, active_button):
        for name, button in self.nav_buttons.items():
            if name == active_button:
                button.config(style="Accent.TButton")
            else:
                button.config(style="TButton")

    def setup_cryptography(self):
        private_key_path = os.path.join(self.crypto_dir, "private_key.pem")
        public_key_path = os.path.join(self.crypto_dir, "public_key.pem")
        
        if os.path.exists(private_key_path) and os.path.exists(public_key_path):
            try:
                with open(private_key_path, "rb") as f:
                    self.private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
                with open(public_key_path, "rb") as f:
                    self.public_key_pem = f.read()
                logger.info("Chaves criptográficas carregadas do armazenamento local.")
            except Exception as e:
                logger.error(f"Erro ao carregar chaves existentes: {e}. Gerando novas chaves.")
                self.generate_keys()
        else:
            self.generate_keys()

    def generate_keys(self):
        try:
            self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
            self.public_key_pem = self.private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            logger.info("Novas chaves criptográficas geradas.")
        except Exception as e:
            logger.error(f"Erro ao gerar chaves: {e}")
            messagebox.showerror("Erro", f"Falha ao gerar chaves criptográficas: {e}")

    def save_keys(self):
        if not self.save_keys_var.get():
            return
            
        try:
            private_key_path = os.path.join(self.crypto_dir, "private_key.pem")
            public_key_path = os.path.join(self.crypto_dir, "public_key.pem")
            
            with open(private_key_path, "wb") as f:
                f.write(self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
                
            with open(public_key_path, "wb") as f:
                f.write(self.public_key_pem)
                
            logger.info("Chaves criptográficas salvas localmente.")
        except Exception as e:
            logger.error(f"Erro ao salvar chaves: {e}")

    def generate_new_keys(self):
        if messagebox.askyesno("Confirmar", "Gerar novas chaves criptográficas? Isso pode afetar seu acesso a conteúdo existente."):
            self.generate_keys()
            self.save_keys()
            messagebox.showinfo("Sucesso", "Novas chaves geradas e salvas.")

    def export_keys(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=[("Arquivos PEM", "*.pem")])
        if file_path:
            try:
                with open(file_path, "wb") as f:
                    f.write(self.private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    ))
                messagebox.showinfo("Sucesso", f"Chave privada exportada para: {file_path}")
            except Exception as e:
                messagebox.showerror("Erro", f"Falha ao exportar chave: {e}")

    def import_keys(self):
        file_path = filedialog.askopenfilename(filetypes=[("Arquivos PEM", "*.pem")])
        if file_path:
            try:
                with open(file_path, "rb") as f:
                    self.private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
                self.public_key_pem = self.private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                self.save_keys()
                messagebox.showinfo("Sucesso", "Chaves importadas com sucesso.")
            except Exception as e:
                messagebox.showerror("Erro", f"Falha ao importar chaves: {e}")

    def start_network_thread(self):
        def run_network():
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            
            ssl_context = None
            if self.use_ssl_var.get():
                ssl_context = ssl.create_default_context()
                if not self.ssl_verify:
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE
                    
            self.sio = socketio.AsyncClient(ssl_verify=ssl_context if ssl_context else False, reconnection=True, reconnection_attempts=5, reconnection_delay=1, reconnection_delay_max=5)
            self.setup_socket_handlers()
            
            self.loop.run_forever()
            
        self.network_thread = threading.Thread(target=run_network, daemon=True)
        self.network_thread.start()

    def setup_socket_handlers(self):
        @self.sio.event
        async def connect():
            logger.info(f"Conectado ao servidor {self.current_server}")
            self.root.after(0, lambda: self.update_status(f"Conectado a {self.current_server}"))
            self.connected = True
            self.connection_attempts = 0
            await self.sio.emit('request_server_auth_challenge', {})

        @self.sio.event
        async def disconnect():
            logger.info(f"Desconectado do servidor {self.current_server}")
            self.root.after(0, lambda: self.update_status("Desconectado"))
            self.connected = False
            if self.current_user and self.auto_reconnect_var.get():
                self.root.after(5000, self.try_reconnect)

        @self.sio.event
        async def connect_error(data):
            logger.error(f"Erro de conexão: {data}")
            self.root.after(0, lambda: self.update_login_status(f"Erro de conexão: {data}"))

        @self.sio.event
        async def status(data):
            message = data.get('message', '')
            logger.info(f"Status do servidor: {message}")

        @self.sio.event
        async def server_auth_challenge(data):
            challenge = data.get('challenge')
            server_public_key_b64 = data.get('server_public_key')
            server_signature_b64 = data.get('signature')
            
            if not all([challenge, server_public_key_b64, server_signature_b64]):
                logger.error("Desafio de autenticação do servidor incompleto")
                self.root.after(0, lambda: self.update_login_status("Falha na autenticação do servidor: dados incompletos"))
                return
                
            try:
                server_public_key = serialization.load_pem_public_key(base64.b64decode(server_public_key_b64), backend=default_backend())
                server_public_key.verify(
                    base64.b64decode(server_signature_b64),
                    challenge.encode('utf-8'),
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
                )
                
                self.server_public_keys[self.current_server] = server_public_key_b64
                
                client_challenge = secrets.token_urlsafe(32)
                self.client_auth_challenge = client_challenge
                
                client_signature = self.private_key.sign(
                    client_challenge.encode('utf-8'),
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
                )
                
                await self.sio.emit('verify_server_auth_response', {
                    'client_challenge': client_challenge,
                    'client_signature': base64.b64encode(client_signature).decode('utf-8'),
                    'client_public_key': base64.b64encode(self.public_key_pem).decode('utf-8')
                })
                
                logger.info("Resposta de autenticação do servidor enviada")
                
            except InvalidSignature:
                logger.error("Assinatura do servidor inválida")
                self.root.after(0, lambda: self.update_login_status("Falha na autenticação do servidor: assinatura inválida"))
            except Exception as e:
                logger.error(f"Erro na autenticação do servidor: {e}")
                self.root.after(0, lambda: self.update_login_status(f"Erro na autenticação do servidor: {str(e)}"))

        @self.sio.event
        async def server_auth_result(data):
            success = data.get('success', False)
            if success:
                logger.info("Autenticação do servidor bem-sucedida")
                self.root.after(0, lambda: self.update_login_status("Servidor autenticado com sucesso"))
                if self.username_var.get() and self.password_var.get():
                    await self.request_pow_challenge("login")
            else:
                error = data.get('error', 'Erro desconhecido')
                logger.error(f"Falha na autenticação do servidor: {error}")
                self.root.after(0, lambda: self.update_login_status(f"Falha na autenticação do servidor: {error}"))

        @self.sio.event
        async def pow_challenge(data):
            if 'error' in data:
                error = data['error']
                logger.error(f"Erro no desafio PoW: {error}")
                self.root.after(0, lambda: self.update_login_status(f"Erro PoW: {error}"))
                if 'blocked_until' in data:
                    blocked_until = data['blocked_until']
                    duration = blocked_until - time.time()
                    self.root.after(0, lambda: self.handle_ban(duration, "Rate limit excedido"))
                return
                
            challenge = data.get('challenge')
            target_bits = data.get('target_bits')
            message = data.get('message', '')
            target_seconds = data.get('target_seconds', 30.0)
            action_type = data.get('action_type', 'login')
            
            logger.info(f"Desafio PoW recebido: {message} - {target_bits} bits")
            self.root.after(0, lambda: self.update_login_status(f"Resolvendo PoW: {target_bits} bits"))
            
            self.pow_solver.solve_challenge(challenge, target_bits, target_seconds, action_type)

        @self.sio.event
        async def authentication_result(data):
            success = data.get('success', False)
            if success:
                username = data.get('username')
                reputation = data.get('reputation', 100)
                self.current_user = username
                self.reputation = reputation
                self.stats_data['session_start'] = time.time()
                
                self.root.after(0, lambda: self.update_user_status(username, reputation))
                self.root.after(0, lambda: self.update_login_status("Login bem-sucedido!"))
                self.root.after(0, self.show_browser)
                
                await self.join_network()
                await self.sync_client_files()
                
                logger.info(f"Login bem-sucedido: {username}")
            else:
                error = data.get('error', 'Erro desconhecido')
                self.root.after(0, lambda: self.update_login_status(f"Falha no login: {error}"))
                logger.error(f"Falha no login: {error}")
                if 'blocked_until' in data:
                    blocked_until = data['blocked_until']
                    duration = blocked_until - time.time()
                    self.root.after(0, lambda: self.handle_ban(duration, "Múltiplas tentativas de login falhas"))

        @self.sio.event
        async def network_joined(data):
            success = data.get('success', False)
            if success:
                logger.info("Entrou na rede com sucesso")
                await self.sio.emit('get_network_state', {})
            else:
                error = data.get('error', 'Erro desconhecido')
                logger.error(f"Falha ao entrar na rede: {error}")

        @self.sio.event
        async def search_results(data):
            if 'error' in data:
                error = data['error']
                self.root.after(0, lambda: self.display_content_error(f"Erro na busca: {error}"))
                return
                
            results = data.get('results', [])
            self.root.after(0, lambda: self.display_search_results(results))

        @self.sio.event
        async def content_response(data):
            if 'error' in data:
                error = data['error']
                self.root.after(0, lambda: self.display_content_error(f"Erro no conteúdo: {error}"))
                return
                
            content_b64 = data.get('content')
            title = data.get('title', 'Sem título')
            description = data.get('description', '')
            mime_type = data.get('mime_type', 'text/plain')
            username = data.get('username', 'Desconhecido')
            signature = data.get('signature', '')
            public_key = data.get('public_key', '')
            verified = data.get('verified', False)
            content_hash = data.get('content_hash', '')
            
            try:
                content = base64.b64decode(content_b64)
                self.stats_data['data_received'] += len(content)
                self.stats_data['content_downloaded'] += 1
                
                integrity_ok = True
                actual_hash = hashlib.sha256(content).hexdigest()
                if actual_hash != content_hash:
                    integrity_ok = False
                    logger.warning(f"Integridade do arquivo comprometida para {content_hash}. Esperado: {content_hash}, Real: {actual_hash}")
                    messagebox.showwarning("Aviso de Segurança", "Este arquivo foi adulterado no servidor. A integridade não pode ser garantida.")
                
                self.save_content_to_storage(content_hash, content, {
                    'title': title,
                    'description': description,
                    'mime_type': mime_type,
                    'username': username,
                    'signature': signature,
                    'public_key': public_key,
                    'verified': verified
                })
                
                content_info = {
                    'title': title,
                    'description': description,
                    'mime_type': mime_type,
                    'username': username,
                    'signature': signature,
                    'public_key': public_key,
                    'verified': verified,
                    'content': content,
                    'content_hash': content_hash,
                    'reputation': data.get('reputation', 100),
                    'integrity_ok': integrity_ok,
                }
                
                self.root.after(0, lambda: self.display_content(content_info))
                
            except Exception as e:
                logger.error(f"Erro ao decodificar conteúdo: {e}")
                self.root.after(0, lambda: self.display_content_error(f"Erro ao processar conteúdo: {e}"))

        @self.sio.event
        async def publish_result(data):
            success = data.get('success', False)
            if success:
                content_hash = data.get('content_hash')
                verified = data.get('verified', False)
                self.stats_data['content_uploaded'] += 1
                self.root.after(0, lambda: self.update_upload_status(f"Upload bem-sucedido! Hash: {content_hash}"))
                self.root.clipboard_clear()
                self.root.clipboard_append(content_hash)
                
                if self.upload_window and self.upload_window.window.winfo_exists():
                    self.upload_window.destroy()
                    self.upload_window = None
                    
                messagebox.showinfo("Upload Concluído", f"Upload concluído com sucesso! Hash: {content_hash} Hash copiado para área de transferência!")
            else:
                error = data.get('error', 'Erro desconhecido')
                self.root.after(0, lambda: self.update_upload_status(f"Falha no upload: {error}"))
                if self.upload_window and self.upload_window.window.winfo_exists():
                    self.upload_window.destroy()
                    self.upload_window = None
                messagebox.showerror("Erro no Upload", f"Falha no upload: {error}")
                if 'blocked_until' in data:
                    blocked_until = data['blocked_until']
                    duration = blocked_until - time.time()
                    self.root.after(0, lambda: self.handle_upload_block(duration))

        @self.sio.event
        async def dns_result(data):
            success = data.get('success', False)
            if success:
                domain = data.get('domain')
                verified = data.get('verified', False)
                self.stats_data['dns_registered'] += 1
                self.root.after(0, lambda: self.update_dns_status(f"DNS registrado: {domain}"))
                self.root.after(0, self.refresh_dns_records)
                messagebox.showinfo("DNS Registrado", f"Domínio {domain} registrado com sucesso!")
            else:
                error = data.get('error', 'Erro desconhecido')
                self.root.after(0, lambda: self.update_dns_status(f"Falha no registro DNS: {error}"))
                messagebox.showerror("Erro no DNS", f"Falha no registro DNS: {error}")
                if 'blocked_until' in data:
                    blocked_until = data['blocked_until']
                    duration = blocked_until - time.time()
                    self.root.after(0, lambda: self.handle_dns_block(duration))

        @self.sio.event
        async def dns_resolution(data):
            success = data.get('success', False)
            if success:
                domain = data.get('domain')
                content_hash = data.get('content_hash')
                username = data.get('username')
                verified = data.get('verified', False)
                
                self.root.after(0, lambda: self.update_dns_status(f"DNS resolvido: {domain}"))
                self.browser_url_var.set(f"hps://{content_hash}")
                self.root.after(0, lambda: self.request_content_by_hash(content_hash))
                
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('''
                        INSERT OR REPLACE INTO browser_dns_records 
                        (domain, content_hash, username, verified, timestamp, ddns_hash) 
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (domain, content_hash, username, verified, time.time(), ""))
                    conn.commit()
                    
                self.root.after(0, self.refresh_dns_records)
                
                ddns_content = self.create_ddns_file(domain, content_hash)
                self.save_ddns_to_storage(domain, ddns_content, {
                    'content_hash': content_hash,
                    'username': username,
                    'verified': verified
                })
            else:
                error = data.get('error', 'Erro desconhecido')
                self.root.after(0, lambda: self.update_dns_status(f"Falha na resolução DNS: {error}"))
                messagebox.showerror("Erro no DNS", f"Falha na resolução DNS: {error}")

        @self.sio.event
        async def network_state(data):
            if 'error' in data:
                return
                
            online_nodes = data.get('online_nodes', 0)
            total_content = data.get('total_content', 0)
            total_dns = data.get('total_dns', 0)
            node_types = data.get('node_types', {})
            
            self.root.after(0, lambda: self.update_network_stats(online_nodes, total_content, total_dns, node_types))

        @self.sio.event
        async def server_list(data):
            if 'error' in data:
                return
                
            servers = data.get('servers', [])
            self.root.after(0, lambda: self.update_servers_list(servers))

        @self.sio.event
        async def reputation_update(data):
            reputation = data.get('reputation', 100)
            self.reputation = reputation
            self.root.after(0, lambda: self.update_reputation(reputation))

        @self.sio.event
        async def ban_notification(data):
            duration = data.get('duration', 300)
            reason = data.get('reason', 'Desconhecido')
            self.root.after(0, lambda: self.handle_ban(duration, reason))

        @self.sio.event
        async def backup_server(data):
            if 'error' in data:
                logger.warning(f"Nenhum servidor de backup disponível: {data['error']}")
            else:
                backup_server = data.get('server')
                self.backup_server = backup_server
                logger.info(f"Servidor de backup definido: {backup_server}")
                self.root.after(0, lambda: self.update_status(f"Backup: {backup_server}"))

        @self.sio.event
        async def content_search_status(data):
            status = data.get('status', '')
            content_hash = data.get('content_hash', '')
            if status == 'searching_network':
                self.root.after(0, lambda: self.update_status(f"Buscando conteúdo {content_hash} na rede..."))

        @self.sio.event
        async def dns_search_status(data):
            status = data.get('status', '')
            domain = data.get('domain', '')
            if status == 'searching_network':
                self.root.after(0, lambda: self.update_status(f"Buscando DNS {domain} na rede..."))

        @self.sio.event
        async def client_files_sync(data):
            try:
                files = data.get('files', [])
                await self.process_client_files_sync(files)
            except Exception as e:
                logger.error(f"Erro ao sincronizar arquivos do cliente: {e}")

        @self.sio.event
        async def client_files_response(data):
            try:
                missing_files = data.get('missing_files', [])
                await self.share_missing_files(missing_files)
            except Exception as e:
                logger.error(f"Erro ao processar resposta de arquivos do cliente: {e}")

        @self.sio.event
        async def request_content_from_client(data):
            try:
                content_hash = data.get('content_hash')
                if not content_hash:
                    return
                    
                file_path = os.path.join(self.crypto_dir, "content", f"{content_hash}.dat")
                if os.path.exists(file_path):
                    with open(file_path, 'rb') as f:
                        content = f.read()
                    
                    actual_hash = hashlib.sha256(content).hexdigest()
                    if actual_hash != content_hash:
                        logger.warning(f"Content {content_hash} integrity check failed")
                        return
                        
                    with sqlite3.connect(self.db_path) as conn:
                        cursor = conn.cursor()
                        cursor.execute('SELECT title, description, mime_type, username, signature, public_key, verified FROM browser_content_cache WHERE content_hash = ?', (content_hash,))
                        row = cursor.fetchone()
                        if not row:
                            logger.warning(f"Metadata not found for content {content_hash}")
                            return
                            
                        title, description, mime_type, username, signature, public_key, verified = row
                        
                    await self.sio.emit('content_from_client', {
                        'content_hash': content_hash,
                        'content': base64.b64encode(content).decode('utf-8'),
                        'title': title,
                        'description': description,
                        'mime_type': mime_type,
                        'username': username,
                        'signature': signature,
                        'public_key': public_key,
                        'verified': verified
                    })
                    
                    logger.info(f"Content {content_hash} shared to network")
                    
            except Exception as e:
                logger.error(f"Error sharing content to network: {e}")

        @self.sio.event
        async def report_result(data):
            success = data.get('success', False)
            if success:
                self.stats_data['content_reported'] += 1
                self.root.after(0, lambda: messagebox.showinfo("Sucesso", "Conteúdo reportado com sucesso!"))
                logger.info("Conteúdo reportado com sucesso")
            else:
                error = data.get('error', 'Erro desconhecido')
                self.root.after(0, lambda: messagebox.showerror("Erro", f"Falha no reporte: {error}"))
                logger.error(f"Falha no reporte: {error}")
                if 'blocked_until' in data:
                    blocked_until = data['blocked_until']
                    duration = blocked_until - time.time()
                    self.root.after(0, lambda: self.handle_report_block(duration))

            if self.report_window and self.report_window.window.winfo_exists():
                self.report_window.destroy()
                self.report_window = None

    async def process_client_files_sync(self, files):
        content_hashes = [file['content_hash'] for file in files]
        await self.sio.emit('request_client_files', {
            'content_hashes': content_hashes
        })

    async def share_missing_files(self, missing_files):
        for content_hash in missing_files:
            file_path = os.path.join(self.crypto_dir, "content", f"{content_hash}.dat")
            if os.path.exists(file_path):
                await self.sio.emit('request_content_from_client', {'content_hash': content_hash})
                await asyncio.sleep(0.1)

    async def request_pow_challenge(self, action_type):
        if not self.connected:
            return
            
        await self.sio.emit('request_pow_challenge', {
            'client_identifier': self.client_identifier,
            'action_type': action_type
        })

    async def send_authentication(self, pow_nonce, hashrate_observed):
        if not self.connected:
            return
            
        password_hash = hashlib.sha256(self.password_var.get().encode()).hexdigest()
        
        if not self.client_auth_challenge:
            logger.error("Client authentication challenge not set")
            self.root.after(0, lambda: self.update_login_status("Erro: Desafio de autenticação do cliente ausente"))
            return
            
        client_challenge_signature = self.private_key.sign(
            self.client_auth_challenge.encode('utf-8'),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        
        await self.sio.emit('authenticate', {
            'username': self.username_var.get(),
            'password_hash': password_hash,
            'public_key': base64.b64encode(self.public_key_pem).decode('utf-8'),
            'node_type': 'client',
            'client_identifier': self.client_identifier,
            'pow_nonce': pow_nonce,
            'hashrate_observed': hashrate_observed,
            'client_challenge_signature': base64.b64encode(client_challenge_signature).decode('utf-8'),
            'client_challenge': self.client_auth_challenge
        })

    async def join_network(self):
        if not self.connected or not self.current_user:
            return
            
        await self.sio.emit('join_network', {
            'node_id': self.node_id,
            'address': f"client_{self.client_identifier}",
            'public_key': base64.b64encode(self.public_key_pem).decode('utf-8'),
            'username': self.current_user,
            'node_type': 'client',
            'client_identifier': self.client_identifier
        })

    async def sync_client_files(self):
        if not self.connected or not self.current_user:
            return
            
        files = []
        content_dir = os.path.join(self.crypto_dir, "content")
        if os.path.exists(content_dir):
            for filename in os.listdir(content_dir):
                if filename.endswith('.dat'):
                    file_path = os.path.join(content_dir, filename)
                    content_hash = filename[:-4]
                    file_size = os.path.getsize(file_path)
                    files.append({
                        'content_hash': content_hash,
                        'file_name': filename,
                        'file_size': file_size
                    })
                    
        await self.sio.emit('sync_client_files', {
            'files': files
        })

    def enter_network(self):
        if self.connected:
            messagebox.showinfo("Info", "Você já está conectado à rede.")
            return
            
        server_address = self.server_var.get()
        if not server_address:
            messagebox.showwarning("Aviso", "Por favor, selecione um servidor.")
            return
            
        if not self.username_var.get() or not self.password_var.get():
            messagebox.showwarning("Aviso", "Por favor, preencha nome de usuário e senha.")
            return
            
        self.current_server = server_address
        self.root.after(0, lambda: self.update_login_status("Conectando..."))
        
        asyncio.run_coroutine_threadsafe(self._connect_to_server(server_address), self.loop)

    def exit_network(self):
        if not self.connected:
            messagebox.showinfo("Info", "Você já está desconectado da rede.")
            return
            
        self.auto_reconnect = False
        self.current_user = None
        self.reputation = 100
        self.root.after(0, lambda: self.update_user_status("Não logado", 100))
        self.root.after(0, self.show_login)
        
        asyncio.run_coroutine_threadsafe(self.sio.disconnect(), self.loop)

    def try_reconnect(self):
        if not self.auto_reconnect_var.get() or self.connected:
            return
            
        if self.backup_server and self.backup_server != self.current_server:
            self.server_var.set(self.backup_server)
            self.current_server = self.backup_server
            logger.info(f"Tentando reconectar ao servidor de backup: {self.backup_server}")
        else:
            logger.info(f"Tentando reconectar ao servidor: {self.current_server}")
            
        self.root.after(0, lambda: self.update_login_status("Tentando reconectar..."))
        asyncio.run_coroutine_threadsafe(self._connect_to_server(self.current_server), self.loop)

    async def _connect_to_server(self, server_address):
        try:
            if self.sio and self.connected:
                await self.sio.disconnect()
                
            protocol = "https" if self.use_ssl_var.get() else "http"
            server_url = f"{protocol}://{server_address}"
            
            await self.sio.connect(server_url, wait_timeout=10)
            logger.info(f"Conectando a {server_url}")
            
        except Exception as e:
            logger.error(f"Erro de conexão: {e}")
            self.root.after(0, lambda: self.update_login_status(f"Erro de conexão: {e}"))
            self.connection_attempts += 1
            if self.connection_attempts < self.max_connection_attempts and self.auto_reconnect_var.get():
                self.root.after(5000, self.try_reconnect)
            else:
                self.root.after(0, lambda: self.update_login_status("Falha na conexão após múltiplas tentativas"))

    def update_status(self, status):
        self.status_var.set(status)

    def update_user_status(self, username, reputation):
        self.user_var.set(f"{username}")
        self.reputation_var.set(f"{reputation}")

    def update_login_status(self, message):
        self.login_status.config(text=message)
        if "bem-sucedido" in message or "conectado" in message:
            self.login_status.config(foreground="green")
        elif "Falha" in message or "Erro" in message:
            self.login_status.config(foreground="red")
        else:
            self.login_status.config(foreground="black")

    def update_upload_status(self, message):
        self.upload_status.config(text=message)
        if "bem-sucedido" in message:
            self.upload_status.config(foreground="green")
        elif "Falha" in message:
            self.upload_status.config(foreground="red")
        else:
            self.upload_status.config(foreground="black")

    def update_dns_status(self, message):
        self.dns_status.config(text=message)
        if "registrado" in message or "resolvido" in message:
            self.dns_status.config(foreground="green")
        elif "Falha" in message:
            self.dns_status.config(foreground="red")
        else:
            self.dns_status.config(foreground="black")

    def update_reputation(self, reputation):
        self.reputation = reputation
        self.reputation_var.set(f"{reputation}")

    def handle_ban(self, duration, reason):
        self.banned_until = time.time() + duration
        self.ban_duration = duration
        self.ban_reason = reason
        self.ban_status_var.set(f"Banido por {int(duration)}s: {reason}")
        
        def update_ban_timer():
            if self.banned_until and time.time() < self.banned_until:
                remaining = int(self.banned_until - time.time())
                self.ban_status_var.set(f"Banido por {remaining}s: {reason}")
                self.root.after(1000, update_ban_timer)
            else:
                self.banned_until = None
                self.ban_status_var.set("")
                
        update_ban_timer()

    def handle_upload_block(self, duration):
        self.upload_blocked_until = time.time() + duration
        messagebox.showwarning("Upload Bloqueado", f"Upload bloqueado por {int(duration)} segundos devido a limite de taxa.")

    def handle_dns_block(self, duration):
        self.dns_blocked_until = time.time() + duration
        messagebox.showwarning("DNS Bloqueado", f"Operações DNS bloqueadas por {int(duration)} segundos devido a limite de taxa.")

    def handle_report_block(self, duration):
        self.report_blocked_until = time.time() + duration
        messagebox.showwarning("Reporte Bloqueado", f"Reportes bloqueados por {int(duration)} segundos devido a limite de taxa.")

    def browser_navigate(self):
        url = self.browser_url_var.get().strip()
        if url.startswith("hps://"):
            if url == "hps://rede":
                self.show_network_content()
            elif url.startswith("hps://dns:"):
                domain = url[len("hps://dns:"):]
                self.resolve_dns_url(domain)
            elif url.startswith("hps://"):
                content_hash = url[len("hps://"):]
                if len(content_hash) == 64:
                    self.request_content_by_hash(content_hash)
                else:
                    self.resolve_dns_url(content_hash)
        else:
            messagebox.showwarning("Aviso", "URL deve começar com hps://")

    def browser_back(self):
        if self.history_index > 0:
            self.history_index -= 1
            url = self.history[self.history_index]
            self.browser_url_var.set(url)
            self.browser_navigate()

    def browser_forward(self):
        if self.history_index < len(self.history) - 1:
            self.history_index += 1
            url = self.history[self.history_index]
            self.browser_url_var.set(url)
            self.browser_navigate()

    def browser_reload(self):
        current_url = self.browser_url_var.get()
        if current_url:
            self.browser_navigate()

    def browser_home(self):
        self.browser_url_var.set("hps://rede")
        self.browser_navigate()

    def add_to_history(self, url):
        if self.history and self.history[-1] == url:
            return
        self.history.append(url)
        self.history_index = len(self.history) - 1

    def show_search_dialog(self):
        if self.search_dialog and self.search_dialog.window.winfo_exists():
            self.search_dialog.window.lift()
            return
            
        self.search_dialog = SearchDialog(self.root, self)

    async def _search_content(self, query, content_type="all", sort_by="reputation"):
        if not self.connected:
            return
            
        await self.sio.emit('search_content', {
            'query': query,
            'limit': 50,
            'content_type': content_type if content_type != "all" else "",
            'sort_by': sort_by
        })

    def display_search_results(self, results):
        if not self.search_dialog or not self.search_dialog.window.winfo_exists():
            return
            
        search_dialog_instance = self.search_dialog
        search_dialog_instance.results_text.config(state=tk.NORMAL)
        search_dialog_instance.results_text.delete(1.0, tk.END)
        
        if not results:
            search_dialog_instance.results_text.insert(tk.END, "Nenhum resultado encontrado.")
            search_dialog_instance.results_text.config(state=tk.DISABLED)
            return
            
        for result in results:
            verified = result.get('verified', False)
            status_tag = "verified" if verified else "unverified"
            status_text = "✓" if verified else "⚠"
            
            search_dialog_instance.results_text.insert(tk.END, f"{status_text} ", status_tag)
            search_dialog_instance.results_text.insert(tk.END, f"{result['title']}", "title")
            search_dialog_instance.results_text.insert(tk.END, f"   Hash: {result['content_hash']}")
            search_dialog_instance.results_text.insert(tk.END, f"   Autor: {result['username']} (Reputação: {result.get('reputation', 100)})")
            search_dialog_instance.results_text.insert(tk.END, f"   Tipo: {result['mime_type']}")
            search_dialog_instance.results_text.insert(tk.END, f"   Acessar: hps://{result['content_hash']}", "link")
            search_dialog_instance.results_text.insert(tk.END, "")
            
        search_dialog_instance.results_text.config(state=tk.DISABLED)

    def display_content(self, content_info):
        content = content_info['content']
        title = content_info['title']
        description = content_info['description']
        mime_type = content_info['mime_type']
        username = content_info['username']
        verified = content_info['verified']
        integrity_ok = content_info.get('integrity_ok', True)
        
        self.current_content_info = content_info
        
        self.browser_content.config(state=tk.NORMAL)
        self.browser_content.delete(1.0, tk.END)
        
        if not integrity_ok:
            self.browser_content.insert(tk.END, "⚠ ATENÇÃO: Este conteúdo foi adulterado no servidor. A integridade não pode ser garantida.", "unverified")
        elif not verified:
            self.browser_content.insert(tk.END, "⚠ ATENÇÃO: Este conteúdo não foi verificado. A autenticidade não pode ser garantida.", "unverified")
            
        header_end_marker = b'### :END START'
        if content.startswith(b'# HSYST P2P SERVICE') and header_end_marker in content:
            header_part, content = content.split(header_end_marker, 1)
            
        if mime_type.startswith('text/'):
            try:
                text_content = content.decode('utf-8')
                self.browser_content.insert(tk.END, text_content)
            except UnicodeDecodeError:
                self.browser_content.insert(tk.END, "[Conteúdo binário não pode ser exibido como texto]")
        elif mime_type.startswith('image/'):
            try:
                image = Image.open(io.BytesIO(content))
                image.thumbnail((400, 400), Image.Resampling.LANCZOS)
                photo = ImageTk.PhotoImage(image)
                
                image_label = ttk.Label(self.browser_content, image=photo)
                image_label.image = photo
                self.browser_content.window_create(tk.END, window=image_label)
                self.browser_content.insert(tk.END, "")
            except Exception as e:
                self.browser_content.insert(tk.END, f"[Erro ao exibir imagem: {e}]")
        elif mime_type in ['application/pdf', 'application/octet-stream']:
            self.browser_content.insert(tk.END, f"[Arquivo binário - {len(content)} bytes]")
            
        self.browser_content.config(state=tk.DISABLED)

    def display_content_error(self, error):
        self.browser_content.config(state=tk.NORMAL)
        self.browser_content.delete(1.0, tk.END)
        self.browser_content.insert(tk.END, f"Erro: {error}")
        self.browser_content.config(state=tk.DISABLED)

    def handle_content_click(self, event):
        index = self.browser_content.index(f"@{event.x},{event.y}")
        for tag in self.browser_content.tag_names(index):
            if tag == "link":
                line_start = self.browser_content.index(f"{index} linestart")
                line_end = self.browser_content.index(f"{index} lineend")
                line_text = self.browser_content.get(line_start, line_end)
                import re
                match = re.search(r'hps://(\S+)', line_text)
                if match:
                    url = f"hps://{match.group(1)}"
                    self.browser_url_var.set(url)
                    self.browser_navigate()
                break

    def show_security_dialog(self):
        if self.current_content_info:
            ContentSecurityDialog(self.root, self.current_content_info, self)
        else:
            messagebox.showinfo("Segurança", "Nenhum conteúdo carregado para verificar.")

    def show_network_content(self):
        self.browser_content.config(state=tk.NORMAL)
        self.browser_content.delete(1.0, tk.END)
        self.browser_content.insert(tk.END, "Rede P2P Hsyst", "title")
        self.browser_content.insert(tk.END, "Bem-vindo à rede descentralizada Hsyst!")
        self.browser_content.insert(tk.END, "Recursos disponíveis:")
        self.browser_content.insert(tk.END, "• Navegar por conteúdo publicado")
        self.browser_content.insert(tk.END, "• Pesquisar por palavras-chave")
        self.browser_content.insert(tk.END, "• Acessar via DNS personalizado")
        self.browser_content.insert(tk.END, "• Upload de novos conteúdos")
        self.browser_content.insert(tk.END, "Use a barra de endereços para navegar:")
        self.browser_content.insert(tk.END, "• hps://rede - Esta página")
        self.browser_content.insert(tk.END, "• hps://<hash> - Conteúdo específico")
        self.browser_content.insert(tk.END, "• hps://dns:<domínio> - Via DNS")
        self.browser_content.config(state=tk.DISABLED)

    def request_content_by_hash(self, content_hash):
        self.add_to_history(f"hps://{content_hash}")
        asyncio.run_coroutine_threadsafe(self._request_content_by_hash(content_hash), self.loop)

    async def _request_content_by_hash(self, content_hash):
        if not self.connected:
            return
            
        await self.sio.emit('request_content', {'content_hash': content_hash})

    def resolve_dns_url(self, domain):
        self.add_to_history(f"hps://dns:{domain}")
        asyncio.run_coroutine_threadsafe(self._resolve_dns(domain), self.loop)

    def save_content_to_storage(self, content_hash, content, metadata=None):
        content_dir = os.path.join(self.crypto_dir, "content")
        os.makedirs(content_dir, exist_ok=True)
        
        file_path = os.path.join(content_dir, f"{content_hash}.dat")
        with open(file_path, 'wb') as f:
            f.write(content)
            
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            if metadata:
                cursor.execute('''
                    INSERT OR REPLACE INTO browser_content_cache 
                    (content_hash, file_path, file_name, mime_type, size, last_accessed, title, description, username, signature, public_key, verified) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    content_hash, file_path, f"{content_hash}.dat", 
                    metadata.get('mime_type', 'application/octet-stream'), 
                    len(content), time.time(),
                    metadata.get('title', ''),
                    metadata.get('description', ''),
                    metadata.get('username', ''),
                    metadata.get('signature', ''),
                    metadata.get('public_key', ''),
                    metadata.get('verified', 0)
                ))
            else:
                cursor.execute('''
                    INSERT OR REPLACE INTO browser_content_cache 
                    (content_hash, file_path, file_name, mime_type, size, last_accessed) 
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (content_hash, file_path, f"{content_hash}.dat", 'application/octet-stream', len(content), time.time()))
            conn.commit()
            
        logger.info(f"Conteúdo salvo em: {file_path}")

    def save_ddns_to_storage(self, domain, ddns_content, metadata=None):
        ddns_dir = os.path.join(self.crypto_dir, "ddns")
        os.makedirs(ddns_dir, exist_ok=True)
        
        ddns_hash = hashlib.sha256(ddns_content).hexdigest()
        file_path = os.path.join(ddns_dir, f"{ddns_hash}.ddns")
        with open(file_path, 'wb') as f:
            f.write(ddns_content)
            
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            if metadata:
                cursor.execute('''
                    INSERT OR REPLACE INTO browser_ddns_cache 
                    (domain, ddns_hash, content_hash, username, verified, timestamp) 
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    domain, ddns_hash,
                    metadata.get('content_hash', ''),
                    metadata.get('username', ''),
                    metadata.get('verified', 0),
                    time.time()
                ))
            conn.commit()
            
        logger.info(f"DDNS salvo em: {file_path}")
        return ddns_hash

    def create_ddns_file(self, domain, content_hash):
        ddns_content = f"""# HSYST P2P SERVICE
### START:
# USER: {self.current_user}
# KEY: {base64.b64encode(self.public_key_pem).decode('utf-8')}
### :END START
### DNS:
# DNAME: {domain} = {content_hash}
### :END DNS
"""
        return ddns_content.encode('utf-8')

    def extract_content_hash_from_ddns(self, ddns_content):
        try:
            lines = ddns_content.decode('utf-8').splitlines()
            in_dns_section = False
            for line in lines:
                if line.strip() == '### DNS:':
                    in_dns_section = True
                    continue
                if line.strip() == '### :END DNS':
                    break
                if in_dns_section and line.strip().startswith('# DNAME:'):
                    parts = line.strip().split('=')
                    if len(parts) == 2:
                        return parts[1].strip()
            return None
        except Exception as e:
            logger.error(f"Erro ao extrair hash do conteúdo do DDNS: {e}")
            return None

    def select_upload_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.upload_file_var.set(file_path)
            file_name = os.path.basename(file_path)
            self.upload_title_var.set(file_name)
            
            mime_type, _ = mimetypes.guess_type(file_name)
            if not mime_type:
                mime_type = 'application/octet-stream'
            self.upload_mime_var.set(mime_type)

    def select_dns_content_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            try:
                with open(file_path, 'rb') as f:
                    content = f.read()
                content_hash = hashlib.sha256(content).hexdigest()
                self.dns_content_hash_var.set(content_hash)
            except Exception as e:
                messagebox.showerror("Erro", f"Erro ao ler arquivo: {e}")

    def upload_file(self):
        if not self.connected:
            messagebox.showwarning("Aviso", "Por favor, conecte-se à rede primeiro.")
            return
            
        file_path = self.upload_file_var.get()
        if not file_path or not os.path.exists(file_path):
            messagebox.showwarning("Aviso", "Por favor, selecione um arquivo válido.")
            return
            
        title = self.upload_title_var.get()
        if not title:
            messagebox.showwarning("Aviso", "Por favor, insira um título.")
            return
            
        self.upload_window = UploadProgressWindow(self.root)
        
        def upload_thread():
            try:
                if self.upload_window and self.upload_window.window.winfo_exists():
                    self.upload_window.update_progress(10, "Lendo arquivo...")
                    
                with open(file_path, 'rb') as f:
                    content = f.read()
                    
                if len(content) > self.max_upload_size:
                    self.root.after(0, lambda: messagebox.showwarning("Aviso", f"Arquivo muito grande. Tamanho máximo: {self.max_upload_size // (1024*1024)}MB"))
                    if self.upload_window and self.upload_window.window.winfo_exists():
                        self.upload_window.destroy()
                        self.upload_window = None
                    return
                    
                if self.upload_window and self.upload_window.window.winfo_exists():
                    self.upload_window.update_progress(30, "Calculando hash...")
                    
                header = b"# HSYST P2P SERVICE"
                header += b"### START:"
                header += b"# USER: " + self.current_user.encode('utf-8') + b""
                header += b"# KEY: " + base64.b64encode(self.public_key_pem) + b""
                header += b"### :END START"
                
                full_content_with_header = header + content
                content_hash = hashlib.sha256(full_content_with_header).hexdigest()
                
                if self.upload_window and self.upload_window.window.winfo_exists():
                    self.upload_window.update_progress(50, "Preparando cabeçalho...", content_hash, len(full_content_with_header))
                    self.upload_window.log_message(f"Hash calculado: {content_hash}")
                    
                if self.upload_window and self.upload_window.window.winfo_exists():
                    self.upload_window.update_progress(70, "Assinando conteúdo...")
                    self.upload_window.log_message("Assinando conteúdo com chave privada...")
                    
                signature = self.private_key.sign(
                    content,
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
                )
                
                self.save_content_to_storage(content_hash, full_content_with_header, {
                    'title': title,
                    'description': self.upload_description_var.get(),
                    'mime_type': self.upload_mime_var.get(),
                    'username': self.current_user,
                    'signature': base64.b64encode(signature).decode('utf-8'),
                    'public_key': base64.b64encode(self.public_key_pem).decode('utf-8'),
                    'verified': True
                })
                
                self.local_files[content_hash] = {
                    'name': os.path.basename(file_path),
                    'path': file_path,
                    'size': len(content),
                    'content': content,
                    'published': True
                }
                
                if self.upload_window and self.upload_window.window.winfo_exists():
                    self.upload_window.update_progress(90, "Solicitando PoW...")
                    self.upload_window.log_message("Solicitando prova de trabalho para upload...")
                    
                self.root.after(0, lambda: self.update_upload_status("Solicitando PoW para upload..."))
                
                def do_upload(pow_nonce, hashrate_observed):
                    asyncio.run_coroutine_threadsafe(
                        self._upload_file(
                            content_hash, title, self.upload_description_var.get(),
                            self.upload_mime_var.get(), len(full_content_with_header),
                            signature, full_content_with_header, pow_nonce, hashrate_observed
                        ), self.loop
                    )
                    
                self.upload_callback = do_upload
                asyncio.run_coroutine_threadsafe(self.request_pow_challenge("upload"), self.loop)
                
            except Exception as e:
                logger.error(f"Erro no upload: {e}")
                self.root.after(0, lambda: messagebox.showerror("Erro", f"Falha no upload: {e}"))
                if self.upload_window and self.upload_window.window.winfo_exists():
                    self.upload_window.destroy()
                    self.upload_window = None
                    
        threading.Thread(target=upload_thread, daemon=True).start()

    async def _upload_file(self, content_hash, title, description, mime_type, size, signature, full_content_with_header, pow_nonce, hashrate_observed):
        if not self.connected:
            return
            
        try:
            content_b64 = base64.b64encode(full_content_with_header).decode('utf-8')
            data = {
                'content_hash': content_hash,
                'title': title,
                'description': description,
                'mime_type': mime_type,
                'size': size,
                'signature': base64.b64encode(signature).decode('utf-8'),
                'public_key': base64.b64encode(self.public_key_pem).decode('utf-8'),
                'content_b64': content_b64,
                'pow_nonce': pow_nonce,
                'hashrate_observed': hashrate_observed
            }
            
            await self.sio.emit('publish_content', data)
            
        except Exception as e:
            logger.error(f"Erro no upload: {e}")
            self.root.after(0, lambda: self.update_upload_status(f"Erro no upload: {e}"))

    def register_dns(self):
        if not self.connected:
            messagebox.showwarning("Aviso", "Por favor, conecte-se à rede primeiro.")
            return
            
        domain = self.dns_domain_var.get().lower().strip()
        content_hash = self.dns_content_hash_var.get().strip()
        
        if not domain:
            messagebox.showwarning("Aviso", "Por favor, insira um domínio.")
            return
            
        if not content_hash:
            messagebox.showwarning("Aviso", "Por favor, insira um hash de conteúdo.")
            return
            
        if not self.is_valid_domain(domain):
            messagebox.showwarning("Aviso", "Domínio inválido. Use apenas letras, números e hífens.")
            return
            
        self.ddns_window = DDNSProgressWindow(self.root)
        self.ddns_window.update_progress(10, "Criando arquivo DDNS...", domain, content_hash)
        
        def register_thread():
            try:
                self.ddns_window.log_message(f"Criando arquivo DDNS para domínio: {domain}")
                ddns_content = self.create_ddns_file(domain, content_hash)
                ddns_hash = hashlib.sha256(ddns_content).hexdigest()
                
                self.ddns_window.update_progress(30, "Assinando arquivo DDNS...", domain, ddns_hash)
                self.ddns_window.log_message(f"Hash do arquivo DDNS: {ddns_hash}")
                
                signature = self.private_key.sign(
                    ddns_content,
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
                )
                
                self.ddns_window.update_progress(50, "Preparando envio...", domain, content_hash)
                self.ddns_window.log_message("Arquivo DDNS assinado com sucesso")
                
                self.root.after(0, lambda: self.update_dns_status("Solicitando PoW para registro DNS..."))
                
                def do_register(pow_nonce, hashrate_observed):
                    asyncio.run_coroutine_threadsafe(
                        self._register_dns(domain, ddns_content, signature, pow_nonce, hashrate_observed),
                        self.loop
                    )
                    
                self.dns_callback = do_register
                asyncio.run_coroutine_threadsafe(self.request_pow_challenge("dns"), self.loop)
                
            except Exception as e:
                logger.error(f"Erro no registro DNS: {e}")
                self.root.after(0, lambda: messagebox.showerror("Erro", f"Falha no registro DNS: {e}"))
                if self.ddns_window and self.ddns_window.winfo_exists():
                    self.ddns_window.destroy()
                    self.ddns_window = None
                    
        threading.Thread(target=register_thread, daemon=True).start()

    async def _register_dns(self, domain, ddns_content, signature, pow_nonce, hashrate_observed):
        if not self.connected:
            return
            
        try:
            ddns_content_b64 = base64.b64encode(ddns_content).decode('utf-8')
            await self.sio.emit('register_dns', {
                'domain': domain,
                'ddns_content': ddns_content_b64,
                'signature': base64.b64encode(signature).decode('utf-8'),
                'public_key': base64.b64encode(self.public_key_pem).decode('utf-8'),
                'pow_nonce': pow_nonce,
                'hashrate_observed': hashrate_observed
            })
        except Exception as e:
            logger.error(f"Erro no registro DNS: {e}")
            self.root.after(0, lambda: self.update_dns_status(f"Erro no registro DNS: {e}"))

    def resolve_dns(self):
        domain = self.dns_domain_var.get().lower().strip()
        if not domain:
            messagebox.showwarning("Aviso", "Por favor, insira um domínio para resolver.")
            return
            
        self.root.after(0, lambda: self.update_dns_status("Resolvendo DNS..."))
        asyncio.run_coroutine_threadsafe(self._resolve_dns(domain), self.loop)

    async def _resolve_dns(self, domain):
        if not self.connected:
            return
            
        await self.sio.emit('resolve_dns', {'domain': domain})

    def is_valid_domain(self, domain):
        import re
        pattern = r'^[a-z0-9-]+(\.[a-z0-9-]+)*$'
        return re.match(pattern, domain) is not None

    def refresh_dns_records(self):
        for item in self.dns_tree.get_children():
            self.dns_tree.delete(item)
            
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT domain, content_hash, verified FROM browser_dns_records ORDER BY timestamp DESC LIMIT 100')
            rows = cursor.fetchall()
            for row in rows:
                domain, content_hash, verified = row
                verified_text = "Sim" if verified else "Não"
                self.dns_tree.insert("", tk.END, values=(
                    domain,
                    content_hash[:20] + "...",
                    verified_text
                ))

    def open_dns_content(self, event):
        selection = self.dns_tree.selection()
        if not selection:
            return
            
        item = selection[0]
        domain = self.dns_tree.item(item, 'values')[0]
        self.browser_url_var.set(f"hps://dns:{domain}")
        self.browser_navigate()

    def refresh_network(self):
        if not self.connected:
            messagebox.showwarning("Aviso", "Conecte-se à rede primeiro.")
            return
            
        asyncio.run_coroutine_threadsafe(self._refresh_network(), self.loop)

    async def _refresh_network(self):
        if not self.connected:
            return
            
        await self.sio.emit('get_network_state', {})
        await self.sio.emit('get_servers', {})

    def sync_network(self):
        if not self.connected:
            messagebox.showwarning("Aviso", "Conecte-se à rede primeiro.")
            return
            
        if messagebox.askyesno("Confirmar Sincronização", "Deseja sincronizar com a rede P2P? Isso pode levar alguns minutos e consumir dados."):
            self.sync_dialog = NetworkSyncDialog(self.root, self)
            self.sync_dialog.log_message("Iniciando sincronização com a rede...")
            
            def sync_thread():
                async def async_sync():
                    try:
                        self.sync_dialog.log_message("Solicitando lista de servidores conhecidos...")
                        await self.sio.emit('get_servers', {})
                        await asyncio.sleep(1)
                        
                        if self.sync_dialog and self.sync_dialog.cancelled:
                            return
                            
                        self.sync_dialog.log_message("Enviando lista de servidores locais para a rede...")
                        await self.sio.emit('sync_servers', {'servers': self.known_servers})
                        await asyncio.sleep(1)
                        
                        if self.sync_dialog and self.sync_dialog.cancelled:
                            return
                            
                        self.sync_dialog.log_message("Sincronizando arquivos locais com a rede...")
                        await self.sync_client_files()
                        await asyncio.sleep(2)
                        
                        if self.sync_dialog and self.sync_dialog.cancelled:
                            return
                            
                        self.sync_dialog.log_message("Sincronização concluída!")
                        
                    except Exception as e:
                        if self.sync_dialog and self.sync_dialog.window.winfo_exists():
                            self.sync_dialog.update_status("Erro na sincronização")
                            self.sync_dialog.log_message(f"Erro durante sincronização: {e}")
                
                asyncio.run_coroutine_threadsafe(async_sync(), self.loop)
                        
            threading.Thread(target=sync_thread, daemon=True).start()

    async def _sync_network_full(self):
        if not self.connected:
            return
            
        if self.sync_dialog and self.sync_dialog.cancelled:
            return
            
        self.sync_dialog.log_message("Solicitando lista de servidores conhecidos...")
        await self.sio.emit('get_servers', {})
        await asyncio.sleep(1)
        
        if self.sync_dialog and self.sync_dialog.cancelled:
            return
            
        self.sync_dialog.log_message("Enviando lista de servidores locais para a rede...")
        await self.sio.emit('sync_servers', {'servers': self.known_servers})
        await asyncio.sleep(1)
        
        if self.sync_dialog and self.sync_dialog.cancelled:
            return
            
        self.sync_dialog.log_message("Sincronizando arquivos locais com a rede...")
        await self.sync_client_files()
        await asyncio.sleep(2)
        
        if self.sync_dialog and self.sync_dialog.cancelled:
            return
            
        self.sync_dialog.log_message("Sincronização concluída!")

    def update_network_stats(self, online_nodes, total_content, total_dns, node_types):
        self.network_stats_var.set(f"Nós: {online_nodes} | Conteúdo: {total_content} | DNS: {total_dns}")
        
        for item in self.network_tree.get_children():
            self.network_tree.delete(item)
            
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT node_id, address, node_type, reputation, status FROM browser_network_nodes ORDER BY last_seen DESC LIMIT 50')
            rows = cursor.fetchall()
            for row in rows:
                node_id, address, node_type, reputation, status = row
                self.network_tree.insert("", tk.END, values=(
                    node_id[:16] + "...",
                    address,
                    node_type,
                    reputation,
                    status
                ))

    def show_my_node(self):
        messagebox.showinfo("Meu Nó", f"""
ID do Nó: {self.node_id}
ID do Cliente: {self.client_identifier}
ID da Sessão: {self.session_id}
Usuário: {self.current_user or 'Não logado'}
Reputação: {self.reputation}
Tipo: {self.node_type}
Conectado: {'Sim' if self.connected else 'Não'}
Servidor: {self.current_server or 'Nenhum'}
        """)

    def refresh_servers(self):
        if not self.connected:
            messagebox.showwarning("Aviso", "Conecte-se à rede primeiro.")
            return
            
        asyncio.run_coroutine_threadsafe(self._refresh_servers(), self.loop)

    async def _refresh_servers(self):
        if not self.connected:
            return
            
        await self.sio.emit('get_servers', {})

    def update_servers_list(self, servers):
        for item in self.servers_tree.get_children():
            self.servers_tree.delete(item)
            
        for server in servers:
            address = server['address']
            status = server.get('status', 'Desconhecido')
            reputation = server.get('reputation', 100)
            self.servers_tree.insert("", tk.END, values=(
                address,
                status,
                reputation
            ))

    def add_server(self):
        server_address = self.new_server_var.get().strip()
        if not server_address:
            messagebox.showwarning("Aviso", "Por favor, insira um endereço de servidor.")
            return
            
        if server_address not in self.known_servers:
            self.known_servers.append(server_address)
            self.server_combo['values'] = self.known_servers
            self.new_server_var.set("")
            self.save_known_servers()
            messagebox.showinfo("Sucesso", f"Servidor {server_address} adicionado com sucesso!")
            self.refresh_servers()
        else:
            messagebox.showinfo("Info", "Este servidor já está na lista.")

    def remove_server(self):
        selection = self.servers_tree.selection()
        if not selection:
            messagebox.showwarning("Aviso", "Por favor, selecione um servidor para remover.")
            return
            
        item = selection[0]
        address = self.servers_tree.item(item, 'values')[0]
        
        if messagebox.askyesno("Confirmar", f"Remover servidor {address}?"):
            if address in self.known_servers:
                self.known_servers.remove(address)
                self.server_combo['values'] = self.known_servers
                self.save_known_servers()
                self.refresh_servers()
                messagebox.showinfo("Sucesso", f"Servidor {address} removido com sucesso!")

    def connect_selected_server(self):
        selection = self.servers_tree.selection()
        if not selection:
            messagebox.showwarning("Aviso", "Por favor, selecione um servidor para conectar.")
            return
            
        item = selection[0]
        address = self.servers_tree.item(item, 'values')[0]
        self.server_var.set(address)
        self.current_server = address
        self.root.after(0, lambda: self.update_login_status("Conectando..."))
        asyncio.run_coroutine_threadsafe(self._connect_to_server(address), self.loop)

    def update_stats(self):
        session_duration = time.time() - self.stats_data['session_start']
        hours = int(session_duration // 3600)
        minutes = int((session_duration % 3600) // 60)
        seconds = int(session_duration % 60)
        
        self.stats_vars["Tempo de Sessão:"].set(f"{hours}h {minutes}m {seconds}s")
        self.stats_vars["Dados Enviados:"].set(f"{self.stats_data['data_sent'] // (1024*1024)} MB")
        self.stats_vars["Dados Recebidos:"].set(f"{self.stats_data['data_received'] // (1024*1024)} MB")
        self.stats_vars["Conteúdo Baixado:"].set(f"{self.stats_data['content_downloaded']} arquivos")
        self.stats_vars["Conteúdo Publicado:"].set(f"{self.stats_data['content_uploaded']} arquivos")
        self.stats_vars["DNS Registrados:"].set(f"{self.stats_data['dns_registered']} domínios")
        self.stats_vars["PoW Resolvidos:"].set(f"{self.stats_data['pow_solved']}")
        self.stats_vars["Tempo Total PoW:"].set(f"{int(self.stats_data['pow_time'])}s")
        self.stats_vars["Conteúdos Reportados:"].set(f"{self.stats_data['content_reported']}")

    def pow_solution_found(self, nonce, solve_time, hashrate):
        self.stats_data['pow_solved'] += 1
        self.stats_data['pow_time'] += solve_time
        
        if self.upload_callback:
            self.upload_callback(nonce, hashrate)
            self.upload_callback = None
        elif self.dns_callback:
            self.dns_callback(nonce, hashrate)
            self.dns_callback = None
        elif self.report_callback:
            self.report_callback(nonce, hashrate)
            self.report_callback = None
        else:
            asyncio.run_coroutine_threadsafe(self.send_authentication(nonce, hashrate), self.loop)

    def pow_solution_failed(self):
        if self.upload_callback:
            self.upload_callback = None
        elif self.dns_callback:
            self.dns_callback = None
        elif self.report_callback:
            self.report_callback = None
        self.root.after(0, lambda: self.update_login_status("Falha na solução do PoW"))

    def report_content_action(self, content_hash, reported_user):
        if not self.connected:
            messagebox.showwarning("Aviso", "Conecte-se à rede primeiro.")
            return
            
        if not self.current_user:
            messagebox.showwarning("Aviso", "Você precisa estar logado para reportar conteúdo.")
            return
            
        if reported_user == self.current_user:
            messagebox.showwarning("Aviso", "Você não pode reportar seu próprio conteúdo.")
            return
            
        self.report_window = ReportProgressWindow(self.root)
        self.report_window.update_progress(10, "Iniciando processo de reporte...", content_hash, reported_user, self.reputation)
        
        def report_thread():
            try:
                self.report_window.log_message(f"Validando dados para reporte...")
                self.report_window.log_message(f"Conteúdo: {content_hash}")
                self.report_window.log_message(f"Usuário reportado: {reported_user}")
                self.report_window.log_message(f"Sua reputação: {self.reputation}")
                
                if self.reputation < 20:
                    self.root.after(0, lambda: messagebox.showwarning("Aviso", "Sua reputação é muito baixa para reportar conteúdo."))
                    if self.report_window and self.report_window.window.winfo_exists():
                        self.report_window.destroy()
                        self.report_window = None
                    return
                    
                self.report_window.update_progress(30, "Validando informações...", content_hash, reported_user, self.reputation)
                
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('''
                        SELECT COUNT(*) FROM browser_reports 
                        WHERE reporter_user = ? AND content_hash = ?
                    ''', (self.current_user, content_hash))
                    count = cursor.fetchone()[0]
                    if count > 0:
                        self.root.after(0, lambda: messagebox.showwarning("Aviso", "Você já reportou este conteúdo."))
                        if self.report_window and self.report_window.window.winfo_exists():
                            self.report_window.destroy()
                            self.report_window = None
                        return
                        
                self.report_window.update_progress(50, "Preparando solicitação...", content_hash, reported_user, self.reputation)
                self.report_window.log_message("Dados validados com sucesso")
                
                self.root.after(0, lambda: self.update_status("Solicitando PoW para reporte..."))
                
                def do_report(pow_nonce, hashrate_observed):
                    asyncio.run_coroutine_threadsafe(
                        self._report_content(content_hash, reported_user, pow_nonce, hashrate_observed),
                        self.loop
                    )
                    
                self.report_callback = do_report
                asyncio.run_coroutine_threadsafe(self.request_pow_challenge("report"), self.loop)
                
            except Exception as e:
                logger.error(f"Erro no processo de reporte: {e}")
                self.root.after(0, lambda: messagebox.showerror("Erro", f"Falha no reporte: {e}"))
                if self.report_window and self.report_window.window.winfo_exists():
                    self.report_window.destroy()
                    self.report_window = None
                    
        threading.Thread(target=report_thread, daemon=True).start()

    async def _report_content(self, content_hash, reported_user, pow_nonce, hashrate_observed):
        if not self.connected:
            return
            
        try:
            report_id = hashlib.sha256(f"{content_hash}{reported_user}{self.current_user}{time.time()}".encode()).hexdigest()
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO browser_reports 
                    (report_id, content_hash, reported_user, reporter_user, timestamp, status, reason) 
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (report_id, content_hash, reported_user, self.current_user, time.time(), 'pending', ''))
                conn.commit()
                
            await self.sio.emit('report_content', {
                'content_hash': content_hash,
                'reported_user': reported_user,
                'reporter': self.current_user,
                'pow_nonce': pow_nonce,
                'hashrate_observed': hashrate_observed
            })
            
        except Exception as e:
            logger.error(f"Erro no envio do reporte: {e}")
            self.root.after(0, lambda: messagebox.showerror("Erro", f"Falha no envio do reporte: {e}"))

if __name__ == "__main__":
    root = tk.Tk()
    app = HPSBrowser(root)
    root.mainloop()