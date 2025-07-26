from flask import Blueprint, render_template, redirect, request, flash, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required
from .models import User
from . import db
from sqlalchemy.exc import IntegrityError # IMPORT INI!

auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            # Pastikan 'chatbot.chat' adalah nama endpoint yang benar untuk halaman chatbot Anda
            return redirect(url_for('chatbot.chat'))
        flash("Login gagal. Periksa email dan password.", "error") # Tambahkan kategori flash message
    return render_template('login.html')

@auth.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        name = request.form['name']
        password_raw = request.form['password'] # Ambil password mentah
        confirm_password_raw = request.form.get('confirm_password') # Asumsi ada confirm password di form

        # Tambahkan validasi dasar (jika belum ada di template HTML atau frontend)
        if not email or not name or not password_raw:
            flash("Semua kolom harus diisi.", "error")
            return redirect(url_for('auth.register'))

        if password_raw != confirm_password_raw:
            flash("Konfirmasi password tidak cocok.", "error")
            return redirect(url_for('auth.register'))

        # **OPSIONAL TAPI DISARANKAN**: Cek keberadaan email SEBELUM add/commit
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("Email sudah terdaftar. Silakan gunakan email lain atau login.", "error")
            return redirect(url_for('auth.register'))

        try:
            password_hashed = generate_password_hash(password_raw) # Hash password
            user = User(email=email, name=name, password=password_hashed)
            db.session.add(user)
            db.session.commit() # Ini baris yang bisa memicu IntegrityError
            flash("Akun berhasil dibuat. Silakan login.", "success") # Tambahkan kategori flash message
            return redirect(url_for('auth.login'))
        except IntegrityError:
            # Jika terjadi IntegrityError (misal, karena UNIQUE constraint failed pada email)
            db.session.rollback() # Sangat penting: Batalkan transaksi yang gagal
            flash("Email sudah terdaftar. Silakan gunakan email lain atau login.", "error")
            return redirect(url_for('auth.register'))
        except Exception as e:
            # Tangkap error lain yang mungkin terjadi selama proses commit
            db.session.rollback()
            flash(f"Terjadi kesalahan tak terduga: {str(e)}", "error")
            return redirect(url_for('auth.register'))

    return render_template('register.html')

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))
