# auth.py — Autenticação segura (Flask + SQLAlchemy)
import re, time, secrets
from datetime import datetime
from functools import wraps
from flask import Blueprint, request, session, redirect, url_for, flash, current_app, render_template
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User

bp = Blueprint("auth", __name__)

# ----------------------- Config/Helpers -----------------------
_email_re = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_cpf_digits_re = re.compile(r"^\d{11}$")

def is_valid_email(email: str) -> bool:
    return bool(_email_re.match((email or "").strip().lower()))

def normalize_cpf(cpf: str) -> str:
    return re.sub(r"\D", "", cpf or "")

def is_valid_cpf_digits(cpf: str) -> bool:
    return bool(_cpf_digits_re.match(cpf or ""))

def _hash(texto: str) -> str:
    return generate_password_hash(texto, method="pbkdf2:sha256", salt_length=16)

def _check_hash(hashval: str, texto: str) -> bool:
    try:
        return check_password_hash(hashval or "", texto or "")
    except Exception:
        return False

def _now() -> int:
    return int(time.time())

def _cfg(key, default=None):
    defaults = {"MAX_LOGIN_ATTEMPTS": 5, "LOCKOUT_SECONDS": 150}
    return current_app.config.get(key, defaults.get(key, default))

# ----------------------- CSRF -----------------------
def ensure_csrf():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token

def validate_csrf_from_form():
    sess = session.get("csrf_token")
    form = (request.form.get("csrf_token") or "").strip()
    return bool(sess and form and secrets.compare_digest(sess, form))

@bp.app_context_processor
def inject_ctx():
    return {
        "csrf_token": ensure_csrf,
        "current_user": session.get("user"),
        "is_admin": bool(session.get("user", {}).get("is_admin")),
    }

# ----------------------- Rate limit de login -----------------------
_login_attempts = {}

def _key_for_login(email: str) -> str:
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "0.0.0.0").split(",")[0].strip()
    return f"{(email or '').lower()}|{ip}"

def _is_locked(email: str) -> int:
    entry = _login_attempts.get(_key_for_login(email))
    if not entry:
        return 0
    if entry.get("lock_until", 0) > _now():
        return max(0, entry["lock_until"] - _now())
    return 0

def _register_fail(email: str):
    key = _key_for_login(email)
    e = _login_attempts.get(key, {"count": 0, "lock_until": 0})
    e["count"] += 1
    if e["count"] >= _cfg("MAX_LOGIN_ATTEMPTS"):
        e["lock_until"] = _now() + _cfg("LOCKOUT_SECONDS")
        e["count"] = 0
    _login_attempts[key] = e

def _clear_attempts(email: str):
    _login_attempts.pop(_key_for_login(email), None)

# ----------------------- Guards -----------------------
def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not session.get("user"):
            flash("Faça login para continuar.", "warning")
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)
    return wrapper

def admin_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        user = session.get("user")
        if not user:
            flash("Faça login para continuar.", "warning")
            return redirect(url_for("auth.login"))
        if not user.get("is_admin"):
            flash("Acesso restrito a administradores.", "danger")
            return redirect(url_for("assinar"))
        return view(*args, **kwargs)
    return wrapper

# ----------------------- Rotas -----------------------
@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        # evita mensagens antigas aparecendo (ex.: “Login realizado…” depois do logout)
        #session.pop("_flashes", None)
        ensure_csrf()
        return render_template("login.html")

    # POST
    if not validate_csrf_from_form():
        flash("Sessão expirada ou solicitação inválida (CSRF). Tente novamente.", "danger")
        return redirect(url_for("auth.login"))

    email = (request.form.get("email") or "").strip().lower()
    cpf_digits = normalize_cpf(request.form.get("cpf"))

    if not is_valid_email(email) or not is_valid_cpf_digits(cpf_digits):
        flash("E-mail ou CPF incorreto.", "danger")
        return redirect(url_for("auth.login"))

    locked = _is_locked(email)
    if locked > 0:
        mins = (locked + 59) // 60
        flash(f"Tentativas excedidas. Aguarde {mins} min para tentar novamente.", "danger")
        return redirect(url_for("auth.login"))

    u = User.query.filter_by(email=email).first()
    if not u or not _check_hash(u.cpf_hash, cpf_digits):
        _register_fail(email)
        flash("Usuário ou senha inválidos.", "danger")
        return redirect(url_for("auth.login"))

    _clear_attempts(email)
    session.clear()          # previne fixation
    ensure_csrf()          # novo token para sessão autenticada
    session.permanent = True
    session["user"] = {
        "email": u.email,
        "nome": u.nome,
        "cpf": u.cpf_masked,
        "is_admin": bool(u.is_admin),
        "login_at": datetime.utcnow().isoformat() + "Z",
        "orgao": u.orgao,      # <— ESSENCIAL
        "cargo": u.cargo,      # opcional (útil pro carimbo)
        "matricula": u.matricula  # opcional (útil pro carimbo)
    }
    

    # redirecionamento condicional
    next_url = request.args.get("next")
    if not u.is_admin and next_url:
        return redirect(next_url)

    if u.is_admin:
        return redirect(url_for("cadastro"))
    return redirect(url_for("assinar"))

@bp.route("/logout", methods=["POST"])
def logout():
    if not validate_csrf_from_form():
        return redirect(url_for("assinar"))

    # Mostra mensagem APENAS no logout
    flash("Você saiu com segurança.", "info")

    # Limpa dados de auth, mas preserva o flash
    session.pop("user", None)
    session.pop("csrf_token", None)
    ensure_csrf()  # novo CSRF anônimo

    return redirect(url_for("auth.login"))

# ----------------------- Cadastro/Atualização -----------------------
def register_user(nome: str, email: str, cpf: str, is_admin=False):
    email = (email or "").strip().lower()
    cpf_digits = normalize_cpf(cpf)

    if not is_valid_email(email):
        raise ValueError("E-mail inválido.")
    if not is_valid_cpf_digits(cpf_digits):
        raise ValueError("CPF inválido: forneça 11 dígitos.")

    masked = f"{cpf_digits[:3]}.{cpf_digits[3:6]}.{cpf_digits[6:9]}-{cpf_digits[9:]}"
    u = User.query.filter_by(email=email).first()

    if u is None:
        u = User(
            email=email,
            nome=(nome or "").strip(),
            cpf_hash=_hash(cpf_digits),
            cpf_masked=masked,
            is_admin=bool(is_admin),
        )
        db.session.add(u)
    else:
        u.nome = (nome or "").strip()
        u.cpf_hash = _hash(cpf_digits)
        u.cpf_masked = masked
        u.is_admin = bool(is_admin)

    db.session.commit()
    return u
