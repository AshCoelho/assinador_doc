
# Assinador de Documentos (Flask + PyMuPDF + PIL) - com segurança integrada (auth.py)
# ------------------------------------------------------------------------------------
import os, textwrap, hashlib
from datetime import datetime, timedelta
from flask import (
    Flask, render_template, request, redirect, url_for, send_file,
    abort, flash, session
)
from werkzeug.utils import secure_filename
import qrcode
from qrcode.constants import ERROR_CORRECT_Q, ERROR_CORRECT_H
from PIL import Image, ImageDraw, ImageFont
import fitz  # PyMuPDF
import re
# ORM
from models import db, User

# Importa segurança
from auth import (
    bp as auth_bp, login_required, admin_required, register_user,
    ensure_csrf, validate_csrf_from_form
)

app = Flask(__name__)

# ------------------ Config de Banco ------------------
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL",
    "postgresql+psycopg://postgres:postgres@localhost:5432/assinador"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Inicializa ORM
db.init_app(app)
with app.app_context():
    db.create_all()

# ------------------ Segurança de sessão/cookies ------------------
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "troque-por-um-valor-grande-e-segredo")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# app.config["SESSION_COOKIE_SECURE"] = True  # em produção com HTTPS
app.permanent_session_lifetime = timedelta(minutes=30)

# Blueprint de autenticação
app.register_blueprint(auth_bp)


# ---------- Filtros/Utils ----------
def fmt_dt(value):
    if not value:
        return ""
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value)
        except ValueError:
            return value
    else:
        dt = value
    return dt.astimezone().strftime("%d/%m/%Y %H:%M:%S")

app.jinja_env.filters["fmt_dt"] = fmt_dt


def sha256_of_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()


def build_verification_url(crc: str) -> str:
    """
    Constrói URL absoluta para o QR.
    Se PUBLIC_BASE_URL estiver setada (ex.: https://seu-dominio.gov.br), usa-a.
    Senão, usa o host da requisição atual (_external=True).
    """
    base = os.environ.get("PUBLIC_BASE_URL")
    if base:
        return f"{base.rstrip('/')}{url_for('verificar', crc=crc)}"
    return url_for('verificar', crc=crc, _external=True)


def make_qr_image(data: str, box_size: int = 6, border: int = 4, strong: bool = True):
    """
    Gera QR nítido (sem borrão), já no tamanho final 50x50.
    """
    qr = qrcode.QRCode(
        version=None,
        error_correction=ERROR_CORRECT_H if strong else ERROR_CORRECT_Q,
        box_size=box_size,
        border=border,
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white").convert("RGB")
    return img.resize((50, 50), resample=Image.NEAREST)


@app.context_processor
def toast_utils():
    def toast_class_for(cat: str) -> str:
        cat = (cat or "").lower()
        if cat in ("danger", "error"):
            return "toast-error"
        if cat == "warning":
            return "toast-warning"
        if cat == "info":
            return "toast-info"
        return "toast-success"
    def toast_icon_for(cat: str) -> str:
        cat = (cat or "").lower()
        if cat in ("danger", "error"):
            return "bi-x-circle-fill"
        if cat == "warning":
            return "bi-exclamation-triangle-fill"
        if cat == "info":
            return "bi-info-circle-fill"
        return "bi-check-circle-fill"
    return dict(toast_class_for=toast_class_for, toast_icon_for=toast_icon_for)


# ---------- Navegação básica ----------
@app.route("/", methods=["GET"])
def home():
    if session.get("user"):
        return redirect(url_for("assinar"))
    return redirect(url_for("auth.login"))


# ---------- CADASTRO (somente admin) ----------
@app.route("/cadastro", methods=["GET", "POST"])
@admin_required
def cadastro():
    if request.method == "GET":
        email_edit = (request.args.get("email") or "").strip().lower()
        usuario_editar = User.query.filter_by(email=email_edit).first() if email_edit else None
        usuarios = [u.to_dict() for u in User.query.order_by(User.nome.asc()).all()]
        return render_template(
            "cadastro.html",
            usuarios=usuarios,
            usuario_editar=usuario_editar.to_dict() if usuario_editar else None
        )

    # POST
    if not validate_csrf_from_form():
        flash("Sessão expirada ou solicitação inválida (CSRF).", "danger")
        return redirect(url_for("cadastro"))

    nome = (request.form.get("nome") or "").strip()
    email = (request.form.get("email") or "").strip().lower()
    cpf = (request.form.get("cpf") or "").strip()
    editar_email = (request.form.get("editar_email") or "").strip().lower()

    try:
        if editar_email and editar_email != email:
            register_user(nome=nome, email=email, cpf=cpf, is_admin=False)
            antigo = User.query.filter_by(email=editar_email).first()
            if antigo:
                db.session.delete(antigo)
                db.session.commit()
            flash("Usuário atualizado com sucesso.", "success")
        else:
            register_user(nome=nome, email=email, cpf=cpf, is_admin=False)
            flash("Usuário salvo com sucesso.", "success")
    except ValueError as e:
        flash(str(e), "danger")

    return redirect(url_for("cadastro"))


@app.route("/editar/<path:email>", methods=["GET"])
@admin_required
def editar(email):
    return redirect(url_for("cadastro", email=email))


@app.route("/excluir/<path:email>", methods=["GET"])
@admin_required
def excluir(email):
    u = User.query.filter_by(email=(email or "").strip().lower()).first()
    if u:
        db.session.delete(u)
        db.session.commit()
        flash("Usuário excluído.", "info")
    else:
        flash("Usuário não encontrado.", "warning")
    return redirect(url_for("cadastro"))


# ---------- ASSINAR DOCUMENTO (somente logado) ----------
@app.route("/assinar", methods=["GET", "POST"])
@login_required
def assinar():
    usr = session.get("user") or {}
    nome = usr.get("nome") or "Desconhecido"
    cpf_masked = usr.get("cpf") or "***********"

    if request.method == "GET":
        return render_template("assinar.html", nome=nome, cpf=cpf_masked)

    # POST
    if not validate_csrf_from_form():
        return render_template("assinar.html", nome=nome, cpf=cpf_masked, erro="❌ CSRF inválido. Recarregue a página.")

    if 'arquivo' not in request.files:
        return render_template("assinar.html", nome=nome, cpf=cpf_masked, erro="❌ Nenhum arquivo enviado.")
    arquivo = request.files['arquivo']
    if not arquivo or arquivo.filename.strip() == '':
        return render_template("assinar.html", nome=nome, cpf=cpf_masked, erro="❌ Arquivo inválido.")

    # Campos extras
    orgao = request.form.get('orgao', '')
    matricula = request.form.get('matricula', '')
    status = request.form.get('status', '')
    cargo = request.form.get('cargo', '')

    # Coordenadas e canvas (o front envia relativas ao canvas real)
    def _float(val, default=0.0):
        try:
            return float(val)
        except Exception:
            return default

    x = _float(request.form.get('x'))
    y = _float(request.form.get('y'))
    w = _float(request.form.get('w'))
    h = _float(request.form.get('h'))
    canvas_w = _float(request.form.get('canvas_w'), 1.0)
    canvas_h = _float(request.form.get('canvas_h'), 1.0)

    # Página (para PDF) — robusto
    try:
        page_num = int(request.form.get('page') or 1)
    except Exception:
        page_num = 1

    # Upload
    nome_arquivo = secure_filename(arquivo.filename)
    extensao = os.path.splitext(nome_arquivo)[1].lower()
    nome_base = os.path.splitext(nome_arquivo)[0]

    os.makedirs('static/arquivos/uploads', exist_ok=True)
    caminho_upload = os.path.join('static/arquivos/uploads', nome_arquivo)
    arquivo.save(caminho_upload)

    # CRC curto baseado no arquivo original (para URL/consulta)
    hash_crc = hashlib.sha256()
    with open(caminho_upload, 'rb') as f:
        hash_crc.update(f.read())
    crc = hash_crc.hexdigest()[:10]

    nome_final = f"assinado_{nome_base}_{crc}{extensao}"
    os.makedirs('static/arquivos/assinados', exist_ok=True)
    caminho_assinado = os.path.join("static/arquivos/assinados", nome_final)

    # QR + brasão (QR pequeno 50x50 e brasão 35x50)
    qr_url = build_verification_url(crc)
    qr_img = make_qr_image(qr_url, box_size=6, border=4, strong=True)  # 50x50 final
    qr_path = f"static/temp_qr_{crc}.png"
    qr_img.save(qr_path, format="PNG")
    brasao_path = "static/brasao/brasao.png"

    try:
        from zoneinfo import ZoneInfo
        _agora = datetime.now(ZoneInfo("America/Fortaleza"))
    except Exception:
        _agora = datetime.now()

    _datahora = _agora.strftime('%d/%m/%Y %H:%M')

    linhas = [
        "Assinado digitalmente por",
        f"{nome}",
        f"{cpf_masked}",
        (f"Matrícula: {matricula}" if matricula else ""),  # mantém ordem mesmo se vazio
        (f"{cargo}" if cargo else ""),
        orgao if orgao else "",
        f"em: {_datahora}",
        f"CRC: {crc}",
    ]

    try:
        if extensao == '.pdf':
            doc = fitz.open(caminho_upload)

            # Garantir página válida
            total = doc.page_count
            if page_num < 1:
                page_num = 1
            if page_num > total:
                page_num = total

            page = doc.load_page(page_num - 1)

            pdf_w = page.rect.width
            pdf_h = page.rect.height

            # Salvaguarda: se canvas_w/h vierem 0 (por alguma razão), evita divisão por zero
            if canvas_w <= 0: canvas_w = pdf_w
            if canvas_h <= 0: canvas_h = pdf_h

            # Escalas: do canvas (frontend) para a página real do PDF
            escala_x = pdf_w / canvas_w
            escala_y = pdf_h / canvas_h

            ponto_x = int(x * escala_x)
            ponto_y = int(y * escala_y)
            ponto_w = max(1, int(w * escala_x))
            ponto_h = max(1, int(h * escala_y))

            
            # ===== Escala pelo tamanho do retângulo (base pensado para A4) =====
            BASE_W = 190.0   # largura útil de referência
            BASE_H = 180.0   # altura útil de referência

            s_w = ponto_w / BASE_W
            s_h = ponto_h / BASE_H
            s = max(0.6, min(4.0, min(s_w, s_h)))  # trava entre 60% e 400%

            # tamanhos em pontos (PDF)
            qr_w = int(round(35 * s))
            qr_h = int(round(35 * s))
            brasao_w = int(round(25 * s))
            brasao_h = int(round(35 * s))
            gap_pt = int(round(6 * s))

            font_size_normal = max(6, int(round(9 * s)))
            font_size_status = max(8, int(round(13 * s)))
            espaco_entre_linhas = max(8, int(round(12 * s)))

            # Centraliza ícones no topo do retângulo
            total_icons_w = qr_w + gap_pt + brasao_w
            x_icones = ponto_x + int((ponto_w - total_icons_w) / 2)
            y_icones = ponto_y + int(round(10 * s))

            #  Moldura debug 
            #page.draw_rect(fitz.Rect(ponto_x, ponto_y, ponto_x + ponto_w, ponto_y + ponto_h),
            #              color=(1, 0, 0), width=max(1, int(round(1*s))))

            # Ícones
            page.insert_image(
                fitz.Rect(x_icones, y_icones, x_icones + qr_w, y_icones + qr_h),
                filename=qr_path
            )
            page.insert_image(
                fitz.Rect(x_icones + qr_w + gap_pt, y_icones,
                        x_icones + qr_w + gap_pt + brasao_w, y_icones + brasao_h),
                filename=brasao_path
            )

            # Texto (logo abaixo dos ícones)
            inicio_y_texto = y_icones + max(qr_h, brasao_h) + int(round(8 * s))

            for linha in linhas:
                if not linha.strip():
                    inicio_y_texto += int(round(5 * s))
                    continue

                if status and linha.strip() == status.strip():
                    largura_status = fitz.get_text_length(linha, fontname="helv", fontsize=font_size_status)
                    x_central = ponto_x + (ponto_w - largura_status) / 2
                    page.insert_text((x_central, inicio_y_texto), linha,
                                    fontsize=font_size_status, fontname="helv", color=(0, 0, 0))
                    inicio_y_texto += font_size_status - int(round(4 * s))
                    continue

                # wrap dinâmico baseado na largura disponível e no tamanho de fonte
                chars_por_linha = max(20, int((ponto_w - 16) / (font_size_normal * 0.6)))
                for sub in textwrap.wrap(linha, width=chars_por_linha):
                    largura_sub = fitz.get_text_length(sub, fontname="helv", fontsize=font_size_normal)
                    x_sub = ponto_x + (ponto_w - largura_sub) / 2
                    page.insert_text((x_sub, inicio_y_texto), sub,
                                    fontsize=font_size_normal, fontname="helv", color=(0, 0, 0))
                    inicio_y_texto += espaco_entre_linhas

                if linha.startswith("Data/Hora:") or linha.startswith("Matrícula:"):
                    inicio_y_texto += int(round(6 * s))



            # Salva
            doc.save(caminho_assinado)
            doc.close()
            if os.path.exists(qr_path):
                os.remove(qr_path)

            # SHA-256 do arquivo final assinado
            sha256_hex = sha256_of_file(caminho_assinado)

            signed_url = f"/static/arquivos/assinados/{nome_final}"
            return render_template(
                "assinar.html", nome=nome, cpf=cpf_masked,
                show_result=True, is_pdf=True, signed_url=signed_url, arquivo=nome_final,
                sha256_hex=sha256_hex
            )

        elif extensao in ['.jpg', '.jpeg', '.png']:
            imagem = Image.open(caminho_upload).convert('RGB')
            largura_real, altura_real = imagem.size

            # Salvaguarda: se canvas_w/h vierem 0
            if canvas_w <= 0: canvas_w = largura_real
            if canvas_h <= 0: canvas_h = altura_real

            draw = ImageDraw.Draw(imagem)
            try:
                fonte = ImageFont.truetype("static/fonts/DejaVuSans.ttf", size=12)
                fonte_b = ImageFont.truetype("static/fonts/DejaVuSans-Bold.ttf", size=18)
            except Exception:
                fonte = ImageFont.load_default()
                fonte_b = ImageFont.load_default()

            # Escalas: do canvas (frontend) para a imagem real
            escala_x = largura_real / canvas_w
            escala_y = altura_real / canvas_h

            x_real = int(x * escala_x)
            y_real = int(y * escala_y)
            w_real = max(1, int(w * escala_x))
            h_real = max(1, int(h * escala_y))

            # Moldura (debug)
            draw.rectangle([x_real, y_real, x_real + w_real, y_real + h_real], outline="red", width=2)

            # Ícones pequenos lado a lado
            qr_rgba = Image.open(qr_path).convert("RGBA")  # 50x50
            brasao = Image.open(brasao_path).resize((35, 50)).convert("RGBA")
            gap_px = 6
            total_icons_w = qr_rgba.width + gap_px + brasao.width
            x_icones = x_real + int((w_real - total_icons_w) / 2)
            y_icones = y_real + 10

            imagem.paste(qr_rgba, (x_icones, y_icones), qr_rgba)
            imagem.paste(brasao, (x_icones + qr_rgba.width + gap_px, y_icones), brasao)

            # Texto
            y_texto = y_icones + max(qr_rgba.height, brasao.height) + 8
            for linha in linhas:
                if not linha.strip():
                    y_texto += fonte.size + 6
                    continue
                if status and linha.strip() == status.strip():
                    bbox = fonte_b.getbbox(linha)
                    largura_status = bbox[2] - bbox[0]
                    x_render = x_real + (w_real - largura_status) // 2
                    draw.text((x_render, y_texto), linha, font=fonte_b, fill=(0, 0, 0))
                    y_texto += (bbox[3] - bbox[1]) + 8
                    continue
                for sub in textwrap.wrap(linha, width=40):
                    bbox = fonte.getbbox(sub)
                    largura_sub = bbox[2] - bbox[0]
                    x_render = x_real + (w_real - largura_sub) // 2
                    draw.text((x_render, y_texto), sub, font=fonte, fill=(0, 0, 0))
                    y_texto += (bbox[3] - bbox[1]) + 2

            imagem.save(caminho_assinado)
            if os.path.exists(qr_path):
                os.remove(qr_path)

            # SHA-256 do arquivo final assinado
            sha256_hex = sha256_of_file(caminho_assinado)

            signed_url = f"/static/arquivos/assinados/{nome_final}"
            return render_template(
                "assinar.html", nome=nome, cpf=cpf_masked,
                show_result=True, is_pdf=False, signed_url=signed_url, arquivo=nome_final,
                sha256_hex=sha256_hex
            )

        else:
            if os.path.exists(qr_path):
                os.remove(qr_path)
            return render_template("assinar.html", nome=nome, cpf=cpf_masked,
                                   erro="❌ Formato não suportado. Envie PDF/JPG/PNG.")

    except Exception as e:
        try:
            if os.path.exists(qr_path):
                os.remove(qr_path)
        except Exception:
            pass
        return render_template("assinar.html", nome=nome, cpf=cpf_masked, erro=f"❌ Erro ao assinar: {e}")


# ---------- Imports/Utils ----------
import os, re, hashlib
from flask import request, render_template, url_for, redirect

def sha256_of_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()

def _validate_csrf_safe() -> bool:
    """Usa sua validate_csrf_from_form() se existir; senão, assume True."""
    try:
        return validate_csrf_from_form()
    except Exception:
        return True

ASSINADOS_DIRNAME = os.path.join('static', 'arquivos', 'assinados')

def _assinados_abs_dir():
    return os.path.join(app.root_path, ASSINADOS_DIRNAME)


# ---------- Menu (verificar.html) ----------
@app.route("/verificar", methods=["GET"], endpoint="verificar")
def verificar_menu():
    return render_template("verificar.html")


# ---------- Validar por CRC (validar_crc.html) ----------
@app.route("/verificar/crc", methods=["GET", "POST"], endpoint="validar_crc")
def validar_crc():
    pasta = _assinados_abs_dir()
    erro = None
    caminho = None
    canonical_sha256 = None
    match = None
    user_sha256 = None

    # CRC vindo por GET (e também no POST quando for comparar)
    crc = (request.values.get("crc") or "").strip().lower()

    # GET: buscar a cópia oficial
    if request.method == "GET":
        if crc:
            # validação simples (ajuste o range se seu CRC tiver tamanho fixo)
            if not re.fullmatch(r"[0-9a-f]{8,64}", crc):
                erro = "CRC inválido. Use apenas caracteres hexadecimais."
            else:
                try:
                    for nome in os.listdir(pasta):
                        if f"_{crc}" in nome:
                            abs_path = os.path.join(pasta, nome)
                            caminho = url_for('static', filename=f'arquivos/assinados/{nome}')
                            canonical_sha256 = sha256_of_file(abs_path)
                            break
                    if not caminho:
                        erro = "Documento não encontrado para o CRC fornecido."
                except FileNotFoundError:
                    erro = "Nenhum documento assinado foi encontrado."

    # POST: comparar upload com a oficial já encontrada
    if request.method == "POST":
        if not _validate_csrf_safe():
            erro = "❌ CSRF inválido. Recarregue a página."
        else:
            # Recarrega dados da oficial, a partir do CRC informado
            if not crc or not re.fullmatch(r"[0-9a-f]{8,64}", crc):
                erro = "CRC inválido. Use apenas caracteres hexadecimais."
            else:
                try:
                    for nome in os.listdir(pasta):
                        if f"_{crc}" in nome:
                            abs_path = os.path.join(pasta, nome)
                            caminho = url_for('static', filename=f'arquivos/assinados/{nome}')
                            canonical_sha256 = sha256_of_file(abs_path)
                            break
                    if not caminho:
                        erro = "Documento não encontrado para o CRC fornecido."
                except FileNotFoundError:
                    erro = "Nenhum documento assinado foi encontrado."

            # Se já temos a oficial, compara
            if not erro and canonical_sha256:
                up = request.files.get("arquivo")
                if not up:
                    erro = "Nenhum arquivo enviado para comparar."
                else:
                    data = up.read()
                    user_sha256 = hashlib.sha256(data).hexdigest()
                    match = (user_sha256 == canonical_sha256)

    return render_template(
        "validar_crc.html",
        crc=crc,
        caminho=caminho,
        canonical_sha256=canonical_sha256,
        match=match,
        user_sha256=user_sha256,
        erro=erro
    )


# ---------- Validar por Upload (validar_upload.html) ----------
@app.route("/verificar/upload", methods=["GET", "POST"], endpoint="validar_upload")
def validar_upload():
    pasta = _assinados_abs_dir()
    erro = None
    caminho = None
    canonical_sha256 = None
    match = None
    user_sha256 = None

    if request.method == "POST":
        if not _validate_csrf_safe():
            erro = "❌ CSRF inválido. Recarregue a página."
        else:
            up = request.files.get("arquivo")
            if not up:
                erro = "Nenhum arquivo enviado."
            else:
                data = up.read()
                user_sha256 = hashlib.sha256(data).hexdigest()

                # Procura algum oficial com o mesmo SHA-256
                try:
                    for nome in os.listdir(pasta):
                        abs_path = os.path.join(pasta, nome)
                        sha = sha256_of_file(abs_path)
                        if sha == user_sha256:
                            match = True
                            canonical_sha256 = sha
                            caminho = url_for('static', filename=f'arquivos/assinados/{nome}')
                            break
                    if match is None:
                        match = False
                except FileNotFoundError:
                    erro = "Nenhum documento assinado foi encontrado."

    return render_template(
        "validar_upload.html",
        caminho=caminho,
        canonical_sha256=canonical_sha256,
        match=match,
        user_sha256=user_sha256,
        erro=erro
    )



# ---------- Download seguro ----------
@app.route('/download/<path:filename>')
@login_required
def download(filename):
    base_dir = os.path.join(app.root_path, 'static', 'arquivos', 'assinados')
    file_path = os.path.normpath(os.path.join(base_dir, filename))
    if not file_path.startswith(base_dir) or not os.path.isfile(file_path):
        return abort(404)
    return send_file(file_path, as_attachment=True, download_name=os.path.basename(file_path))


if __name__ == '__main__':
    app.run(debug=True)
