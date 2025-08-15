# Assinador de Documentos (Flask + PyMuPDF + PIL) - com segurança integrada (auth.py)
# ------------------------------------------------------------------------------------
import os, textwrap, hashlib
from datetime import datetime, timedelta
from flask import (
    Flask, render_template, request, redirect, url_for, send_file,
    abort, flash, session
)
from werkzeug.utils import secure_filename
from datetime import datetime
import qrcode
from PIL import Image, ImageDraw, ImageFont
import fitz  # PyMuPDF
# ORM
from models import db, User

# Importa segurança
from auth import (
    bp as auth_bp, login_required, admin_required, register_user,
    ensure_csrf, validate_csrf_from_form
)

app = Flask(__name__)

# ------------------ Config de Banco ------------------
# URL do Postgres (use variável de ambiente em produção)
# psycopg3: postgresql+psycopg://usuario:senha@host:5432/nome_db
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL",
    "postgresql+psycopg://postgres:postgres@localhost:5432/assinador"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Inicializa ORM
db.init_app(app)

# Cria tabelas (para começar rápido; em produção, use Alembic)
with app.app_context():
    db.create_all()

# ------------------ Segurança de sessão/cookies ------------------
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "troque-por-um-valor-grande-e-segredo")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# Em produção com HTTPS:
# app.config["SESSION_COOKIE_SECURE"] = True

app.permanent_session_lifetime = timedelta(minutes=30)

# Blueprint de autenticação (/login, /logout)
app.register_blueprint(auth_bp)

def fmt_dt(value):
    if not value:
        return ""
    # aceita tanto datetime quanto string ISO
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value)
        except ValueError:
            return value  # se não for ISO, mostra como veio
    else:
        dt = value
    # usa o fuso local da máquina
    return dt.astimezone().strftime("%d/%m/%Y %H:%M:%S")

app.jinja_env.filters["fmt_dt"] = fmt_dt

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
    # Se logado, manda para assinar; senão, tela de login do blueprint
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

    # POST (criar/atualizar) – exige CSRF
    if not validate_csrf_from_form():
        flash("Sessão expirada ou solicitação inválida (CSRF).", "danger")
        return redirect(url_for("cadastro"))

    nome = (request.form.get("nome") or "").strip()
    email = (request.form.get("email") or "").strip().lower()
    cpf = (request.form.get("cpf") or "").strip()
    editar_email = (request.form.get("editar_email") or "").strip().lower()

    try:
        # Se está editando e trocou o e-mail: cria/atualiza novo e apaga o antigo
        if editar_email and editar_email != email:
            register_user(nome=nome, email=email, cpf=cpf, is_admin=False)
            antigo = User.query.filter_by(email=editar_email).first()
            if antigo:
                db.session.delete(antigo)
                db.session.commit()
            flash("Usuário atualizado com sucesso.", "success")
        else:
            # Cria/atualiza no mesmo e-mail
            register_user(nome=nome, email=email, cpf=cpf, is_admin=False)
            flash("Usuário salvo com sucesso.", "success")

    except ValueError as e:
        flash(str(e), "danger")

    return redirect(url_for("cadastro"))


@app.route("/editar/<path:email>", methods=["GET"])
@admin_required
def editar(email):
    # Redireciona para cadastro com parâmetro de edição
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
    # Dados do usuário vindos da sessão segura
    usr = session.get("user") or {}
    nome = usr.get("nome") or "Desconhecido"
    cpf_masked = usr.get("cpf") or "***********"

    if request.method == "GET":
        return render_template("assinar.html", nome=nome, cpf=cpf_masked)

    # POST – exige CSRF
    if not validate_csrf_from_form():
        return render_template("assinar.html", nome=nome, cpf=cpf_masked, erro="❌ CSRF inválido. Recarregue a página.")

    # 1) Arquivo
    if 'arquivo' not in request.files:
        return render_template("assinar.html", nome=nome, cpf=cpf_masked, erro="❌ Nenhum arquivo enviado.")
    arquivo = request.files['arquivo']
    if not arquivo or arquivo.filename.strip() == '':
        return render_template("assinar.html", nome=nome, cpf=cpf_masked, erro="❌ Arquivo inválido.")

    # 2) Campos extras
    orgao = request.form.get('orgao', '')
    setor = request.form.get('setor', '')
    status = request.form.get('status', '')
    processo = request.form.get('processo', '')

    try:
        x = float(request.form.get('x') or 0)
        y = float(request.form.get('y') or 0)
        w = float(request.form.get('w') or 0)
        h = float(request.form.get('h') or 0)
        canvas_w = float(request.form.get('canvas_w') or 1)
        canvas_h = float(request.form.get('canvas_h') or 1)
    except Exception:
        return render_template("assinar.html", nome=nome, cpf=cpf_masked, erro="❌ Coordenadas inválidas.")

    center_h = (request.form.get('center_h') in ('on', 'true', '1'))
    center_v = (request.form.get('center_v') in ('on', 'true', '1'))

    # 3) Upload
    nome_arquivo = secure_filename(arquivo.filename)
    extensao = os.path.splitext(nome_arquivo)[1].lower()
    nome_base = os.path.splitext(nome_arquivo)[0]

    os.makedirs('static/arquivos/uploads', exist_ok=True)
    caminho_upload = os.path.join('static/arquivos/uploads', nome_arquivo)
    arquivo.save(caminho_upload)

    # 4) CRC e saída
    hash_crc = hashlib.sha256()
    with open(caminho_upload, 'rb') as f:
        hash_crc.update(f.read())
    crc = hash_crc.hexdigest()[:10]

    nome_final = f"assinado_{nome_base}_{crc}{extensao}"
    os.makedirs('static/arquivos/assinados', exist_ok=True)
    caminho_assinado = os.path.join("static/arquivos/assinados", nome_final)

    # 5) QR + brasão
    # (Se já usa domínio público, troque pelo URL público)
    qr_url = f"http://127.0.0.1:5000/verificar?crc={crc}"
    qr_img = qrcode.make(qr_url).resize((50, 50))
    qr_path = f"static/temp_qr_{crc}.png"
    qr_img.save(qr_path)
    brasao_path = "static/brasao/brasao.png"

    # 6) Texto do carimbo
    linhas = [
        "Assinado digitalmente por",
        f"{nome} ({cpf_masked})",
        f"em: {datetime.now().strftime('%d/%m/%Y %H:%M')}",
        orgao if orgao else "",
        f"Setor: {setor}" if setor else "",
        status,
        f"Processo: {processo}",
        f"CRC: {crc}"
    ]

    try:
        if extensao == '.pdf':
            doc = fitz.open(caminho_upload)
            page = doc[-1]  # última página

            pdf_w = page.rect.width
            pdf_h = page.rect.height

            escala_x = pdf_w / max(canvas_w, 1)
            escala_y = pdf_h / max(canvas_h, 1)

            ponto_x = int(x * escala_x)
            ponto_y = int(y * escala_y)
            ponto_w = int(max(w, 1) * escala_x)
            ponto_h = int(max(h, 1) * escala_y)

            # Se centralizar, sobrescreve X/Y
            if center_h:
                ponto_x = max(0, int((pdf_w - ponto_w) / 2))
            if center_v:
                ponto_y = max(0, int((pdf_h - ponto_h) / 2))

            # Moldura (debug)
            page.draw_rect(
                fitz.Rect(ponto_x, ponto_y, ponto_x + ponto_w, ponto_y + ponto_h),
                color=(1, 0, 0), width=1
            )

            # Ícones
            x_icones = ponto_x + int((ponto_w - 110) / 2)
            page.insert_image(
                fitz.Rect(x_icones, ponto_y + 10, x_icones + 50, ponto_y + 60),
                filename=qr_path
            )
            page.insert_image(
                fitz.Rect(x_icones + 60, ponto_y + 10, x_icones + 110, ponto_y + 60),
                filename=brasao_path
            )

            # Texto
            inicio_y_texto = ponto_y + 70
            font_size_normal = 9
            font_size_status = 14
            espaco_entre_linhas = 12

            for linha in linhas:
                if not linha.strip():
                    inicio_y_texto += 5
                    continue
                if linha.strip() == status:
                    largura_status = fitz.get_text_length(linha, fontname="helv", fontsize=font_size_status)
                    x_central = ponto_x + (ponto_w - largura_status) / 2
                    page.insert_text(
                        (x_central, inicio_y_texto),
                        linha, fontsize=font_size_status, fontname="helv", color=(0, 0, 0)
                    )
                    inicio_y_texto += font_size_status - 4
                    continue

                espacamento_extra = 6 if linha.startswith("em:") or linha.startswith("Setor:") else 0
                for sub in textwrap.wrap(linha, width=40):
                    largura_sub = fitz.get_text_length(sub, fontname="helv", fontsize=font_size_normal)
                    x_sub = ponto_x + (ponto_w - largura_sub) / 2
                    page.insert_text(
                        (x_sub, inicio_y_texto),
                        sub, fontsize=font_size_normal, fontname="helv", color=(0, 0, 0)
                    )
                    inicio_y_texto += espaco_entre_linhas
                inicio_y_texto += espacamento_extra

            doc.save(caminho_assinado)
            doc.close()
            if os.path.exists(qr_path):
                os.remove(qr_path)

            signed_url = f"/static/arquivos/assinados/{nome_final}"
            return render_template(
                "assinar.html", nome=nome, cpf=cpf_masked,
                show_result=True, is_pdf=True, signed_url=signed_url, arquivo=nome_final
            )

        elif extensao in ['.jpg', '.jpeg', '.png']:
            imagem = Image.open(caminho_upload).convert('RGB')
            largura_real, altura_real = imagem.size

            draw = ImageDraw.Draw(imagem)
            fonte = ImageFont.truetype("static/fonts/DejaVuSans.ttf", size=12)
            brasao = Image.open(brasao_path).resize((35, 50)).convert("RGBA")

            escala_x = largura_real / max(canvas_w, 1)
            escala_y = altura_real / max(canvas_h, 1)

            x_real = int(x * escala_x)
            y_real = int(y * escala_y)
            w_real = int(max(w, 1) * escala_x)
            h_real = int(max(h, 1) * escala_y)

            if center_h:
                x_real = max(0, int((largura_real - w_real) / 2))
            if center_v:    
                y_real = max(0, int((altura_real - h_real) / 2))

            # Moldura (debug)
            draw.rectangle([x_real, y_real, x_real + w_real, y_real + h_real], outline="red", width=2)

            # Ícones
            x_icones = x_real + int((w_real - 110) / 2)
            qr_rgba = qrcode.make(f"http://127.0.0.1:5000/verificar?crc={crc}").resize((50, 50)).convert("RGBA")
            imagem.paste(qr_rgba, (x_icones, y_real + 10), qr_rgba)
            imagem.paste(brasao, (x_icones + 60, y_real + 5), brasao)

            # Texto
            y_texto = y_real + 60
            for linha in linhas:
                if not linha.strip():
                    y_texto += fonte.size + 6
                    continue
                if linha.strip() == status:
                    fonte_status = ImageFont.truetype("static/fonts/DejaVuSans-Bold.ttf", size=18)
                    bbox = fonte_status.getbbox(linha)
                    largura_status = bbox[2] - bbox[0]
                    x_render = x_real + (w_real - largura_status) // 2
                    draw.text((x_render, y_texto), linha, font=fonte_status, fill=(0, 0, 0))
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

            signed_url = f"/static/arquivos/assinados/{nome_final}"
            return render_template(
                "assinar.html", nome=nome, cpf=cpf_masked,
                show_result=True, is_pdf=False, signed_url=signed_url, arquivo=nome_final
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


# ---------- Verificação por CRC ----------
@app.route("/verificar", methods=["GET", "POST"])
def verificar():
    caminho = None
    erro = None

    # POST – exige CSRF
    if request.method == "POST":
        if not validate_csrf_from_form():
            erro = "❌ CSRF inválido. Recarregue a página."
        else:
            crc = (request.form.get("crc") or "").strip()
            pasta = 'static/arquivos/assinados'
            try:
                for nome in os.listdir(pasta):
                    if f"_{crc}" in nome:
                        caminho = f"/{pasta}/{nome}"
                        break
                if not caminho:
                    erro = "Documento não encontrado para o CRC fornecido."
            except FileNotFoundError:
                erro = "Nenhum documento assinado foi encontrado."
    else:
        # GET com ?crc=xxxx
        crc = (request.args.get("crc") or "").strip()
        if crc:
            pasta = 'static/arquivos/assinados'
            try:
                for nome in os.listdir(pasta):
                    if f"_{crc}" in nome:
                        caminho = f"/{pasta}/{nome}"
                        break
                if not caminho:
                    erro = "Documento não encontrado para o CRC fornecido."
            except FileNotFoundError:
                erro = "Nenhum documento assinado foi encontrado."

    return render_template('verificar.html', caminho=caminho, erro=erro)


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


