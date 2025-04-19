from flask import Flask, render_template, request, redirect, url_for, session, flash, g, make_response,jsonify,json,request
from models import db, Usuario, Feedback, NotaPermitida, ConfiguracaoAvaliacao, Resposta, AcaoCorretiva, Avaliacao, AvaliacaoItem, Setor, Habilidades, CategoriaHabilidade
from datetime import datetime,timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from weasyprint import HTML
from io import BytesIO
from collections import defaultdict
from flask_mail import Mail, Message
from dotenv import load_dotenv
import matplotlib
matplotlib.use('Agg')  # Usar backend não interativo
import matplotlib.pyplot as plt
import seaborn as sns
import os,  base64,  logging,  secrets,  urllib.parse, requests


# Carregar variáveis de ambiente
load_dotenv()

# Configurar logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:masterkey@localhost:5432/feedbacks'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'chave_secreta_super_segura'
XAI_API_KEY = os.getenv('XAI_API_KEY')

if not XAI_API_KEY:
    raise ValueError("XAI_API_KEY não configurada no ambiente.")

db.init_app(app)  # importante!

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'nayhanbsb@gmail.com'
app.config['MAIL_PASSWORD'] = 'txkt aiqx qqvk vjdr'
mail = Mail(app)

# ROTA PARA GERENCIAR HABILIDADES
@app.route('/habilidades', methods=['GET', 'POST'])
def gerenciar_habilidades():
    if 'usuario_id' not in session or not g.usuario_logado.is_admin:
        return redirect(url_for('login'))

    # Lidar com cadastro de categoria
    if request.method == 'POST' and 'nova_categoria' in request.form:
        nome_categoria = request.form['nova_categoria'].strip()
        if nome_categoria:
            if CategoriaHabilidade.query.filter_by(nome=nome_categoria, setor_id=g.usuario_logado.setor_id).first():
                flash('Já existe uma categoria com este nome neste setor.', 'warning')
            else:
                nova_categoria = CategoriaHabilidade(
                    nome=nome_categoria,
                    setor_id=g.usuario_logado.setor_id,
                    usuario_id=g.usuario_logado.id,
                    ativa=True
                )
                db.session.add(nova_categoria)
                db.session.commit()
                flash('Categoria adicionada com sucesso!', 'success')
        else:
            flash('Nome da categoria é obrigatório.', 'danger')
        return redirect(url_for('gerenciar_habilidades'))

    # Lidar com cadastro de habilidade
    if request.method == 'POST' and 'nome_habilidade' in request.form:
        nome_habilidade = request.form['nome_habilidade'].strip()
        categoria_id = request.form['categoria_id']
        if nome_habilidade and categoria_id:
            if Habilidades.query.filter_by(nome=nome_habilidade, categoria_id=categoria_id).first():
                flash('Já existe uma habilidade com este nome nesta categoria.', 'warning')
            else:
                nova_habilidade = Habilidades(
                    nome=nome_habilidade,
                    categoria_id=categoria_id,
                    ativa=True
                )
                db.session.add(nova_habilidade)
                db.session.commit()
                flash('Habilidade adicionada com sucesso!', 'success')
        else:
            flash('Nome da habilidade e categoria são obrigatórios.', 'danger')
        return redirect(url_for('gerenciar_habilidades'))

    # Consultar todas as categorias ativas do setor
    categorias = CategoriaHabilidade.query.filter_by(setor_id=g.usuario_logado.setor_id, ativa=True).order_by(CategoriaHabilidade.nome).all()

    # Consultar habilidades ativas, incluindo apenas categorias ativas do setor
    habilidades = Habilidades.query.filter_by(ativa=True).join(CategoriaHabilidade).filter(
        CategoriaHabilidade.setor_id == g.usuario_logado.setor_id,
        CategoriaHabilidade.ativa == True
    ).order_by(Habilidades.nome).all()

    # Agrupar habilidades por categoria e incluir todas as categorias
    habilidades_por_categoria = defaultdict(list)
    for habilidade in habilidades:
        habilidades_por_categoria[habilidade.categoria].append(habilidade)
    
    # Adicionar categorias sem habilidades
    for categoria in categorias:
        if categoria not in habilidades_por_categoria:
            habilidades_por_categoria[categoria] = []

    return render_template(
        'habilidades.html',
        habilidades_por_categoria=habilidades_por_categoria,
        categorias=categorias,
        usuario=g.usuario_logado
    )

@app.route('/habilidade/<int:id>/editar', methods=['GET', 'POST'])
def editar_habilidade(id):
    if 'usuario_id' not in session:
        return redirect(url_for('login'))

    habilidade = Habilidades.query.get_or_404(id)
    categorias = CategoriaHabilidade.query.filter_by(setor_id=g.usuario_logado.setor_id).all()

    if request.method == 'POST':
        habilidade.nome = request.form['nome']
        habilidade.categoria_id = request.form['categoria_id']
        db.session.commit()
        flash('Habilidade atualizada com sucesso!', 'success')
        return redirect(url_for('gerenciar_habilidades'))

    return render_template('editar_habilidade.html', habilidade=habilidade, categorias=categorias, usuario=g.usuario_logado)


@app.route('/habilidade/<int:id>/excluir', methods=['POST'])
def excluir_habilidade(id):
    if 'usuario_id' not in session:
        return redirect(url_for('login'))

    habilidade = Habilidades.query.get_or_404(id)
    db.session.delete(habilidade)
    db.session.commit()
    flash('Habilidade excluída com sucesso!', 'success')
    return redirect(url_for('gerenciar_habilidades'))

@app.route('/habilidade/<int:id>/toggle', methods=['POST'])
def toggle_habilidade(id):
    if 'usuario_id' not in session:
        return redirect(url_for('login'))

    habilidade = Habilidades.query.get_or_404(id)
    habilidade.ativa = not habilidade.ativa
    db.session.commit()
    return redirect(url_for('gerenciar_habilidades'))


@app.route('/categoria/<int:id>/excluir', methods=['POST'])
def excluir_categoria(id):
    if 'usuario_id' not in session or not g.usuario_logado.is_admin:
        return redirect(url_for('login'))

    categoria = CategoriaHabilidade.query.get_or_404(id)
    # Verificar permissões
    if categoria.setor_id != g.usuario_logado.setor_id:
        flash('Você não tem permissão para excluir esta categoria.', 'danger')
        return redirect(url_for('gerenciar_habilidades'))

    # Excluir habilidades associadas (opcional, dependendo da lógica de negócio)
    Habilidades.query.filter_by(categoria_id=categoria.id).delete()

    db.session.delete(categoria)
    db.session.commit()
    flash('Categoria e habilidades associadas excluídas com sucesso!', 'success')
    return redirect(url_for('gerenciar_habilidades'))

# ROTAS
# ROTA PARA CADASTRAR USUÁRIO
@app.route('/usuarios/cadastrar', methods=['GET', 'POST'])
def cadastrar_usuario():
    if 'usuario_id' not in session:
        return redirect(url_for('login'))

    setores = Setor.query.order_by(Setor.nome).all()

    if request.method == 'POST':
        nome = request.form['nome']
        email = request.form['email']
        senha = request.form['senha']
        cargo = request.form['cargo']
        setor_id = request.form['setor']
        is_admin = 'is_admin' in request.form

        if Usuario.query.filter_by(email=email).first():
            flash('E-mail já cadastrado.', 'warning')
        else:
            novo = Usuario(
                nome=nome,
                email=email,
                senha_hash=generate_password_hash(senha),
                cargo=cargo,
                setor_id=setor_id,
                is_admin=is_admin
            )
            db.session.add(novo)
            db.session.commit()
            flash('Usuário cadastrado com sucesso!', 'success')
            return redirect(url_for('listar_usuarios'))

    return render_template('cadastrar_usuario.html', setores=setores, usuario=g.usuario_logado)


@app.route('/usuarios')
def listar_usuarios():
    if 'usuario_id' not in session or not g.usuario_logado.is_admin:
        return redirect(url_for('login'))

    nome = request.args.get('nome', '').strip()
    setor = request.args.get('setor', '').strip()

    query = Usuario.query

    if nome:
        query = query.filter(Usuario.nome.ilike(f"%{nome}%"))
    if setor:
        query = query.join(Setor).filter(Setor.nome == setor)

    usuarios = query.order_by(Usuario.nome).all()
    setores = Setor.query.order_by(Setor.nome).all()

    return render_template('usuarios.html', usuarios=usuarios, setores=setores, usuario=g.usuario_logado)


@app.route('/usuario/<int:id>/excluir')
def excluir_usuario(id):
    if 'usuario_id' not in session or not g.usuario_logado.is_admin:
        return redirect(url_for('login'))

    usuario = Usuario.query.get_or_404(id)
    db.session.delete(usuario)
    db.session.commit()
    flash('Usuário excluído com sucesso.', 'success')
    return redirect(url_for('listar_usuarios'))

@app.route('/usuario/<int:id>/editar', methods=['GET', 'POST'])
def editar_usuario(id):
    if 'usuario_id' not in session or not g.usuario_logado.is_admin:
        return redirect(url_for('login'))

    usuario = Usuario.query.get_or_404(id)
    setores = Setor.query.order_by(Setor.nome).all()

    if request.method == 'POST':
        usuario.nome = request.form['nome']
        usuario.email = request.form['email']
        usuario.cargo = request.form['cargo']
        usuario.setor_id = request.form['setor']
        usuario.is_admin = 'is_admin' in request.form

   # Atualizar senha se fornecida
        nova_senha = request.form.get('nova_senha')
        confirmar_senha = request.form.get('confirmar_senha')
        
        if nova_senha and confirmar_senha:
            if nova_senha != confirmar_senha:
                flash('As senhas não coincidem!', 'danger')
            elif len(nova_senha) < 6:
                flash('A senha deve ter pelo menos 6 caracteres', 'danger')
            else:
                usuario.senha_hash = generate_password_hash(nova_senha)
                flash('Senha alterada com sucesso!', 'success')



        db.session.commit()
        flash('Dados do usuário atualizados com sucesso.', 'success')
        return redirect(url_for('listar_usuarios'))

    return render_template('editar_usuario.html', usuario_editado=usuario, setores=setores, usuario=g.usuario_logado)

@app.route('/recuperar-senha', methods=['GET', 'POST'])
def recuperar_senha():
    if request.method == 'POST':
        email = request.form['email'].strip()
        logger.debug(f"Solicitação de recuperação de senha para e-mail: {email}")
        usuario = Usuario.query.filter_by(email=email).first()

        if not usuario:
            logger.warning(f"E-mail não encontrado: {email}")
            flash('E-mail não encontrado.', 'danger')
            return redirect(url_for('recuperar_senha'))

        try:
            # Gerar token e definir expiração
            token = secrets.token_urlsafe(32)
            usuario.reset_token = token
            usuario.reset_token_expiry = datetime.utcnow() + timedelta(minutes=30)
            db.session.commit()
            logger.debug(f"Token salvo para {email}: {token}")
            logger.debug(f"Expiração do token: {usuario.reset_token_expiry}")

            # Gerar URL de redefinição
            reset_url = url_for('redefinir_senha', token=urllib.parse.quote(token), _external=True)
            logger.info(f"URL de redefinição gerada: {reset_url}")

            # Renderizar template HTML
            html_content = render_template(
                'email/recuperacao_senha.html',
                nome_usuario=usuario.nome,
                reset_url=reset_url,
                expiracao=30,
                ano_atual=datetime.utcnow().year
            )
            logger.debug(f"Template de e-mail renderizado com sucesso para {email}")
            # Configurar e-mail
            msg = Message(
                subject='Redefinição de Senha',
                sender=app.config['MAIL_USERNAME'],
                recipients=[email]
            )
            msg.body = f'Olá, {usuario.nome or "Usuário"},\n\nPara redefinir sua senha, clique no link: {reset_url}\nO link expira em 30 minutos.\n\nSe não solicitou a redefinição, ignore este e-mail.\n\nAtenciosamente,\nSua Empresa'
            msg.html = html_content

            # Enviar e-mail
            try:
                mail.send(msg)
                logger.info(f"E-mail enviado para {email}")
            except Exception as e:
                logger.error(f"Erro ao enviar e-mail: {str(e)}")
                flash('Erro ao enviar e-mail. Tente novamente.', 'danger')
                return redirect(url_for('recuperar_senha'))

            flash('Instruções para redefinir sua senha foram enviadas para o seu e-mail.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            logger.error(f"Erro ao salvar token para {email}: {str(e)}")
            db.session.rollback()
            flash('Erro ao processar a solicitação. Tente novamente.', 'danger')
            return redirect(url_for('recuperar_senha'))

    return render_template('recuperar_senha.html')

@app.route('/redefinir-senha/<token>', methods=['GET', 'POST'])
def redefinir_senha(token):
    logger.debug(f"Acessando redefinição de senha com token: {token}")
    usuario = Usuario.query.filter_by(reset_token=token).first()

    if not usuario:
        logger.warning(f"Token não encontrado: {token}")
        flash('Token inválido ou não encontrado.', 'danger')
        return redirect(url_for('login'))

    if usuario.reset_token_expiry < datetime.utcnow():
        logger.warning(f"Token expirado para e-mail: {usuario.email}")
        usuario.reset_token = None
        usuario.reset_token_expiry = None
        db.session.commit()
        flash('O token de recuperação expirou.', 'danger')
        return redirect(url_for('login'))

    logger.debug(f"Token válido para e-mail: {usuario.email}")
    if request.method == 'POST':
        nova_senha = request.form['nova_senha']
        confirmar_senha = request.form['confirmar_senha']

        if nova_senha != confirmar_senha:
            logger.warning(f"Senhas não coincidem para e-mail: {usuario.email}")
            flash('As senhas não coincidem.', 'danger')
            return render_template('redefinir_senha.html', token=token)

        if len(nova_senha) < 6:
            logger.warning(f"Senha muito curta para e-mail: {usuario.email}")
            flash('A senha deve ter pelo menos 6 caracteres.', 'danger')
            return render_template('redefinir_senha.html', token=token)

        try:
            usuario.senha_hash = generate_password_hash(nova_senha)
            usuario.reset_token = None
            usuario.reset_token_expiry = None
            db.session.commit()
            logger.info(f"Senha redefinida com sucesso para e-mail: {usuario.email}")
            flash('Senha redefinida com sucesso! Faça login com a nova senha.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            logger.error(f"Erro ao redefinir senha para {usuario.email}: {str(e)}")
            db.session.rollback()
            flash('Erro ao redefinir a senha. Tente novamente.', 'danger')
            return render_template('redefinir_senha.html', token=token)

    return render_template('redefinir_senha.html', token=token)

# ... (outras rotas mantidas inalteradas, como exportar_relatorio_completo, login, etc.)

@app.before_request
def carregar_usuario_logado():
    g.usuario_logado = None
    if 'usuario_id' in session:
        g.usuario_logado = Usuario.query.get(session['usuario_id'])


# ROTAS
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        senha = request.form['senha']
        usuario = Usuario.query.filter_by(email=email).first()

        if usuario and usuario.verificar_senha(senha):
            session['usuario_id'] = usuario.id
            session['usuario_nome'] = usuario.nome
            flash('Login realizado com sucesso!', 'success')
            if usuario.is_admin:
                return redirect(url_for('dashboard_colaboradores'))
            else:
                return redirect(url_for('avaliar_funcionario'))
        else:
            flash('Credenciais inválidas.', 'danger')

    return render_template('login.html')


@app.route('/bibliotecas')
def bibliotecas():
    return render_template('bibliotecas.html', usuario=g.usuario_logado)


@app.route('/relatorio/completo')
def exportar_relatorio_completo():
    if 'usuario_id' not in session or not g.usuario_logado.is_admin:
        return redirect(url_for('login'))

    # Obter filtros
    setor_filtro = request.args.get('setor')
    nome_filtro = request.args.get('nome', '').strip()
    media_min = request.args.get('media_min', type=float)
    media_max = request.args.get('media_max', type=float)

    # Consultar usuários com filtros
    query_usuarios = Usuario.query.filter(Usuario.is_admin == False)
    if setor_filtro:
        query_usuarios = query_usuarios.join(Setor).filter(Setor.nome == setor_filtro)
    if nome_filtro:
        query_usuarios = query_usuarios.filter(Usuario.nome.ilike(f"%{nome_filtro}%"))

    funcionarios = query_usuarios.all()
    dados_dashboard = []
    funcionario_ids = []
    for f in funcionarios:
        avaliacoes = Avaliacao.query.filter_by(id_funcionario=f.id).all()
        total = len(avaliacoes)
        if total == 0:  # Excluir funcionários sem avaliações
            continue

        if total > 0:
            notas = AvaliacaoItem.query.join(Avaliacao, AvaliacaoItem.id_avaliacao == Avaliacao.id)
            notas = notas.filter(Avaliacao.id_funcionario == f.id)
            media_geral = round(sum(i.nota for i in notas) / notas.count(), 2)
        else:
            media_geral = 0

        # Aplicar filtros de média
        if (media_min is not None and media_geral < media_min) or (media_max is not None and media_geral > media_max):
            continue

        dados_dashboard.append({
            'nome': f.nome,
            'cargo': f.cargo,
            'setor': f.setor.nome if f.setor else '',
            'total_avaliacoes': total,
            'media_geral': media_geral
        })
        funcionario_ids.append(f.id)

    # Consultar avaliações apenas dos funcionários filtrados
    avaliacoes = Avaliacao.query.filter(Avaliacao.id_funcionario.in_(funcionario_ids)).order_by(Avaliacao.data_avaliacao.desc()).all()
    dados_avaliacoes = []
    for av in avaliacoes:
        funcionario = Usuario.query.get(av.id_funcionario)
        avaliador = Usuario.query.get(av.id_avaliador)
        itens = AvaliacaoItem.query.filter_by(id_avaliacao=av.id).all()

        dados_avaliacoes.append({
            'id': av.id,
            'funcionario': funcionario.nome if funcionario else 'Desconhecido',
            'avaliador': avaliador.nome if avaliador else 'Desconhecido',
            'data': av.data_avaliacao.strftime('%d/%m/%Y'),
            'observacoes': av.observacoes,
            'itens': itens
        })

    # Resumo de habilidades apenas para avaliações filtradas
    resumo = defaultdict(lambda: {'total': 0, 'soma': 0, 'categoria': ''})
    for av in avaliacoes:
        itens = AvaliacaoItem.query.filter_by(id_avaliacao=av.id).all()
        for item in itens:
            key = item.nome_habilidade
            resumo[key]['total'] += 1
            resumo[key]['soma'] += item.nota
            resumo[key]['categoria'] = item.categoria

    resumo_habilidades = [
        {
            'nome_habilidade': nome,
            'categoria': dados['categoria'],
            'media': round(dados['soma'] / dados['total'], 2) if dados['total'] > 0 else 0,
            'total': dados['total']
        }
        for nome, dados in resumo.items()
    ]

    # Criar diretório temporário no projeto
    temp_dir = os.path.join(os.path.dirname(__file__), 'static', 'temp')
    try:
        os.makedirs(temp_dir, exist_ok=True)
        logger.debug(f"Diretório temporário criado/acessado: {temp_dir}")
    except Exception as e:
        logger.error(f"Erro ao criar diretório temporário: {str(e)}")
        flash('Erro ao configurar diretório temporário. Contate o administrador.', 'danger')
        return redirect(url_for('dashboard_colaboradores'))

    bar_chart_path = os.path.join(temp_dir, 'bar_chart.png')
    pie_chart_path = os.path.join(temp_dir, 'pie_chart.png')
    bar_chart_base64 = None
    pie_chart_base64 = None

    # Gerar gráficos
    try:
        if dados_dashboard:
            logger.debug(f"Gerando gráficos para {len(dados_dashboard)} colaboradores")
            # Gráfico de barras (Média por Colaborador)
            nomes = [d['nome'] for d in dados_dashboard]
            medias = [d['media_geral'] for d in dados_dashboard]

            plt.figure(figsize=(10, max(6, len(nomes) * 0.4)))
            ax = sns.barplot(x=medias, y=nomes, color='#0d6efd')
            plt.xlabel('Média Geral')
            plt.ylabel('Colaborador')
            plt.xlim(0, 5)
            for i, v in enumerate(medias):
                ax.text(v + 0.1, i, f'{v:.2f}', va='center')
            plt.tight_layout()
            plt.savefig(bar_chart_path, format='png', dpi=150)
            plt.close()
            logger.debug(f"Gráfico de barras salvo em: {bar_chart_path}")

            # Converter para base64
            with open(bar_chart_path, 'rb') as f:
                bar_chart_base64 = base64.b64encode(f.read()).decode('utf-8')
            logger.debug(f"Gráfico de barras convertido para base64 ({len(bar_chart_base64)} bytes)")

            # Gráfico de pizza (Distribuição)
            faixas = [
                len([d for d in dados_dashboard if d['media_geral'] <= 2]),
                len([d for d in dados_dashboard if 2 < d['media_geral'] < 4]),
                len([d for d in dados_dashboard if d['media_geral'] >= 4])
            ]
            logger.debug(f"Faixas do gráfico de pizza: {faixas}")
            if sum(faixas) > 0:  # Verificar se há dados para o gráfico
                labels = ['1-2 Estrelas', '2.5-3.5 Estrelas', '4-5 Estrelas']
                colors = ['#dc3545', '#ffc107', '#198754']

                plt.figure(figsize=(6, 6))
                plt.pie(faixas, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
                plt.tight_layout()
                plt.savefig(pie_chart_path, format='png', dpi=150)
                plt.close()
                logger.debug(f"Gráfico de pizza salvo em: {pie_chart_path}")

                # Converter para base64
                with open(pie_chart_path, 'rb') as f:
                    pie_chart_base64 = base64.b64encode(f.read()).decode('utf-8')
                logger.debug(f"Gráfico de pizza convertido para base64 ({len(pie_chart_base64)} bytes)")
            else:
                logger.warning("Nenhum dado válido para o gráfico de pizza")
        else:
            logger.warning("Nenhum dado em dados_dashboard para gerar gráficos")
    except Exception as e:
        logger.error(f"Erro ao gerar gráficos: {str(e)}")
        bar_chart_base64 = None
        pie_chart_base64 = None

    # Renderizar PDF
    try:
        rendered = render_template('relatorio_completo_pdf.html',
                                  dados_dashboard=dados_dashboard,
                                  dados_avaliacoes=dados_avaliacoes,
                                  resumo_habilidades=resumo_habilidades,
                                  bar_chart_base64=bar_chart_base64,
                                  pie_chart_base64=pie_chart_base64,
                                  setor_filtro=setor_filtro,
                                  nome_filtro=nome_filtro,
                                  media_min=media_min,
                                  media_max=media_max)
        pdf = HTML(string=rendered).write_pdf()
        logger.debug("PDF renderizado com sucesso")
    except Exception as e:
        logger.error(f"Erro ao renderizar PDF: {str(e)}")
        flash('Erro ao gerar o PDF. Contate o administrador.', 'danger')
        return redirect(url_for('dashboard_colaboradores'))

    # Limpar arquivos temporários
    try:
        if os.path.exists(bar_chart_path):
            os.remove(bar_chart_path)
            logger.debug(f"Arquivo temporário removido: {bar_chart_path}")
        if os.path.exists(pie_chart_path):
            os.remove(pie_chart_path)
            logger.debug(f"Arquivo temporário removido: {pie_chart_path}")
    except Exception as e:
        logger.error(f"Erro ao limpar arquivos temporESETtários: {str(e)}")

    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'inline; filename=relatorio_completo.pdf'
    return response

# ... (outras rotas mantidas inalteradas)

@app.route('/logout')
def logout():
    session.clear()
    flash('Logout realizado com sucesso.', 'info')
    return redirect(url_for('login'))

@app.route('/index')
def index():
    if 'usuario_id' not in session:
        return redirect(url_for('login'))

    feedbacks = Feedback.query.order_by(Feedback.data_envio.desc()).all()
    return render_template('index.html', feedbacks=feedbacks, usuario=g.usuario_logado)

@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
    if 'usuario_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        texto = request.form['texto']
        categoria = request.form['categoria']
        anonimo = 'anonimo' in request.form

        novo_feedback = Feedback(texto=texto, categoria=categoria, anonimo=anonimo)
        db.session.add(novo_feedback)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('feedback.html', usuario=g.usuario_logado)


@app.route('/notas', methods=['GET', 'POST'])
def gerenciar_notas():
    if 'usuario_id' not in session:
        return redirect(url_for('login'))

    usuario = g.usuario_logado
    setor_id = usuario.setor_id
    setor = Setor.query.get(usuario.setor_id)
    if request.method == 'POST':
        nova_nota = request.form.get('valor_nota')
        if nova_nota:
            try:
                valor = round(float(nova_nota), 2)
                nova = NotaPermitida(valor=valor, setor_id=setor_id)
                db.session.add(nova)
                db.session.commit()
                flash('Nota cadastrada com sucesso!', 'success')
            except ValueError:
                flash('Valor inválido.', 'danger')
        return redirect(url_for('gerenciar_notas'))

    notas = NotaPermitida.query.filter_by(setor_id=setor_id).order_by(NotaPermitida.valor).all()

    return render_template('notas.html', notas=notas, usuario=usuario,setor=setor)

@app.route('/nota/<int:id>/excluir', methods=['POST'])
def excluir_nota(id):
    if 'usuario_id' not in session:
        return redirect(url_for('login'))

    nota = NotaPermitida.query.get_or_404(id)

    # Garante que só o setor do usuário logado possa excluir
    if nota.setor_id != g.usuario_logado.setor_id:
        flash('Você não tem permissão para excluir esta nota.', 'danger')
        return redirect(url_for('gerenciar_notas'))

    db.session.delete(nota)
    db.session.commit()
    flash('Nota excluída com sucesso!', 'success')
    return redirect(url_for('gerenciar_notas'))

# ROTA DE AVALIAÇÃO
@app.route('/avaliar', methods=['GET', 'POST'])
def avaliar_funcionario():
    if 'usuario_id' not in session:
        return redirect(url_for('login'))

    usuario = g.usuario_logado
    setor_id = request.form.get('setor_filtro')
    
    # Filtra funcionários
    if setor_id:
        funcionarios = Usuario.query.filter_by(setor_id=setor_id).filter(Usuario.is_admin == False).all()
    else:
        funcionarios = Usuario.query.filter(Usuario.is_admin == False).all()

    # Categorias do setor do usuário
    categorias = CategoriaHabilidade.query.filter_by(setor_id=usuario.setor_id).order_by(CategoriaHabilidade.nome).all()
    
    # Organizar habilidades por categoria
    habilidades_por_categoria = {}
    for cat in categorias:
        habilidades_por_categoria[cat.nome] = Habilidades.query.filter_by(categoria_id=cat.id, ativa=True).all()

    if request.method == 'POST' and request.form.get('funcionario'):
        from datetime import datetime
        id_funcionario = request.form['funcionario']
        observacoes = request.form['observacoes']

        avaliacao = Avaliacao(
            id_funcionario=id_funcionario,
            id_avaliador=session['usuario_id'],
            observacoes=observacoes,
            data_avaliacao=datetime.now()
        )
        db.session.add(avaliacao)
        db.session.commit()
        #notas_disponiveis = NotaPermitida.query.filter_by(setor_id=g.usuario_logado.setor_id).order_by(NotaPermitida.valor).all()

        for key, nota in request.form.items():
            if key.startswith('cat_'):
                habilidade_id = int(key.split('_')[1])
                habilidade = Habilidades.query.get(habilidade_id)
                if habilidade:
                    item = AvaliacaoItem(
                        id_avaliacao=avaliacao.id,
                        nome_habilidade=habilidade.nome,
                        categoria=habilidade.categoria.nome,
                        nota=float(nota)
                    )
                    db.session.add(item)

        db.session.commit()
        session['avaliacao_realizada'] = True
        return redirect(url_for('avaliar_funcionario'))
    
    notas_permitidas = NotaPermitida.query.filter_by(setor_id=g.usuario_logado.setor_id).order_by(NotaPermitida.valor).all()
    notas_disponiveis = [float(n.valor) for n in notas_permitidas]

    return render_template(
        'avaliar.html',
        funcionarios=funcionarios,
        habilidades_por_categoria=habilidades_por_categoria,
        setores=Setor.query.all(),
        usuario=usuario,
        notas_disponiveis=notas_disponiveis
    )

#rota para excluir avaliação
@app.route('/avaliacao/<int:id>/excluir', methods=['POST'])
def excluir_avaliacao(id):
    if 'usuario_id' not in session:
        return redirect(url_for('login'))

    avaliacao = Avaliacao.query.get_or_404(id)
    
    try:
        # Primeiro exclui os itens associados
        AvaliacaoItem.query.filter_by(id_avaliacao=id).delete()
        
        # Depois exclui a avaliação
        db.session.delete(avaliacao)
        db.session.commit()
        flash('Avaliação excluída com sucesso.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Erro ao excluir avaliação: {str(e)}', 'danger')
    
    return redirect(request.referrer or url_for('listar_avaliacoes'))

@app.route('/avaliacoes', methods=['GET', 'POST'])
def listar_avaliacoes():
    if 'usuario_id' not in session:
        return redirect(url_for('login'))


    setores = Setor.query.order_by(Setor.nome).all()
    setor_id = request.form.get('setor_filtro')

    if setor_id:
        funcionarios = Usuario.query.filter_by(setor_id=setor_id).filter(Usuario.is_admin == False).all()
    else:
        funcionarios = Usuario.query.filter(Usuario.is_admin == False).all()

    funcionarios = Usuario.query.filter(Usuario.is_admin == False).all()

    id_funcionario = request.args.get('funcionario')
    data_inicio = request.args.get('data_inicio')
    data_fim = request.args.get('data_fim')
    mostrar_todas = request.args.get('todas') == '1'

    query = Avaliacao.query

    if id_funcionario:
        query = query.filter_by(id_funcionario=id_funcionario)

    if data_inicio:
        query = query.filter(Avaliacao.data_avaliacao >= data_inicio)
    if data_fim:
        query = query.filter(Avaliacao.data_avaliacao <= data_fim)

    query = query.order_by(Avaliacao.data_avaliacao.desc())
    avaliacoes_raw = query.all() if mostrar_todas else query.limit(5).all()
    pode_excluir = g.usuario_logado.is_admin  # ou com base no cargo/setor

    dados = []
    for av in avaliacoes_raw:
        funcionario = Usuario.query.get(av.id_funcionario)
        avaliador = Usuario.query.get(av.id_avaliador)
        itens = AvaliacaoItem.query.filter_by(id_avaliacao=av.id).all()

        dados.append({
            'id': av.id,
            'funcionario': funcionario.nome if funcionario else 'Desconhecido',
            'avaliador': avaliador.nome if avaliador else 'Desconhecido',
            'data': av.data_avaliacao.strftime('%d/%m/%Y'),
            'observacoes': av.observacoes,
            'itens': itens
        })


    return render_template('avaliacoes.html',
                           avaliacoes=dados,
                           funcionarios=funcionarios,
                           mostrar_todas=mostrar_todas,
                           usuario=g.usuario_logado,
                           setores=setores,
                           pode_excluir=pode_excluir)

# ROTAS PARA HABILIDADES
@app.route('/habilidade/<int:id>/alternar', methods=['POST'])
def alternar_status_habilidade(id):
    if 'usuario_id' not in session or not g.usuario_logado.is_admin:
        return jsonify({'error': 'Não autorizado'}), 403
        
    habilidade = Habilidades.query.get_or_404(id)
    habilidade.ativa = not habilidade.ativa
    db.session.commit()
    
    return jsonify({
        'success': True,
        'nova_ativa': habilidade.ativa
    })


@app.route('/')
def dashboard_colaboradores():
    if 'usuario_id' not in session:
        return redirect(url_for('login'))

    if not g.usuario_logado.is_admin:
        flash('Acesso restrito a administradores.', 'danger')
        return redirect(url_for('avaliar_funcionario'))

    setor_filtro = request.args.get('setor')
    nome_filtro = request.args.get('nome', '').strip()
    media_min = request.args.get('media_min', type=float)
    media_max = request.args.get('media_max', type=float)

    # Consulta base - apenas usuários com avaliações e suas médias
    query = db.session.query(
        Usuario,
        db.func.count(Avaliacao.id).label('total_avaliacoes'),
        db.func.avg(AvaliacaoItem.nota).label('media_geral')
    ).join(
        Avaliacao, Usuario.id == Avaliacao.id_funcionario
    ).join(
        AvaliacaoItem, AvaliacaoItem.id_avaliacao == Avaliacao.id
    ).filter(
        Usuario.is_admin == False
    ).group_by(
        Usuario.id
    )

    if setor_filtro:
        query = query.join(Setor).filter(Setor.nome == setor_filtro)
    
    if nome_filtro:
        query = query.filter(Usuario.nome.ilike(f'%{nome_filtro}%'))

    # Executa a consulta e processa os resultados
    dados = []
    for usuario, total_avaliacoes, media_geral in query.all():
        media_geral = round(float(media_geral), 2) if media_geral else 0
        
        # Aplicar filtros de média
        if (media_min is not None and media_geral < media_min) or \
           (media_max is not None and media_geral > media_max):
            continue
        
        dados.append({
            'id': usuario.id,
            'nome': usuario.nome,
            'cargo': usuario.cargo,
            'setor': usuario.setor.nome if usuario.setor else 'Sem setor',
            'total_avaliacoes': total_avaliacoes,
            'media_geral': media_geral
        })

    # Ordenar por maior média
    dados.sort(key=lambda x: x['media_geral'], reverse=True)

    # Estatísticas - agora baseadas apenas nos dados filtrados
    total_colaboradores = len(dados)
    media_geral_geral = round(sum(d['media_geral'] for d in dados) / total_colaboradores, 2) if dados else 0

    return render_template(
        'dashboard.html',
        dados=dados,
        setores=Setor.query.all(),
        setor_filtro=setor_filtro,
        total_colaboradores=total_colaboradores,
        media_geral=media_geral_geral,
        usuario=g.usuario_logado
    )

# ROTA PARA CADASTRAR SETOR
@app.route('/setores/cadastrar', methods=['GET', 'POST'])
def cadastrar_setor():
    if 'usuario_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        nome = request.form['nome'].strip()
        if nome:
            existente = Setor.query.filter_by(nome=nome).first()
            if existente:
                flash('Já existe um setor com este nome.', 'warning')
            else:
                novo_setor = Setor(nome=nome)
                db.session.add(novo_setor)
                db.session.commit()
                flash('Setor cadastrado com sucesso!', 'success')
                return redirect(url_for('bibliotecas'))
    return render_template('cadastrar_setor.html', usuario=g.usuario_logado)


@app.route('/relatorio_avaliacoes/<int:usuario_id>', methods=['GET'])
def relatorio_avaliacoes(usuario_id):
    avaliacoes = Avaliacao.query.filter_by(usuario_id=usuario_id).all()
    relatorio = []
    for av in avaliacoes:
        for item in av.itens:
            response = requests.post(
                "https://api.x.ai/v1/completions",
                headers={"Authorization": f"Bearer {XAI_API_KEY}", "Content-Type": "application/json"},
                json={"model": "grok-3", "prompt": f"Resuma: {item.comentario}", "max_tokens": 50}
            )
            resumo = response.json()['choices'][0]['text']
            relatorio.append({"criterio": item.criterio, "nota": item.nota, "resumo": resumo})
    return render_template('relatorio.html', relatorio=relatorio)


if __name__ == '__main__':
    with app.app_context():
        #db.create_all()
        #app.run(debug=True)

        app.run(host='192.168.10.34', port=8000, debug=True)

