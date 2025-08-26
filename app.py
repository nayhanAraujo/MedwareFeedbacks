from flask import Flask, render_template, request, redirect, url_for, session, flash, g, make_response,jsonify,json,request,send_file
from models import db, Usuario, Feedback, NotaPermitida, AvaliacaoResumo, ConfiguracaoAvaliacao, Resposta, AcaoCorretiva, Avaliacao, AvaliacaoItem, Setor, Habilidades, CategoriaHabilidade
from datetime import datetime,timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import pdfkit
from io import BytesIO
from collections import defaultdict
from flask_mail import Mail, Message
from dotenv import load_dotenv
import matplotlib
matplotlib.use('Agg')  # Usar backend não interativo
import matplotlib.pyplot as plt
import seaborn as sns
import os,  base64,  logging,  secrets,  urllib.parse, requests, redis,re,io
# ... (outras importações mantidas)
import numpy as np




# Carregar variáveis de ambiente
load_dotenv()

# Configurar logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
0

@app.template_filter('extract_summary_sections')
def extract_summary_sections(text):
    pattern = re.compile(
        r"\*\*Pontos Fortes:\*\*.*?\n-\n\*\*Áreas a Melhorar:\*\*.*?\n-\n\*\*Sugestões de Desenvolvimento:\*\*.*?(?=\n*$)",
        re.DOTALL
    )
    match = pattern.search(text)
    return match.group(0).strip() if match else text


# Habilitar a extensão 'do' no Jinja2
app.jinja_env.add_extension('jinja2.ext.do')
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:masterkey@localhost:5432/feedbacks'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'chave_secreta_super_segura'
XAI_API_KEY = os.getenv('XAI_API_KEY')

if not XAI_API_KEY:
    raise ValueError("XAI_API_KEY não configurada no ambiente.")


# Configurar Redis
redis_client = redis.Redis(host='localhost', port=6379, db=0)

db.init_app(app)  # importante!




app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'nayhanbsb@gmail.com'
app.config['MAIL_PASSWORD'] = 'txkt aiqx qqvk vjdr'
app.config['MAIL_DEFAULT_SENDER'] = ('Sistema de Avaliação', 'nayhanbsb@gmail.com')
mail = Mail(app)


@app.before_request
def carregar_usuario_logado():
    g.usuario_logado = None
    if 'usuario_id' in session:
        g.usuario_logado = Usuario.query.get(session['usuario_id'])
        logger.debug(f"Usuário logado: {g.usuario_logado.nome if g.usuario_logado else 'Nenhum'}")
    else:
        logger.debug("Nenhum usuário logado na sessão")

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
    if 'usuario_id' in session:
        logger.debug("Usuário já logado, redirecionando para dashboard")
        return redirect(url_for('dashboard_colaboradores'))

    if request.method == 'POST':
        email = request.form['email']
        senha = request.form['senha']
        logger.debug(f"Tentativa de login com email: {email}")
        usuario = Usuario.query.filter_by(email=email).first()

        if usuario and usuario.verificar_senha(senha):
            session['usuario_id'] = usuario.id
            session['usuario_nome'] = usuario.nome
            session.permanent = True  # Sessão persiste por 1 dia
            logger.info(f"Login bem-sucedido para usuário ID {usuario.id}")
            flash('Login realizado com sucesso!', 'success')
            if usuario.is_admin:
                return redirect(url_for('dashboard_colaboradores'))
            else:
                return redirect(url_for('avaliar_funcionario'))
        else:
            logger.warning("Falha no login: credenciais inválidas")
            flash('Credenciais inválidas.', 'danger')

    logger.debug("Renderizando página de login")
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
            logger.debug(f"Funcionário {f.nome} excluído: sem avaliações")
            continue

        # Consultar itens de avaliação diretamente
        notas = AvaliacaoItem.query.join(Avaliacao, AvaliacaoItem.id_avaliacao == Avaliacao.id).filter(Avaliacao.id_funcionario == f.id).all()
        if not notas:  # Excluir funcionários sem notas
            logger.debug(f"Funcionário {f.nome} excluído: sem notas em avaliações")
            continue

        media_geral = round(sum(i.nota for i in notas) / len(notas), 2) if notas else 0

        # Aplicar filtros de média
        if (media_min is not None and media_geral < media_min) or (media_max is not None and media_geral > media_max):
            logger.debug(f"Funcionário {f.nome} excluído: média {media_geral} fora do intervalo ({media_min}, {media_max})")
            continue

        dados_dashboard.append({
            'nome': f.nome,
            'cargo': f.cargo,
            'setor': f.setor.nome if f.setor else '',
            'total_avaliacoes': total,
            'media_geral': media_geral
        })
        funcionario_ids.append(f.id)

    logger.info(f"Total de funcionários com avaliações e notas após filtros: {len(dados_dashboard)}")

    # Consultar avaliações apenas dos funcionários filtrados
    avaliacoes = Avaliacao.query.filter(Avaliacao.id_funcionario.in_(funcionario_ids)).order_by(Avaliacao.data_avaliacao.desc()).all()
    dados_avaliacoes = []
    for av in avaliacoes:
        funcionario = Usuario.query.get(av.id_funcionario)
        avaliador = Usuario.query.get(av.id_avaliador)
        itens = AvaliacaoItem.query.filter_by(id_avaliacao=av.id).all()

        # Gerar o resumo detalhado para a avaliação atual
        resumo_detalhado = get_detailed_evaluation_summary(av, itens, force_refresh=False)

        dados_avaliacoes.append({
            'id': av.id,
            'funcionario': funcionario.nome if funcionario else 'Desconhecido',
            'avaliador': avaliador.nome if avaliador else 'Desconhecido',
            'data': av.data_avaliacao.strftime('%d/%m/%Y'),
            'observacoes': av.observacoes,
            'itens': itens,
            'resumo_detalhado': resumo_detalhado
        })

    # Resumo de habilidades apenas para avaliações filtradas
    resumo = defaultdict(lambda: {'total': 0, 'soma': 0, 'categoria': ''})
    data_geracao = datetime.now().strftime('%d/%m/%Y %H:%M')
    usuario = g.usuario_logado
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

    # Agregar médias por categoria
    resumo_categorias = defaultdict(lambda: {'total_habilidades': 0, 'soma_medias': 0})
    for habilidade in resumo_habilidades:
        categoria = habilidade['categoria']
        resumo_categorias[categoria]['total_habilidades'] += 1
        resumo_categorias[categoria]['soma_medias'] += habilidade['media']

    medias_por_categoria = [
        {
            'categoria': categoria,
            'media': round(dados['soma_medias'] / dados['total_habilidades'], 2) if dados['total_habilidades'] > 0 else 0
        }
        for categoria, dados in resumo_categorias.items()
    ]

    # Sort categories alphabetically for consistent radar chart
    medias_por_categoria.sort(key=lambda x: x['categoria'])
    categorias = [d['categoria'] for d in medias_por_categoria]
    medias_categoria = [d['media'] for d in medias_por_categoria]

    logger.info(f"Total de categorias com médias calculadas: {len(medias_por_categoria)}")

    # Criar diretório temporário no projeto
    temp_dir = os.path.join(os.path.dirname(__file__), 'static', 'temp')
    try:
        os.makedirs(temp_dir, exist_ok=True)
        logger.debug(f"Diretório temporário criado/acessado: {temp_dir}")
    except Exception as e:
        logger.error(f"Erro ao criar diretório temporário: {str(e)}")
        flash('Erro ao configurar diretório temporário. Contate o administrador.', 'danger')
        return redirect(url_for('dashboard_colaboradores'))

    bar_chart_path = os.path.join(temp_dir, 'bar_chart.png')  # Média por Colaborador
    histogram_path = os.path.join(temp_dir, 'histogram.png')  # Histograma de Médias
    radar_chart_path = os.path.join(temp_dir, 'radar_chart.png')  # Média por Categoria (Radar)
    category_bar_chart_path = os.path.join(temp_dir, 'category_bar_chart.png')  # Média por Categoria (Barras)

    bar_chart_base64 = None
    histogram_base64 = None
    radar_chart_base64 = None
    category_bar_chart_base64 = None

    # Gerar gráficos
    try:
        if dados_dashboard:
            logger.debug(f"Gerando gráficos para {len(dados_dashboard)} colaboradores")
            # Gráfico de barras (Média por Colaborador)
            nomes = [d['nome'] for d in dados_dashboard]
            medias = [d['media_geral'] for d in dados_dashboard]

            plt.figure(figsize=(8, max(4, len(nomes) * 0.3)))
            ax = sns.barplot(x=medias, y=nomes, color='#0d6efd')
            plt.xlabel('Média Geral')
            plt.ylabel('Colaborador')
            plt.xlim(0, 5)
            for i, v in enumerate(medias):
                ax.text(v + 0.1, i, f'{v:.2f}', va='center')
            plt.tight_layout()
            plt.savefig(bar_chart_path, format='png', dpi=150)
            plt.close()
            logger.debug(f"Gráfico de barras (Colaborador) salvo em: {bar_chart_path}")

            # Converter para base64
            with open(bar_chart_path, 'rb') as f:
                bar_chart_base64 = base64.b64encode(f.read()).decode('utf-8')
            logger.debug(f"Gráfico de barras (Colaborador) convertido para base64 ({len(bar_chart_base64)} bytes)")

            # Histograma de Médias Gerais
            media_geral_total = sum(medias) / len(medias) if medias else 0
            plt.figure(figsize=(4, 4))
            sns.histplot(medias, bins=10, color='#ff7f0e', kde=False, stat='count')
            plt.axvline(x=media_geral_total, color='red', linestyle='--', label=f'Média: {media_geral_total:.2f}')
            plt.xlabel('Média Geral')
            plt.ylabel('Número de Colaboradores')
            plt.xlim(0, 5)
            plt.legend()
            plt.tight_layout()
            plt.savefig(histogram_path, format='png', dpi=150)
            plt.close()
            logger.debug(f"Histograma de médias salvo em: {histogram_path}")

            # Converter para base64
            with open(histogram_path, 'rb') as f:
                histogram_base64 = base64.b64encode(f.read()).decode('utf-8')
            logger.debug(f"Histograma convertido para base64 ({len(histogram_base64)} bytes)")

        else:
            logger.warning("Nenhum dado em dados_dashboard para gerar gráficos de Colaborador e Histograma")

        # Geração dos gráficos de categoria
        if medias_por_categoria:
            logger.debug(f"Gerando gráficos para {len(medias_por_categoria)} categorias")

            # Gráfico de Radar (Média por Categoria)
            num_categorias = len(categorias)
            if num_categorias >= 3:  # Radar chart precisa de pelo menos 3 categorias
                angles = np.linspace(0, 2 * np.pi, num_categorias, endpoint=False).tolist()
                values = medias_categoria

                # Fechar o gráfico de radar
                values = values + [values[0]]
                angles = angles + [angles[0]]

                fig, ax = plt.subplots(figsize=(6, 6), subplot_kw=dict(polar=True))
                ax.fill(angles, values, color='#0d6efd', alpha=0.25)
                ax.plot(angles, values, color='#0d6efd', linewidth=2)
                ax.set_thetagrids(np.degrees(angles[:-1]), categorias)
                ax.set_title("Média por Categoria", va='bottom')
                ax.set_ylim(0, 5)
                plt.tight_layout()
                plt.savefig(radar_chart_path, format='png', dpi=150)
                plt.close()
                logger.debug(f"Gráfico de radar salvo em: {radar_chart_path}")

                # Converter para base64
                with open(radar_chart_path, 'rb') as f:
                    radar_chart_base64 = base64.b64encode(f.read()).decode('utf-8')
                logger.debug(f"Gráfico de radar convertido para base64 ({len(radar_chart_base64)} bytes)")
            else:
                logger.warning(f"Número insuficiente de categorias ({num_categorias}) para o gráfico de radar. Mínimo necessário: 3")

            # Gráfico de Barras (Média por Categoria)
            if num_categorias > 0:
                plt.figure(figsize=(8, max(4, num_categorias * 0.5)))
                ax = sns.barplot(x=medias_categoria, y=categorias, color='#198754')
                plt.xlabel('Média')
                plt.ylabel('Categoria')
                plt.xlim(0, 5)
                for i, v in enumerate(medias_categoria):
                    ax.text(v + 0.1, i, f'{v:.2f}', va='center')
                plt.title('Média por Categoria (Barras)')
                plt.tight_layout()
                plt.savefig(category_bar_chart_path, format='png', dpi=150)
                plt.close()
                logger.debug(f"Gráfico de barras (Categoria) salvo em: {category_bar_chart_path}")

                # Converter para base64
                with open(category_bar_chart_path, 'rb') as f:
                    category_bar_chart_base64 = base64.b64encode(f.read()).decode('utf-8')
                logger.debug(f"Gráfico de barras (Categoria) convertido para base64 ({len(category_bar_chart_base64)} bytes)")
            else:
                logger.warning("Nenhum dado válido para o gráfico de barras por categoria")
        else:
            logger.warning("Nenhum dado em medias_por_categoria para gerar gráficos de Categoria")

    except Exception as e:
        logger.error(f"Erro ao gerar gráficos: {str(e)}")
        bar_chart_base64 = None
        histogram_base64 = None
        radar_chart_base64 = None
        category_bar_chart_base64 = None

    # Renderizar PDF
    try:
        rendered = render_template('relatorio_completo_pdf.html',
                                   dados_dashboard=dados_dashboard,
                                   dados_avaliacoes=dados_avaliacoes,
                                   resumo_habilidades=resumo_habilidades,
                                   bar_chart_base64=bar_chart_base64,
                                   histogram_base64=histogram_base64,
                                   radar_chart_base64=radar_chart_base64,
                                   category_bar_chart_base64=category_bar_chart_base64,
                                   setor_filtro=setor_filtro,
                                   nome_filtro=nome_filtro,
                                   media_min=media_min,
                                   media_max=media_max,
                                   data_geracao=data_geracao,
                                   usuario=usuario,
                                   categorias=categorias)

        # Configurar pdfkit para Windows
        config = pdfkit.configuration(wkhtmltopdf='C:\\Program Files\\wkhtmltopdf\\bin\\wkhtmltopdf.exe')
        pdf = pdfkit.from_string(rendered, False, configuration=config)
        logger.debug("PDF renderizado com sucesso")
    except Exception as e:
        logger.error(f"Erro ao renderizar PDF: {str(e)}")
        flash('Erro ao gerar o PDF. Contate o administrador.', 'danger')
        return redirect(url_for('dashboard_colaboradores'))

    # Limpar arquivos temporários
    try:
        for path in [bar_chart_path, histogram_path, radar_chart_path, category_bar_chart_path]:
            if os.path.exists(path):
                os.remove(path)
                logger.debug(f"Arquivo temporário removido: {path}")
    except Exception as e:
        logger.error(f"Erro ao limpar arquivos temporários: {str(e)}")

    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'inline; filename=relatorio_completo.pdf'
    return response
# ... (outras rotas mantidas)

@app.route('/analisar_comentarios_habilidades/<int:avaliacao_id>', methods=['POST'])
def analisar_comentarios_habilidades(avaliacao_id):
    if 'usuario_id' not in session:
        logger.debug("Usuário não autenticado, redirecionando para login")
        return redirect(url_for('login'))

    avaliacao = Avaliacao.query.get_or_404(avaliacao_id)
    if avaliacao.id_avaliador != g.usuario_logado.id and not g.usuario_logado.is_admin:
        flash('Acesso negado: Você não tem permissão para analisar comentários.', 'danger')
        return redirect(url_for('analisar_observacao', avaliacao_id=avaliacao_id))

    itens = AvaliacaoItem.query.filter_by(id_avaliacao=avaliacao_id).all()
    comentarios = [item.comentario for item in itens if item.comentario]

    if not comentarios:
        flash('Nenhum comentário disponível para análise.', 'warning')
        return redirect(url_for('analisar_observacao', avaliacao_id=avaliacao_id) + '#analise-comentarios')

    # Usar a API para analisar o sentimento dos comentários
    prompt = (
        "Você é um assistente de RH que analisa comentários de avaliações de desempenho. "
        "Com base nos comentários fornecidos, determine o sentimento geral (Positivo, Negativo ou Neutro) e forneça uma breve explicação (máximo de 2 frases). "
        "Formato:\n"
        "Sentimento: [Positivo/Negativo/Neutro]\n"
        "Explicação: [sua explicação]\n\n"
        f"Comentários:\n{'\n'.join([f'- {c}' for c in comentarios])}\n"
    )

    try:
        response = requests.post(
            "https://api.x.ai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {XAI_API_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "model": "grok-3-mini-beta",
                "prompt": prompt,
                "max_tokens": 150,
                "temperature": 0.7
            }
        )
        response.raise_for_status()
        result = response.json()
        analise = result['choices'][0]['text'].strip()
        session['analise_comentarios'] = analise
    except Exception as e:
        logger.error(f"Erro ao analisar comentários: {str(e)}")
        session['analise_comentarios'] = "Erro ao analisar comentários. Tente novamente."

    return redirect(url_for('analisar_observacao', avaliacao_id=avaliacao_id) + '#analise-comentarios')


@app.route('/gerar_perguntas_feedback/<int:avaliacao_id>', methods=['POST'])
def gerar_perguntas_feedback(avaliacao_id):
    if 'usuario_id' not in session:
        logger.debug("Usuário não autenticado, redirecionando para login")
        return redirect(url_for('login'))

    avaliacao = Avaliacao.query.get_or_404(avaliacao_id)
    if avaliacao.id_avaliador != g.usuario_logado.id and not g.usuario_logado.is_admin:
        flash('Acesso negado: Você não tem permissão para gerar perguntas de feedback.', 'danger')
        return redirect(url_for('analisar_observacao', avaliacao_id=avaliacao_id))

    itens = AvaliacaoItem.query.filter_by(id_avaliacao=avaliacao_id).all()
    habilidades_baixas = [f"{item.categoria} - {item.nome_habilidade} ({item.nota}/5)" for item in itens if item.nota < 2.5]

    # Montar o prompt para a API
    system_prompt = (
        "Você é um assistente de RH especializado em gerar perguntas de feedback para reuniões de follow-up. "
        "Sua tarefa é criar 3 perguntas abertas, específicas e úteis para discutir com o colaborador, focando nas habilidades com notas baixas (menores que 2.5). "
        "As perguntas devem ser no formato:\n"
        "- Pergunta 1\n"
        "- Pergunta 2\n"
        "- Pergunta 3\n\n"
        "Não repita as informações fornecidas, apenas gere as perguntas com base nelas."
    )
    user_prompt = (
        f"**Informações do Colaborador**:\n"
        f"Nome: {avaliacao.funcionario.nome}\n"
        f"Cargo: {avaliacao.funcionario.cargo}\n"
        f"Setor: {avaliacao.funcionario.setor.nome if avaliacao.funcionario.setor else 'Sem setor'}\n"
        f"Habilidades com Notas Baixas: {', '.join(habilidades_baixas) if habilidades_baixas else 'Nenhuma habilidade com nota baixa.'}\n"
    )

    try:
        # Fazer a requisição para o endpoint correto
        response = requests.post(
            "https://api.x.ai/v1/chat/completions",  # Endpoint corrigido
            headers={
                "Authorization": f"Bearer {XAI_API_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "model": "grok-3-mini-beta",
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                "max_tokens": 500,
                "temperature": 0.7
            }
        )
        response.raise_for_status()  # Levanta uma exceção para códigos de status 4xx/5xx
        result = response.json()
        
        # Extrair as perguntas da resposta
        perguntas_raw = result['choices'][0]['message']['content'].strip()
        logger.debug(f"Perguntas brutas retornadas pela API: {perguntas_raw}")

        # Limpar e formatar as perguntas
        perguntas_lista = []
        for linha in perguntas_raw.split('\n'):
            linha = linha.strip()
            if linha.startswith('- '):
                pergunta = linha[2:].strip()
                if pergunta and not pergunta.startswith("Habilidades com Notas Baixas"):
                    perguntas_lista.append(pergunta)
            elif linha and not linha.startswith('Gerado em:') and not linha.startswith("Habilidades com Notas Baixas"):
                perguntas_lista.append(linha)

        # Validar perguntas
        perguntas_validas = [
            p for p in perguntas_lista
            if any(p.lower().startswith(palavra) for palavra in ["como ", "quais ", "por que ", "o que ", "você "]) and len(p) > 10
        ]

        if not perguntas_validas:
            logger.warning(f"Nenhuma pergunta válida foi gerada pela API. Resposta bruta: {perguntas_raw}")
            perguntas_lista = ["Nenhuma pergunta válida gerada. A API não retornou perguntas no formato esperado."]
        else:
            perguntas_lista = perguntas_validas

        # Adicionar timestamp e formatar
        timestamp = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
        perguntas_formatadas = f"Gerado em: {timestamp}\n\n" + '\n'.join(perguntas_lista)
        session['perguntas_feedback'] = perguntas_formatadas
        logger.debug(f"Perguntas formatadas salvas na sessão: {perguntas_formatadas}")

    except requests.exceptions.HTTPError as e:
        logger.error(f"Erro HTTP ao chamar a API: {str(e)}")
        logger.debug(f"Resposta da API: {e.response.text if e.response else 'Sem resposta'}")
        timestamp = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
        perguntas_formatadas = f"Gerado em: {timestamp}\n\nErro ao gerar perguntas de feedback: {str(e)}"
        session['perguntas_feedback'] = perguntas_formatadas
    except Exception as e:
        logger.error(f"Erro inesperado ao gerar perguntas de feedback: {str(e)}")
        timestamp = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
        perguntas_formatadas = f"Gerado em: {timestamp}\n\nErro ao gerar perguntas de feedback: {str(e)}"
        session['perguntas_feedback'] = perguntas_formatadas

    return redirect(url_for('analisar_observacao', avaliacao_id=avaliacao_id) + '#perguntas-feedback')


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

                # Verifica se a nota já existe para o setor
                nota_existente = NotaPermitida.query.filter_by(setor_id=setor_id, valor=valor).first()
                if nota_existente:
                    flash('Esta nota já foi cadastrada para o seu setor.', 'warning')
                else:
                    nova = NotaPermitida(valor=valor, setor_id=setor_id)
                    db.session.add(nova)
                    db.session.commit()
                    flash('Nota cadastrada com sucesso!', 'success')
            except ValueError:
                flash('Valor inválido.', 'danger')

            return redirect(url_for('gerenciar_notas'))

    # Esta parte deve estar FORA do bloco POST, para ser executada em GET também
    notas = NotaPermitida.query.filter_by(setor_id=setor_id).order_by(NotaPermitida.valor).all()
    return render_template('notas.html', notas=notas, usuario=usuario, setor=setor)

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


@app.route('/analises_sentimentos', methods=['GET'])
def analises_sentimentos():
    if 'usuario_id' not in session:
        logger.debug("Usuário não autenticado, redirecionando para login")
        return redirect(url_for('login'))
    
    logger.debug("Carregando análises de sentimentos")
    sentimento_filtro = request.args.get('sentimento')
    data_inicio = request.args.get('data_inicio')
    data_fim = request.args.get('data_fim')
    
    query = Avaliacao.query.filter(Avaliacao.sentimento != None)
    
    # Filtro por sentimento
    if sentimento_filtro in ['Positivo', 'Negativo', 'Neutro']:
        logger.debug(f"Filtro aplicado: sentimento = {sentimento_filtro}")
        query = query.filter(Avaliacao.sentimento == sentimento_filtro)
    
    # Filtro por data
    try:
        if data_inicio:
            data_inicio_dt = datetime.strptime(data_inicio, '%Y-%m-%d')
            query = query.filter(Avaliacao.data_avaliacao >= data_inicio_dt)
            logger.debug(f"Filtro aplicado: data_inicio = {data_inicio}")
        if data_fim:
            data_fim_dt = datetime.strptime(data_fim, '%Y-%m-%d')
            # Incluir o dia inteiro até 23:59:59
            data_fim_dt = data_fim_dt.replace(hour=23, minute=59, second=59)
            query = query.filter(Avaliacao.data_avaliacao <= data_fim_dt)
            logger.debug(f"Filtro aplicado: data_fim = {data_fim}")
    except ValueError as e:
        logger.error(f"Erro ao converter datas: {str(e)}")
        flash('Formato de data inválido. Use o formato AAAA-MM-DD.', 'danger')
    
    avaliacoes = query.order_by(Avaliacao.data_avaliacao.desc()).all()
    logger.debug(f"Total de avaliações carregadas: {len(avaliacoes)}")
    
    return render_template(
        'analises_sentimentos.html',
        avaliacoes=avaliacoes,
        sentimento_filtro=sentimento_filtro,
        data_inicio=data_inicio,
        data_fim=data_fim
    )
# Função auxiliar para consultar ou chamar a API com Redis
def get_sentiment_from_cache_or_api(observacoes):
    if not observacoes or not observacoes.strip():
        return "Não analisado"

    # Verificar cache no Redis
    cache_key = f"sentiment:{observacoes}"
    try:
        sentimento = redis_client.get(cache_key)
        if sentimento:
            logger.debug(f"Sentimento encontrado no cache (Redis) para observações: {observacoes[:50]}... - {sentimento}")
            return sentimento
    except redis.RedisError as e:
        logger.error(f"Erro ao acessar o Redis: {str(e)}")
        # Fallback: chamar a API diretamente
        pass

    # Se não estiver no cache, chamar a API
    try:
        logger.debug("Chamando xAI API para análise de sentimento")
        response = requests.post(
            "https://api.x.ai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {XAI_API_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "model": "grok-3-mini-beta",
                "prompt": f"Analise o seguinte comentário e retorne apenas uma palavra: Positivo, Negativo ou Neutro.\nComentário: {observacoes}",
                "max_tokens": 10,
                "temperature": 0.2
            }
        )
        response.raise_for_status()
        
        result = response.json()
        sentimento = result['choices'][0]['text'].strip()
        
        valid_sentiments = ['Positivo', 'Negativo', 'Neutro']
        if sentimento not in valid_sentiments:
            logger.warning(f"Sentimento inválido retornado pela API: {sentimento}")
            sentimento = "Neutro"

        # Salvar no cache (Redis) com expiração de 24 horas
        try:
            redis_client.setex(cache_key, 86400, sentimento)
            logger.info(f"Sentimento salvo no cache (Redis): {sentimento}")
        except redis.RedisError as e:
            logger.error(f"Erro ao salvar no Redis: {str(e)}")

        return sentimento
    except requests.exceptions.RequestException as e:
        logger.error(f"Erro ao chamar xAI API: {str(e)}")
        return "Não analisado"
    except Exception as e:
        logger.error(f"Erro inesperado ao processar análise de sentimento: {str(e)}")
        return "Não analisado"




def get_detailed_evaluation_summary(avaliacao, itens, force_refresh=False):
    observacoes = avaliacao.observacoes or ""
    
    # Reavaliar o sentimento com base nas notas para maior consistência
    media_geral = sum(item.nota for item in itens) / len(itens) if itens else 0
    sentimento = avaliacao.sentimento or "Não analisado"
    if media_geral >= 4.0 and "Negativo" not in sentimento:
        sentimento = "Positivo"
    elif media_geral <= 2.5 and "Positivo" not in sentimento:
        sentimento = "Negativo"
    elif media_geral > 2.5 and media_geral < 4.0:
        sentimento = "Neutro"

    # Verificar cache no Redis
    cache_key = f"resumo:{avaliacao.id}:{sentimento}:{media_geral:.2f}"
    if not force_refresh:
        try:
            cached_summary = redis_client.get(cache_key)
            if cached_summary:
                logger.debug(f"Resumo encontrado no cache (Redis) para avaliação ID {avaliacao.id}")
                return cached_summary.decode('utf-8') if isinstance(cached_summary, bytes) else cached_summary
        except Exception as e:
            logger.warning(f"Erro ao acessar o cache Redis: {str(e)}. Prosseguindo sem cache.")

    # Se não há itens ou observações, retornar uma resposta padrão
    if not itens and not observacoes:
        summary = (
            "**Pontos Fortes:**\nNenhuma informação disponível para avaliar pontos fortes.\n-\n"
            "**Áreas a Melhorar:**\nNenhuma informação disponível para identificar áreas a melhorar.\n-\n"
            "**Sugestões de Desenvolvimento:**\nNenhuma sugestão disponível devido à falta de dados.\n"
        )
        try:
            redis_client.setex(cache_key, timedelta(days=7), summary)
            logger.info(f"Resumo padrão salvo no cache para avaliação ID {avaliacao.id}")
        except Exception as e:
            logger.warning(f"Erro ao salvar resumo padrão no cache: {str(e)}")
        return summary

    # Estruturar os dados das habilidades e notas
    habilidades_info = "\n".join([
        f"- {item.categoria} - {item.nome_habilidade}: {item.nota}/5"
        for item in itens
    ])

    # Identificar habilidades com notas baixas e medianas
    habilidades_baixas = [f"{item.categoria} - {item.nome_habilidade} ({item.nota}/5)" for item in itens if item.nota < 2.5]
    habilidades_medias = [f"{item.categoria} - {item.nome_habilidade} ({item.nota}/5)" for item in itens if 2.5 <= item.nota < 4.0]

    # Criar o prompt para a API
    system_prompt = (
        "Você é um assistente de RH que analisa avaliações de desempenho de colaboradores. "
        "Com base nas informações fornecidas, gere um resumo detalhado e construtivo sobre o desempenho do colaborador. "
        "Considere as notas das habilidades, a média geral, as observações e o sentimento das observações. "
        "Divida o resumo em três seções: **Pontos Fortes**, **Áreas a Melhorar** e **Sugestões de Desenvolvimento**. "
        "Use o formato exato abaixo, com títulos em negrito e quebras de linha entre as seções:\n"
        "**Pontos Fortes:**\n(texto da seção)\n- Em seguida, uma quebra de linha.\n-\n"
        "**Áreas a Melhorar:**\n(texto da seção)\n- Em seguida, uma quebra de linha.\n-\n"
        "**Sugestões de Desenvolvimento:**\n(texto da seção)\n"
        "Escreva de forma clara, com parágrafos bem estruturados e linguagem profissional. "
        "Evite adicionar informações que não estejam presentes nos dados fornecidos. "
        "Certifique-se de completar todas as frases e ideias, evitando cortar o texto no meio de uma frase. "
        "Dedique atenção especial à seção **Sugestões de Desenvolvimento**, garantindo que ela tenha pelo menos 2 frases completas e seja específica. "
        "Se as observações forem genéricas ou insuficientes, baseie as sugestões nas notas das habilidades e no sentimento. "
        "Por exemplo, sugira treinamentos ou ações específicas para melhorar as habilidades com notas baixas ou medianas. "
        "Forneça um resumo de até 300 palavras, distribuindo o espaço de forma equilibrada entre as três seções. "
        "Não inclua introduções, explicações ou análises preliminares; comece diretamente com **Pontos Fortes:**."
    )
    user_prompt = (
        f"**Informações do Colaborador**:\n"
        f"Nome: {avaliacao.funcionario.nome}\n"
        f"Cargo: {avaliacao.funcionario.cargo}\n"
        f"Setor: {avaliacao.funcionario.setor.nome if avaliacao.funcionario.setor else 'Sem setor'}\n\n"
        f"**Média Geral**: {media_geral:.2f}/5\n\n"
        f"**Habilidades Avaliadas**:\n{habilidades_info}\n\n"
        f"**Habilidades com Notas Baixas (menor que 2.5)**:\n{', '.join(habilidades_baixas) if habilidades_baixas else 'Nenhuma habilidade com nota baixa.'}\n\n"
        f"**Habilidades com Notas Medianas (entre 2.5 e 4.0)**:\n{', '.join(habilidades_medias) if habilidades_medias else 'Nenhuma habilidade com nota mediana.'}\n\n"
        f"**Observações**: {observacoes}\n\n"
        f"**Sentimento das Observações**: {sentimento}\n"
    )

    try:
        logger.debug("Chamando xAI API para gerar resumo detalhado da avaliação")
        response = requests.post(
            "https://api.x.ai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {XAI_API_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "model": "grok-3",
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                "max_tokens": 800,
                "temperature": 0.7,
                "timeout": 10
            }
        )
        response.raise_for_status()

        result = response.json()
        raw_summary = result['choices'][0]['message']['content'].strip()

        # Extrair apenas o resumo formatado usando regex
        pattern = re.compile(
            r"\*\*Pontos Fortes:\*\*.*?\n-\n\*\*Áreas a Melhorar:\*\*.*?\n-\n\*\*Sugestões de Desenvolvimento:\*\*.*?(?=\n*$)",
            re.DOTALL
        )
        match = pattern.search(raw_summary)
        if match:
            summary = match.group(0).strip()
            # Verificar se há texto antes de **Pontos Fortes:**
            if raw_summary[:match.start()].strip():
                logger.warning(f"Texto indesejado encontrado antes de **Pontos Fortes:**: {raw_summary[:match.start()].strip()}")
        else:
            logger.warning(f"Resumo não contém o formato esperado: {raw_summary}")
            summary = (
                "**Pontos Fortes:**\nResumo incompleto devido a resposta inválida da API.\n-\n"
                "**Áreas a Melhorar:**\nResumo incompleto devido a resposta inválida da API.\n-\n"
                "**Sugestões de Desenvolvimento:**\nNenhuma sugestão gerada devido a erro na resposta.\n"
            )

        # Validar o formato do resumo
        required_sections = ["**Pontos Fortes:**", "**Áreas a Melhorar:**", "**Sugestões de Desenvolvimento:**"]
        if not all(section in summary for section in required_sections):
            logger.warning(f"Resumo fora do formato esperado após regex: {summary}")
            summary = (
                "**Pontos Fortes:**\nResumo incompleto devido a resposta inválida da API.\n-\n"
                "**Áreas a Melhorar:**\nResumo incompleto devido a resposta inválida da API.\n-\n"
                "**Sugestões de Desenvolvimento:**\nNenhuma sugestão gerada devido a erro na resposta.\n"
            )

        # Estimar número de palavras para validar limite de 300 palavras
        word_count = len(summary.split())
        if word_count > 350:
            logger.warning(f"Resumo excede limite de palavras: {word_count} palavras")
            summary = summary[:1000] + "\n(Resumo truncado para ajustar ao limite de tamanho)"

        # Salvar no cache (Redis) com expiração de 7 dias
        try:
            redis_client.setex(cache_key, timedelta(days=7), summary)
            logger.info(f"Resumo detalhado gerado e salvo no cache para avaliação ID {avaliacao.id}")
        except Exception as e:
            logger.warning(f"Erro ao salvar resumo no cache: {str(e)}")

        return summary

    except requests.exceptions.HTTPError as e:
        logger.error(f"Erro HTTP ao chamar xAI API: {str(e)}")
        logger.debug(f"Resposta da API: {e.response.text if e.response else 'Sem resposta'}")
        return (
            "**Pontos Fortes:**\nNão foi possível gerar o resumo devido a um erro na API.\n-\n"
            "**Áreas a Melhorar:**\nNão foi possível gerar o resumo devido a um erro na API.\n-\n"
            "**Sugestões de Desenvolvimento:**\nNenhuma sugestão disponível devido a erro na API.\n"
        )
    except requests.exceptions.RequestException as e:
        logger.error(f"Erro de rede ao chamar xAI API: {str(e)}")
        return (
            "**Pontos Fortes:**\nNão foi possível gerar o resumo devido a um erro de rede.\n-\n"
            "**Áreas a Melhorar:**\nNão foi possível gerar o resumo devido a um erro de rede.\n-\n"
            "**Sugestões de Desenvolvimento:**\nNenhuma sugestão disponível devido a erro de rede.\n"
        )
    except Exception as e:
        logger.error(f"Erro inesperado ao processar resumo detalhado: {str(e)}")
        return (
            "**Pontos Fortes:**\nNão foi possível gerar o resumo devido a um erro inesperado.\n-\n"
            "**Áreas a Melhorar:**\nNão foi possível gerar o resumo devido a um erro inesperado.\n-\n"
            "**Sugestões de Desenvolvimento:**\nNenhuma sugestão disponível devido a erro inesperado.\n"
        )


@app.route('/avaliar', methods=['GET', 'POST'])
def avaliar_funcionario():
    if 'usuario_id' not in session:
        logger.debug("Usuário não autenticado, redirecionando para login")
        return redirect(url_for('login'))

    usuario = g.usuario_logado
    setor_id = request.form.get('setor_filtro')
    
    if setor_id:
        funcionarios = Usuario.query.filter_by(setor_id=setor_id).filter(Usuario.is_admin == False).all()
    else:
        funcionarios = Usuario.query.filter(Usuario.is_admin == False).all()

    categorias = CategoriaHabilidade.query.filter_by(setor_id=usuario.setor_id).order_by(CategoriaHabilidade.nome).all()
    
    habilidades_por_categoria = {}
    for cat in categorias:
        habilidades_por_categoria[cat.nome] = Habilidades.query.filter_by(categoria_id=cat.id, ativa=True).all()

    if request.method == 'POST' and request.form.get('funcionario'):
        id_funcionario = request.form['funcionario']
        observacoes = request.form['observacoes']

        try:
            avaliacao = Avaliacao(
                id_funcionario=id_funcionario,
                id_avaliador=session['usuario_id'],
                observacoes=observacoes,
                data_avaliacao=datetime.now()
            )
            db.session.add(avaliacao)
            db.session.commit()
            logger.debug(f"Avaliação criada com ID {avaliacao.id}")

            for key, nota in request.form.items():
                if key.startswith('cat_'):
                    habilidade_id = int(key.split('_')[1])
                    habilidade = Habilidades.query.get(habilidade_id)
                    if habilidade:
                        # Capturar o comentário correspondente
                        comentario_key = f'comentario_{habilidade_id}'
                        comentario = request.form.get(comentario_key, '').strip()
                        
                        item = AvaliacaoItem(
                            id_avaliacao=avaliacao.id,
                            nome_habilidade=habilidade.nome,
                            categoria=habilidade.categoria.nome,
                            nota=float(nota),
                            comentario=comentario if comentario else None  # Salvar o comentário
                        )
                        db.session.add(item)
                        logger.debug(f"Item salvo: Habilidade {habilidade.nome}, Nota {nota}, Comentário {comentario}")

            db.session.commit()
            logger.debug(f"Itens de avaliação salvos para avaliação ID {avaliacao.id}")

            # Analisar sentimento usando cache
            sentimento = get_sentiment_from_cache_or_api(observacoes)
            avaliacao.sentimento = sentimento
            db.session.commit()
            logger.info(f"Sentimento salvo para avaliação ID {avaliacao.id}: {sentimento}")

            session['avaliacao_realizada'] = True
            flash('Avaliação registrada com sucesso!', 'success')
            return redirect(url_for('avaliar_funcionario'))
        
        except Exception as e:
            logger.error(f"Erro ao processar avaliação: {str(e)}")
            db.session.rollback()
            flash(f"Erro ao registrar avaliação: {str(e)}", 'danger')
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


def get_corrective_actions(avaliacao, itens, force_refresh=False):
    habilidades_baixas = [f"{item.categoria} - {item.nome_habilidade} ({item.nota}/5)" for item in itens if item.nota < 2.5]
    media_geral = sum(item.nota for item in itens) / len(itens) if itens else 0

    cache_key = f"acoes_corretivas:{avaliacao.id}:{media_geral:.2f}"
    
    # Invalidar cache se force_refresh=True
    if force_refresh:
        try:
            redis_client.delete(cache_key)
            logger.debug(f"Cache Redis invalidado para chave: {cache_key}")
        except Exception as e:
            logger.warning(f"Erro ao invalidar cache Redis: {str(e)}")

    # Verificar cache no Redis
    if not force_refresh:
        try:
            cached_actions = redis_client.get(cache_key)
            if cached_actions:
                logger.debug(f"Ações corretivas encontradas no cache (Redis) para avaliação ID {avaliacao.id}")
                return cached_actions.decode('utf-8') if isinstance(cached_actions, bytes) else cached_actions
        except Exception as e:
            logger.warning(f"Erro ao acessar o cache Redis: {str(e)}. Prosseguindo sem cache.")

    # Se não há habilidades com notas baixas, retornar uma resposta padrão
    if not habilidades_baixas:
        actions = "- Nenhuma ação corretiva necessária, pois não há habilidades com notas baixas."
        try:
            redis_client.setex(cache_key, timedelta(days=7), actions)
            logger.info(f"Resposta padrão salva no cache para avaliação ID {avaliacao.id}")
        except Exception as e:
            logger.warning(f"Erro ao salvar resposta padrão no cache: {str(e)}")
        return actions

    # Criar o prompt para a API
    system_prompt = (
        "Você é um assistente de RH que sugere ações corretivas para melhorar o desempenho de colaboradores. "
        "Com base nas informações fornecidas, gere exatamente 3 ações corretivas práticas e específicas para o colaborador. "
        "Considere o cargo, o setor e as habilidades com notas baixas (menores que 2.5). "
        "As ações devem ser claras, profissionais e no formato exato:\n"
        "- Ação 1\n"
        "- Ação 2\n"
        "- Ação 3\n"
        "Evite ações genéricas, texto introdutório ou explicações adicionais. "
        "Foque em soluções práticas, como treinamentos, mentorias ou tarefas específicas. "
        "Certifique-se de que cada ação comece com '- ' e seja uma frase completa."
    )
    user_prompt = (
        f"**Informações do Colaborador**:\n"
        f"Nome: {avaliacao.funcionario.nome}\n"
        f"Cargo: {avaliacao.funcionario.cargo}\n"
        f"Setor: {avaliacao.funcionario.setor.nome if avaliacao.funcionario.setor else 'Sem setor'}\n"
        f"Habilidades com Notas Baixas: {', '.join(habilidades_baixas)}\n"
        f"Média Geral: {media_geral:.2f}/5"
    )

    try:
        logger.debug("Chamando xAI API para gerar ações corretivas")
        response = requests.post(
            "https://api.x.ai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {XAI_API_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "model": "grok-3-mini-beta",
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                "max_tokens": 500,  # Aumentado para evitar truncamento
                "temperature": 0.5,  # Reduzido para maior consistência
                "timeout": 15  # Aumentado para respostas mais lentas
            }
        )
        response.raise_for_status()

        result = response.json()
        actions = result['choices'][0]['message']['content'].strip()
        logger.debug(f"Resposta bruta da API: {actions}")

        # Extrair ações usando regex mais flexível
        actions_list = [line.strip() for line in actions.split('\n') if line.strip().startswith('- ')]
        
        # Validar o formato
        if len(actions_list) >= 3 and all(line.startswith('- ') for line in actions_list):
            # Usar as primeiras 3 ações
            actions = '\n'.join(actions_list[:3])
            logger.info(f"Ações corretivas válidas geradas para avaliação ID {avaliacao.id}")
        else:
            # Tentar extrair ações com formato próximo (fallback)
            fallback_actions = re.findall(r'^-?\s*(.+?)(?=\n|$)', actions, re.MULTILINE)
            if len(fallback_actions) >= 3:
                actions = '\n'.join(f"- {action.strip()}" for action in fallback_actions[:3])
                logger.info(f"Ações corretivas recuperadas via fallback para avaliação ID {avaliacao.id}")
            else:
                logger.warning(f"Resposta da API fora do formato esperado: {actions}")
                actions = "- Nenhuma ação corretiva válida gerada. A API não retornou ações no formato esperado."

        # Salvar no cache (Redis) com expiração de 7 dias
        try:
            redis_client.setex(cache_key, timedelta(days=7), actions)
            logger.info(f"Ações corretivas geradas e salvas no cache para avaliação ID {avaliacao.id}")
        except Exception as e:
            logger.warning(f"Erro ao salvar ações no cache: {str(e)}")

        return actions

    except requests.exceptions.HTTPError as e:
        logger.error(f"Erro HTTP ao chamar xAI API: {str(e)}")
        logger.debug(f"Resposta da API: {e.response.text if e.response else 'Sem resposta'}")
        return f"- Não foi possível gerar ações corretivas devido a um erro HTTP na API (código: {e.response.status_code if e.response else 'desconhecido'})."
    except requests.exceptions.RequestException as e:
        logger.error(f"Erro de rede ao chamar xAI API: {str(e)}")
        return "- Não foi possível gerar ações corretivas devido a um erro de rede."
    except Exception as e:
        logger.error(f"Erro inesperado ao processar ações corretivas: {str(e)}")
        return "- Não foi possível gerar ações corretivas devido a um erro inesperado."


# Rota de análise de observação
@app.route('/analisar_observacao/<int:avaliacao_id>', methods=['GET'])
def analisar_observacao(avaliacao_id):
    if 'usuario_id' not in session:
        logger.debug("Usuário não autenticado, redirecionando para login")
        return redirect(url_for('login'))
    
    logger.debug(f"Iniciando análise para avaliação ID {avaliacao_id}")
    avaliacao = Avaliacao.query.get_or_404(avaliacao_id)

    # Verificar permissões: apenas o avaliador ou administrador pode acessar
    if avaliacao.id_avaliador != g.usuario_logado.id and not g.usuario_logado.is_admin:
        flash('Acesso negado: Você não tem permissão para visualizar esta avaliação.', 'danger')
        return redirect(url_for('dashboard_colaboradores'))

    observacoes = avaliacao.observacoes or ""
    
    # Analisar sentimento se ainda não foi analisado
    if not avaliacao.sentimento:
        if not observacoes.strip():
            flash('Observações vazias, não há nada para analisar.', 'warning')
            avaliacao.sentimento = "Não analisado"
        else:
            sentimento = get_sentiment_from_cache_or_api(observacoes)
            avaliacao.sentimento = sentimento
            db.session.commit()
            logger.info(f"Análise de sentimento para avaliação ID {avaliacao_id}: {sentimento}")
    
    # Buscar os itens da avaliação
    itens = AvaliacaoItem.query.filter_by(id_avaliacao=avaliacao_id).all()

    # Calcular a média geral
    media_geral = sum(item.nota for item in itens) / len(itens) if itens else 0

    # Calcular as cores para o gráfico
    background_colors = []
    border_colors = []
    for item in itens:
        if item.nota >= 4:
            background_colors.append('rgba(40, 167, 69, 0.7)')  # Verde
            border_colors.append('rgba(40, 167, 69, 1)')
        elif item.nota >= 2.5:
            background_colors.append('rgba(255, 193, 7, 0.7)')  # Amarelo
            border_colors.append('rgba(255, 193, 7, 1)')
        else:
            background_colors.append('rgba(220, 53, 69, 0.7)')  # Vermelho
            border_colors.append('rgba(220, 53, 69, 1)')

    # Recuperar o resumo mais recente
    ultimo_resumo = AvaliacaoResumo.query.filter_by(id_avaliacao=avaliacao_id).order_by(AvaliacaoResumo.data_criacao.desc()).first()
    resumo = ultimo_resumo.resumo if ultimo_resumo else None

    # Validar o resumo
    required_sections = ["**Pontos Fortes:**", "**Áreas a Melhorar:**", "**Sugestões de Desenvolvimento:**"]
    if resumo and (not all(section in resumo for section in required_sections) or resumo.strip().startswith("**Pontos Fortes:**") is False):
        logger.warning(f"Resumo inválido encontrado no banco para avaliação ID {avaliacao_id}: {resumo[:100]}...")
        resumo = get_detailed_evaluation_summary(avaliacao, itens, force_refresh=True)
        novo_resumo = AvaliacaoResumo(id_avaliacao=avaliacao_id, resumo=resumo)
        db.session.add(novo_resumo)
        db.session.commit()
        logger.info(f"Novo resumo gerado e salvo para avaliação ID {avaliacao_id} devido a resumo inválido")

    # Se não há resumo, gerar um novo
    if not resumo:
        resumo = get_detailed_evaluation_summary(avaliacao, itens, force_refresh=True)
        novo_resumo = AvaliacaoResumo(id_avaliacao=avaliacao_id, resumo=resumo)
        db.session.add(novo_resumo)
        db.session.commit()
        logger.info(f"Resumo inicial gerado e salvo para avaliação ID {avaliacao_id}")

    # Recuperar ações corretivas (se já geradas)
    acoes_corretivas = get_corrective_actions(avaliacao, itens) if itens else None

    # Inicializar variáveis para as novas abas
    feedback_status = session.pop('feedback_status', None)
    analise_comentarios = session.pop('analise_comentarios', None)
    perguntas_feedback = session.pop('perguntas_feedback', None)

    logger.debug("Renderizando template com detalhes da avaliação")
    return render_template(
        'analisar_observacao.html',
        avaliacao=avaliacao,
        itens=itens,
        resumo=resumo,
        acoes_corretivas=acoes_corretivas,
        feedback_status=feedback_status,
        analise_comentarios=analise_comentarios,
        perguntas_feedback=perguntas_feedback,
        usuario=g.usuario_logado,
        media_geral=media_geral,
        background_colors=background_colors,
        border_colors=border_colors
    )

@app.route('/analisar_observacao/<int:avaliacao_id>/regenerar_resumo', methods=['POST'])
def regenerar_resumo(avaliacao_id):
    if 'usuario_id' not in session:
        logger.debug("Usuário não autenticado, redirecionando para login")
        return redirect(url_for('login'))

    avaliacao = Avaliacao.query.get_or_404(avaliacao_id)
    if avaliacao.id_avaliador != g.usuario_logado.id and not g.usuario_logado.is_admin:
        flash('Acesso negado: Você não tem permissão para regenerar o resumo.', 'danger')
        return redirect(url_for('analisar_observacao', avaliacao_id=avaliacao_id))

    itens = AvaliacaoItem.query.filter_by(id_avaliacao=avaliacao_id).all()
    media_geral = sum(item.nota for item in itens) / len(itens) if itens else 0
    sentimento = avaliacao.sentimento or "Não analisado"

    # Invalidar o cache do Redis
    cache_key = f"resumo:{avaliacao_id}:{sentimento}:{media_geral:.2f}"
    try:
        redis_client.delete(cache_key)
        logger.debug(f"Cache Redis invalidado para chave: {cache_key}")
    except Exception as e:
        logger.warning(f"Erro ao invalidar cache Redis: {str(e)}")

    # Gerar novo resumo
    resumo = get_detailed_evaluation_summary(avaliacao, itens, force_refresh=True)
    novo_resumo = AvaliacaoResumo(id_avaliacao=avaliacao_id, resumo=resumo)
    db.session.add(novo_resumo)

    # Opcional: remover resumos antigos para evitar acumulação
    AvaliacaoResumo.query.filter(AvaliacaoResumo.id_avaliacao == avaliacao_id, AvaliacaoResumo.id != novo_resumo.id).delete()

    db.session.commit()
    logger.info(f"Novo resumo salvo para avaliação ID {avaliacao_id}")

    flash('Resumo regenerado com sucesso!', 'success')
    return redirect(url_for('analisar_observacao', avaliacao_id=avaliacao_id) + '#resumo')
# Rota para gerar ações corretivas

@app.route('/gerar_acao_corretiva/<int:avaliacao_id>', methods=['POST'])
def gerar_acao_corretiva(avaliacao_id):
    if 'usuario_id' not in session:
        logger.debug("Usuário não autenticado, redirecionando para login")
        return redirect(url_for('login'))

    avaliacao = Avaliacao.query.get_or_404(avaliacao_id)
    if avaliacao.id_avaliador != g.usuario_logado.id and not g.usuario_logado.is_admin:
        flash('Acesso negado: Você não tem permissão para gerar ações corretivas.', 'danger')
        return redirect(url_for('analisar_observacao', avaliacao_id=avaliacao_id))

    itens = AvaliacaoItem.query.filter_by(id_avaliacao=avaliacao_id).all()
    media_geral = sum(item.nota for item in itens) / len(itens) if itens else 0

    # Invalidar cache
    cache_key = f"acoes_corretivas:{avaliacao_id}:{media_geral:.2f}"
    try:
        redis_client.delete(cache_key)
        logger.debug(f"Cache Redis invalidado para chave: {cache_key}")
    except Exception as e:
        logger.warning(f"Erro ao invalidar cache Redis: {str(e)}")

    acoes_corretivas = get_corrective_actions(avaliacao, itens, force_refresh=True)
    flash('Ações corretivas geradas com sucesso!', 'success')
    return redirect(url_for('analisar_observacao', avaliacao_id=avaliacao_id) + '#acoes')


# Rota para enviar feedback ao colaborador
@app.route('/gerar_feedback_colaborador/<int:avaliacao_id>', methods=['POST'])
def gerar_feedback_colaborador(avaliacao_id):
    if 'usuario_id' not in session:
        logger.debug("Usuário não autenticado, redirecionando para login")
        return redirect(url_for('login'))

    avaliacao = Avaliacao.query.get_or_404(avaliacao_id)
    if avaliacao.id_avaliador != g.usuario_logado.id and not g.usuario_logado.is_admin:
        flash('Acesso negado: Você não tem permissão para enviar feedback.', 'danger')
        return redirect(url_for('analisar_observacao', avaliacao_id=avaliacao_id))

    ultimo_resumo = AvaliacaoResumo.query.filter_by(id_avaliacao=avaliacao_id).order_by(AvaliacaoResumo.data_criacao.desc()).first()
    if not ultimo_resumo:
        flash('Nenhum resumo disponível para enviar ao colaborador.', 'warning')
        return redirect(url_for('analisar_observacao', avaliacao_id=avaliacao_id) + '#feedback')

    resumo = ultimo_resumo.resumo

    # Limpar o feedback_status para permitir reenvio
    if 'feedback_status' in session:
        session.pop('feedback_status')

    try:
        # Verificar se o template existe (para depuração)
        template_path = os.path.join(app.root_path, 'templates/email', 'email_feedback.html')
        if not os.path.exists(template_path):
            raise FileNotFoundError(f"Template 'email_feedback.html' não encontrado em {template_path}")

        # Gerar a data atual formatada
        data_geracao = datetime.now().strftime('%d/%m/%Y %H:%M')

        # Gerar a URL para o PDF
        pdf_url = url_for('exportar_feedback_pdf', avaliacao_id=avaliacao_id, _external=True)

        # Renderizar o corpo HTML do e-mail
        html_content = render_template('email/email_feedback.html', 
                                       avaliacao=avaliacao, 
                                       resumo=resumo,
                                       pdf_url=pdf_url,
                                       data_geracao=data_geracao)

        # Definir a versão em texto simples
        texto_simples = f"Olá, {avaliacao.funcionario.nome},\n\nSegue o feedback da sua avaliação:\n\n{resumo}\n\nAtenciosamente,\nEquipe de Gestão"

        # Enviar o e-mail
        msg = Message(
            subject=f"Feedback da Avaliação #{avaliacao.id}",
            sender=app.config['MAIL_DEFAULT_SENDER'],
            recipients=[avaliacao.funcionario.email]
        )
        msg.body = texto_simples
        msg.html = html_content
        mail.send(msg)

        session['feedback_status'] = f"Feedback enviado com sucesso para {avaliacao.funcionario.email}!"
        logger.info(f"Feedback enviado para {avaliacao.funcionario.email} (Avaliação ID {avaliacao_id})")
    except Exception as e:
        logger.error(f"Erro ao enviar feedback: {str(e)}")
        session['feedback_status'] = f"Erro ao enviar feedback: {str(e)}"

    return redirect(url_for('analisar_observacao', avaliacao_id=avaliacao_id) + '#feedback')

# Rota para exportar o feedback em PDF (mantida para contexto)
@app.route('/exportar_feedback_pdf/<int:avaliacao_id>')
def exportar_feedback_pdf(avaliacao_id):
    if 'usuario_id' not in session:
        logger.debug("Usuário não autenticado, redirecionando para login")
        return redirect(url_for('login'))

    avaliacao = Avaliacao.query.get_or_404(avaliacao_id)
    if avaliacao.id_avaliador != g.usuario_logado.id and not g.usuario_logado.is_admin:
        flash('Acesso negado: Você não tem permissão para exportar este feedback.', 'danger')
        return redirect(url_for('analisar_observacao', avaliacao_id=avaliacao_id))

    # Verificar se o feedback foi gerado
    feedback_content = session.get('feedback_colaborador')
    if not feedback_content:
        flash('Nenhum feedback gerado para exportar. Gere o feedback primeiro.', 'warning')
        return redirect(url_for('analisar_observacao', avaliacao_id=avaliacao_id) + '#feedback')

    # Renderizar o template HTML para o PDF
    html_content = render_template('feedback_pdf.html', 
                                   avaliacao=avaliacao, 
                                   feedback_content=feedback_content)

    # Gerar o PDF usando pdfkit
    config = pdfkit.configuration(wkhtmltopdf='C:\\Program Files\\wkhtmltopdf\\bin\\wkhtmltopdf.exe')
    pdf_content = pdfkit.from_string(html_content, False, configuration=config)
    pdf_file = io.BytesIO(pdf_content)
    pdf_file.seek(0)

    # Enviar o PDF como resposta
    return send_file(
        pdf_file,
        mimetype='application/pdf',
        as_attachment=True,
        download_name=f'feedback_colaborador_{avaliacao_id}.pdf'
    )



@app.route('/teste_template')
def teste_template():
    logger.debug("Testando renderização do template")
    return render_template('analisar_observacao.html', avaliacao_id=0, observacoes="Teste", sentimento="Teste")

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


@app.route('/', methods=['GET'])
def dashboard_colaboradores():
    if 'usuario_id' not in session:
        logger.debug("Usuário não autenticado, redirecionando para login")
        return redirect(url_for('login'))

    # Filtros
    setor_filtro = request.args.get('setor')
    nome_filtro = request.args.get('nome', '').strip()
    media_min = request.args.get('media_min', type=float)
    media_max = request.args.get('media_max', type=float)

    # Consulta base - avaliações feitas pelo usuário logado
    query = db.session.query(
        Avaliacao,
        Usuario,
        Setor.nome.label('setor_nome'),
        db.func.avg(AvaliacaoItem.nota).label('media_geral')
    ).join(
        Usuario, Avaliacao.id_funcionario == Usuario.id
    ).join(
        Setor, Usuario.setor_id == Setor.id, isouter=True
    ).join(
        AvaliacaoItem, AvaliacaoItem.id_avaliacao == Avaliacao.id, isouter=True
    ).filter(
        Avaliacao.id_avaliador == g.usuario_logado.id
    ).group_by(
        Avaliacao.id, Usuario.id, Setor.nome
    )

    # Aplicar filtros
    if setor_filtro:
        query = query.filter(Setor.nome == setor_filtro)
    
    if nome_filtro:
        query = query.filter(Usuario.nome.ilike(f'%{nome_filtro}%'))

    # Executar a consulta e processar os resultados
    dados = []
    for avaliacao, usuario, setor_nome, media_geral in query.all():
        media_geral = round(float(media_geral), 2) if media_geral else 0
        
        # Aplicar filtros de média
        if (media_min is not None and media_geral < media_min) or \
           (media_max is not None and media_geral > media_max):
            continue
        
        dados.append({
            'id': avaliacao.id,
            'nome': usuario.nome,
            'cargo': usuario.cargo,
            'setor': setor_nome if setor_nome else 'Sem setor',
            'media_geral': media_geral,
            'observacoes': avaliacao.observacoes,
            'sentimento': avaliacao.sentimento if avaliacao.sentimento else 'Não analisado',
            'data_avaliacao': avaliacao.data_avaliacao
        })

    # Ordenar por data de avaliação (mais recente primeiro)
    dados.sort(key=lambda x: x['data_avaliacao'], reverse=True)

    # Estatísticas
   # Na sua rota dashboard_colaboradores
    total_avaliados = len({avaliacao.id_funcionario for avaliacao, _, _, _ in query.all()})
    total_avaliacoes = len(dados)
    media_geral_geral = round(sum(d['media_geral'] for d in dados) / total_avaliacoes, 2) if total_avaliacoes > 0 else 0

    logger.debug(f"Total de avaliações do usuário {g.usuario_logado.nome}: {total_avaliacoes}")

    return render_template(
        'dashboard.html',
        dados=dados,
        setores=Setor.query.all(),
        setor_filtro=setor_filtro,
        total_colaboradores=total_avaliados,
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





if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        app.run(host='192.168.10.34', port=8000, debug=True)

