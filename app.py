import os
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, flash, request
from werkzeug.utils import secure_filename
from flask import Flask, render_template, redirect, url_for, flash, request
from werkzeug.utils import secure_filename

# --- Placeholder para la extracción de datos del comprobante ---
def extract_data_from_comprobante(file_path):
    """
    Función placeholder para simular la extracción de datos de un comprobante.
    En una implementación real, esto usaría OCR o una API de procesamiento de documentos.
    Retorna un diccionario con los datos extraídos o None si falla.
    """
    # Simulación: 50% de probabilidad de éxito
    import random
    if random.random() < 0.5: # Simula un fallo en la lectura
        return None
    else:
        # Datos de ejemplo (ajustar según el formato real del comprobante)
        return {
            'proof_number': 'COMPR-12345',
            'amount': 150.75,
            'origin_account': 'ES12345678901234567890',
            'destination_account': 'ES09876543210987654321',
            'timestamp': datetime.now(),
            'description': 'Depósito automático por comprobante'
        }

from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

# --- Configuración ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'una-clave-secreta-muy-dificil-de-adivinar'
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'deposits.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Por favor, inicia sesión para acceder a esta página.'

# --- Modelos de la Base de Datos ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='normal') # Roles: 'admin' o 'normal'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self):
        return self.role == 'admin'

class Deposit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(200), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    proof_number = db.Column(db.String(100), nullable=True) # Nuevo campo
    origin_account = db.Column(db.String(100), nullable=True) # Nuevo campo
    destination_account = db.Column(db.String(100), nullable=True) # Nuevo campo
    # Este ID ahora se refiere al usuario al que pertenece el depósito
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    # ID del admin que crea el depósito
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    recipient = db.relationship('User', foreign_keys=[recipient_id], backref=db.backref('deposits', lazy='dynamic'))
    creator = db.relationship('User', foreign_keys=[creator_id], backref=db.backref('created_deposits', lazy=True))

# --- Cargar Usuario para Flask-Login ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Decorador para rutas de Admin ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            flash('Esta área es solo para administradores.', 'warning')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# --- Rutas de Autenticación ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and user.check_password(request.form['password']):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Usuario o contraseña inválidos.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- Rutas Principales ---
@app.route('/')
def index():
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
@login_required
def dashboard():
    page = request.args.get('page', 1, type=int)
    
    # Suma total de todos los depósitos en el sistema (visible para todos)
    global_total_sum = db.session.query(db.func.sum(Deposit.amount)).scalar() or 0

    # Suma de los depósitos personales del usuario actual (recibidos por él)
    personal_total_sum = db.session.query(db.func.sum(Deposit.amount)).filter(Deposit.recipient_id == current_user.id).scalar() or 0

    if current_user.is_admin:
        # El admin ve todos los depósitos con paginación, ordenados por fecha
        deposits_query = Deposit.query.order_by(Deposit.timestamp.desc())
    else:
        # Un usuario normal solo ve sus propios depósitos, ordenados por fecha
        deposits_query = current_user.deposits.order_by(Deposit.timestamp.desc())

    # Se usará un máximo de 5 depósitos por página
    deposits_pagination = deposits_query.paginate(page=page, per_page=5, error_out=False)
    deposits = deposits_pagination.items

    return render_template(
        'dashboard.html', 
        deposits=deposits, 
        global_total_sum=global_total_sum, 
        personal_total_sum=personal_total_sum,
        pagination=deposits_pagination
    )

# --- Rutas de Depósitos (CRUD para Admins) ---
@app.route('/deposit/new', methods=['GET', 'POST'])
@login_required
@admin_required
def create_deposit():
    users = User.query.all()
    if request.method == 'POST':
        description = request.form['description']
        amount = float(request.form['amount'])
        recipient_id = request.form['user_id']
        new_deposit = Deposit(description=description, amount=amount, recipient_id=recipient_id, creator_id=current_user.id)
        db.session.add(new_deposit)
        db.session.commit()
        flash('Depósito creado exitosamente.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('create_deposit.html', users=users)

@app.route('/deposit/<int:deposit_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_deposit(deposit_id):
    deposit = Deposit.query.get_or_404(deposit_id)
    users = User.query.all()
    if request.method == 'POST':
        deposit.description = request.form['description']
        deposit.amount = float(request.form['amount'])
        deposit.recipient_id = request.form['user_id']
        db.session.commit()
        flash('Depósito actualizado exitosamente.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('edit_deposit.html', deposit=deposit, users=users)

@app.route('/deposit/<int:deposit_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_deposit(deposit_id):
    deposit = Deposit.query.get_or_404(deposit_id)
    db.session.delete(deposit)
    db.session.commit()
    flash('Depósito eliminado exitosamente.', 'success')
    return redirect(url_for('dashboard'))

# --- Rutas de Gestión de Usuarios (para Admins) ---
@app.route('/users')
@login_required
@admin_required
def list_users():
    users = User.query.all()
    return render_template('users.html', users=users)

@app.route('/user/new', methods=['GET', 'POST'])
@login_required
@admin_required
def create_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('El nombre de usuario ya existe.', 'danger')
        else:
            new_user = User(username=username, role=role)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            flash('Usuario creado exitosamente.', 'success')
            return redirect(url_for('list_users'))
    return render_template('create_user.html')

@app.route('/user/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        user.username = request.form['username']
        user.role = request.form['role']
        password = request.form['password']
        if password:
            user.set_password(password)
        db.session.commit()
        flash('Usuario actualizado exitosamente.', 'success')
        return redirect(url_for('list_users'))
    return render_template('edit_user.html', user=user)

@app.route('/user/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    # Prevenir que el admin se elimine a sí mismo
    if user.id == current_user.id:
        flash('No puedes eliminar tu propia cuenta de administrador.', 'danger')
        return redirect(url_for('list_users'))
    # Eliminar depósitos asociados
    Deposit.query.filter_by(recipient_id=user.id).delete()
    db.session.delete(user)
    db.session.commit()
    flash('Usuario y sus depósitos asociados han sido eliminados.', 'success')
    return redirect(url_for('list_users'))

# --- Inicialización y Ejecución ---
def init_db():
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin_user = User(username='admin', role='admin')
            admin_user.set_password('admin')
            db.session.add(admin_user)
            print("Usuario 'admin' creado con contraseña 'admin'.")
        if not User.query.filter_by(username='usuario_normal').first():
            normal_user = User(username='usuario_normal', role='normal')
            normal_user.set_password('normal123')
            db.session.add(normal_user)
            print("Usuario 'usuario_normal' creado con contraseña 'normal123'.")
            
            # Commit para obtener los IDs de los usuarios
            db.session.commit()

            # Añadir un depósito de ejemplo
            admin_user = User.query.filter_by(username='admin').first()
            normal_user = User.query.filter_by(username='usuario_normal').first()
            if admin_user and normal_user and not Deposit.query.first():
                sample_deposit = Deposit(
                    description='Depósito inicial de bienvenida',
                    amount=100.00,
                    recipient_id=normal_user.id,
                    creator_id=admin_user.id
                )
                db.session.add(sample_deposit)
                print("Depósito de ejemplo creado.")

        db.session.commit()

if __name__ == '__main__':
    init_db()
    app.run(debug=True)