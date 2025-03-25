from flask import Flask, render_template, request, redirect, url_for, flash
import sqlite3        
import os 
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Establecer la vista de login
login_manager = LoginManager(app)
login_manager.login_view = 'login' 

# Conectar a la base de datos
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

# Crear la base de datos y tablas si no existen
def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            due_date TIMESTAMP,
            user_id INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    conn.commit()
    conn.close()

# Llamar la funcion para inicializar la base de datos
init_db()

# Configurar Flask-Login para cargar el usuario por su ID
class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    if user:
        return User(user['id'], user['username'])
    return None

# Ruta para el registro de usuario
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password_hash = generate_password_hash(password)

        conn = get_db_connection()
        # Verificar si el usuario ya existe
        existing_user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

        if existing_user:
            flash("El nombre de usuario ya existe. Intenta con otro.", 'danger')
            return redirect(url_for('register'))

        # Guardar el nuevo usuario en la base de datos
        conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password_hash))
        conn.commit()
        conn.close()
        flash("Usuario registrado con éxito. Puedes iniciar sesión ahora.", 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

# Ruta para el login de usuario
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))  # Si ya esta autenticado se redirige a tareas

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            login_user(User(user['id'], user['username']))
            return redirect(url_for('index'))  # Redirige a la pagina de tareas si las credenciales son correctas
        flash("Credenciales incorrectas, intenta de nuevo.", 'danger')

    return render_template('login.html')

# Ruta para cerrar la sesion
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Ruta para lista de tareas
@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('index'))  # Si esta autenticado se redirige a la pagina de tareas
    return redirect(url_for('login'))  # Si no esta autenticado se redirige al login

# Ruta para la pagina de tareas 
@app.route('/index')
@login_required
def index():
    conn = get_db_connection()
    tasks = conn.execute('SELECT * FROM tasks WHERE user_id = ?', (current_user.id,)).fetchall()
    conn.close()
    return render_template('index.html', tasks=tasks)

# Ruta para agregar una tarea
@app.route('/add_task', methods=['GET', 'POST'])
@login_required
def add_task():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        due_date = request.form['due_date']
        conn = get_db_connection()
        conn.execute('INSERT INTO tasks (title, description, due_date, user_id) VALUES (?, ?, ?, ?)',
                     (title, description, due_date, current_user.id))
        conn.commit()
        conn.close()
        return redirect(url_for('index'))
    return render_template('add_task.html')

# Ruta para editar una tarea
@app.route('/edit_task/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_task(id):
    conn = get_db_connection()
    task = conn.execute('SELECT * FROM tasks WHERE id = ?', (id,)).fetchone()
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        due_date = request.form['due_date']
        conn.execute('UPDATE tasks SET title = ?, description = ?, due_date = ? WHERE id = ?',
                     (title, description, due_date, id))
        conn.commit()
        conn.close()
        return redirect(url_for('index'))
    conn.close()
    return render_template('edit_task.html', task=task)

# Ruta para eliminar una tarea
@app.route('/delete_task/<int:id>', methods=['POST'])
@login_required
def delete_task(id):
    conn = get_db_connection()
    conn.execute('DELETE FROM tasks WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    return redirect(url_for('index'))

if __name__ == '__main__':
    port=int(os.environ.get('PORT',5000))   
    app.run(host='0.0.0.0', port=port)

