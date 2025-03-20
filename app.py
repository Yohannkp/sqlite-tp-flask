from datetime import datetime
from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, RadioField
from wtforms.validators import DataRequired, Length, EqualTo
from flask_bcrypt import Bcrypt
from sqlalchemy import text
from functools import wraps
from flask_mysqldb import MySQL
import uvicorn
from flask_socketio import SocketIO, emit
from flask_login import LoginManager, login_required, current_user,login_user
import os

app = Flask(__name__)

app.config['SECRET_KEY'] = 'ma_cle_secrete'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Initialisation de Flask-SocketIO
socketio = SocketIO(app)

# Configurer Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login'
db = SQLAlchemy(app)

bcrypt = Bcrypt(app)


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Veuillez vous connecter d'abord.", 'warning')
            return redirect(url_for('login'))
        
        if session.get('role') != 'admin':  # Vérifie si l'utilisateur est admin
            flash("Accès refusé. Vous n'avez pas les permissions nécessaires.", 'error')
            return redirect(url_for('tickets'))
        
        return f(*args, **kwargs)
    return decorated_function

# @app.route('/ticket/<int:ticket_id>', methods=['GET', 'POST'])
# def ticket_view(ticket_id):
#     ticket = Ticket.query.get_or_404(ticket_id)
    
#     # Vérifier si l'utilisateur actuel est l'utilisateur du ticket ou un administrateur
#     if ticket.user_id != session['user_id'] and session['role'] != 'admin':
#         return redirect(url_for('index'))  # Redirige si l'utilisateur n'est pas associé au ticket
    
#     # Récupérer tous les messages liés à ce ticket
#     messages = Message.query.filter_by(ticket_id=ticket_id).order_by(Message.timestamp.asc()).all()

#     if request.method == 'POST':
#         content = request.form.get('content')
        
#         # Créer un nouveau message
#         new_message = Message(ticket_id=ticket.id, user_id=session['user_id'], content=content, timestamp=datetime.utcnow())
        
#         # Si l'utilisateur est un admin, nous définissons le champ admin_id pour la réponse
#         if session['role'] == 'admin':
#             new_message.admin_id = session['user_id']

#         # Ajouter le message à la base de données
#         db.session.add(new_message)
#         db.session.commit()

#         # Rediriger vers la page du ticket pour voir les nouveaux messages
#         return redirect(url_for('ticket_view', ticket_id=ticket.id))

#     return render_template('ticket_view.html', ticket=ticket, messages=messages)

@app.route('/ticket/<int:ticket_id>', methods=['GET', 'POST'])

def ticket_view(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    
    if ticket.user_id != current_user.id and current_user.role != 'admin':
        return redirect(url_for('index'))  # Redirige si l'utilisateur n'est pas associé au ticket

    # Récupérer tous les messages liés à ce ticket
    messages = Message.query.filter_by(ticket_id=ticket_id).order_by(Message.timestamp.asc()).all()

    return render_template('ticket_view.html', ticket=ticket, messages=messages, ticket_id=ticket_id)

# La fonction user_loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route('/send_message',methods=["POST"])
def send_message():
    ticket_id = request.form['ticket_id']
    content = request.form['content']
    
    # Créer un nouveau message
    new_message = Message(ticket_id=ticket_id, user_id=current_user.id, content=content, timestamp=datetime.utcnow())
    
    # Si l'utilisateur est un admin, nous définissons le champ admin_id
    if current_user.role == 'admin':
        new_message.admin_id = current_user.id
    
    db.session.add(new_message)
    db.session.commit()

    # Émettre un événement pour que le message apparaisse en temps réel
    socketio.emit('new_message', {
        'user': current_user.username,
        'content': content,
        'timestamp': new_message.timestamp.strftime('%Y-%m-%d %H:%M:%S')
    }, room=ticket_id)

    return redirect(url_for('ticket_view', ticket_id=ticket_id))


@app.route('/admin/tickets')
def admin_tickets():
    if session['role'] != 'admin':
        return redirect(url_for('index'))  # L'utilisateur n'est pas un admin, redirection

    tickets = Ticket.query.all()  # Afficher tous les tickets pour l'admin
    return render_template('admin_tickets.html', tickets=tickets)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey('ticket.id'), nullable=False)  # Clé étrangère vers le ticket
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Clé étrangère vers l'utilisateur
    admin_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Clé étrangère vers l'administrateur (peut être NULL si l'utilisateur est l'auteur du message)
    content = db.Column(db.Text, nullable=False)  # Contenu du message
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)  # Horodatage du message
    
    ticket = db.relationship('Ticket', backref=db.backref('messages', lazy=True))
    user = db.relationship('User', foreign_keys=[user_id], backref=db.backref('user_messages', lazy=True))
    admin = db.relationship('User', foreign_keys=[admin_id], backref=db.backref('admin_messages', lazy=True))


# Modèle Utilisateur
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(60), nullable=True)
    tasks = db.relationship('Task', backref='user', lazy=True)
    tickets = db.relationship('Ticket', backref='user', lazy=True)
    
    def is_active(self):
        return True  # Renvoie True si l'utilisateur est actif. Tu peux aussi implémenter une logique personnalisée.

    # Si tu utilises Flask-Login, tu peux aussi ajouter ces méthodes d'autres attributs par défaut :
    def get_id(self):
        return str(self.id)
class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Clé étrangère
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(50), nullable=False, default="ouvert")  # Exemple : ouvert, en cours, fermé
    
# Modèle Tâches
class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Formulaire d'inscription
class RegistrationForm(FlaskForm):
    username = StringField("Nom d'utilisateur", validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField("Mot de passe", validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField("Confirmer le mot de passe", validators=[DataRequired(), EqualTo('password')])
    role = RadioField('Role', choices=[('admin', 'Admin'), ('user', 'User')], default='user')
    submit = SubmitField("S'inscrire")

# Formulaire de connexion
class LoginForm(FlaskForm):
    username = StringField("Nom d'utilisateur", validators=[DataRequired()])
    password = PasswordField("Mot de passe", validators=[DataRequired()])
    submit = SubmitField("Se connecter")
    
# Formulaire de Mot de pass oublié
class ForgetPassword(FlaskForm):
    username = StringField("Nom d'utilisateur", validators=[DataRequired()])
    new_password = PasswordField("Mot de passe", validators=[DataRequired()])
    confirm_new_password = PasswordField("Confirmation mot de passe", validators=[DataRequired()])
    submit = SubmitField("Se connecter")

with app.app_context():
    db.create_all()
    
# Initialiser Flask-Migrate
migrate = Migrate(app, db)
@app.route('/')
def index():
    if session:
        tasks = Task.query.all()
        tickets = db.session.query(Ticket.id, Ticket.title, Ticket.description, Ticket.status, User.username, User.id.label("user_id")) \
                            .join(User, Ticket.user_id == User.id).all()
        
        total_users = User.query.count()
        total_tickets = Ticket.query.count()
        open_tickets = Ticket.query.filter_by(status="open").count()
        closed_tickets = Ticket.query.filter_by(status="closed").count()
        in_progress_tickets = Ticket.query.filter_by(status="in progress").count()
        pending_tickets = Ticket.query.filter_by(status="pending").count()
        if session['role'] == "user":
            tasks = Task.query.filter_by(user_id=session["user_id"]).all()
            ticket = Ticket.query.filter_by(user_id=session["user_id"]).all()
            print(ticket)
            return render_template('index.html',tasks = tasks,tickets = ticket)
        return render_template('index.html',total_users=total_users, 
                            total_tickets=total_tickets, 
                            open_tickets=open_tickets,
                            tasks=tasks, 
                            tickets=tickets,
                            closed_tickets = closed_tickets,
                            in_progress_tickets = in_progress_tickets,
                            pending_tickets = pending_tickets)
    else:
        return redirect(url_for('login'))

# Page d'inscription
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data ,rounds=5).decode('utf-8')
        user = User(username=form.username.data, password=hashed_password,role = form.role.data)
        db.session.add(user)
        db.session.commit()
        flash('Inscription réussie ! Vous pouvez vous connecter.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)









# Page de connexion
@app.route('/login', methods=['GET', 'POST'])

def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            print(user.password,form.password.data)
            print(bcrypt.check_password_hash(user.password, form.password.data))
            session['username'] = user.username
            session['user_id'] = user.id
            session['role'] = user.role
            
            login_user(user)
            flash('Connexion réussie !', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Identifiants incorrects.', 'danger')
    return render_template('login.html', form=form)



@app.route('/delete_ticket/<int:ticket_id>', methods=['POST','GET'])
def delete_ticket(ticket_id):
    if 'user_id' not in session:
        flash("Veuillez vous connecter d'abord.", 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']
    ticket = Ticket.query.filter_by(id=ticket_id, user_id=user_id).first()

    if ticket:
        db.session.delete(ticket)
        db.session.commit()
        flash("Ticket supprimé avec succès.", 'success')
    else:
        flash("Ticket introuvable ou non autorisé.", 'error')

    return redirect(url_for('index'))

@app.route('/user_tickets/<int:user_id>', methods=['GET'])
def view_user_tickets(user_id):
    if 'user_id' not in session:
        flash("Veuillez vous connecter d'abord.", 'warning')
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    if not user:
        flash("Utilisateur introuvable.", 'error')
        return redirect(url_for('tickets'))

    tickets = Ticket.query.filter_by(user_id=user_id).all()

    return render_template('user_tickets.html', username=user.username, tickets=tickets)


@app.route('/edit_ticket/<int:ticket_id>', methods=['GET', 'POST'])
def edit_ticket(ticket_id):
    if 'user_id' not in session:
        flash("Veuillez vous connecter d'abord.", 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']
    ticket = Ticket.query.filter_by(id=ticket_id, user_id=user_id).first()

    if not ticket:
        flash("Ticket introuvable ou vous n'avez pas les permissions.", 'error')
        return redirect(url_for('tickets'))

    if request.method == 'POST':
        ticket.title = request.form.get('title')
        ticket.description = request.form.get('description')

        db.session.commit()
        flash("Ticket modifié avec succès.", 'success')
        return redirect(url_for('tickets'))

    return render_template('edit_ticket.html', ticket=ticket)


@app.route('/tickets', methods=['GET', 'POST'])
def tickets():
    if 'user_id' not in session:
        flash("Veuillez vous connecter d'abord.", 'warning')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        priority = request.form.get('priority', 'normale')  # Valeur par défaut
        status = "ouvert"  # Tous les nouveaux tickets sont "ouverts" par défaut

        if title and description:
            new_ticket = Ticket(title=title, description=description, status=status, user_id=user.id)
            db.session.add(new_ticket)
            db.session.commit()
            flash("Ticket ajouté avec succès.", 'success')

    tickets = Ticket.query.filter_by(user_id=user.id).all()
    return render_template('tickets.html', username=user.username, tickets=tickets)






# Tableau de bord avec gestion des tâches
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        flash("Veuillez vous connecter d'abord.", 'warning')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        task_content = request.form.get('task')
        if task_content:
            new_task = Task(content=task_content, user_id=user.id)
            db.session.add(new_task)
            db.session.commit()
            flash("Tâche ajoutée avec succès.", 'success')

    tasks = Task.query.filter_by(user_id=user.id).all()
    return render_template('dashboard.html', username=user.username, tasks=tasks)

# Suppression de tâche
@app.route('/delete_task/<int:task_id>')
def delete_task(task_id):
    if 'user_id' not in session:
        flash("Veuillez vous connecter d'abord.", 'warning')
        return redirect(url_for('login'))

    task = Task.query.get(task_id)
    
    if task and task.user_id == session['user_id']:
        db.session.delete(task)
        db.session.commit()
        flash("Tâche supprimée.", 'info')
    
    return redirect(url_for('dashboard'))

# Déconnexion
@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('user_id', None)
    session.pop('role',None)
    flash("Déconnexion réussie.", 'info')
    return redirect(url_for('login'))


# Mot de passe oublié
@app.route('/forget_password', methods=['GET','POST'])

def forgetpassword():
   form = ForgetPassword()
   if form.validate_on_submit():
        new_password = request.form['new_password']
        confirm_new_password = request.form['confirm_new_password']

        if new_password != confirm_new_password:
            flash("Les nouveaux mots de passe ne correspondent pas.", "error")
            return render_template('mdp.html',form=form)
        hashed_password = bcrypt.generate_password_hash(form.new_password.data ,rounds=5).decode('utf-8')
        conn = db.engine.connect()
        conn.execute(text("UPDATE user SET password = :password WHERE username = :username"), 
             {"password": hashed_password, "username": form.username.data})
        conn.commit()
        conn.close()
        flash("Mot de passe changé avec succes", 'success')
        return redirect(url_for('login'))

   return render_template('mdp.html',form=form)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Crée la base de données si elle n'existe pas
    port = int(os.getenv("PORT", 8000))  # Railway définit dynamiquement le port
    uvicorn.run(app, host="", port=port)
    app.run(host='10.74.3.216', port=8080,debug=True)
