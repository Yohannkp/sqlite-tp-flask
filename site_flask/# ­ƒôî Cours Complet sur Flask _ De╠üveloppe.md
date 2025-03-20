# Cours Complet sur Flask : Développement Web en Python

###  Créer une application Flask
Crée un fichier **`app.py`** avec le code suivant :
```python
from flask import Flask

app = Flask(__name__)

@app.route('/')
def home():
    return "Bienvenue sur mon application Flask ! 🚀"

if __name__ == '__main__':
    app.run(debug=True)
```
➡️ Lance l’application :
```bash
python app.py
```
➡️ Accède à **http://127.0.0.1:5000/** depuis ton navigateur.

---

##  Les Routes et les Méthodes HTTP
Une **route** est une URL qui permet d’accéder à une ressource. Flask permet de définir ces routes avec le décorateur `@app.route()`.

### Définir des Routes Simples
```python
@app.route('/hello')
def hello():
    return "Hello, World!"
```
🔹 En accédant à **http://127.0.0.1:5000/hello**, tu verras "Hello, World!".

### Routes avec Paramètres
```python
@app.route('/user/<name>')
def user(name):
    return f"Salut {name} !"
```
➡️ Si tu accèdes à **http://127.0.0.1:5000/user/Alex**, Flask affichera :
```
Salut Alex !
```

### Routes avec Méthodes HTTP
Par défaut, Flask utilise **GET**, mais tu peux aussi gérer d’autres méthodes :
```python
@app.route('/data', methods=['POST'])
def receive_data():
    return "Données reçues avec succès !", 201
```
➡️ Pour tester :
```bash
curl -X POST http://127.0.0.1:5000/data
```

---

## Gestion des Templates avec Jinja2
Flask utilise **Jinja2** pour générer du HTML dynamique.

### 3.1 Créer un Template
Dans le dossier **`templates/`**, crée un fichier **`index.html`** :
```html
<!DOCTYPE html>
<html lang="fr">
<head>
    <title>Accueil</title>
</head>
<body>
    <h1>Bienvenue, {{ name }} !</h1>
</body>
</html>
```

### 3.2 Afficher le Template depuis Flask
```python
from flask import render_template

@app.route('/welcome/<name>')
def welcome(name):
    return render_template('index.html', name=name)
```
➡️ En accédant à **http://127.0.0.1:5000/welcome/Alex**, le HTML affichera :
```html
<h1>Bienvenue, Alex !</h1>
```

---

## 4️⃣ Gérer les Formulaires et les Requêtes
Flask permet d’envoyer et de récupérer des données via **formulaires HTML** et **requêtes POST**.

### 4.1 Formulaire HTML
Crée un fichier **`form.html`** :
```html
<form action="/submit" method="post">
    <input type="text" name="username" placeholder="Entrez votre nom">
    <input type="submit" value="Envoyer">
</form>
```

### 4.2 Récupérer les Données en Flask
```python
from flask import request

@app.route('/submit', methods=['POST'])
def submit():
    username = request.form['username']
    return f"Bonjour, {username} !"
```

---

## 5️⃣ Connexion à une Base de Données avec SQLAlchemy
Flask ne gère pas directement les bases de données, mais il peut utiliser **SQLAlchemy**.

### 5.1 Installer SQLAlchemy
```bash
pip install flask-sqlalchemy
```

### 5.2 Configurer une Base de Données
```python
from flask_sqlalchemy import SQLAlchemy

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
```

### 5.3 Créer un Modèle
```python
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
```

### 5.4 Ajouter un Utilisateur
```python
@app.route('/add_user/<name>')
def add_user(name):
    user = User(name=name)
    db.session.add(user)
    db.session.commit()
    return f"Utilisateur {name} ajouté avec succès !"
```

---

## 6️⃣ Authentification avec Flask-Login
Si tu veux gérer des connexions utilisateurs, **Flask-Login** est une extension utile.

### 6.1 Installer Flask-Login
```bash
pip install flask-login
```

### 6.2 Exemple Simplifié
```python
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user

login_manager = LoginManager()
login_manager.init_app(app)

class User(UserMixin):
    def __init__(self, id):
        self.id = id

@app.route('/login')
def login():
    user = User(id=1)  
    login_user(user)
    return "Connecté !"

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return "Déconnecté !"
```

---

## 7️⃣ Déploiement de Flask
Flask est conçu pour le développement, mais en production, on utilise **Gunicorn** et **Docker**.

### 7.1 Installer Gunicorn
```bash
pip install gunicorn
```

### 7.2 Lancer Flask en Production
```bash
gunicorn -w 4 app:app
```

---

## 🎯 Résumé
✅ **Installation** de Flask et mise en place d’une application.  
✅ **Routes et méthodes HTTP** pour gérer les requêtes.  
✅ **Templates Jinja2** pour générer du HTML dynamique.  
✅ **Gestion des formulaires** et des requêtes POST.  
✅ **Connexion à une base de données avec SQLAlchemy**.  
✅ **Authentification avec Flask-Login**.  
✅ **Déploiement avec Gunicorn et Docker**.  

---

## 🚀 Prochaines étapes
- Construire une API REST avec Flask-RESTful.  
- Tester ton application avec `pytest`.  
- Sécuriser l’application avec Flask-WTF.  

Besoin d’un projet pratique ? 🚀

