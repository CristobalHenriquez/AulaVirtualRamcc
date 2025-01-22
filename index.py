import os
import uuid
import secrets
import yaml
import io
import bcrypt
import pprint
import traceback 
import pymysql
from itsdangerous import URLSafeTimedSerializer as Serializer, BadSignature, SignatureExpired
from werkzeug.security import generate_password_hash
from datetime import datetime, timedelta, timezone
from flask import Flask, render_template, send_file, request, redirect, url_for, flash, session, jsonify
from flask_mail import Mail, Message
from werkzeug.utils import secure_filename
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, IntegerField, FileField, FieldList, FormField
from wtforms.validators import DataRequired


# Inicializa la aplicación Flask
app = Flask(__name__)
# Establece una llave secreta fija
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

# Definimos una nueva clave secreta para el serializer
serializer = Serializer(app.secret_key)
# Configuración del directorio de subidas
app.config['UPLOAD_FOLDER'] = 'static/uploads'

# Cargar configuración de la base de datos desde db.yaml
with open('db.yaml') as f:
    db = yaml.load(f, Loader=yaml.FullLoader)

# Configuración de la base de datos
db_config = {
    'host': db['mysql_host'],
    'user': db['mysql_user'],
    'password': db['mysql_password'],
    'database': db['mysql_db'],
    'port': int(db['mysql_port'])
}

# Configuración de Flask-Mail
app.config['MAIL_SERVER'] = 'localhost'
app.config['MAIL_PORT'] = 8025
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USERNAME'] = None
app.config['MAIL_PASSWORD'] = None
app.config['MAIL_DEFAULT_SENDER'] = 'cristobalhb@live.com'  # Puedes configurar esto según sea necesario
mail = Mail(app)

# Definiciones de formularios WTForms
class RecursoForm(FlaskForm):
    tipo = StringField('Tipo', validators=[DataRequired()])
    descripcion = TextAreaField('Descripcion')
    url = StringField('URL')
    archivo = FileField('Archivo')

class ModuloForm(FlaskForm):
    titulo = StringField('Titulo', validators=[DataRequired()])
    descripcion = TextAreaField('Descripcion')
    recursos = FieldList(FormField(RecursoForm), min_entries=1)

class CursoForm(FlaskForm):
    titulo = StringField('Titulo', validators=[DataRequired()])
    descripcion = TextAreaField('Descripcion')
    cantidad_horas = IntegerField('Cantidad de Horas')
    imagen = FileField('Imagen del Curso')
    programa_pdf = FileField('Programa PDF')
    modulos = FieldList(FormField(ModuloForm), min_entries=1)

# Función para verificar si el archivo cumple con los criterios permitidos
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}

# Función para obtener una nueva conexión a la base de datos
def get_db_connection():
    try:
        # Leer configuración desde db.yaml
        with open("db.yaml", "r") as file:
            db_config = yaml.safe_load(file)

        # Conexión usando pymysql
        connection = pymysql.connect(
            host=db_config['mysql_host'],
            user=db_config['mysql_user'],
            password=db_config['mysql_password'],
            database=db_config['mysql_db'],
            port=int(db_config['mysql_port'])
        )
        print("Conexión exitosa a la base de datos")
        return connection

    except Exception as e:
        print(f"Error al conectar a la base de datos: {e}")
        raise

# Función para generar un token y su fecha de expiración
def generar_token(email):
    token = serializer.dumps(email, salt='email-reset-salt')
    expiration_date = datetime.now(timezone.utc) + timedelta(hours=24)
    return token, expiration_date.strftime("%Y-%m-%d %H:%M:%S")

# Función para verificar la validez del token
def verificar_token(token):
    try:
        email = serializer.loads(token, salt='email-reset-salt', max_age=86400)  # 86400 segundos = 24 horas
        return email
    except SignatureExpired:
        return "Token expirado"
    except BadSignature:
        return "Token inválido"
    
    
def es_token_valido(email, token):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT password_reset_expiration FROM usuarios WHERE email = %s AND password_reset_token = %s", (email, token,))
    expiration = cursor.fetchone()
    cursor.close()
    conn.close()

    if expiration:
        # Asegurarse de que expiration[0] es consciente de la zona horaria.
        expiration_aware = expiration[0].replace(tzinfo=timezone.utc)
        print(f"Ahora: {datetime.now(timezone.utc)}, Expiración: {expiration_aware}, Válido: {expiration_aware >= datetime.now(timezone.utc)}")
        if expiration_aware >= datetime.now(timezone.utc):
            return True
    return False


# Función para enviar el correo electrónico de restablecimiento de contraseña
def enviar_correo_reset(email, token):
    reset_link = f"{request.url_root}reset_password/{token}"
    msg = Message('Restablece tu contraseña',
                  sender=app.config['MAIL_DEFAULT_SENDER'],
                  recipients=[email])
    msg.body = f'''Para restablecer tu contraseña, visita el siguiente enlace:
{reset_link}

Si no solicitaste este cambio, simplemente ignora este correo y no se hará ningún cambio.'''
    try:
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Error al enviar correo de restablecimiento de contraseña: {e}")
        return False


def obtener_modulos_y_recursos(curso_id):
    modulos = []
    conn = get_db_connection()
    cursor = conn.cursor(cursor=pymysql.cursors.DictCursor)

    # Obtener todos los módulos para este curso
    cursor.execute("SELECT * FROM modulos WHERE curso_id = %s", (curso_id,))
    modulos_data = cursor.fetchall()

    for modulo in modulos_data:
        # Para cada módulo, obtener todos los recursos relacionados
        cursor.execute("SELECT * FROM recursos_modulo WHERE modulo_id = %s", (modulo['id'],))
        recursos = cursor.fetchall()
        modulo['recursos'] = recursos
        modulos.append(modulo)

    cursor.close()
    conn.close()

    return modulos



@app.route("/")
def home():
    return render_template("home.html")

@app.route("/reset_password_request", methods=["GET", "POST"])
def reset_password_request():
    if request.method == "POST":
        email = request.form.get("email")
        conn = get_db_connection()
        cursor = conn.cursor(cursor=pymysql.cursors.DictCursor)
        cursor.execute("SELECT * FROM usuarios WHERE email = %s", (email,))
        user = cursor.fetchone()
        
        if user:
            token, expiration_date = generar_token(email)
            cursor.execute("UPDATE usuarios SET password_reset_token=%s, password_reset_expiration=%s WHERE email=%s", (token, expiration_date, email))
            conn.commit()
            cursor.close()
            conn.close()
            
            if enviar_correo_reset(email, token):
                flash('Se ha enviado un correo electrónico con instrucciones para restablecer tu contraseña.', 'info')
            else:
                flash('Error al enviar el correo de restablecimiento de contraseña. Por favor, inténtalo de nuevo más tarde.', 'error')
            return redirect(url_for('login'))
        else:
            flash('No se encontró un usuario con ese correo electrónico.', 'error')
    return render_template("reset_password_request.html")

@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    email = verificar_token(token)
    token_valid = email not in ["Token expirado", "Token inválido"] and es_token_valido(email, token)
    
    if request.method == "POST" and token_valid:
        new_password = request.form.get("password").encode('utf-8')
        
        # Utilizar bcrypt para hashear la nueva contraseña
        hashed_password = bcrypt.hashpw(new_password, bcrypt.gensalt())
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE usuarios SET password=%s WHERE email=%s", (hashed_password.decode('utf-8'), email))
        conn.commit()
        cursor.close()
        conn.close()

        flash('Tu contraseña ha sido restablecida con éxito. Ahora puedes iniciar sesión con tu nueva contraseña.', 'success')
        return redirect(url_for('login'))
    
    # Asegúrate de pasar token_valid al contexto de render_template
    return render_template('reset_password.html', token_valid=token_valid, token=token)

# Corroboramos que la llave secreta sea consistente en todas partes
print("Llave secreta:", app.secret_key)


@app.route('/send_message', methods=['POST'])
def send_message():
    name = request.form['name']
    email = request.form['email']
    subject = request.form['subject']
    message = request.form['message']

    msg = Message(subject,
                  recipients=['destino@correo.com'],  # La dirección de correo donde quieres recibir los mensajes
                  body=f"De: {name}\nEmail: {email}\n\nMensaje:\n{message}")
    try:
        mail.send(msg)
        flash('Tu mensaje ha sido enviado. ¡Gracias!', 'success')
    except Exception as e:
        flash(f'Error al enviar el mensaje: {str(e)}', 'danger')

    return redirect('/contact')  # Ajusta según la URL de tu página de contacto

@app.route('/courses/<int:curso_id>/add_modulo', methods=['POST'])
def add_modulo_to_course(curso_id):
    if request.method == 'POST':
        titulo = request.form['titulo']
        descripcion = request.form['descripcion']
        # Aquí puedes agregar más campos según necesites

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO modulos (curso_id, titulo, descripcion) VALUES (%s, %s, %s)',
                       (curso_id, titulo, descripcion))
        conn.commit()
        cursor.close()
        conn.close()

        flash('Módulo agregado correctamente.', 'success')
        return redirect(url_for('edit_course', curso_id=curso_id))


@app.route('/modulos/edit/<int:modulo_id>', methods=['GET', 'POST'])
def edit_modulo(modulo_id):
    conn = get_db_connection()
    cursor = conn.cursor(cursor=pymysql.cursors.DictCursor)

    if request.method == 'POST':
        titulo = request.form['titulo']
        descripcion = request.form['descripcion']
        # Aquí puedes agregar más campos según necesites
        cursor.execute("""UPDATE modulos SET titulo=%s, descripcion=%s WHERE id=%s""",
                       (titulo, descripcion, modulo_id))
        conn.commit()
        flash('Módulo actualizado correctamente.', 'success')
        return redirect(url_for('edit_course', curso_id=obtener_curso_id_de_modulo(modulo_id)))
    else:
        cursor.execute("SELECT * FROM modulos WHERE id = %s", (modulo_id,))
        modulo = cursor.fetchone()
        return render_template('edit_modulo.html', modulo=modulo)


@app.route('/modulos/delete/<int:modulo_id>', methods=['POST'])
def delete_modulo(modulo_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM modulos WHERE id = %s', (modulo_id,))
    conn.commit()
    cursor.close()
    conn.close()

    flash('Módulo eliminado correctamente.', 'success')
    # Redirigir a la página anterior o a una específica
    return redirect(url_for('edit_recurso.html'))


@app.route('/modulos/<int:modulo_id>/add_recurso', methods=['POST'])
def add_recurso_to_modulo(modulo_id):
    if request.method == 'POST':
        tipo = request.form['tipo']
        descripcion = request.form['descripcion']
        url = request.form.get('url', '')
        # Omitimos el manejo del archivo por brevedad
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""INSERT INTO recursos_modulo (modulo_id, tipo, descripcion, url)
                          VALUES (%s, %s, %s, %s)""",
                       (modulo_id, tipo, descripcion, url))
        conn.commit()
        flash('Recurso agregado correctamente.', 'success')
        return redirect(url_for('edit_modulo', modulo_id=modulo_id))


@app.route('/recursos/edit/<int:recurso_id>', methods=['GET', 'POST'])
def edit_recurso(recurso_id):
    conn = get_db_connection()
    cursor = conn.cursor(cursor=pymysql.cursors.DictCursor)

    if request.method == 'POST':
        tipo = request.form['tipo']
        descripcion = request.form['descripcion']
        url = request.form.get('url', None)  # Asumiendo que el recurso puede tener una URL opcional
        # Aquí agregarías más campos si tu modelo de recurso los requiere

        update_query = """
            UPDATE recursos_modulo SET tipo=%s, descripcion=%s, url=%s
            WHERE id=%s
        """
        cursor.execute(update_query, (tipo, descripcion, url, recurso_id))
        conn.commit()
        cursor.close()
        conn.close()

        flash('Recurso actualizado correctamente.', 'success')
        # Redirigir a una página específica, posiblemente la de edición del módulo al que pertenece el recurso
        return redirect(url_for('edit_modulo', modulo_id=obtener_modulo_id_de_recurso(recurso_id)))
    else:
        # Obtener los detalles del recurso para prellenar el formulario de edición
        cursor.execute('SELECT * FROM recursos_modulo WHERE id = %s', (recurso_id,))
        recurso = cursor.fetchone()
        cursor.close()
        conn.close()

        # Asegurarse de pasar el recurso a la plantilla para prellenar el formulario
        return render_template('edit_recurso.html', recurso=recurso)


@app.route('/recursos/delete/<int:recurso_id>', methods=['POST'])
def delete_recurso(recurso_id):
    modulo_id = obtener_modulo_id_de_recurso(recurso_id)  # Asume una función que obtiene el ID del módulo basado en el ID del recurso

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM recursos_modulo WHERE id = %s', (recurso_id,))
    conn.commit()
    cursor.close()
    conn.close()

    flash('Recurso eliminado correctamente.', 'success')
    # Redirigir a la página de edición del módulo al que pertenecía el recurso
    return redirect(url_for('edit_modulo', modulo_id=modulo_id))


@app.route('/get_modulo_data/<int:modulo_id>')
def get_modulo_data(modulo_id):
    conn = get_db_connection()
    cursor = conn.cursor(cursor=pymysql.cursors.DictCursor)
    
    try:
        cursor.execute("SELECT * FROM modulos WHERE id = %s", (modulo_id,))
        modulo = cursor.fetchone()
        
        cursor.execute("SELECT * FROM recursos_modulo WHERE modulo_id = %s", (modulo_id,))
        recursos = cursor.fetchall()
        
        return jsonify({
            'success': True,
            'modulo': modulo,
            'recursos': recursos
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})
    finally:
        cursor.close()
        conn.close()


@app.route("/courses")
def courses():
    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT id, titulo, descripcion, cantidad_horas, es_sincronico, created_at, updated_at FROM cursos")
        cursos = cur.fetchall()
        print(cursos)  # Esta es la impresión de depuración
        cur.close()
        conn.close()
        return render_template("courses.html", cursos=cursos)
    except Exception as e:
        print(f"Error: {e}")
        return render_template("courses.html", error="Hubo un error al cargar los cursos.")


@app.route("/courses/add", methods=['GET', 'POST'])
def add_course():
    if request.method == 'POST':
        try:
            # Obtener los datos del formulario del curso
            titulo = request.form['titulo']
            descripcion = request.form['descripcion']
            cantidad_horas = request.form.get('cantidad_horas', type=int)
            es_sincronico = request.form.get('es_sincronico', type=int)
            programa_pdf = request.files['programa_pdf'].read() if 'programa_pdf' in request.files else None
            form_insc = request.form.get('form_insc')

            imagen_file = request.files['imagen']
            imagen_path = None
            if imagen_file and allowed_file(imagen_file.filename):
                ext = imagen_file.filename.rsplit('.', 1)[1].lower()
                imagen_filename = secure_filename(f"{uuid.uuid4().hex}.{ext}")
                imagen_path = os.path.join(app.config['UPLOAD_FOLDER'], imagen_filename)
                imagen_file.save(imagen_path)

            # Conexión a la base de datos
            conn = get_db_connection()
            cursor = conn.cursor(cursor=pymysql.cursors.DictCursor)

            # Insertar el nuevo curso
            cursor.execute("""
                INSERT INTO cursos (titulo, descripcion, imagen_path, programa_pdf, cantidad_horas, es_sincronico, form_insc)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (titulo, descripcion, imagen_path, programa_pdf, cantidad_horas, es_sincronico, form_insc))
            curso_id = cursor.lastrowid  # ID del curso recién insertado

            # Insertar módulos y recursos
            modulos_titulos = request.form.getlist('modulo_titulo[]')
            modulos_descripciones = request.form.getlist('modulo_descripcion[]')

            for i, (titulo, descripcion) in enumerate(zip(modulos_titulos, modulos_descripciones)):
                cursor.execute("""
                    INSERT INTO modulos (curso_id, titulo, descripcion)
                    VALUES (%s, %s, %s)
                """, (curso_id, titulo, descripcion))
                modulo_id = cursor.lastrowid  # ID del módulo recién insertado

                # Ahora obtenemos los recursos para este módulo
                recursos_tipos = request.form.getlist(f'recurso_tipo_{i}[]')
                recursos_descripciones = request.form.getlist(f'recurso_descripcion_{i}[]')
                recursos_urls = request.form.getlist(f'recurso_url_{i}[]')

                for tipo, desc, url in zip(recursos_tipos, recursos_descripciones, recursos_urls):
                    cursor.execute("""
                        INSERT INTO recursos_modulo (modulo_id, tipo, descripcion, url)
                        VALUES (%s, %s, %s, %s)
                    """, (modulo_id, tipo, desc, url))

            # Confirmar cambios
            conn.commit()
        except Exception as e:
            # En caso de error, hacer rollback y mostrar mensaje
            conn.rollback()
            flash(f'Error al agregar el curso: {e}', 'error')
        finally:
            # Cerrar la conexión
            cursor.close()
            conn.close()

        flash('Curso agregado con éxito.', 'success')
        return redirect(url_for('admin_view'))

    # Si es una solicitud GET, muestra el formulario para agregar un curso.
    return render_template('add_course.html')

@app.route('/courses/edit/<int:curso_id>', methods=['GET', 'POST'])
def edit_course(curso_id):
    conn = get_db_connection()
    cursor = conn.cursor(cursor=pymysql.cursors.DictCursor)
    curso_form = CursoForm()
    curso = None
    modulos = None

    if request.method == 'POST':
        titulo = request.form['titulo']
        descripcion = request.form['descripcion']
        cantidad_horas = request.form['cantidad_horas']
        # Procesa otros campos según sea necesario, como imagen y programa_pdf

        # Actualización de la información básica del curso
        cursor.execute("""UPDATE cursos SET titulo=%s, descripcion=%s, cantidad_horas=%s
                          WHERE id=%s""", (titulo, descripcion, cantidad_horas, curso_id))
        
        # Manejo de la imagen del curso
        if 'imagen' in request.files:
            imagen = request.files['imagen']
            if imagen and allowed_file(imagen.filename):
                filename = secure_filename(imagen.filename)
                imagen_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                imagen.save(imagen_path)
                cursor.execute("UPDATE cursos SET imagen_path=%s WHERE id=%s", (imagen_path, curso_id))

        # Manejo del programa PDF del curso
        if 'programa_pdf' in request.files:
            programa_pdf = request.files['programa_pdf']
            if programa_pdf:
                pdf_data = programa_pdf.read()
                cursor.execute("UPDATE cursos SET programa_pdf=%s WHERE id=%s", (pdf_data, curso_id))

        # Procesamiento de módulos
        modulos_form = request.form.getlist('modulos[]')  # Asume una estructura del formulario donde los módulos se envían como una lista
        modulos_actuales_ids = [int(id) for id in request.form.getlist('modulos_ids[]')]  # IDs de módulos actuales
        
        # Eliminación de módulos no presentes
        cursor.execute("SELECT id FROM modulos WHERE curso_id = %s", (curso_id,))
        todos_modulos_ids = [row['id'] for row in cursor.fetchall()]
        modulos_eliminar = set(todos_modulos_ids) - set(modulos_actuales_ids)
        for id in modulos_eliminar:
            cursor.execute("DELETE FROM recursos_modulo WHERE modulo_id = %s", (id,))
            cursor.execute("DELETE FROM modulos WHERE id = %s", (id,))
        
        # Actualización y creación de módulos
        for modulo_id in modulos_actuales_ids:
            titulo = request.form['modulo_titulo_' + str(modulo_id)]
            descripcion = request.form['modulo_descripcion_' + str(modulo_id)]
            if modulo_id in todos_modulos_ids:
                # Actualización de módulo existente
                cursor.execute("UPDATE modulos SET titulo = %s, descripcion = %s WHERE id = %s", (titulo, descripcion, modulo_id))
            else:
                # Creación de nuevo módulo
                cursor.execute("INSERT INTO modulos (curso_id, titulo, descripcion) VALUES (%s, %s, %s)", (curso_id, titulo, descripcion))
                modulo_id_actual = cursor.lastrowid or modulo_id  # Usar lastrowid para nuevos módulos, modulo_id para los existentes
        
        # Para cada módulo, obtienes sus recursos de la forma
        for modulo_id in modulos_actuales_ids:
            recursos_ids_form = request.form.getlist(f'modulo_{modulo_id}_recursos_ids[]')
            recursos_actuales_ids = [int(id) for id in recursos_ids_form]
            
            # Eliminación de recursos no presentes para este módulo
            cursor.execute("SELECT id FROM recursos_modulo WHERE modulo_id = %s", (modulo_id,))
            todos_recursos_ids = [row['id'] for row in cursor.fetchall()]
            recursos_eliminar = set(todos_recursos_ids) - set(recursos_actuales_ids)
            for id in recursos_eliminar:
                cursor.execute("DELETE FROM recursos_modulo WHERE id = %s", (id,))
            
            # Actualización y creación de recursos para este módulo
            for recurso_id in recursos_actuales_ids:
                tipo = request.form[f'recurso_tipo_{modulo_id}_{recurso_id}']
                descripcion = request.form[f'recurso_descripcion_{modulo_id}_{recurso_id}']
                # Añade más campos según sea necesario
                if recurso_id in todos_recursos_ids:
                    # Actualización de recurso existente
                    cursor.execute("UPDATE recursos_modulo SET tipo = %s, descripcion = %s WHERE id = %s", (tipo, descripcion, recurso_id))
                else:
                    # Creación de nuevo recurso
                    cursor.execute("INSERT INTO recursos_modulo (modulo_id, tipo, descripcion) VALUES (%s, %s, %s)", (modulo_id, tipo, descripcion))
                    # Añade más campos en el INSERT según sea necesario
        
        # Después de la actualización exitosa del curso en la base de datos
        # Obtener el ID del usuario que está realizando la edición (puedes obtener esta información según la lógica de tu aplicación)
        usuario_id = obtener_usuario_actual_id()

        # Verificar si el usuario ya está inscrito en el curso
        cursor.execute("SELECT * FROM inscripciones WHERE usuario_id = %s AND curso_id = %s", (usuario_id, curso_id))
        inscripcion_existente = cursor.fetchone()

        # Si no hay una inscripción existente para este usuario y curso, crea una nueva inscripción
        if not inscripcion_existente:
            cursor.execute("INSERT INTO inscripciones (usuario_id, curso_id, fecha_inscripcion) VALUES (%s, %s, CURRENT_DATE)", (usuario_id, curso_id))

        conn.commit()
        flash('Curso actualizado correctamente.', 'success')
        cursor.close()
        conn.close()
        return redirect(url_for('admin_view'))

    else:
        # Cargar datos del curso existente en el formulario
        cursor.execute("SELECT * FROM cursos WHERE id = %s", (curso_id,))
        curso = cursor.fetchone()
        if curso:
            curso_form.titulo.data = curso['titulo']
            curso_form.descripcion.data = curso['descripcion']
            curso_form.cantidad_horas.data = curso['cantidad_horas']
        
        # Obtener módulos y recursos
        def obtener_modulos_y_recursos(curso_id):
            cursor.execute("SELECT * FROM modulos WHERE curso_id = %s", (curso_id,))
            modulos = cursor.fetchall()

            for modulo in modulos:
                cursor.execute("SELECT * FROM recursos_modulo WHERE modulo_id = %s", (modulo['id'],))
                recursos = cursor.fetchall()
                modulo['recursos'] = recursos

            return modulos

        modulos = obtener_modulos_y_recursos(curso_id)

        cursor.close()
        conn.close()

        return render_template('edit_course.html', curso=curso, curso_id=curso_id, curso_form=curso_form, modulos=modulos)


@app.route('/courses/delete/<int:id>', methods=['POST'])
def delete_course(id):
    if not session.get('logged_in') or session.get('user_role') != 'Administrador':
        flash('Solo los administradores pueden realizar esta acción.', 'error')
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(cursor=pymysql.cursors.DictCursor)
    
    try:
        # Recuperar la ruta de la imagen del curso antes de eliminar el curso
        cursor.execute("SELECT imagen_path FROM cursos WHERE id = %s", (id,))
        curso = cursor.fetchone()
        ruta_imagen = curso['imagen_path'] if curso else None

        print("ID del curso a eliminar:", id)
        try:
            # Intenta eliminar solo de una tabla como prueba
            print("Intentando eliminar módulos asociados al curso.")
            cursor.execute("DELETE FROM modulos WHERE curso_id = %s", (id,))
            print("Módulos eliminados correctamente.")
            
            print("Intentando eliminar recursos asociados al curso.")
            cursor.execute("DELETE FROM recursos_modulo WHERE curso_id = %s", (id,))
            print("Recursos eliminados correctamente.")
        except Exception as e:
            print("Error durante la eliminación:", e)
            raise e

        # Eliminar el curso
        cursor.execute("DELETE FROM cursos WHERE id = %s", (id,))

        # Si existe una ruta de imagen, eliminar el archivo del sistema de archivos
        if ruta_imagen:
            ruta_completa = os.path.join(app.config['UPLOAD_FOLDER'], ruta_imagen)
            if os.path.exists(ruta_completa):
                os.remove(ruta_completa)

        conn.commit()
        flash('Curso eliminado con éxito.', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'No se pudo eliminar el curso: {e}', 'error')
    finally:
        cursor.close()
        conn.close()
    
    return redirect(url_for('admin_view'))


@app.route('/course_image/<int:curso_id>')
def course_image(curso_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT imagen_path FROM cursos WHERE id = %s", (curso_id,))
    imagen_path = cursor.fetchone()[0]
    cursor.close()
    conn.close()

    if imagen_path and os.path.exists(imagen_path):
        return send_file(imagen_path)
    else:
        return 'No se encontró la imagen', 404
   
    
@app.route('/course_program/<int:curso_id>')
def course_program(curso_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT programa_pdf FROM cursos WHERE id = %s", (curso_id,))
    pdf_data = cursor.fetchone()[0]
    cursor.close()
    conn.close()

    if pdf_data:
        pdf_stream = io.BytesIO(pdf_data)
        pdf_stream.seek(0)
        return send_file(pdf_stream, as_attachment=False, mimetype='application/pdf')
    else:
        return '<h1>El programa del curso estará disponible próximamente.</h1>', 404


@app.route("/signup", methods=["GET", "POST"])
def signup():
    lista_cursos = []
    conn = None
    cursor = None
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor=pymysql.cursors.DictCursor)

        cursor.execute("SELECT id, titulo FROM cursos")  # Asegúrate de que esta es la tabla correcta
        lista_cursos = cursor.fetchall()

        if request.method == 'POST':
            nombre = request.form.get('nombre')
            apellidos = request.form.get('apellidos')
            dni = request.form.get('dni')
            municipio = request.form.get('municipio')
            email = request.form.get('email')
            password = request.form.get('password')
            curso_id = request.form.get('curso_id')  # Cambiado para permitir valores None
            rol = 'Alumno'
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

            cursor.execute("""
                INSERT INTO usuarios (nombre, apellidos, dni, municipio, email, password, rol)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (nombre, apellidos, dni, municipio, email, hashed_password, rol))
            user_id = cursor.lastrowid

            # Se verifica que curso_id sea un valor válido y no None o vacío
            if curso_id and curso_id.isdigit():
                curso_id = int(curso_id)  # Convertimos a entero después de validar que es un dígito
                cursor.execute("""
                    INSERT INTO inscripciones (usuario_id, curso_id, fecha_inscripcion)
                    VALUES (%s, %s, CURDATE())
                """, (user_id, curso_id))
                conn.commit()
                flash('Usuario registrado con éxito y inscrito en el curso.', 'success')
            else:
                conn.commit()
                flash('Usuario registrado con éxito.', 'success')  # Mensaje si no se inscribe en ningún curso

            return redirect(url_for('login'))

    except Exception as e:
        if conn:
            conn.rollback()
        flash(f'Hubo un error al registrar el usuario: {e}', 'error')
        print(f"Error al registrar usuario: {e}")

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

    return render_template("signup.html", cursos=lista_cursos)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == 'POST':
        email = request.form['email']
        contrasena = request.form['contrasena']

        conn = get_db_connection()
        cursor = conn.cursor(cursor=pymysql.cursors.DictCursor)
        cursor.execute("SELECT * FROM usuarios WHERE email = %s", (email,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user and bcrypt.checkpw(contrasena.encode('utf-8'), user['password'].encode('utf-8')):
            session['logged_in'] = True
            session['user_id'] = user['id']
            session['user_name'] = user['nombre']
            session['user_role'] = user['rol']  # Guardar el rol del usuario en la sesión

            # Redirigir según el rol del usuario
            if user['rol'] == 'Administrador':
                return redirect(url_for('admin_view'))  # Redirigir a la vista de administrador
            else:
                # Redirigir a la vista de estudiante
                return redirect(url_for('student', user_id=user['id']))
        else:
            flash('Email o contraseña incorrectos.')
            return render_template("login.html")

    return render_template("login.html")

@app.route('/admin')
def admin_view():
    if not session.get('logged_in') or session.get('user_role') != 'Administrador':
        return redirect(url_for('login'))

    page = request.args.get('page', 1, type=int)
    search_query = request.args.get('search', '')
    users_per_page = 10

    cursos = []
    lista_usuarios = []
    conn = None
    cursor = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor=pymysql.cursors.DictCursor)

        # Obtener cursos
        cursor.execute("SELECT id, titulo, descripcion, imagen_path FROM cursos")
        cursos = cursor.fetchall()

        # Buscar usuarios
        search_pattern = f"%{search_query}%"
        cursor.execute("SELECT COUNT(*) AS total FROM usuarios WHERE nombre LIKE %s OR apellidos LIKE %s",
                       (search_pattern, search_pattern))
        total_users_result = cursor.fetchone()
        total_users = total_users_result['total'] if total_users_result else 0
        total_pages = max(1, -(-total_users // users_per_page))

        offset = (page - 1) * users_per_page
        cursor.execute("""
            SELECT id, nombre, apellidos, municipio, email
            FROM usuarios
            WHERE nombre LIKE %s OR apellidos LIKE %s
            ORDER BY nombre, apellidos
            LIMIT %s OFFSET %s
        """, (search_pattern, search_pattern, users_per_page, offset))
        lista_usuarios = cursor.fetchall()

        # Obtener inscripciones si hay usuarios
        if lista_usuarios:
            user_ids = tuple(user['id'] for user in lista_usuarios)
            if len(user_ids) == 1:
                user_ids = (user_ids[0],)  # Asegurar que sea una tupla para pymysql

            placeholders = ', '.join(['%s'] * len(user_ids))
            cursor.execute(f"""
                SELECT i.usuario_id, c.titulo AS curso_titulo, i.fecha_inscripcion
                FROM inscripciones i
                JOIN cursos c ON i.curso_id = c.id
                WHERE i.usuario_id IN ({placeholders})
            """, user_ids)
            inscripciones = cursor.fetchall()

            # Asignar inscripciones a cada usuario
            for usuario in lista_usuarios:
                usuario_inscripciones = [
                    {'titulo': inscripcion['curso_titulo'], 'fecha_inscripcion': inscripcion['fecha_inscripcion']}
                    for inscripcion in inscripciones if inscripcion['usuario_id'] == usuario['id']
                ]
                usuario['inscripciones'] = usuario_inscripciones

    except Exception as e:
        flash(f'Ocurrió un error al obtener los datos: {e}', 'error')
        traceback.print_exc()

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

    return render_template('admin.html', cursos=cursos, usuarios=lista_usuarios,
                           total_pages=total_pages, current_page=page, search_query=search_query)

@app.route("/users/add", methods=['GET', 'POST'])
def add_user():
    if not session.get('logged_in') or session.get('user_role') != 'Administrador':
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(cursor=pymysql.cursors.DictCursor)
    
    try:
        # Obtener lista de cursos para mostrar en el formulario
        cursor.execute("SELECT id, titulo FROM cursos")
        lista_cursos = cursor.fetchall()

        if request.method == 'POST':
            # Obtener datos del formulario
            nombre = request.form.get('nombre')
            apellidos = request.form.get('apellidos')
            dni = request.form.get('dni')
            municipio = request.form.get('municipio')
            email = request.form.get('email')
            password = request.form.get('password')
            rol = request.form.get('rol')
            curso_id = request.form.get('curso_id')

            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


            cursor.execute("""
                INSERT INTO usuarios (nombre, apellidos, dni, municipio, email, password, rol)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (nombre, apellidos, dni, municipio, email, hashed_password, rol))
            user_id = cursor.lastrowid  # Obtener el ID del usuario recién insertado

            if curso_id and curso_id.isdigit():  # Inscribir en curso si se seleccionó uno y es un valor válido
                cursor.execute("""
                    INSERT INTO inscripciones (usuario_id, curso_id, fecha_inscripcion)
                    VALUES (%s, %s, CURDATE())
                """, (user_id, int(curso_id)))

            conn.commit()  # Confirmar transacción
            flash('Usuario agregado con éxito.', 'success')
            return redirect(url_for('admin_view'))

    except Exception as e:
        conn.rollback()  # Revertir transacción en caso de error
        flash(f'Hubo un error al agregar el usuario: {e}', 'error')
        print(f"Error al agregar usuario: {e}")

    finally:
        cursor.close()
        conn.close()

    return render_template('add_user.html', lista_cursos=lista_cursos)


@app.route('/users/delete/<int:id>', methods=['POST'])
def delete_user(id):
    conn = get_db_connection()
    cursor = conn.cursor(cursor=pymysql.cursors.DictCursor)

    try:
        cursor.execute("DELETE FROM usuarios WHERE id = %s", (id,))
        conn.commit()
        flash('Usuario eliminado con éxito.', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'No se pudo eliminar el usuario: {e}', 'error')
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('admin_view'))


@app.route("/student/<int:user_id>")
def student(user_id):
    conn = get_db_connection()
    cursor = conn.cursor(cursor=pymysql.cursors.DictCursor)
    
    try:
        cursor.execute("SELECT * FROM usuarios WHERE id = %s", (user_id,))
        user_info = cursor.fetchone()

        cursor.execute("""
            SELECT c.* FROM cursos c
            JOIN inscripciones i ON c.id = i.curso_id
            WHERE i.usuario_id = %s
        """, (user_id,))
        cursos_inscritos = cursor.fetchall()

        cursos_info = {}
        for curso in cursos_inscritos:
            cursor.execute("SELECT * FROM modulos WHERE curso_id = %s", (curso['id'],))
            modulos = cursor.fetchall()

            for modulo in modulos:
                cursor.execute("SELECT * FROM recursos_modulo WHERE modulo_id = %s", (modulo['id'],))
                modulo['recursos'] = cursor.fetchall()

            curso['modulos'] = modulos
            cursos_info[curso['id']] = curso

        print("cursos_info:", cursos_info)  # Depuración: Imprimir cursos_info

    except Exception as e:
        flash(f'Hubo un error al obtener la información del estudiante: {e}', 'error')
        return redirect(url_for('home'))

    finally:
        cursor.close()
        conn.close()

    return render_template("student.html", user=user_info, cursos_info=cursos_info)

@app.route('/users/edit/<int:id>', methods=['GET', 'POST'])
def edit_user(id):
    conn = get_db_connection()
    cursor = conn.cursor(cursor=pymysql.cursors.DictCursor)

    if request.method == 'POST':
        nombre = request.form['nombre']
        apellidos = request.form['apellidos']
        email = request.form['email']

        # Actualizar los datos básicos del usuario
        update_query = """
            UPDATE usuarios SET nombre=%s, apellidos=%s, email=%s
            WHERE id=%s
        """
        cursor.execute(update_query, (nombre, apellidos, email, id))

        # Obtener el ID del curso seleccionado en el formulario
        curso_id = request.form.get('curso_id')

        # Actualizar la inscripción del usuario al nuevo curso
        if curso_id and curso_id.isdigit():
            # Eliminar inscripciones existentes
            cursor.execute("DELETE FROM inscripciones WHERE usuario_id = %s", (id,))
            # Insertar nueva inscripción
            cursor.execute("""
                INSERT INTO inscripciones (usuario_id, curso_id, fecha_inscripcion)
                VALUES (%s, %s, CURDATE())
            """, (id, int(curso_id)))
        elif not curso_id:
            # Eliminar todas las inscripciones si se seleccionó "No inscrito"
            cursor.execute("DELETE FROM inscripciones WHERE usuario_id = %s", (id,))

        conn.commit()
        flash('Usuario actualizado con éxito.', 'success')
        return redirect(url_for('admin_view'))

    # Obtener los datos actuales del usuario para el formulario de edición
    cursor.execute("SELECT * FROM usuarios WHERE id = %s", (id,))
    usuario = cursor.fetchone()

    # También obtener los cursos en los que el usuario está inscrito actualmente
    cursor.execute("SELECT curso_id FROM inscripciones WHERE usuario_id = %s", (id,))
    cursos_inscritos = cursor.fetchall()

    cursos_actuales = [curso['curso_id'] for curso in cursos_inscritos] if cursos_inscritos else []

    cursor.close()
    conn.close()

    if usuario is None:
        flash('Usuario no encontrado.', 'error')
        return redirect(url_for('admin_view'))

    # Obtener la lista de todos los cursos para mostrar en el formulario
    conn = get_db_connection()
    cursor = conn.cursor(cursor=pymysql.cursors.DictCursor)
    cursor.execute("SELECT id, titulo FROM cursos")
    lista_cursos = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template('edit_user.html', usuario=usuario, cursos=lista_cursos, cursos_actuales=cursos_actuales)



@app.route("/logout")
def logout():
    session.pop('logged_in', None)
    session.pop('user_id', None)
    session.pop('user_name', None)
    flash('Has cerrado sesión con éxito.')
    
    return redirect(url_for('home'))

@app.route("/cookie-policy")
def cookie_policy():
    return render_template("cookie-policy.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/events")
def events():
    return render_template("events.html")

@app.route("/precing")
def precing():
    return render_template("precing.html")

@app.route("/trainers")
def trainers():
    # Aquí irá la lógica para mostrar los entrenadores
    pass

# Añade aquí las rutas adicionales necesarias...
app.config['TEMPLATES_AUTO_RELOAD'] = True


if __name__ == "__main__":
    app.run(debug=True)
