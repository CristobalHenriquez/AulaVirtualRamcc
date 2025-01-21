import mysql.connector

try:
    connection = mysql.connector.connect(
        host='localhost',
        user='root',
        password='',
        database='app_cursos'
    )
    if connection.is_connected():
        db_Info = connection.get_server_info()
        print("Conectado a MySQL Server versión ", db_Info)
        cursor = connection.cursor()
        cursor.execute("select database();")
        record = cursor.fetchone()
        print("Estás conectado a la base de datos: ", record)
except Exception as e:
    print("Error al conectar a la base de datos", e)
finally:
    if connection.is_connected():
        cursor.close()
        connection.close()
        print("Conexión a MySQL cerrada")
