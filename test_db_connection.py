import pymysql
import yaml

def test_connection():
    try:
        # Leer configuración desde db.yaml
        with open("db.yaml", "r") as file:
            db_config = yaml.safe_load(file)

        # Conexión con pymysql
        connection = pymysql.connect(
            host=db_config['mysql_host'],
            user=db_config['mysql_user'],
            password=db_config['mysql_password'],
            database=db_config['mysql_db'],
            port=int(db_config['mysql_port'])
        )
        print("Conexión exitosa a la base de datos con pymysql")
        connection.close()

    except Exception as e:
        print(f"Error al conectar a la base de datos: {e}")

if __name__ == "__main__":
    test_connection()
