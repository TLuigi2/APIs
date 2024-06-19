from flask import Flask, request, jsonify, make_response
import pymssql
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import jwt
import json
import datetime
from sqlalchemy.sql import select
from waitress import serve
from functools import wraps

#Parametros
app = Flask(__name__)

app.config['SECRET_KEY']='Th1s1ss3cr3tPaasswordlt'
app.config['SQLALCHEMY_DATABASE_URI']='sqlite://///var/www/html/flaskapi/auth_balianza.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

#Datos adicionales, se dejan en codigo puesto que solo funciona interno
app.config["PORT"] = '1043'
app.config["USER"] = 'sa'
app.config["PASSWORD"] = 'VendingPass'
app.config["NAME"] = 'API VENDING MACHINE'


db = SQLAlchemy(app)

#Clases
class Users(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  public_id = db.Column(db.Integer)
  name = db.Column(db.String(50))
  password = db.Column(db.String(50))
  admin = db.Column(db.Boolean)

class Logs(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  pedido = db.Column(db.String(1000), nullable=False)
  serie = db.Column(db.String(20), nullable=False)
  monto = db.Column(db.String(20), nullable=False)
  response = db.Column(db.String(20), nullable=False)
  nombre = db.Column(db.String(50), nullable=False)
  correo = db.Column(db.String(20), nullable=False)
  fecha_nacimiento = db.Column(db.String(20), nullable=False)
  date_time = db.Column(db.DateTime, default=datetime.datetime.utcnow)
  message_machine = db.Column(db.String(50), nullable=False)

#Inicio prueba api online
@app.route('/', methods=['POST','GET'])
def home():
  return "CONEXION EXITOSA"

#Funcion para generar token
def token_required(f):
  @wraps(f)
  def decorator(*args, **kwargs):

     token = None
     jwt_options = {
      'verify_signature': True,
      'verify_exp': True,
      'verify_nbf': False,
      'verify_iat': True,
      'verify_aud': False
      }
     current_user = None

     if 'x-access-tokens' in request.headers:
        token = request.headers['x-access-tokens']


     if not token:
        return jsonify({'message': 'a valid token is missing'})

     try:
        data = jwt.decode(token, app.config['SECRET_KEY'],options=jwt_options)
        current_user = Users.query.filter_by(public_id=data['public_id']).first()
     except:
        return jsonify({'message': 'El token es invalido o ya está caducado'})


     return f(current_user, *args,  **kwargs)
  return decorator

#Registro
@app.route('/register', methods=['POST'])
def signup_user():
  data = request.get_json()
  hashed_password = generate_password_hash(data['password'], method='sha256')
  new_user = Users(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)
  users = Users.query.all()
  if len(users) >= 2:
    return jsonify({'message': 'Solo puede participair 2 usuarios'})
  else:
    db.session.add(new_user)
    db.session.commit()
  return jsonify({'message': 'Registrado correctamente!'})

#Obtener token
@app.route('/login', methods=['GET'])
def login_user():
  auth = request.authorization
  if not auth or not auth.username or not auth.password:
    return make_response('No se puede verificar', 401, {'Authentication': 'Basic realm: "login required"'})

  user = Users.query.filter_by(name=auth.username).first()
  if check_password_hash(user.password, auth.password):
    token = jwt.encode({'public_id': user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=10)}, app.config['SECRET_KEY'])
    return jsonify({'token' : token.decode('UTF-8')})

  return make_response('No se puede verificar',  401, {'Authentication': 'Basic realm: "login required"'})

#Funcion conectar base de SIA
def conecta_sia(ip_server):
  #Conexión a bases
  return pymssql.connect(server=ip_server, port=app.config["PORT"], user=app.config["USER"], password=app.config["PASSWORD"], database=app.config["NAME"])

#Metodo para retornar datos sobre entrega producto en SIA
@app.route('/send/info/alianza', methods=['POST'])
@token_required
def send_info(current_user):
  data = request.get_json()

  if data:
    log = Logs.query.filter_by(pedido=data['pedido'],serie=data['serie'],response='success').update(dict(message_machine=data['status']))
    db.session.commit()
    return jsonify({"Response":"Petición recibida correctamente"})
  else:
    return jsonify({"Response":"No se detectó información"})

#Metodo para petición de datos pedido en SIA
@app.route('/request/info/alianza', methods=['POST'])
@token_required
def request_info(current_user):
  data = request.get_json()
  
  data_serie = data["serie"].upper()

  if data_serie=='F2MN':
    ip_server = '192.168.227.100'
  elif data_serie=='09MN':
    ip_server = '192.168.70.100'
  
  else:
    return jsonify({"ticket":"", "type":"error", "productos":{}})
  try:
    conn = conecta_sia(ip_server)
    conn1 = conecta_sia(ip_server)
    conn2 = conecta_sia(ip_server)
    conn3 = conecta_sia(ip_server)
    conn4 = conecta_sia(ip_server)
    # OK! conexión exitosa
  except Exception as e:
    # Atrapar error
    print("Ocurrió un error al conectar a SQL Server: ", e)

  cursor = conn.cursor(as_dict=True)
  sub_cursor = conn1.cursor(as_dict=True)
  sub_cursor1 = conn2.cursor(as_dict=True)
  sub_cursor2 = conn3.cursor(as_dict=True)
  sub_cursor3 = conn4.cursor(as_dict=True)
  
  #con = sqlite3.connect('auth_balianza.db')
  #cur = con.cursor()
  #cur.execute("select pedido,serie,response from Logs where pedido=:noticket and response='success'", {"noticket": int(data['noticket'])})
  redimido = False
  pedido_old = Logs.query.filter(Logs.pedido.endswith(data['noticket']),Logs.serie.endswith(data['serie']),Logs.response.endswith('success')).all()

  if pedido_old:
    redimido = True


  if redimido == True:
    return jsonify({"ticket":"", "type":"error_redeemed", "productos":{}})

  query= "IF OBJECT_ID('dbo.pedidom') IS NOT NULL BEGIN select * from dbo.pedidom where id_pedido=%s and serie=%s and autorizado<>'3' END"
  cursor.execute(query,(data['noticket'],data['serie']))
  number_records = len(list(cursor))
  cursor.execute(query,(data['noticket'],data['serie']))
  print("Esto es number_records",number_records)

  if cursor and number_records == 1:
    for row in cursor:
      pedido = row["id_pedido"]
      punto_venta = row["id_pto_venta"]
      total_pedido = float(row["subtotal"]) + float(row["total_impuesto"]) + float(row["imp_x_cr"])
      total_pedido = round(total_pedido, 2)
      data_total_pedido = float(data['monto'])
      fecha_pedido = row["fecha_ped"]
      date_now = (datetime.datetime.now())
      dias = (date_now  - fecha_pedido).days
      print("total_pedido",total_pedido)
      print("data_total_pedido",data_total_pedido)
      print("Esto es dias ",dias)
      


      if total_pedido == data_total_pedido:
        if dias >= 2:
          new_log = Logs(pedido=data['noticket'], serie=data['serie'], monto=data['monto'],  response="expired" ,  nombre=data['nombre'],  correo=data['correo'] ,  fecha_nacimiento=data['fecha_nacimiento'], message_machine="")
          db.session.add(new_log)
          db.session.commit()
          conn.close()
          conn1.close()
          conn2.close()
          conn3.close()
          conn4.close()
          return jsonify({"ticket":"", "type":"expired", "productos":{}})
          
        else:
          participa = False
          sub_query = "IF OBJECT_ID('dbo.pedidod') IS NOT NULL BEGIN select * from dbo.pedidod where id_pedido=%s and serie=%s END"
          sub_cursor.execute(sub_query,(str(row["id_pedido"]),str(row["serie"])))
          list_products = []
          cantidad_suma = 0
          for row1 in sub_cursor:
            print("productos",row1["id_articulo"])
            sub_query1 = "IF OBJECT_ID('dbo.productos') IS NOT NULL BEGIN select * from dbo.productos where id_articulo=%s END"
            sub_cursor1.execute(sub_query1,(row1["id_articulo"]))
            for row2 in sub_cursor1:
              if str(row2["id_prov"]) == "184":
                descripcion = str(row2["descripcion"])
                articulo = str(row2["id_articulo"])

                if articulo in "25854,30021,32674,9874,34045,25852,31503,25855,25853":
                  participa = True
                  sub_query2 = "IF OBJECT_ID('dbo.sub_und_compra') IS NOT NULL BEGIN select * from dbo.sub_und_compra where id_subunidad=%s END"
                  sub_cursor2.execute(sub_query2,row2['id_subunidad'])
                  for row3 in sub_cursor2:
                    cantidad = int(row3['unidades'])
                  cantidad_total = (int(row1['unidad']) * cantidad) +  row1["subunidad"]

                  vals = {
                    "name":descripcion,
                    "cantidad":str(cantidad_total)
                    #"cantidad":str(row1["subunidad"])
                  }
                  list_products.append(vals)

          print("list_products",list_products)

          if participa == True:
            print ("list_products",list_products)
            new_log = Logs(pedido=data['noticket'], serie=data['serie'], monto=data['monto'],  response="success" ,  nombre=data['nombre'],  correo=data['correo'] ,  fecha_nacimiento=data['fecha_nacimiento'], message_machine="")
            db.session.add(new_log)
            db.session.commit()
            conn.close()
            conn1.close()
            conn2.close()
            conn3.close()
            conn4.close()
            return jsonify({
              "ticket":str(pedido),
              "type":"success", 
              "productos":str(list_products),
              "tienda":str(punto_venta)
              })
          else:
            new_log = Logs(pedido=data['noticket'], serie=data['serie'], monto=data['monto'],  response="error_products" ,  nombre=data['nombre'],  correo=data['correo'] ,  fecha_nacimiento=data['fecha_nacimiento'], message_machine="")
            db.session.add(new_log)
            db.session.commit()
            conn.close()
            conn1.close()
            conn2.close()
            conn3.close()
            conn4.close()
            return jsonify({"ticket":"", "type":"error_products", "productos":{}})

          
      else:
        new_log = Logs(pedido=data['noticket'], serie=data['serie'], monto=data['monto'],  response="error_monto" ,  nombre=data['nombre'],  correo=data['correo'] ,  fecha_nacimiento=data['fecha_nacimiento'], message_machine="")
        db.session.add(new_log)
        db.session.commit()
        conn.close()
        conn1.close()
        conn2.close()
        conn3.close()
        conn4.close()
        return jsonify({"ticket":"", "type":"error_monto", "productos":{}})

  else:
    new_log = Logs(pedido=data['noticket'], serie=data['serie'], monto=data['monto'],  response="error" ,  nombre=data['nombre'],  correo=data['correo'] ,  fecha_nacimiento=data['fecha_nacimiento'], message_machine="")
    db.session.add(new_log)
    db.session.commit()
    conn.close()
    conn1.close()
    conn2.close()
    conn3.close()
    conn4.close()
    return jsonify({"ticket":"", "type":"error", "productos":{}})
  
  
#Peticion Usuarios
@app.route('/users', methods=['GET'])
@token_required
def get_all_users():
  users = Users.query.all()
  result = []
  for user in users:
    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['admin'] = user.admin
    result.append(user_data)

  return jsonify({'users': result})

#Peticion Log
@app.route('/log', methods=['GET'])
@token_required
def get_logs(current_user):
  logs = Logs.query.all()

  output = []

  for log in logs:
    log_data = {}
    log_data['id'] = log.id
    log_data['pedido'] = log.pedido
    log_data['serie'] = log.serie
    log_data['monto'] = log.monto
    log_data['response'] = log.response
    log_data['date_time'] = log.date_time
    log_data['nombre'] = log.nombre
    log_data['correo'] = log.correo
    log_data['fecha_nacimiento'] = log.fecha_nacimiento
    log_data['message_machine'] = log.message_machine
    output.append(log_data)
  return jsonify({'Log Registros' : output})


if  __name__ == '__main__':
  serve(app)
