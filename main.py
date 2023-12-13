import sqlite3
from pydantic import BaseModel
from fastapi.responses import JSONResponse
from uuid import uuid4 as new_token
import hashlib
from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials, HTTPBearer, HTTPAuthorizationCredentials
import time

security = HTTPBasic()

securirtyBearer = HTTPBearer()

# Crea la base de datos
conn = sqlite3.connect("sql/contactos.db")

app = FastAPI()

# Permitimos los origenes para conectarse
origins = [
    "http://127.0.0.1:8080"
]

# Agregamos las opciones de origenes, credenciales, métodos y headers
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)


class Contacto(BaseModel):
    email: str
    nombre: str
    telefono: str

class UsuarioRegistro(BaseModel):
    username: str
    password: str

def validar_token(token):
    c = conn.cursor()
    c.execute("SELECT token FROM usuarios WHERE token = ?", (token,))
    result = c.fetchone()
    return result

# Respuesta de error
def error_response(mensaje: str, status_code: int):
    return JSONResponse(content={"mensaje": mensaje}, status_code=status_code)


async def cambiar_token_en_login(email):
    token = str(new_token())
    c = conn.cursor()
    c.execute("UPDATE usuarios SET token = ? WHERE username = ?", (token, email))
    conn.commit()
    return token
    
async def get_user_token(email: str, password_hash: str):
    c = conn.cursor()
    c.execute("SELECT token FROM usuarios WHERE username = ? AND password = ?", (email, password_hash))
    result = c.fetchone()
    return result


@app.get("/token/")
async def validate_user(credentials: HTTPBasicCredentials = Depends(security)):
    username = credentials.username
    password_hash = hashlib.md5(credentials.password.encode()).hexdigest()

    user_token = await get_user_token(username, password_hash)

    if user_token:
        token = await cambiar_token_en_login(username)
        response = {"token": token}
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales inválidas",
            headers={"WWW-Authenticate": "Basic"},
        )

    return response


@app.get("/")
async def root(credentialsv: HTTPAuthorizationCredentials = Depends(securirtyBearer)):
    token = credentialsv.credentials
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token no proporcionado",
            headers={"WWW-Authenticate": "Bearer"},
        )

    c = conn.cursor()
    c.execute("SELECT token FROM usuarios WHERE token = ?", (token,))
    result = c.fetchone()

    if not result:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token no válido",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return {"message": "Token válido"}


# Rutas para las operaciones CRUD de Usuarios

@app.post("/usuarios")
async def registrar_usuario(credentials: HTTPBasicCredentials = Depends(security)):
    email = credentials.username
    password_hash = hashlib.md5(credentials.password.encode()).hexdigest()

    # Verifica si el usuario ya existe en la tabla de usuarios
    c = conn.cursor()
    c.execute("SELECT * FROM usuarios WHERE username = ?", (email,))
    existing_user = c.fetchone()

    if existing_user:
        return error_response("El usuario ya existe", 400)

    # Registra el nuevo usuario
    c.execute("INSERT INTO usuarios (username, password, token) VALUES (?, ?, ?)", (email, password_hash, ""))
    conn.commit()
    return {"mensaje": "Usuario registrado"}

@app.post("/usuarios/registro", response_model=dict)
async def registrar_usuario(usuario: UsuarioRegistro):
    hashed_password = hashlib.md5(usuario.password.encode()).hexdigest()

    # Verifica si el usuario ya existe en la tabla de usuarios
    c = conn.cursor()
    c.execute("SELECT * FROM usuarios WHERE username = ?", (usuario.username,))
    existing_user = c.fetchone()

    if existing_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="El usuario ya existe")

    # Registra el nuevo usuario
    c.execute("INSERT INTO usuarios (username, password, token) VALUES (?, ?, ?)", (usuario.username, hashed_password, ""))
    conn.commit()
    return {"mensaje": "Usuario registrado"}

# Ruta para cambiar la contraseña de un usuario
@app.put("/usuarios/cambiar-contrasena", response_model=dict)
async def cambiar_contrasena(new_password: str, credentials: HTTPBasicCredentials = Depends(security)):
    username = credentials.username
    password_hash = hashlib.md5(credentials.password.encode()).hexdigest()

    # Verifica si el usuario existe en la tabla de usuarios
    c = conn.cursor()
    c.execute("SELECT * FROM usuarios WHERE username = ? AND password = ?", (username, password_hash))
    existing_user = c.fetchone()

    if not existing_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales inválidas",
            headers={"WWW-Authenticate": "Basic"},
        )

    # Cambia la contraseña del usuario
    new_password_hash = hashlib.md5(new_password.encode()).hexdigest()
    c.execute("UPDATE usuarios SET password = ? WHERE username = ?", (new_password_hash, username))
    conn.commit()
    return {"mensaje": "Contraseña cambiada exitosamente"}



# Rutas para las operaciones CRUD de Contactos

@app.post("/contactos")
async def crear_contacto(contacto: Contacto, credentialsv: HTTPAuthorizationCredentials = Depends(securirtyBearer)):
    token = credentialsv.credentials
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token no proporcionado",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Verifica si el token es válido para el usuario actual
    if not validar_token(token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token no válido",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        c = conn.cursor()
        c.execute('INSERT INTO contactos (email, nombre, telefono) VALUES (?, ?, ?)',
                  (contacto.email, contacto.nombre, contacto.telefono))
        conn.commit()
        return contacto
    except sqlite3.Error as e:
        return error_response("El email ya existe" if "UNIQUE constraint failed" in str(e) else "Error al consultar los datos", 400)


@app.get("/contactos")
async def obtener_contactos(credentialsv: HTTPAuthorizationCredentials = Depends(securirtyBearer)):
    token = credentialsv.credentials
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token no proporcionado",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Verifica si el token es válido para el usuario actual
    if not validar_token(token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token no válido",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        c = conn.cursor()
        c.execute('SELECT * FROM contactos;')
        response = []
        for row in c:
            contacto = {"email": row[0], "nombre": row[1], "telefono": row[2]}
            response.append(contacto)
        if not response:
            return []
        return response
    except sqlite3.Error:
        return error_response("Error al consultar los datos", 500)


@app.get("/contactos/{email}")
async def obtener_contacto(email: str, credentialsv: HTTPAuthorizationCredentials = Depends(securirtyBearer)):
    token = credentialsv.credentials
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token no proporcionado",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Verifica si el token es válido para el usuario actual
    if not validar_token(token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token no válido",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        c = conn.cursor()
        c.execute('SELECT * FROM contactos WHERE email = ?', (email,))
        contacto = None
        for row in c:
            contacto = {"email": row[0], "nombre": row[1], "telefono": row[2]}
        if not contacto:
            return error_response("El email de no existe", 404)
        return contacto
    except sqlite3.Error:
        return error_response("Error al consultar los datos", 500)


@app.put("/contactos/{email}")
async def actualizar_contacto(email: str, contacto: Contacto, credentialsv: HTTPAuthorizationCredentials = Depends(securirtyBearer)):
    token = credentialsv.credentials
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token no proporcionado",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Verifica si el token es válido para el usuario actual
    if not validar_token(token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token no válido",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        c = conn.cursor()
        c.execute('UPDATE contactos SET nombre = ?, telefono = ? WHERE email = ?',
                  (contacto.nombre, contacto.telefono, email))
        conn.commit()
        return contacto
    except sqlite3.Error:
        return error_response("El contacto no existe" if not obtener_contacto(email) else "Error al consultar los datos", 400)


@app.delete("/contactos/{email}")
async def eliminar_contacto(email: str, credentialsv: HTTPAuthorizationCredentials = Depends(securirtyBearer)):
    token = credentialsv.credentials
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token no proporcionado",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Verifica si el token es válido para el usuario actual
    if not validar_token(token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token no válido",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        c = conn.cursor()
        c.execute('DELETE FROM contactos WHERE email = ?', (email,))
        conn.commit()
        if c.rowcount == 0:
            return error_response("El contacto no existe", 404)
        return {"mensaje": "Contacto eliminado"}
    except sqlite3.Error:
        return error_response("Error al consultar los datos", 500)
