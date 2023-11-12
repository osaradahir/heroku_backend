import fastapi
import sqlite3
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware

# Crea la base de datos
conn = sqlite3.connect("sql/contactos.db")

app = fastapi.FastAPI()

origins = [
    "https://frontend-api-f54e97981b98.herokuapp.com",
    "http://127.0.0.0:8080",
    "http://127.0.0.1:8000/"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class Contacto(BaseModel):
    email : str
    nombre : str
    telefono : str

@app.post("/contactos")
async def crear_contacto(contacto: Contacto):
    c = conn.cursor()
    c.execute('INSERT INTO contactos (email, nombre, telefono) VALUES (?, ?, ?)',
              (contacto.email, contacto.nombre, contacto.telefono))
    conn.commit()
    return contacto

@app.get("/contactos")
async def obtener_contactos():
    """Obtiene todos los contactos."""
    c = conn.cursor()
    c.execute('SELECT * FROM contactos;')
    response = []
    for row in c:
        contacto = {"email":row[0],"nombre":row[1], "telefono":row[2]}
        response.append(contacto)
    return response


@app.get("/contactos/{email}")
async def obtener_contacto(email: str):
    """Obtiene un contacto por su email."""
    # Consulta el contacto por su email
    c = conn.cursor()
    c.execute('SELECT * FROM contactos WHERE email = ?', (email,))
    contacto = None
    for row in c:
        contacto = {"email":row[0],"nombre":row[1],"telefono":row[2]}
    return contacto



@app.put("/contactos/{email}")
async def actualizar_contacto(email: str, nuevo_contacto: Contacto):
    # Verifica si el nuevo email ya existe en la base de datos
    c = conn.cursor()
    c.execute('SELECT * FROM contactos WHERE email = ?', (nuevo_contacto.email,))
    existing_contact = c.fetchone()

    if existing_contact:
        return {"error": "El nuevo correo electrónico ya está en uso.", "status_code": 400}

    # Actualiza el contacto
    c.execute('UPDATE contactos SET email = ?, nombre = ?, telefono = ? WHERE email = ?',
              (nuevo_contacto.email, nuevo_contacto.nombre, nuevo_contacto.telefono, email))
    conn.commit()
    
    return nuevo_contacto

@app.delete("/contactos/{email}")
async def eliminar_contacto(email: str):
    """Elimina un contacto."""
    # TODO Elimina el contacto de la base de datos
    c = conn.cursor()
    c.execute('DELETE FROM contactos WHERE email = ?', (email,))
    conn.commit()
    return {"mensaje":"Contacto eliminado"}
