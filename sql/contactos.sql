CREATE TABLE contactos (
    email varchar(100) PRIMARY KEY,
    nombre varchar(50),
    telefono varchar(12)
);

INSERT INTO contactos (email, nombre, telefono)
VALUES ('juan@example.com', 'Juan Pérez', '555-123-4567');

INSERT INTO contactos (email, nombre, telefono)
VALUES ('maria@example.com', 'María García', '555-678-9012');

CREATE TABLE IF NOT EXISTS usuarios(
    username TEXT PRIMARY KEY,
    password  TEXT NOT NULL,
    token     TEXT NOT NULL
);