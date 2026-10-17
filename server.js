const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const { randomUUID } = require('crypto');

const app = express();

// ================= CONFIGURACIÓN (variables de entorno) =================
const JWT_SECRET = process.env.JWT_SECRET || (process.env.RAILWAY_ENVIRONMENT ? null : 'clave_solo_para_desarrollo_local');
if (!JWT_SECRET) {
    console.error('❌ Falta la variable JWT_SECRET');
    process.exit(1);
}

app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ================= CONEXIÓN A MYSQL (pool) =================
const db = mysql.createPool({
    host: process.env.MYSQLHOST || 'localhost',
    port: process.env.MYSQLPORT || 3306,
    user: process.env.MYSQLUSER || 'root',
    password: process.env.MYSQLPASSWORD || '',
    database: process.env.MYSQLDATABASE || 'infoemp',
    waitForConnections: true,
    connectionLimit: 10
});

// Creación automática de tablas + migración de share_token
async function iniciarBaseDeDatos() {
    const p = db.promise();
    try {
        await p.query(`
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) NOT NULL UNIQUE,
                password VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log('✅ Tabla users verificada/creada');

        await p.query(`
            CREATE TABLE IF NOT EXISTS employees (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                name VARCHAR(100) NOT NULL,
                document VARCHAR(50) NOT NULL,
                employeeNumber VARCHAR(50) NOT NULL,
                celular VARCHAR(20),
                seguroMedico VARCHAR(100),
                tipoSangre VARCHAR(20),
                lugarTrabajo VARCHAR(100),
                telefonoEmpresa VARCHAR(20),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Agregar share_token si la tabla ya existía sin esa columna
        const [cols] = await p.query("SHOW COLUMNS FROM employees LIKE 'share_token'");
        if (cols.length === 0) {
            await p.query('ALTER TABLE employees ADD COLUMN share_token VARCHAR(36) UNIQUE');
        }
        // Dar token a los empleados que ya existían
        await p.query('UPDATE employees SET share_token = UUID() WHERE share_token IS NULL');
        console.log('✅ Tabla employees verificada/creada');
    } catch (err) {
        console.error('❌ Error de base de datos:', err.message);
    }
}
iniciarBaseDeDatos();

// ================= MIDDLEWARE JWT =================
const verificarToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: 'Acceso denegado, token faltante' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Token inválido o expirado' });
        req.user = user;
        next();
    });
};

// ================= RUTAS DE AUTENTICACIÓN =================

app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Faltan datos requeridos' });

    try {
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        db.query('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], (err) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') {
                    return res.status(400).json({ error: 'El nombre de usuario ya existe' });
                }
                console.error('Error register:', err.message);
                return res.status(500).json({ error: 'Error al guardar el usuario' });
            }
            res.status(201).json({ message: 'Usuario registrado con éxito' });
        });
    } catch (err) {
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Campos incompletos' });

    db.query('SELECT * FROM users WHERE username = ?', [username], async (err, results) => {
        if (err) return res.status(500).json({ error: 'Error en el servidor' });
        if (results.length === 0) return res.status(400).json({ error: 'El usuario no existe' });

        const user = results[0];
        const passwordCorrecto = await bcrypt.compare(password, user.password);
        if (!passwordCorrecto) return res.status(400).json({ error: 'Contraseña incorrecta' });

        const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ token, username: user.username });
    });
});

// ================= RUTAS DE EMPLEADOS =================

app.get('/api/employees', verificarToken, (req, res) => {
    db.query('SELECT * FROM employees WHERE user_id = ? ORDER BY id DESC', [req.user.id], (err, results) => {
        if (err) {
            console.error('Error GET employees:', err);
            return res.status(500).json({ error: 'Error al obtener empleados' });
        }
        res.json(results);
    });
});

app.post('/api/employees', verificarToken, (req, res) => {
    const userId = req.user.id;
    const { name, document, employeeNumber, celular, seguroMedico, tipoSangre, lugarTrabajo, telefonoEmpresa } = req.body;

    if (!name || !document || !employeeNumber) {
        return res.status(400).json({ error: 'Nombre, documento y número de empleado son obligatorios' });
    }

    const query = `INSERT INTO employees (user_id, name, document, employeeNumber, celular, seguroMedico, tipoSangre, lugarTrabajo, telefonoEmpresa, share_token) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

    db.query(query, [userId, name, document, employeeNumber, celular || '', seguroMedico || '', tipoSangre || '', lugarTrabajo || '', telefonoEmpresa || '', randomUUID()], (err) => {
        if (err) {
            console.error('Error POST employee:', err);
            return res.status(500).json({ error: 'Error al guardar el empleado' });
        }
        res.status(201).json({ message: 'Empleado guardado exitosamente para tu cuenta' });
    });
});

app.put('/api/employees/:id', verificarToken, (req, res) => {
    const { id } = req.params;
    const userId = req.user.id;
    const { name, document, employeeNumber, celular, seguroMedico, tipoSangre, lugarTrabajo, telefonoEmpresa } = req.body;

    const query = `UPDATE employees SET name=?, document=?, employeeNumber=?, celular=?, seguroMedico=?, tipoSangre=?, lugarTrabajo=?, telefonoEmpresa=? WHERE id=? AND user_id=?`;

    db.query(query, [name, document, employeeNumber, celular || '', seguroMedico || '', tipoSangre || '', lugarTrabajo || '', telefonoEmpresa || '', id, userId], (err) => {
        if (err) {
            console.error('Error PUT employee:', err);
            return res.status(500).json({ error: 'Error al actualizar empleado' });
        }
        res.json({ message: 'Empleado actualizado' });
    });
});

app.post('/api/employees/delete-multiple', verificarToken, (req, res) => {
    const { ids } = req.body;
    const userId = req.user.id;

    if (!ids || !Array.isArray(ids) || ids.length === 0) {
        return res.status(400).json({ error: 'No se enviaron IDs válidos' });
    }

    const placeholders = ids.map(() => '?').join(',');
    const query = `DELETE FROM employees WHERE user_id = ? AND id IN (${placeholders})`;

    db.query(query, [userId, ...ids], (err) => {
        if (err) {
            console.error('Error DELETE multiple:', err);
            return res.status(500).json({ error: 'Error al eliminar empleados' });
        }
        res.json({ message: 'Empleados eliminados con éxito' });
    });
});

// Ver detalles públicos mediante link compartido (PÚBLICO, por token aleatorio)
app.get('/api/share/employee/:token', (req, res) => {
    const { token } = req.params;
    db.query(
        `SELECT name, document, employeeNumber, celular, seguroMedico, tipoSangre, lugarTrabajo, telefonoEmpresa
         FROM employees WHERE share_token = ?`,
        [token],
        (err, results) => {
            if (err) return res.status(500).json({ error: 'Error del servidor' });
            if (results.length === 0) return res.status(404).json({ error: 'Empleado no encontrado' });
            res.json(results[0]);
        }
    );
});

// ================= INICIAR SERVIDOR =================
const PORT = process.env.PORT || 3001;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`⭐ Servidor InfoEmp corriendo en el puerto ${PORT}`);
});