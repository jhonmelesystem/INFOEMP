const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs'); 
const jwt = require('jsonwebtoken');
const cors = require('cors');

// 1. Inicializar app PRIMERO
const app = express();

const JWT_SECRET = 'INFOEMP_SUPER_SECRET_KEY_2026';

// 2. Configurar middlewares (CORS, JSON y archivos estáticos)
app.use(cors({
    origin: '*', 
    methods: ['GET', 'POST', 'PUT', 'DELETE'], 
    allowedHeaders: ['Content-Type', 'Authorization'] 
}));
app.use(express.json());

// Sirve los archivos del frontend (HTML, CSS, JS) de la carpeta public
app.use(express.static('public'));

// Conexión a la base de datos infoemp 192.168.100.24 5000
// ================= CONEXIÓN A MYSQL LOCAL =================
const db = mysql.createConnection({
    host: 'localhost',
    port: 3306, // Puerto donde corre tu MySQL Workbench
    user: 'root',
    password: 'ODod123456',
    database: 'infoemp'
});

db.connect((err) => {
    if (err) {
        console.error('❌ Error conectando a la base de datos de infoemp:', err.message);
        return;
    }
    console.log('🚀 ¡Conectado con éxito a la base de datos de infoemp!');
});

// Creación automática de tablas
const crearTablasDeFormaAutomatica = () => {
    const tablaUsuarios = `
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) NOT NULL UNIQUE,
            password VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    `;

    const tablaEmpleados = `
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
        );
    `;

    db.query(tablaUsuarios, (err) => {
        if (err) console.error('Error creando tabla users:', err.message);
        else console.log('✅ Tabla users verificada/creada');
    });

    db.query(tablaEmpleados, (err) => {
        if (err) {
            console.error('Error creando tabla employees:', err.message);
        } else {
            console.log('✅ Tabla employees verificada/creada');
        }

        const agregarUserId = `ALTER TABLE employees ADD COLUMN IF NOT EXISTS user_id INT;`;
        const agregarSeguro = `ALTER TABLE employees ADD COLUMN IF NOT EXISTS seguroMedico VARCHAR(100);`;
        const agregarSangre = `ALTER TABLE employees ADD COLUMN IF NOT EXISTS tipoSangre VARCHAR(20);`;

        db.query(agregarUserId, (errAlter) => {
            if (!errAlter) console.log('✅ Columna user_id verificada');
        });
        db.query(agregarSeguro, (errAlter) => {
            if (!errAlter) console.log('✅ Columna seguroMedico verificada');
        });
        db.query(agregarSangre, (errAlter) => {
            if (!errAlter) console.log('✅ Columna tipoSangre verificada');
        });
    });
};
crearTablasDeFormaAutomatica();

// Middleware de autenticación JWT
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

// Registrarse
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Faltan datos requeridos' });

    try {
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const query = 'INSERT INTO users (username, password) VALUES (?, ?)';
        db.query(query, [username, hashedPassword], (err, result) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') {
                    return res.status(400).json({ error: 'El nombre de usuario ya existe' });
                }
                return res.status(500).json({ error: 'Error al guardar el usuario' });
            }
            res.status(201).json({ message: 'Usuario registrado con éxito' });
        });
    } catch (err) {
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Iniciar Sesión
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Campos incompletos' });

    const query = 'SELECT * FROM users WHERE username = ?';
    db.query(query, [username], async (err, results) => {
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

// Obtener todos los empleados (Protegido)
app.get('/api/employees', verificarToken, (req, res) => {
    const userId = req.user.id;

    db.query('SELECT * FROM employees WHERE user_id = ? ORDER BY id DESC', [userId], (err, results) => {
        if (err) return res.status(500).json({ error: 'Error al obtener empleados' });
        res.json(results);
    });
});

// Guardar nuevo empleado (Protegido)
app.post('/api/employees', verificarToken, (req, res) => {
    const userId = req.user.id;
    const { name, document, employeeNumber, celular, seguroMedico, tipoSangre, lugarTrabajo, telefonoEmpresa } = req.body;

    const query = `INSERT INTO employees (user_id, name, document, employeeNumber, celular, seguroMedico, tipoSangre, lugarTrabajo, telefonoEmpresa) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`;

    db.query(query, [userId, name, document, employeeNumber, celular, seguroMedico, tipoSangre, lugarTrabajo, telefonoEmpresa], (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ error: 'Error al guardar el empleado' });
        }
        res.status(201).json({ message: 'Empleado guardado exitosamente para tu cuenta' });
    });
});

// Editar empleado (Protegido)
app.put('/api/employees/:id', verificarToken, (req, res) => {
    const { id } = req.params;
    const userId = req.user.id;
    const { name, document, employeeNumber, celular, seguroMedico, tipoSangre, lugarTrabajo, telefonoEmpresa } = req.body;
    const query = `UPDATE employees SET name=?, document=?, employeeNumber=?, celular=?, seguroMedico=?, tipoSangre=?, lugarTrabajo=?, telefonoEmpresa=? WHERE id=? AND user_id=?`;

    db.query(query, [name, document, employeeNumber, celular, seguroMedico, tipoSangre, lugarTrabajo, telefonoEmpresa, id, userId], (err, result) => {
        if (err) return res.status(500).json({ error: 'Error al actualizar empleado' });
        res.json({ message: 'Empleado actualizado' });
    });
});

// Eliminar múltiples empleados (Protegido)
app.post('/api/employees/delete-multiple', verificarToken, (req, res) => {
    const { ids } = req.body;
    const userId = req.user.id;
    if (!ids || ids.length === 0) return res.status(400).json({ error: 'No se enviaron IDs' });

    const query = 'DELETE FROM employees WHERE user_id = ? AND id IN (?)';
    db.query(query, [userId, ids], (err, result) => {
        if (err) return res.status(500).json({ error: 'Error al eliminar empleados' });
        res.json({ message: 'Empleados eliminados con éxito' });
    });
});

// Ver detalles públicos mediante Link compartido (PÚBLICO)
app.get('/api/share/employee/:id', (req, res) => {
    const { id } = req.params;
    db.query('SELECT * FROM employees WHERE id = ?', [id], (err, results) => {
        if (err) return res.status(500).json({ error: 'Error del servidor' });
        if (results.length === 0) return res.status(404).json({ error: 'Empleado no encontrado' });
        res.json(results[0]);
    });
});

// Inicializar Servidor
// AHORA (forzamos el 5000)
const PORT = 5000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`⭐ Servidor InfoEmp corriendo perfectamente en el puerto ${PORT}`);
});