const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// Conexión a la base de datos de XAMPP
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'infoemp_db'
});

db.connect((err) => {
    if (err) {
        console.error('❌ Error conectando a la base de datos:', err);
        return;
    }
    console.log('✅ Conectado a la base de datos SQL en XAMPP');
});

// Ruta para Registrarse
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Faltan datos' });

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.query('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], (err, result) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') return res.status(400).json({ error: 'El usuario ya existe' });
                return res.status(500).json({ error: err.message });
            }
            res.json({ message: 'Usuario registrado con éxito' });
        });
    } catch (e) {
        res.status(500).json({ error: 'Error en el servidor' });
    }
});

// Ruta para Iniciar Sesión
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    
    db.query('SELECT * FROM users WHERE username = ?', [username], async (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        if (results.length === 0) return res.status(400).json({ error: 'Usuario no encontrado' });

        const user = results[0];
        const validPass = await bcrypt.compare(password, user.password);
        if (!validPass) return res.status(400).json({ error: 'Contraseña incorrecta' });

        const token = jwt.sign({ id: user.id }, 'secreto_super_seguro', { expiresIn: '1h' });
        res.json({ message: '¡Login exitoso!', token });
    });
});


// Función intermedia para proteger las rutas con el Token
const verificarToken = (req, res, next) => {
    // Captura la cabecera de autorización
    const authHeader = req.headers['authorization'] || req.headers['Authorization'];
    
    // Separa la palabra 'Bearer' del token real
    const token = authHeader && authHeader.split(' ')[1];

    // Si no hay token, frena con un 401
    if (!token) {
        console.log("❌ Intento de acceso sin Token");
        return res.status(401).json({ error: 'Acceso denegado, falta token' });
    }

    // Verifica que el token sea válido usando la misma palabra secreta
    jwt.verify(token, 'secreto_super_seguro', (err, user) => {
        if (err) {
            console.log("❌ Token inválido o expirado:", err.message);
            return res.status(403).json({ error: 'Token inválido o expirado' });
        }
        
        req.user = user; // Guarda el usuario en la solicitud
        next(); // Permite pasar a la ruta (ej. /api/employees)
    });
};

// 1. Ruta para AGREGAR Empleado (POST)
app.post('/api/employees', verificarToken, (req, res) => {
    const { name, document, employeeNumber, celular, lugarTrabajo, telefonoEmpresa } = req.body;
    
    const query = 'INSERT INTO employees (name, document, employeeNumber, celular, lugarTrabajo, telefonoEmpresa) VALUES (?, ?, ?, ?, ?, ?)';
    db.query(query, [name, document, employeeNumber, celular, lugarTrabajo, telefonoEmpresa], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Empleado guardado con éxito', id: result.insertId });
    });
});

// 2. Ruta para EDITAR Empleado (PUT)
app.put('/api/employees/:id', verificarToken, (req, res) => {
    const { id } = req.params;
    const { name, document, employeeNumber, celular, lugarTrabajo, telefonoEmpresa } = req.body;

    const query = 'UPDATE employees SET name=?, document=?, employeeNumber=?, celular=?, lugarTrabajo=?, telefonoEmpresa=? WHERE id=?';
    db.query(query, [name, document, employeeNumber, celular, lugarTrabajo, telefonoEmpresa, id], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Empleado actualizado con éxito' });
    });
});

// 3. Ruta para LEER todos los empleados (GET) - Tu función loadEmployees() la va a necesitar
app.get('/api/employees', verificarToken, (req, res) => {
    db.query('SELECT * FROM employees', (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results);
    });
});

// Ruta PÚBLICA exacta para el visor integrado de tu index.html (Sin verificarToken)
app.get('/api/share/employee/:id', (req, res) => {
    const { id } = req.params;
    
    // Usamos los mismos nombres de columna que tu base de datos y tu frontend manejan
    db.query('SELECT * FROM employees WHERE id = ?', [id], (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        if (results.length === 0) return res.status(404).json({ error: 'Empleado no encontrado' });
        
        // Mapeamos los campos para asegurarnos de que el frontend reciba lo que espera
        const emp = results[0];
        res.json({
            id: emp.id,
            name: emp.name,
            document: emp.document,
            employee_number: emp.employeeNumber || emp.employee_number,
            celular: emp.celular || 'No registrado',
            lugar_trabajo: emp.lugarTrabajo || emp.lugar_trabajo || 'No registrado',
            telefono_empresa: emp.telefonoEmpresa || emp.telefono_empresa || 'No registrado'
        });
    });
});

// Ruta para eliminar múltiples empleados seleccionados (POST)
app.post('/api/employees/delete-multiple', verificarToken, (req, res) => {
    const { ids } = req.body;
    if (!ids || !Array.from(ids).length) return res.status(400).json({ error: 'No se enviaron IDs' });

    db.query('DELETE FROM employees WHERE id IN (?)', [ids], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Empleados eliminados con éxito' });
    });
});

app.listen(3000, () => {
    console.log('🚀 Servidor corriendo en http://192.168.11.211:3000');
});