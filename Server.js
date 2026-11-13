const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');

const app = express();
const PORT = 3000;

// Middleware
app.use(express.json());
app.use(cors());

// Initialize SQLite Database
const db = new sqlite3.Database('./securevpn.db', (err) => {
  if (err) {
    console.error('Error opening database:', err.message);
  } else {
    console.log('Connected to the SecureVPN SQLite database.');
    
    // 1. Users Table
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      email TEXT,
      department TEXT,
      role TEXT,
      status TEXT
    )`, () => {
      db.get(`SELECT COUNT(*) as count FROM users`, (err, row) => {
        if (row && row.count === 0) {
          db.run(`INSERT INTO users (username, email, department, role, status) VALUES 
            ('johndoe', 'john@securevpn.com', 'Engineering', 'Developer', 'Active'),
            ('janecodes', 'jane@securevpn.com', 'Security', 'Analyst', 'Active')`);
        }
      });
    });

    // 2. Devices Table
    db.run(`CREATE TABLE IF NOT EXISTS devices (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      device_name TEXT,
      os_platform TEXT,
      mac_address TEXT,
      assigned_user TEXT,
      compliance TEXT
    )`, () => {
      db.get(`SELECT COUNT(*) as count FROM devices`, (err, row) => {
        if (row && row.count === 0) {
          db.run(`INSERT INTO devices (device_name, os_platform, mac_address, assigned_user, compliance) VALUES 
            ('MacBook-Pro-M3', 'macOS Sonoma', '34:77:42:19:88:10', 'johndoe', 'Compliant'),
            ('Legacy-Win7-PC', 'Windows 7', 'A0:B1:C2:D3:E4:F5', 'janecodes', 'Non-Compliant (Legacy OS)')`);
        }
      });
    });

    // 3. Audit Logs Table
    db.run(`CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp TEXT,
      user_account TEXT,
      action_performed TEXT,
      ip_address TEXT
    )`);

    // 4. Admin Users Table
    db.run(`CREATE TABLE IF NOT EXISTS admin_users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT
    )`, () => {
      db.get(`SELECT COUNT(*) as count FROM admin_users`, (err, row) => {
        if (row && row.count === 0) {
          db.run(`INSERT INTO admin_users (username, password) VALUES ('admin', 'password123')`);
        }
      });
    });

    // 5. VPN Tunnels Table
    db.run(`CREATE TABLE IF NOT EXISTS vpn_tunnels (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT,
      client_ip TEXT,
      assigned_virtual_ip TEXT,
      protocol TEXT,
      bytes_transferred TEXT,
      duration TEXT
    )`);

    // 6. Policies Table
    db.run(`CREATE TABLE IF NOT EXISTS policies (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      policy_name TEXT,
      target_department TEXT,
      enforcement_rule TEXT,
      status TEXT
    )`, () => {
      db.get(`SELECT COUNT(*) as count FROM policies`, (err, row) => {
        if (row && row.count === 0) {
          db.run(`INSERT INTO policies (policy_name, target_department, enforcement_rule, status) VALUES 
            ('IT Infrastructure Hardening', 'IT', 'Enforce AES-256 Encryption Tunnels', 'Enforced'),
            ('HR Confidentiality Guard', 'HR', 'Mandatory Multi-Factor Authentication (MFA)', 'Enforced'),
            ('Finance Compliance Lock', 'FINANCE', 'Restrict Access to Office IP Range Only', 'Enforced')`);
        }
      });
    });

    // 7. Modules Table (Enterprise Feature Toggles)
    db.run(`CREATE TABLE IF NOT EXISTS modules (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      module_name TEXT,
      description TEXT,
      status TEXT
    )`, () => {
      db.get(`SELECT COUNT(*) as count FROM modules`, (err, row) => {
        if (row && row.count === 0) {
          db.run(`INSERT INTO modules (module_name, description, status) VALUES 
            ('AI Threat Detection', 'Analyzes anomalous packet signatures using machine learning heuristics.', 'Enabled'),
            ('Deep Packet Inspection (DPI)', 'Inspects data payloads passing through active VPN tunnels.', 'Enabled'),
            ('Automated Device Quarantine', 'Instantly revokes VPN access for non-compliant endpoints.', 'Enabled'),
            ('Cloud SIEM Integration', 'Streams real-time audit logs to external security monitoring hubs.', 'Disabled')`);
        }
      });
    });
  }
});

function getTimestamp() {
  return new Date().toISOString().slice(0, 19).replace('T', ' ');
}

function checkCompliance(os_platform) {
  if (!os_platform) return 'Non-Compliant';
  const lowerOS = os_platform.toLowerCase();
  if (lowerOS.includes('windows 7') || lowerOS.includes('windows 8') || lowerOS.includes('vista') || lowerOS.includes('xp')) {
    return 'Non-Compliant (Legacy OS)';
  }
  return 'Compliant';
}

// --- API ROUTES ---

// Admin Login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  db.get(`SELECT * FROM admin_users WHERE username = ? AND password = ?`, [username, password], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (row) {
      db.run(`INSERT INTO audit_logs (timestamp, user_account, action_performed, ip_address) VALUES (?, ?, ?, ?)`,
        [getTimestamp(), username, `Successful administrator login`, '10.0.0.12']);
      res.json({ success: true, message: 'Login successful' });
    } else {
      res.status(401).json({ success: false, message: 'Invalid username or password' });
    }
  });
});

// Live VPN Connections Routes
app.get('/api/vpn/connections', (req, res) => {
  db.all(`SELECT * FROM vpn_tunnels`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ connections: rows });
  });
});

app.post('/api/vpn/connections', (req, res) => {
  const { username, client_ip, assigned_virtual_ip, protocol } = req.body;
  const bytes_transferred = '12.4 MB';
  const duration = '00:01:05';

  db.run(`INSERT INTO vpn_tunnels (username, client_ip, assigned_virtual_ip, protocol, bytes_transferred, duration) VALUES (?, ?, ?, ?, ?, ?)`,
    [username, client_ip, assigned_virtual_ip, protocol, bytes_transferred, duration], function(err) {
      if (err) return res.status(400).json({ error: err.message });
      db.run(`INSERT INTO audit_logs (timestamp, user_account, action_performed, ip_address) VALUES (?, ?, ?, ?)`,
        [getTimestamp(), username, `Established live VPN tunnel via ${protocol} (Virtual IP: ${assigned_virtual_ip})`, client_ip]);
      res.json({ success: true, id: this.lastID });
    });
});

app.delete('/api/vpn/connections/:id', (req, res) => {
  const { id } = req.params;
  db.get(`SELECT username FROM vpn_tunnels WHERE id = ?`, [id], (err, row) => {
    const username = row ? row.username : `Tunnel #${id}`;
    db.run(`DELETE FROM vpn_tunnels WHERE id = ?`, [id], function(err) {
      if (err) return res.status(400).json({ error: err.message });
      db.run(`INSERT INTO audit_logs (timestamp, user_account, action_performed, ip_address) VALUES (?, ?, ?, ?)`,
        [getTimestamp(), 'admin@securevpn.com', `Terminated live VPN tunnel for user: ${username}`, '10.0.0.12']);
      res.json({ success: true });
    });
  });
});

app.post('/api/vpn/killswitch', (req, res) => {
  db.run(`DELETE FROM vpn_tunnels`, [], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    db.run(`INSERT INTO audit_logs (timestamp, user_account, action_performed, ip_address) VALUES (?, ?, ?, ?)`,
      [getTimestamp(), 'admin@securevpn.com', `CRITICAL: Emergency Kill Switch activated! All tunnels terminated.`, '10.0.0.12']);
    res.json({ success: true });
  });
});

// Devices Routes
app.get('/api/devices', (req, res) => {
  db.all(`SELECT * FROM devices`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ devices: rows });
  });
});

app.post('/api/devices', (req, res) => {
  const { device_name, os_platform, mac_address, assigned_user } = req.body;
  const compliance = checkCompliance(os_platform);

  db.run(`INSERT INTO devices (device_name, os_platform, mac_address, assigned_user, compliance) VALUES (?, ?, ?, ?, ?)`,
    [device_name, os_platform, mac_address, assigned_user, compliance], function(err) {
      if (err) return res.status(400).json({ error: err.message });
      db.run(`INSERT INTO audit_logs (timestamp, user_account, action_performed, ip_address) VALUES (?, ?, ?, ?)`,
        [getTimestamp(), assigned_user || 'admin@securevpn.com', `Auto-inspected device ${device_name} (${os_platform}) -> Status: ${compliance}`, '10.0.0.12']);
      res.json({ id: this.lastID, compliance, success: true });
    });
});

app.delete('/api/devices/:id', (req, res) => {
  const { id } = req.params;
  db.get(`SELECT device_name FROM devices WHERE id = ?`, [id], (err, row) => {
    const deviceName = row ? row.device_name : `ID #${id}`;
    db.run(`DELETE FROM devices WHERE id = ?`, [id], function(err) {
      if (err) return res.status(400).json({ error: err.message });
      db.run(`INSERT INTO audit_logs (timestamp, user_account, action_performed, ip_address) VALUES (?, ?, ?, ?)`,
        [getTimestamp(), 'admin@securevpn.com', `Deleted device: ${deviceName}`, '10.0.0.12']);
      res.json({ success: true, message: `Device ${deviceName} deleted successfully.` });
    });
  });
});

// Department-Scoped Policies Routes
app.get('/api/policies', (req, res) => {
  db.all(`SELECT * FROM policies`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ policies: rows });
  });
});

app.post('/api/policies', (req, res) => {
  const { policy_name, target_department, enforcement_rule } = req.body;
  const allowedDepartments = ['HR', 'IT', 'FINANCE', 'ACCOUNTING', 'MARKETING'];
  if (!allowedDepartments.includes(target_department)) {
    return res.status(400).json({ success: false, error: 'Invalid department selected.' });
  }

  db.run(`INSERT INTO policies (policy_name, target_department, enforcement_rule, status) VALUES (?, ?, ?, ?)`,
    [policy_name, target_department, enforcement_rule, 'Enforced'], function(err) {
      if (err) return res.status(400).json({ error: err.message });
      db.run(`INSERT INTO audit_logs (timestamp, user_account, action_performed, ip_address) VALUES (?, ?, ?, ?)`,
        [getTimestamp(), 'admin@securevpn.com', `Created security policy '${policy_name}' for department: ${target_department}`, '10.0.0.12']);
      res.json({ success: true, id: this.lastID });
    });
});

app.delete('/api/policies/:id', (req, res) => {
  const { id } = req.params;
  db.run(`DELETE FROM policies WHERE id = ?`, [id], function(err) {
    if (err) return res.status(400).json({ error: err.message });
    res.json({ success: true });
  });
});

// Modules (Feature Toggles) Routes
app.get('/api/modules', (req, res) => {
  db.all(`SELECT * FROM modules`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ modules: rows });
  });
});

app.post('/api/modules/:id/toggle', (req, res) => {
  const { id } = req.params;
  db.get(`SELECT * FROM modules WHERE id = ?`, [id], (err, mod) => {
    if (err || !mod) return res.status(404).json({ error: 'Module not found.' });

    const newStatus = mod.status === 'Enabled' ? 'Disabled' : 'Enabled';
    db.run(`UPDATE modules SET status = ? WHERE id = ?`, [newStatus, id], function(err) {
      if (err) return res.status(500).json({ error: err.message });
      db.run(`INSERT INTO audit_logs (timestamp, user_account, action_performed, ip_address) VALUES (?, ?, ?, ?)`,
        [getTimestamp(), 'admin@securevpn.com', `Toggled security module '${mod.module_name}' status to ${newStatus}`, '10.0.0.12']);
      res.json({ success: true, status: newStatus });
    });
  });
});

// Real-Time Monitoring & Telemetry Route
app.get('/api/monitoring/stats', (req, res) => {
  db.get(`SELECT COUNT(*) as activeTunnels FROM vpn_tunnels`, [], (err, tunRow) => {
    if (err) return res.status(500).json({ error: err.message });
    db.get(`SELECT COUNT(*) as totalDevices FROM devices`, [], (err, devRow) => {
      if (err) return res.status(500).json({ error: err.message });

      const tunnels = tunRow ? tunRow.activeTunnels : 0;
      // Dynamically scale simulated server telemetry based on active load
      const cpuUsage = Math.min(15 + (tunnels * 12), 94);
      const memoryUsage = Math.min(32 + (tunnels * 8), 88);
      const throughput = (tunnels * 42.5).toFixed(1);

      res.json({
        serverStatus: 'Optimal & Secure',
        uptime: '99.98%',
        activeTunnels: tunnels,
        totalDevices: devRow ? devRow.totalDevices : 0,
        cpuUsage: `${cpuUsage}%`,
        memoryUsage: `${memoryUsage}%`,
        networkThroughput: `${throughput} Mbps`
      });
    });
  });
});

// Real-Time System Reports & Analytics Endpoint
app.get('/api/reports/summary', (req, res) => {
  db.get(`SELECT COUNT(*) as totalDevices, SUM(CASE WHEN compliance LIKE '%Compliant%' AND compliance NOT LIKE '%Non%' THEN 1 ELSE 0 END) as compliantDevices FROM devices`, (err, devStats) => {
    if (err) return res.status(500).json({ error: err.message });
    db.get(`SELECT COUNT(*) as totalTunnels FROM vpn_tunnels`, (err, tunStats) => {
      if (err) return res.status(500).json({ error: err.message });
      db.get(`SELECT COUNT(*) as totalPolicies FROM policies`, (err, polStats) => {
        if (err) return res.status(500).json({ error: err.message });
        db.all(`SELECT target_department, COUNT(*) as count FROM policies GROUP BY target_department`, (err, deptBreakdown) => {
          if (err) return res.status(500).json({ error: err.message });
          db.all(`SELECT * FROM audit_logs ORDER BY id DESC LIMIT 5`, (err, recentLogs) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({
              devices: {
                total: devStats.totalDevices || 0,
                compliant: devStats.compliantDevices || 0,
                nonCompliant: (devStats.totalDevices || 0) - (devStats.compliantDevices || 0)
              },
              tunnels: { active: tunStats.totalTunnels || 0 },
              policies: { total: polStats.totalPolicies || 0, breakdown: deptBreakdown || [] },
              auditSummary: recentLogs || []
            });
          });
        });
      });
    });
  });
});

// Audit Logs Routes
app.get('/api/audit', (req, res) => {
  db.all(`SELECT * FROM audit_logs ORDER BY id DESC`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ audit_logs: rows });
  });
});

app.delete('/api/audit', (req, res) => {
  db.run(`DELETE FROM audit_logs`, [], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    db.run(`INSERT INTO audit_logs (timestamp, user_account, action_performed, ip_address) VALUES (?, ?, ?, ?)`,
      [getTimestamp(), 'admin@securevpn.com', `WARNING: System audit logs cleared by administrator.`, '10.0.0.12']);
    res.json({ success: true, message: 'Audit logs cleared successfully.' });
  });
});

// Dashboard Statistics Route
app.get('/api/dashboard/stats', (req, res) => {
  db.get(`SELECT COUNT(*) as totalDevices FROM devices`, [], (err, devRow) => {
    if (err) return res.status(500).json({ error: err.message });
    db.get(`SELECT COUNT(*) as activeTunnels FROM vpn_tunnels`, [], (err, tunRow) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({
        totalConnectedDevices: devRow ? devRow.totalDevices : 0,
        activeTunnels: tunRow ? tunRow.activeTunnels : 0,
        systemStatus: "Optimal"
      });
    });
  });
});

app.listen(PORT, () => {
  console.log(`Backend server running at http://localhost:${PORT}`);
});