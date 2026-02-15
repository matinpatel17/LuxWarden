-- LuxWarden Universal Database Schema
-- Compatible with MySQL 5.7, 8.0, and MariaDB
-- --------------------------------------------------------

-- 1. Create Database
CREATE DATABASE IF NOT EXISTS luxwarden;
USE luxwarden;

-- 2. Drop Tables if they exist (Order matters due to foreign keys)
DROP TABLE IF EXISTS support_tickets;
DROP TABLE IF EXISTS firewall_rules;
DROP TABLE IF EXISTS blocked_ips;
DROP TABLE IF EXISTS attack_logs;
DROP TABLE IF EXISTS domains;
DROP TABLE IF EXISTS contact_messages;
DROP TABLE IF EXISTS payments;
DROP TABLE IF EXISTS users;

-- --------------------------------------------------------

-- 3. Users Table
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    full_name VARCHAR(100) NOT NULL,
    email VARCHAR(120) UNIQUE NOT NULL,
    phone_number VARCHAR(20),
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- --------------------------------------------------------

CREATE TABLE contact_messages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    first_name VARCHAR(50) NOT NULL,
    last_name VARCHAR(50),
    email VARCHAR(100) NOT NULL,
    phone_number VARCHAR(15),
    message TEXT NOT NULL,
    submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- -------------------------------------------------------

CREATE TABLE payments (
    payment_id INT AUTO_INCREMENT PRIMARY KEY,

    user_id INT NOT NULL,

    full_name VARCHAR(100) NOT NULL,
    date_of_birth DATE NOT NULL,
    email VARCHAR(100) NOT NULL,
    phone VARCHAR(15) NOT NULL,
    billing_address TEXT NOT NULL,

    card_holder_name VARCHAR(100) NOT NULL,

    card_number_encrypted TEXT NOT NULL,
    card_expiry VARCHAR(7) NOT NULL, -- MM/YYYY
    cvv_hash VARCHAR(255) NOT NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_payments_user
        FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
);

-- 4. Domains Table (Protected Websites)
CREATE TABLE domains (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    domain_name VARCHAR(255) NOT NULL,
    target_url VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- --------------------------------------------------------

-- 5. Attack Logs Table (History)
CREATE TABLE attack_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    domain_id INT NOT NULL,
    attack_type VARCHAR(50),
    payload TEXT,
    attacker_ip VARCHAR(45),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- --------------------------------------------------------

-- 6. Blocked IPs Table
CREATE TABLE blocked_ips (
    id INT AUTO_INCREMENT PRIMARY KEY,
    domain_id INT NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- --------------------------------------------------------

-- 7. Firewall Rules Table (Settings)
CREATE TABLE firewall_rules (
    id INT AUTO_INCREMENT PRIMARY KEY,
    domain_id INT NOT NULL,
    block_sqli BOOLEAN DEFAULT TRUE,
    block_xss BOOLEAN DEFAULT TRUE,
    block_ip BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- --------------------------------------------------------

-- 8. Support Tickets Table (NEW)
CREATE TABLE support_tickets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    subject VARCHAR(100) NOT NULL,
    message TEXT NOT NULL,
    status ENUM('Open', 'In Progress', 'Closed') DEFAULT 'Open',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;