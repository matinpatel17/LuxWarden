-- Parent Tables (users, domains)
-- Child tables (attack_logs, blocked_ips, firewall_rules, payments, support_tickets, custom_report_request)
-- Independent table (contact_messages)

DROP TABLE IF EXISTS `users`;
CREATE TABLE `users` (
  `id` int NOT NULL AUTO_INCREMENT,
  `full_name` varchar(100) NOT NULL,
  `email` varchar(100) NOT NULL,
  `phone_number` varchar(15) DEFAULT NULL,
  `password` varchar(255) NOT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `is_paid` tinyint(1) DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `email` (`email`)
);

DROP TABLE IF EXISTS `domains`;
CREATE TABLE `domains` (
  `id` int NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `domain_name` varchar(255) NOT NULL,
  `target_url` varchar(255) NOT NULL,
  `proxy_url` varchar(255) DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `proxy_url` (`proxy_url`),
  KEY `user_id` (`user_id`),
  CONSTRAINT `domains_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
);

DROP TABLE IF EXISTS `attack_logs`;
CREATE TABLE `attack_logs` (
  `id` int NOT NULL AUTO_INCREMENT,
  `domain_id` int NOT NULL,
  `attacker_ip` varchar(45) DEFAULT NULL,
  `attack_type` varchar(50) DEFAULT NULL,
  `payload` text,
  `timestamp` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `country` varchar(50) DEFAULT 'Unknown',
  PRIMARY KEY (`id`),
  KEY `domain_id` (`domain_id`),
  CONSTRAINT `attack_logs_ibfk_1` FOREIGN KEY (`domain_id`) REFERENCES `domains` (`id`) ON DELETE CASCADE
);

DROP TABLE IF EXISTS `blocked_ips`;
CREATE TABLE `blocked_ips` (
  `id` int NOT NULL AUTO_INCREMENT,
  `domain_id` int NOT NULL,
  `ip_address` varchar(45) NOT NULL,
  `added_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `domain_id` (`domain_id`),
  CONSTRAINT `blocked_ips_ibfk_1` FOREIGN KEY (`domain_id`) REFERENCES `domains` (`id`) ON DELETE CASCADE
);

DROP TABLE IF EXISTS `firewall_rules`;
CREATE TABLE `firewall_rules` (
  `id` int NOT NULL AUTO_INCREMENT,
  `domain_id` int NOT NULL,
  `block_sqli` tinyint(1) DEFAULT '1',
  `block_xss` tinyint(1) DEFAULT '1',
  `block_ip` tinyint(1) DEFAULT '0',
  `rate_limit` int DEFAULT '100',
  PRIMARY KEY (`id`),
  KEY `domain_id` (`domain_id`),
  CONSTRAINT `firewall_rules_ibfk_1` FOREIGN KEY (`domain_id`) REFERENCES `domains` (`id`) ON DELETE CASCADE
);

DROP TABLE IF EXISTS `payments`;
CREATE TABLE `payments` (
  `payment_id` int NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `full_name` varchar(100) NOT NULL,
  `date_of_birth` date NOT NULL,
  `email` varchar(100) NOT NULL,
  `phone` varchar(15) NOT NULL,
  `billing_address` text NOT NULL,
  `card_holder_name` varchar(100) NOT NULL,
  `card_number_encrypted` text NOT NULL,
  `card_expiry` varchar(7) NOT NULL,
  `cvv_hash` varchar(255) NOT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`payment_id`),
  KEY `fk_payments_user` (`user_id`),
  CONSTRAINT `fk_payments_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
);

DROP TABLE IF EXISTS `support_tickets`;
CREATE TABLE `support_tickets` (
  `id` int NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `subject` varchar(100) NOT NULL,
  `message` text NOT NULL,
  `status` enum('Open','In Progress','Closed') DEFAULT 'Open',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`),
  CONSTRAINT `support_tickets_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
);

DROP TABLE IF EXISTS `contact_messages`;
CREATE TABLE `contact_messages` (
  `first_name` varchar(50) NOT NULL,
  `last_name` varchar(50) DEFAULT NULL,
  `email` varchar(100) NOT NULL,
  `phone_number` varchar(15) DEFAULT NULL,
  `message` text NOT NULL,
  `submitted_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE users ADD COLUMN status ENUM('active', 'inactive') DEFAULT 'active';

-- 1. Add the admin column if it doesn't exist
ALTER TABLE users ADD COLUMN is_admin BOOLEAN DEFAULT FALSE;

-- 2. CRITICAL: Update Support Tickets to allow 'Resolved' status
-- (Without this, the "Mark Resolved" button will crash your app)
ALTER TABLE support_tickets MODIFY COLUMN status ENUM('Open', 'In Progress', 'Resolved', 'Closed') DEFAULT 'Open';


-- 3. Update your database 
ALTER TABLE users ADD COLUMN plan_type ENUM('free', 'pro') DEFAULT 'free';
ALTER TABLE users ADD COLUMN plan_expiry DATETIME NULL;

-- 4. add a new table for custom reports
CREATE TABLE custom_report_requests (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    requirements TEXT NOT NULL,
    status ENUM('Pending', 'Completed') DEFAULT 'Pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 5. Add these new colomns for MFA
ALTER TABLE users ADD COLUMN mfa_secret VARCHAR(32) DEFAULT NULL;
ALTER TABLE users ADD COLUMN mfa_enabled TINYINT(1) DEFAULT 0;