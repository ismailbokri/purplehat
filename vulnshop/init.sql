-- VulnShop database schema + seed data
-- Loaded automatically by the MySQL container on first boot.

CREATE DATABASE IF NOT EXISTS vulnshop;
USE vulnshop;

-- A low-privilege app user that actually has broad grants (misconfig).
CREATE USER IF NOT EXISTS 'vulnshop'@'%' IDENTIFIED BY 'vulnshop123';
GRANT ALL PRIVILEGES ON *.* TO 'vulnshop'@'%' WITH GRANT OPTION;
FLUSH PRIVILEGES;

-- ---------------------------------------------------------------------------
DROP TABLE IF EXISTS order_items;
DROP TABLE IF EXISTS orders;
DROP TABLE IF EXISTS reviews;
DROP TABLE IF EXISTS products;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    username    VARCHAR(80)  NOT NULL,
    password    VARCHAR(255) NOT NULL,   -- VULN: stored in cleartext
    email       VARCHAR(120),
    is_admin    TINYINT DEFAULT 0,
    bio         TEXT,
    avatar      VARCHAR(255),
    credit_card VARCHAR(32),             -- VULN: PAN stored in cleartext
    api_key     VARCHAR(64)
);

CREATE TABLE products (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    name        VARCHAR(140) NOT NULL,
    price       DECIMAL(10,2) NOT NULL,
    description TEXT,
    category    VARCHAR(60),
    stock       INT DEFAULT 100
);

CREATE TABLE reviews (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    product_id INT,
    author     VARCHAR(80),
    body       TEXT                       -- VULN: rendered unescaped (stored XSS)
);

CREATE TABLE orders (
    id      INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    total   DECIMAL(10,2),
    status  VARCHAR(30) DEFAULT 'paid'
);

CREATE TABLE order_items (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    order_id   INT,
    product_id INT,
    qty        INT
);

-- ---------------------------------------------------------------------------
-- Users (secrets left in cleartext on purpose)
INSERT INTO users (id, username, password, email, is_admin, bio, credit_card, api_key) VALUES
 (1, 'admin',   'admin123',    'admin@vulnshop.local',  1, 'Store administrator.',        '4111-1111-1111-1111', 'ak_live_admin_8f3c21aa'),
 (2, 'alice',   'password123', 'alice@example.com',     0, 'Loves gadgets.',              '5500-0000-0000-0004', 'ak_live_alice_19be77'),
 (3, 'bob',     'qwerty',      'bob@example.com',        0, 'Just browsing.',              '3400-0000-0000-009',  'ak_live_bob_55aa01'),
 (4, 'charlie', 'letmein',     'charlie@example.com',    0, 'Audiophile.',                 '6011-0000-0000-0004', 'ak_live_charlie_c0ffee'),
 (5, 'support', 'Support@2021', 'support@vulnshop.local', 0, 'Internal support desk. ssh key on /backup.', '', 'ak_live_support_d00r');

-- Products
INSERT INTO products (id, name, price, description, category, stock) VALUES
 (1,  'Aurora Wireless Headphones', 129.99, 'Over-ear ANC headphones with 40h battery life and spatial audio.', 'Audio', 42),
 (2,  'Pulse Fitness Band 3',        59.00,  'Heart-rate, SpO2 and sleep tracking in a 5-day-battery band.',     'Wearables', 88),
 (3,  'Nimbus Mechanical Keyboard',  89.50,  'Hot-swappable 75% keyboard with gasket mount and PBT caps.',       'Computing', 25),
 (4,  'Lumen Smart Bulb (4-pack)',   34.99,  '16M-colour Wi-Fi bulbs with schedules and scenes.',               'Home', 150),
 (5,  'Terra Travel Backpack 28L',   74.00,  'Water-resistant commuter pack with a padded 16-inch laptop bay.',  'Accessories', 60),
 (6,  'Echo Bluetooth Speaker',      45.00,  'Pocket speaker, IPX7 waterproof, 12h playtime, deep bass.',        'Audio', 73),
 (7,  'Vertex 4K Webcam',            79.99,  '4K30 webcam with dual mics, auto-framing and a privacy shutter.',  'Computing', 31),
 (8,  'Halo Smartwatch Pro',         199.00, 'AMOLED smartwatch with GPS, ECG and 2-week battery.',              'Wearables', 19),
 (9,  'Cobalt USB-C Hub 8-in-1',     39.90,  'HDMI 4K, 100W PD, SD, and 3x USB-A in an aluminium shell.',        'Accessories', 120),
 (10, 'Drift Ergonomic Mouse',       49.00,  'Vertical wireless mouse with 6 buttons and silent clicks.',       'Computing', 54),
 (11, 'Mono Desk Lamp',              29.00,  'Dimmable LED lamp with wireless-charging base and USB port.',      'Home', 90),
 (12, 'Nova Noise Earbuds',          99.00,  'True-wireless ANC earbuds with wireless charging case.',           'Audio', 47);

-- Reviews (one shows that HTML is rendered, inviting an XSS test)
INSERT INTO reviews (product_id, author, body) VALUES
 (1, 'alice',   'Incredible sound, the ANC is <b>excellent</b> on flights.'),
 (1, 'bob',     'Comfortable but a little heavy after a few hours.'),
 (3, 'charlie', 'Typing feels amazing. Thocky out of the box.'),
 (8, 'alice',   'Battery really does last two weeks. Highly recommend.');

-- Orders (IDOR targets; note the non-sequential ids and one admin order)
INSERT INTO orders (id, user_id, total, status) VALUES
 (1001, 2, 188.99, 'paid'),
 (1002, 3, 45.00,  'shipped'),
 (1003, 4, 298.99, 'paid'),
 (1004, 1, 0.00,   'paid');

INSERT INTO order_items (order_id, product_id, qty) VALUES
 (1001, 1, 1), (1001, 6, 1),
 (1002, 6, 1),
 (1003, 8, 1), (1003, 12, 1),
 (1004, 3, 1);
