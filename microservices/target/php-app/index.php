<?php
// Intentionally Vulnerable PHP Application for Pentesting Workflows
// Warning: Contains RCE, SQLi, LFI, and XSS. Do NOT deploy in production.

// 1. Local File Inclusion (LFI) / Directory Traversal
// Vulnerable to null byte injection (%00) in older PHP versions and standard directory traversal (../../).
if (isset($_GET['page'])) {
    $file = $_GET['page'];
    // No sanitization, direct inclusion
    include($file); 
}

// 2. OS Command Injection (RCE)
// Simulates a legacy network diagnostic tool. Vulnerable to shell metacharacters (; | &).
if (isset($_POST['ip_address'])) {
    $target = $_POST['ip_address'];
    echo "<h3>Ping Results:</h3>";
    echo "<pre>";
    // Unsafe execution of system commands without escapeshellarg()
    echo shell_exec("ping -c 3 " . $target);
    echo "</pre>";
}

// 3. SQL Injection (SQLi) - Authentication Bypass
// Simulates an old login form. Vulnerable to classic boolean-based or union-based payloads (e.g., ' OR '1'='1).
if (isset($_POST['username']) && isset($_POST['password'])) {
    // Assuming a local MySQL database setup
    $conn = new mysqli("localhost", "root", "", "test_db");
    
    $user = $_POST['username'];
    $pass = $_POST['password'];
    
    // Direct concatenation of user input into the SQL query
    $query = "SELECT * FROM users WHERE username = '$user' AND password = '$pass'";
    $result = $conn->query($query);
    
    if ($result && $result->num_rows > 0) {
        echo "<h3 style='color:green;'>Welcome, System Admin!</h3>";
    } else {
        echo "<h3 style='color:red;'>Login Failed.</h3>";
    }
}

// 4. Reflected Cross-Site Scripting (XSS)
// Useful for testing payload delivery and log generation without backend execution.
if (isset($_GET['search'])) {
    // Directly echoing unsanitized input
    echo "<div style='background:#eee; padding:10px;'>Search results for: " . $_GET['search'] . "</div>";
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Legacy System Management</title>
    <style>
        body { font-family: monospace; margin: 40px; background: #f4f4f9; }
        .module { background: white; padding: 20px; border: 1px solid #ccc; margin-bottom: 20px; }
        input[type="text"], input[type="password"] { padding: 5px; margin: 5px 0; width: 250px; }
    </style>
</head>
<body>
    <h1>Legacy System Portal v1.0</h1>
    <p><i>Warning: System deprecation scheduled.</i></p>

    <div class="module">
        <h3>Documentation</h3>
        <a href="?page=docs/help.txt">System Help</a> | <a href="?page=docs/config_guide.txt">Config Guide</a>
    </div>

    <div class="module">
        <h3>Network Diagnostics</h3>
        <form method="POST">
            Target IP: <input type="text" name="ip_address" placeholder="127.0.0.1"><br>
            <input type="submit" value="Run Ping">
        </form>
    </div>

    <div class="module">
        <h3>Admin Access</h3>
        <form method="POST">
            Username: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            <input type="submit" value="Login">
        </form>
    </div>

    <div class="module">
        <h3>Log Search</h3>
        <form method="GET">
            Query: <input type="text" name="search"><br>
            <input type="submit" value="Search Logs">
        </form>
    </div>
</body>
</html>