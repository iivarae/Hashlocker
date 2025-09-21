<?php
header("Access-Control-Allow-Origin:  {$_SERVER['HTTP_ORIGIN']}");
header("Access-Control-Allow-Methods: *");
header("Access-Control-Allow-Headers: Content-Type");
header("Access-Control-Allow-Credentials: true");

$credentials = parse_ini_file('credentials.txt');
$db_host = $credentials['DB_HOST'];
$db_name = $credentials['DB_NAME'];
$db_user = $credentials['DB_USER'];
$db_pass = $credentials['DB_PASS'];
$key = $credentials['CSRF_SECRET_KEY'];

//Get database connection using credentials from credentials.txt
$conn = new mysqli($db_host, $db_user, $db_pass, $db_name);

// Check for connection error
if ($conn->connect_error) {
    die(json_encode(['status' => 'error', 'message' => 'Database connection failed', 'user_data' => ['username' => '']]));
}

//Get the input.
$data = json_decode(file_get_contents('php://input'), true);

//If username is not set from input, make empty. Same with password.
$username = isset($data['username']) ? $data['username'] : '';
$password = isset($data['password']) ? $data['password'] : '';

// Return failure for empty username
if (empty($username)) {
    echo json_encode(['status' => 'failure', 'message' => 'Login Failure: Incorrect Credentials Provided', 'user_data' => ['username' => $username]]);
    exit;
}

// Return failure for empty password
if (empty($password)) {
    echo json_encode(['status' => 'failure', 'message' => 'Login Failure: Incorrect Credentials Provided', 'user_data' => ['username' => $username]]);
    exit;
}


try {
    //Query database for the user.
    //Bind param to prevent SQL injection vulnerability.
    $stmt = $conn->prepare("SELECT ID, USERNAME, PASSWORD FROM user WHERE USERNAME = ? LIMIT 1");
    $stmt->bind_param("s", $username); // "s" indicates that the parameter is a string
    $stmt->execute();
    $result = $stmt->get_result();

    // Check if the user exists
    if ($user = $result->fetch_assoc()) {
        //Password verify compares a password to the hash that was stored in the DB.
        if (password_verify($password, $user['PASSWORD'])) {
            // Generate a session token and store it in the database
            $sessionToken = bin2hex(random_bytes(16));
            $csrfToken = bin2hex(random_bytes(32));
            $hashedCsrfHeader = hash_hmac('sha256', $csrfToken, $key);
            $updateStmt = $conn->prepare("UPDATE user SET SESSION = ? WHERE ID = ?");
            $updateStmt->bind_param("si", $sessionToken, $user['ID']);
            $updateStmt->execute();

            setcookie("session_token", $sessionToken, [
                'expires' => time() + 3600,
                'path' => '/',
                'secure' => true,
                'httponly' => true,
                'domain' => 'buffalo.edu',
                'samesite' => 'Strict'
            ]);

            setcookie("csrf_token", $hashedCsrfHeader, [
                'expires' => time() + 3600,
                'path' => '/',
                'secure' => true,
                'httponly' => false,
                'domain' => 'buffalo.edu',
                'samesite' => 'Strict'
            ]);

            // Return success response
            echo json_encode([
                'status' => 'success',
                'message' => 'Login Success',
                'user_data' => [
                    'id' => $user['ID'],
                    'username' => htmlspecialchars($user['USERNAME']),
                ],
                'csrf_token' => $csrfToken,
            ]);
        } else {
            $username = htmlspecialchars($username);
            // Password does not match
            echo json_encode(['status' => 'failure', 'message' => 'Login Failure: Incorrect Credentials Provided','user_data' => ['username' => $username]]);
        }
    } else {
        // Username not found
        $username = htmlspecialchars($username);
        echo json_encode(['status' => 'failure', 'message' => 'Login Failure: Incorrect Credentials Provided', 'user_data' => ['username' => $username]]);
    }
} catch (Exception $e) {
    // Handle errors
    echo json_encode(['status' => 'error', 'message' => 'An internal error occurred']);
} finally {
    // Close the database connection
    $conn->close();
}
?>


