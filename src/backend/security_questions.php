<?php
// Kill CORS error once and for all
header("Access-Control-Allow-Origin:  {$_SERVER['HTTP_ORIGIN']}");
header("Access-Control-Allow-Methods: *");
header("Access-Control-Allow-Headers: Content-Type");
header("Access-Control-Allow-Credentials: true");

// Database connection credentials.
$credentials = parse_ini_file('credentials.txt');
$db_host = $credentials['DB_HOST'];
$db_name = $credentials['DB_NAME'];
$db_user = $credentials['DB_USER'];
$db_pass = $credentials['DB_PASS'];
$key = $credentials['CSRF_SECRET_KEY'];

// Get database connection using credentials from credentials.txt
$conn = new mysqli($db_host, $db_user, $db_pass, $db_name);

// Check for connection error
if ($conn->connect_error) {
    die(json_encode(['status' => 'error', 'message' => 'Database connection failed']));
}

// Get the input.
$data = json_decode(file_get_contents('php://input'), true);
// Extract registration data
$username = isset($data['username']) ? trim($data['username']) : '';
$email = isset($data['email']) ? trim($data['email']) : '';
$password = isset($data['password']) ? $data['password'] : '';
// take a string, to an int and change to a fixed int
$question_map = [
    "1" => 1,
    "2" => 2,
    "3" => 3
];
$received_question = isset($data['question']) ? trim($data['question']) : '';
$security_question = isset($question_map[$received_question]) ? $question_map[$received_question] : -1;
$security_answer = isset($data['answer']) ? trim($data['answer']) : '';
// Validate input

$errors = [];

// Check if username is empty or too short
if (empty($username) || strlen($username) < 3) {
    $errors[] = "Username must be at least 3 characters long";
}

// Validate email
if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $errors[] = "Please provide a valid email address";
}

// Check password
if (empty($password)) {
    $errors[] = "Password cannot be empty";
}
// Validate security question selection
if (!in_array($security_question, [1, 2, 3])) {
    $errors[] = "Invalid security question selection";
}

// Validate security answer
if (empty($security_answer)) {
    $errors[] = "Security answer cannot be empty";
}

// Return errors if any
if (!empty($errors)) {
    echo json_encode([
        'status' => 'failure',
        'message' => 'Registration failed',
        'errors' => $errors
    ]);
    exit;
}

try {
    // Check if username already exists
    $stmt = $conn->prepare("SELECT ID FROM user WHERE USERNAME = ? LIMIT 1");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        echo json_encode([
            'status' => 'failure',
            'message' => 'Registration failed',
            'errors' => ['Username already taken']
        ]);
        exit;
    }

    // Check if email already exists
    $stmt = $conn->prepare("SELECT ID FROM user WHERE EMAIL = ? LIMIT 1");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        echo json_encode([
            'status' => 'failure',
            'message' => 'Registration failed',
            'errors' => ['Email already registered']
        ]);
        exit;
    }

    // Hash password and security answer for secure storage
    $password_hash = password_hash($password, PASSWORD_DEFAULT);
    // $security_answer_hash = password_hash($security_answer, PASSWORD_DEFAULT);

    // Generate a session token
    $sessionToken = bin2hex(random_bytes(16));

    // Insert new user
    $stmt = $conn->prepare("INSERT INTO user (USERNAME, EMAIL, PASSWORD, SECURITY_QUESTION, SECURITY_ANSWER, SESSION) VALUES (?, ?, ?, ?, ?, ?)");
    $stmt->bind_param("sssiss", $username, $email, $password_hash, $security_question, $security_answer, $sessionToken);
    $stmt->execute();

    if ($stmt->affected_rows > 0) {
        $user_id = $conn->insert_id;
        $csrfToken = bin2hex(random_bytes(32));
        $hashedCsrfHeader = hash_hmac('sha256', $csrfToken, $key);

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
            'message' => 'Registration successful',
            'user_data' => [
                'id' => $user_id,
                'username' => htmlspecialchars($username),
            ],
            'csrf_token' => $csrfToken,
        ]);
    } else {
        echo json_encode([
            'status' => 'failure',
            'message' => 'Registration failed',
            'errors' => ['Failed to create account']
        ]);
    }
} catch (Exception $e) {
    // Handle errors
    echo json_encode([
        'status' => 'error',
        'message' => 'An internal error occurred',
        'errors' => [$e->getMessage()]
    ]);
}

finally {
    // Close the database connection
    $conn->close();
}