<?php
// Kill CORS error once and for all

header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: *");
header("Access-Control-Allow-Headers: Content-Type");


// Database connection credentials.

$credentials = parse_ini_file('credentials.txt');
$db_host = $credentials['DB_HOST'];
$db_name = $credentials['DB_NAME'];
$db_user = $credentials['DB_USER'];
$db_pass = $credentials['DB_PASS'];


// Get database connection

$conn = new mysqli($db_host, $db_user, $db_pass, $db_name);

// Check for connection error
if ($conn->connect_error) {
    die(json_encode(['status' => 'error', 'message' => 'Database connection failed']));
}

// Get the input.
$data = json_decode(file_get_contents('php://input'), true);

// Extract registration data
$username = isset($data['username']) ? trim($data['username']) : '';
$password = isset($data['password']) ? $data['password'] : '';
$email = isset($data['email']) ? trim($data['email']) : '';

$verify_password = isset($data['verify_password']) ? $data['verify_password'] : '';

// Validate input
$errors = [];

if (empty($username) || strlen($username) < 3) {
    $errors[] = "Username must be at least 3 characters long";
}
if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $errors[] = "Please provide a valid email address";
}
if (empty($password)) {
    $errors[] = "Password cannot be empty";

} elseif ($password !== $verify_password) {
    $errors[] = "Passwords do not match";
}

if (!empty($errors)) {
    echo json_encode([
        'status' => 'failure',
        'message' => 'Validation failed',

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

            'message' => 'Validation failed',

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

            'message' => 'Validation failed',

            'errors' => ['Email already registered']
        ]);
        exit;
    }


    echo json_encode([
        'status' => 'success',
        'message' => 'Validation passed',
    ]);
} catch (Exception $e) {

    echo json_encode([
        'status' => 'error',
        'message' => 'An internal error occurred',
        'errors' => [$e->getMessage()]
    ]);
} finally {

    $conn->close();
}