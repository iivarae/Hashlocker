<?php
require '../backend/security.php';
header("Access-Control-Allow-Origin:  {$_SERVER['HTTP_ORIGIN']}");
header("Access-Control-Allow-Methods: *");
header("Access-Control-Allow-Headers: Content-Type");
header("Access-Control-Allow-Credentials: true");

$credentials = parse_ini_file('credentials.txt');
$db_host = $credentials['DB_HOST'];
$db_name = $credentials['DB_NAME'];
$db_user = $credentials['DB_USER'];
$db_pass = $credentials['DB_PASS'];

//Get database connection using credentials from credentials.txt
$conn = new mysqli($db_host, $db_user, $db_pass, $db_name);

// Check for connection error
if ($conn->connect_error) {
    die(json_encode(['status' => 'error', 'message' => 'Database connection failed', 'user_data' => ['username' => '']]));
}

$input = json_decode(file_get_contents('php://input'), true);
if (!isset($input['id'])) {
    echo json_encode(['result' => false, 'error' => 'Missing user ID']);
    exit;
}

$userId = intval($input['id']);

if (authorize_user($userId, $conn)) {
    echo json_encode(['result' => true]);
} else {
    echo json_encode(['result' => false]);
}