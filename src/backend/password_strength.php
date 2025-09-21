<?php
require_once 'lib_loader.php';
require_once 'security.php';
use ZxcvbnPhp\Zxcvbn;

header("Access-Control-Allow-Origin:  {$_SERVER['HTTP_ORIGIN']}");
header("Access-Control-Allow-Methods: *");
header("Access-Control-Allow-Headers: Content-Type");
header("Access-Control-Allow-Credentials: true");
header('Content-Type: application/json');

// Get JSON data from request
$input = file_get_contents('php://input');
$data = json_decode($input, true);

// Check for required field
if (!isset($data['password'])) {
    echo json_encode([
        'status' => 'failure',
        'message' => 'Password is required'
    ]);
    exit;
}

// Shouldn't need to use authentication as this is not storing password, only checking for its stength

/*
if (!isset($data['id'])) {
    echo json_encode([
        'status' => 'failure',
        'message' => 'User ID is required'
    ]);
    exit;
}

$credentials = parse_ini_file('credentials.txt');
$db_host = $credentials['DB_HOST'];
$db_name = $credentials['DB_NAME'];
$db_user = $credentials['DB_USER'];
$db_pass = $credentials['DB_PASS'];
$conn = new mysqli($db_host, $db_user, $db_pass, $db_name);

if ($conn->connect_error) {
    die(json_encode(['status' => 'error', 'message' => 'Database connection failed']));
}

if (!authorize_user($data['id'], $conn)){
    die(json_encode(['status' => 'error', 'message' => 'User authentication failed']));
}
*/

$password = $data['password'];

// Use zxcvbn-php to evaluate password strength
try {
    $zxcvbn = new Zxcvbn();
    $strength = $zxcvbn->passwordStrength($password);
    
    // Get the score (0-4, where 0 is weakest and 4 is strongest)
    $score = $strength['score'];
    
    // Determine message based on score
    $message = ($score >= 3) ? "Strong :)" : "Weak :( ";
    
    echo json_encode([
        'status' => 'success',
        'message' => $message
    ]);
} catch (Exception $e) {
    echo json_encode([
        'status' => 'failure',
        'message' => 'Error evaluating password strength'
    ]);
}
?>