<?php
require 'security.php';
header("Access-Control-Allow-Origin:  {$_SERVER['HTTP_ORIGIN']}");
header("Access-Control-Allow-Methods: *");
header("Access-Control-Allow-Headers: Content-Type");
header("Access-Control-Allow-Credentials: true");


$input = file_get_contents("php://input");
$data = json_decode($input, true);

if (!isset($data['id']) || !isset($data['max']) || !isset($data['Special'])) {
    echo json_encode(["status" => "failure", "message" => "Invalid request format. Missing required fields."]);
    exit;
}

//Authenticate the user.
$credentials = parse_ini_file('credentials.txt');
$db_host = $credentials['DB_HOST'];
$db_name = $credentials['DB_NAME'];
$db_user = $credentials['DB_USER'];
$db_pass = $credentials['DB_PASS'];
$conn = new mysqli($db_host, $db_user, $db_pass, $db_name);

if ($conn->connect_error) {
    die(json_encode(['status' => 'error', 'message' => 'User authentication failed']));
}

if (!authorize_user($data['id'], $conn)){
    die(json_encode(['status' => 'error', 'message' => 'User authentication failed']));
}

$maxLength = (int)$data['max'];
$includeSpecial = (bool)$data['Special'];

// Ensure the password length is within allowed limits
if ($maxLength > 128) {
    echo json_encode(["status" => "failure", "message" => "Maximum password length too long. Please choose a shorter password."]);
    exit;
} else if ($maxLength < 1){
    echo json_encode(["status" => "failure", "message" => "Maximum password length too short. Please choose a longer password."]);
    exit;
}

// Define character sets
$letters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
$numbers = '0123456789';
$special = '!@#$%^&*()-_=+[]{}|;:,.<>?/';
$password = '';


// Construct character pool based on user choice
$characters = $letters . $numbers;
if ($includeSpecial) {
    $characters .= $special;
}

if ($includeSpecial && $maxLength > 0) {
    // Ensure at least one special character
    $password .= $special[random_int(0, strlen($special) - 1)];
    $maxLength--;
}

// Generate random password
$charLen = strlen($characters);
for ($i = 0; $i < $maxLength; $i++) {
    $password .= $characters[random_int(0, $charLen - 1)];
}

// Return success response
$response = [
    "status" => "success",
    "password" => $password
];

echo json_encode($response);
