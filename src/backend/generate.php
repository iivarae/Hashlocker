<?php
require 'security.php';
header("Access-Control-Allow-Origin:  {$_SERVER['HTTP_ORIGIN']}");
header("Access-Control-Allow-Methods: *");
header("Access-Control-Allow-Headers: Content-Type");
header("Access-Control-Allow-Credentials: true");

$input = file_get_contents("php://input");
$data = json_decode($input, true);

if (!isset($data['id']) || !isset($data['min']) || !isset($data['max']) || !isset($data['Special']) || !isset($data['upper']) || !isset($data['lower']) || !isset($data['Numbers']) || !isset($data['OneEach'])) {
    echo json_encode(["status" => "failure", "message" => "Invalid request format. Missing required fields."]);
    exit;
}

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

$minLength = (int)$data['min'];
$maxLength = (int)$data['max'];
$includeUpper = (bool)$data['upper'];
$includeLower = (bool)$data['lower'];
$includeNumbers = (bool)$data['Numbers'];
$includeSpecial = (bool)$data['Special'];
$requireOneEach = (bool)$data['OneEach'];

//Ensure the password length is within allowed limits.

if ($maxLength > 128){
    echo json_encode(['status' => 'failure', 'message' => 'Requested password too long.']);
    exit;
}

if ($minLength < 1){
    echo json_encode(['status' => 'failure', 'message' => 'Requested password too short.']);
    exit;
}

if ($minLength > $maxLength) {
    echo json_encode(["status" => "failure", "message" => "Invalid password length constraints: min > max."]);
    exit;
}

$upperChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
$lowerChars = 'abcdefghijklmnopqrstuvwxyz';
$numberChars = '0123456789';
$specialChars = '!@#$%^&*()-_=+[]{}|;:,.<>?';

$charPool = '';
if ($includeUpper) $charPool .= $upperChars;
if ($includeLower) $charPool .= $lowerChars;
if ($includeNumbers) $charPool .= $numberChars;
if ($includeSpecial) $charPool .= $specialChars;

if (empty($charPool)) {
    echo json_encode(["status" => "failure", "message" => "No character types selected for password generation."]);
    exit;
}

$length = rand($minLength, $maxLength);
$password = '';

// Ensure at least one of each selected category if required
$requiredChars = '';
if ($requireOneEach) {
    if ($includeUpper) $requiredChars .= $upperChars[rand(0, strlen($upperChars) - 1)];
    if ($includeLower) $requiredChars .= $lowerChars[rand(0, strlen($lowerChars) - 1)];
    if ($includeNumbers) $requiredChars .= $numberChars[rand(0, strlen($numberChars) - 1)];
    if ($includeSpecial) $requiredChars .= $specialChars[rand(0, strlen($specialChars) - 1)];
}

// Fill the remaining characters randomly
for ($i = strlen($requiredChars); $i < $length; $i++) {
    $password .= $charPool[rand(0, strlen($charPool) - 1)];
}

// Shuffle the password to ensure randomness
$password .= $requiredChars;
$password = str_shuffle($password);

echo json_encode(["status" => "success", "password" => $password]);
?>