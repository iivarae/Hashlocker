<?php
require 'security.php';

header("Access-Control-Allow-Origin: {$_SERVER['HTTP_ORIGIN']}");
header("Access-Control-Allow-Methods: *");
header("Access-Control-Allow-Headers: Content-Type");
header("Access-Control-Allow-Credentials: true");
header("Content-Type: application/json");

// Database connection
$credentials = parse_ini_file('credentials.txt');
$db_host = $credentials['DB_HOST'];
$db_name = $credentials['DB_NAME'];
$db_user = $credentials['DB_USER'];
$db_pass = $credentials['DB_PASS'];

$conn = new mysqli($db_host, $db_user, $db_pass, $db_name);
if ($conn->connect_error) {
    $response = array(
        "status" => "error",
        "message" => "Database connection failed"
    );
    echo json_encode($response);
    exit;
}

// Get and validate input data
$data = json_decode(file_get_contents('php://input'), true);
$userId = isset($data['id']) ? $data['id'] : '';
$accId = isset($data['accid']) ? $data['accid'] : '';

if (empty($userId) || empty($accId)) {
    $response = array(
        "status" => "error",
        "message" => "Invalid parameters"
    );
    echo json_encode($response);
    exit;
}

// Authenticate user
if (!authorize_user($userId, $conn)) {
    $response = array(
        "status" => "error",
        "message" => "Unauthorized action"
    );
    echo json_encode($response);
    exit;
}

// Check for active invite that belongs to this user
$stmt = $conn->prepare("SELECT SHARE_ID FROM invites WHERE SHARED_WITH = ? AND ACCID = ? AND STATUS = 0");
$stmt->bind_param("ii", $userId, $accId);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows === 0) {
    $response = array(
        "status" => "error",
        "message" => "Invite not found"
    );
    echo json_encode($response);
    exit;
}

$row = $result->fetch_assoc();
$shareId = $row['SHARE_ID'];

// Update invite status to denied (2)
$stmt = $conn->prepare("UPDATE invites SET STATUS = 2 WHERE SHARE_ID = ?");
$stmt->bind_param("i", $shareId);
$success = $stmt->execute();

if (!$success) {
    $response = array(
        "status" => "error",
        "message" => "Failed to deny invite"
    );
    echo json_encode($response);
    exit;
}

// Success response
$response = array(
    "status" => "success",
    "message" => "Invite denied successfully"
);

// Close connection
$conn->close();

// Output response
echo json_encode($response);
?>