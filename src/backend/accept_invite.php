<?php
require 'security.php';

// Set necessary headers
header("Access-Control-Allow-Origin: {$_SERVER['HTTP_ORIGIN']}");
header("Access-Control-Allow-Methods: *");
header("Access-Control-Allow-Headers: Content-Type");
header("Access-Control-Allow-Credentials: true");
header("Content-Type: application/json");

// Disable output buffering
if (ob_get_level()) ob_end_clean();

// Database connection
$credentials = parse_ini_file('credentials.txt');
$db_host = $credentials['DB_HOST'];
$db_name = $credentials['DB_NAME'];
$db_user = $credentials['DB_USER'];
$db_pass = $credentials['DB_PASS'];

$conn = new mysqli($db_host, $db_user, $db_pass, $db_name);
if ($conn->connect_error) {
    $response = array(
        "status" => "failure",
        "message" => "Database connection failed",
        "accid" => 0
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
        "status" => "failure",
        "message" => "Invalid parameters",
        "accid" => $accId
    );
    echo json_encode($response);
    exit;
}

// Authenticate user
if (!authorize_user($userId, $conn)) {
    $response = array(
        "status" => "failure",
        "message" => "Unauthorized request.",
        "accid" => $accId
    );
    echo json_encode($response);
    exit;
}

// Check for active invite
$stmt = $conn->prepare("SELECT SHARE_ID FROM invites WHERE SHARED_WITH = ? AND ACCID = ? AND STATUS = 0");
$stmt->bind_param("ii", $userId, $accId);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows === 0) {
    $response = array(
        "status" => "failure",
        "message" => "No active invite for this account.",
        "accid" => $accId
    );
    echo json_encode($response);
    exit;
}

$row = $result->fetch_assoc();
$shareId = $row['SHARE_ID'];

// Update invite status
$stmt = $conn->prepare("UPDATE invites SET STATUS = 1 WHERE SHARE_ID = ?");
$stmt->bind_param("i", $shareId);
$success = $stmt->execute();

if (!$success) {
    $response = array(
        "status" => "failure",
        "message" => "Failed to accept invite",
        "accid" => $accId
    );
    echo json_encode($response);
    exit;
}

// Success response - exactly as required by tests
$response = array(
    "status" => "success",
    "message" => "Invite accepted.",
    "accid" => $accId
);

// Close connection
$conn->close();

// Output response
echo json_encode($response);
?>
