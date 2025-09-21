<?php
require 'security.php';

header("Access-Control-Allow-Origin:  {$_SERVER['HTTP_ORIGIN']}");
header("Access-Control-Allow-Methods: *");
header("Access-Control-Allow-Headers: Content-Type");
header("Access-Control-Allow-Credentials: true");

$credentials = parse_ini_file('credentials.txt');
$db_host = $credentials['DB_HOST'];
$db_name = $credentials['DB_NAME'];
$db_user = $credentials['DB_USER'];
$db_pass = $credentials['DB_PASS'];

// Get database connection using credentials from credentials.txt
$conn = new mysqli($db_host, $db_user, $db_pass, $db_name);

// Check for connection error
if ($conn->connect_error) {
    $conn->close();
    die(json_encode(['status' => 'error', 'message' => 'Database connection failed']));
}

// Get the input
$data = json_decode(file_get_contents('php://input'), true);
$user_id = isset($data['id']) ? $data['id'] : '';
$account_id = isset($data['accid']) ? $data['accid'] : '';

// Validate input
if (empty($user_id) || empty($account_id)) {
    $conn->close();
    die(json_encode(['status' => 'error', 'message' => 'Invalid User ID or Account ID']));
}

// Authenticate the user via the security function
if (!authorize_user($user_id, $conn)) {
    $conn->close();
    die(json_encode(['status' => 'failure', 'message' => 'Unauthorized access detected']));
}

try {
    // First, verify the account exists and belongs to the user
    $stmt = $conn->prepare("SELECT ID FROM accounts WHERE ID = ? AND USER_ID = ?");
    $stmt->bind_param("ii", $account_id, $user_id);
    $stmt->execute();
    $result = $stmt->get_result();

    // If no matching account is found
    if ($result->num_rows === 0) {
        $conn->close();
        die(json_encode(['status' => 'error', 'message' => 'Account not found.']));
    }

    // Prepare and execute delete statement
    $delete_stmt = $conn->prepare("DELETE FROM accounts WHERE ID = ? AND USER_ID = ?");
    $delete_stmt->bind_param("ii", $account_id, $user_id);
    $delete_result = $delete_stmt->execute();

    // Find and delete any associated account invites.
    $stmt = $conn->prepare("DELETE FROM invites WHERE ACCID = ? AND ACCOUNT_OWNER = ?");
    $stmt->bind_param("ii", $account_id, $user_id);
    $result = $stmt->execute();
    $stmt->close();

    // Check if deletion was successful
    if ($delete_result && $result) {
        $conn->close();
        die(json_encode(['status' => 'success', 'message' => 'Account successfully deleted.']));
    } else {
        $conn->close();
        die(json_encode(['status' => 'error', 'message' => 'Failed to delete account.']));
    }

} catch (Exception $e) {
    $conn->close();
    die(json_encode(['status' => 'error', 'message' => 'An internal error occurred']));

}
?>
