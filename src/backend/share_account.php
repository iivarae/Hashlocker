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

//Get database connection using credentials from credentials.txt
$conn = new mysqli($db_host, $db_user, $db_pass, $db_name);

//Check for connection error
if ($conn->connect_error) {
    $conn->close();
    die(json_encode(['status' => 'error', 'message' => 'Database connection failed', 'invites' => []]));
}

//Get the input.
$data = json_decode(file_get_contents('php://input'), true);
$sender_id = $data['sender_id'] ?? '';
$username = $data['username'] ?? '';
$accid =  $data['accid'] ?? '';

if (empty($sender_id) || empty($username) || empty($accid)) {
    $conn->close();
    die(json_encode(['status' => 'error', 'message' => 'Missing required fields.']));
}

//Authenticate the requesting user via the security function.
if (!authorize_user($sender_id, $conn)) {
    $conn->close();
    die(json_encode(['status' => 'error', 'message' => 'Unauthorized access detected.']));
}

//Attempt to determine user ID of recipient with username $username
$recipient_id = 0;
try {
    //Make sure the match is not case sensitive.
    $sql = "SELECT ID FROM user WHERE LOWER(USERNAME) = LOWER(?)";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows === 0) {
        $conn->close();
        die(json_encode(['status' => 'error', 'message' => 'Target user not found.']));
    } else {
        $recipient_id = $result->fetch_array(MYSQLI_ASSOC)['ID'];
    }

    if ($recipient_id == $sender_id) {
        $conn->close();
        die(json_encode(['status' => 'error', 'message' => 'Cannot share account with self.']));
    }

    //Verify that sender owns the account.
    $sql = "SELECT ID FROM accounts WHERE ID = ? AND USER_ID = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("ii", $accid, $sender_id);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows === 0) {
        $conn->close();
        die(json_encode(['status' => 'error', 'message' => 'Unauthorized access detected.']));
    }


    //The recipient exists, see if they have already been invited to this account by the sender.
    $sql = "SELECT SHARE_ID FROM invites WHERE SHARED_WITH = ? AND ACCOUNT_OWNER = ? AND ACCID = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("iii", $recipient_id, $sender_id, $accid);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($result->num_rows != 0) {
        $conn->close();
        die(json_encode(['status' => 'error', 'message' => 'Account already shared or invite already sent.']));
    }

    //Otherwise, the recipient is valid and hasn't been with, so insert.
    $zero = 0;
    $sql = "INSERT INTO invites (ACCOUNT_OWNER, SHARED_WITH, ACCID, STATUS) VALUES (?, ?, ?, ?)";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("iiii", $sender_id, $recipient_id, $accid, $zero);

    if (!$stmt->execute()){
        $conn ->close();
        die(json_encode(['status' => 'error', 'message' => 'Failed to share invite.']));
    } else {
        $conn->close();
        die(json_encode(['status' => 'success', 'message' => 'Account shared successfully']));
    }
} catch (mysqli_sql_exception $e) {
    $conn->close();
    die(json_encode(['status' => 'error', 'message' => 'Database query failed.']));
} finally {
    $conn->close();
}
