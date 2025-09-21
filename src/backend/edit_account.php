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

//Read input.
$data = json_decode(file_get_contents('php://input'), true);
$id = isset($data['id']) ? $data['id'] : '';
$accplatform =  isset($data['accplatform']) ? $data['accplatform'] : '';
$accusername  =  isset($data['accusername']) ? $data['accusername'] : '';
$accpassword  =  isset($data['accpassword']) ? $data['accpassword'] : '';
$accid   =  isset($data['accid']) ? $data['accid'] : '';

if (empty($accplatform) || empty($accusername) || empty($accpassword) || empty($accid) || empty($id)) {
    die(json_encode(['status' => 'failure', 'message' => 'Missing required fields.']));
}

if (ctype_space($accplatform) || ctype_space($accusername) || ctype_space($accpassword)) {
    die(json_encode(['status' => 'failure', 'message' => 'Missing required fields.']));
}

//Get a DB connection.
$conn = new mysqli($db_host, $db_user, $db_pass, $db_name);

//Check for connection error
if ($conn->connect_error) {
    $conn->close();
    die(json_encode(['status' => 'error', 'message' => 'Database connection failed']));
}

//Authorize user.
if (!authorize_user($id, $conn)){
    $conn->close();
    die(json_encode(['status' => 'failure', 'message' => 'Unauthorized access.']));
}

$stmt = $conn->prepare("SELECT USERNAME, WEBSITE, PASSWORD, ICON_PATH FROM accounts WHERE USER_ID = ? AND ID = ?");
$stmt->bind_param("ii", $id,  $accid);
$stmt->execute();
$result = $stmt->get_result();

if  ($result->num_rows == 0) {
    $stmt->close();
    $message = 'Invalid account for user with id: '.$id;
    die(json_encode(['status' => 'failure', 'message' => $message]));
} else if  ($result->num_rows == 1) {
    $row = $result->fetch_assoc();
    $icon_path = $row['ICON_PATH'];
    $stmt->close();

    $stmt = $conn->prepare("UPDATE accounts SET WEBSITE = ?, USERNAME = ?, PASSWORD = ? WHERE ID = ?");
    $stmt->bind_param("sssi", $accplatform, $accusername, $accpassword, $accid);
    $stmt->execute();

    if ($stmt->affected_rows > 0) {
        $updated_account = [
            'accplatform' => htmlspecialchars($accplatform),
            'accusername' => htmlspecialchars($accusername),
            'iconpath' => $icon_path,  // Return the original icon path
            'accpassword' => htmlspecialchars($accpassword),
            'accid' => $accid
        ];

        $stmt->close();
        $conn->close();

        // Return success response with updated account data.
        echo json_encode([
            'status' => 'success',
            'account' => $updated_account
        ]);
    } else {
        $stmt->close();
        $conn->close();
        // If no rows were affected, something went wrong with the update.
        echo json_encode(['status' => 'failure', 'message' => 'Failed to update the account.']);
    }
}
