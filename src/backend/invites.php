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
$id = isset($data['id']) ? $data['id'] : '';

if (empty($id)) {
    $conn->close();
    die(json_encode(['status' => 'error', 'message' => 'Invalid User ID', 'invites' => []]));
}

//Authenticate the user via the security function.
if (!authorize_user($id, $conn)) {
    $conn->close();
    die(json_encode(['status' => 'error', 'message' => 'Unauthorized access detected', 'invites' => []]));

}

//Try to get the list of invites for the user.
try {
    $stmt = $conn->prepare("SELECT SHARE_ID, ACCOUNT_OWNER, ACCID, STATUS FROM invites WHERE SHARED_WITH = ? AND STATUS = 0");
    $stmt->bind_param("i", $id);
    $stmt->execute();
    $result = $stmt->get_result();
    $accounts = [];

    if ($result->num_rows === 0){
        $conn->close();
        die(json_encode(['status' => 'success', 'message' => 'Invites page loaded successfully', 'invites' => []]));
    }


    while ($row = $result->fetch_assoc()) {
        $accid = $row['ACCID'];
        $senderid = $row['ACCOUNT_OWNER'];

        //Fetch the account information for ACCID.
        $stmt2 = $conn->prepare("SELECT USERNAME, WEBSITE, ICON_PATH FROM accounts WHERE ID = ?");
        $stmt2->bind_param("i", $accid);
        $stmt2->execute();
        $stmt2->bind_result($accusername, $accplatform, $iconpath);
        $stmt2->fetch();
        $stmt2->close();

        //Fetch the sender's username from the users table.
        $stmt3 = $conn->prepare("SELECT USERNAME FROM user WHERE ID = ?");
        $stmt3->bind_param("i", $senderid);
        $stmt3->execute();
        $stmt3->bind_result($sender);
        $stmt3->fetch();
        $stmt3->close();

        //Build the array entry.
        $accounts[] = [
            'sender' => htmlspecialchars($sender),
            'accid' => $accid,
            'accplatform' => htmlspecialchars($accplatform),
            'accusername' => htmlspecialchars($accusername),
            'iconpath' => $iconpath,
            'status' => $row['STATUS'],
        ];
    }

    if (count($accounts) > 0) {
        $conn->close();
        die(json_encode(['status' => 'success', 'message' => 'Invites page loaded successfully','invites' => $accounts]));
    }
} catch (Exception $e) {
    $conn->close();
    die(json_encode(['status' => 'error', 'message' => 'Database query failed', 'invites' => []]));
} finally {
    $conn->close();
}