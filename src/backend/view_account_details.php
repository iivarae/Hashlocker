<?php
require 'security.php';

header("Access-Control-Allow-Origin: {$_SERVER['HTTP_ORIGIN']}");
header("Access-Control-Allow-Methods: *");
header("Access-Control-Allow-Headers: Content-Type, X-CSRF-Token");
header("Access-Control-Allow-Credentials: true");
header("Content-Type: application/json");

// Get database connection credentials
$credentials = parse_ini_file('credentials.txt');
$db_host = $credentials['DB_HOST'];
$db_name = $credentials['DB_NAME'];
$db_user = $credentials['DB_USER'];
$db_pass = $credentials['DB_PASS'];

// Establish database connection
$conn = new mysqli($db_host, $db_user, $db_pass, $db_name);

// Check for connection error
if ($conn->connect_error) {
    $conn->close();
    die(json_encode(['status' => 'error', 'message' => 'Database connection failed', 'account' => [], 'sharing' => []]));
}

// Get the input data
$data = json_decode(file_get_contents('php://input'), true);
$id = $data['id'] ?? '';
$accid   = $data['accid'] ?? '';

//Verify correct request data.
if (empty($id) || empty($accid)) {
    $conn->close();
    die(json_encode(['status' => 'error', 'message' => 'Missing required fields', 'account' => [], 'sharing' => []]));
}

// Verify user authorization
if (!authorize_user($id, $conn)) {
    $conn->close();
    die(json_encode(['status' => 'error', 'message' => 'Unauthorized access', 'account' => [], 'sharing' => []]));
}

try {
    //Get the required information from the accounts table.
    $stmt = $conn->prepare("SELECT USERNAME, WEBSITE, PASSWORD, ICON_PATH, USER_ID FROM accounts WHERE ID = ?");
    $stmt->bind_param("i", $accid);
    $stmt->execute();
    $stmt->bind_result($username, $website, $password, $icon_path, $ownerid);
    $stmt->fetch();
    $stmt->close();

    $owner = false;
    if ($id == $ownerid) {
        $owner = true;
    }

    $account = [
        'accid' => $accid,
        'accplatform' => htmlspecialchars($website),
        'accusername' => htmlspecialchars($username),
        'accpassword' => htmlspecialchars($password),
        'iconpath' => $icon_path,
        'owner' => $owner
    ];

    //Now figure out who the password is being shared with.
    $allowed = false;
    $stmt2 = $conn->prepare("SELECT SHARE_ID, ACCOUNT_OWNER, SHARED_WITH, STATUS FROM invites WHERE ACCID = ? AND STATUS < 2");
    $stmt2->bind_param("i", $accid);
    $stmt2->execute();
    $result2 = $stmt2->get_result();
    $stmt2->close();

    //Fill sharing array.
    $sharing = [];
    //First, find and add account owner.
    $stmt4 = $conn->prepare("SELECT USERNAME FROM user WHERE ID = ?");
    $stmt4->bind_param("i", $ownerid);
    $stmt4->execute();
    $stmt4->bind_result($owner_username);
    $stmt4->fetch();
    $stmt4->close();
    $sharing[] = [
        'username' => htmlspecialchars($owner_username),
        'status' => 1,
        'owner' => true
    ];

    //Fetch people who account has been shared with for the response.
    while ($row = $result2->fetch_assoc()) {
        $sharedid = $row['SHARED_WITH'];
        $status =  $row['STATUS'];
        if ($sharedid == $id) {
            $allowed = true;
        }

        //Get the username of the target.
        $stmt3 = $conn->prepare("SELECT USERNAME FROM user WHERE ID = ?");
        $stmt3->bind_param("i", $sharedid);
        $stmt3->execute();
        $stmt3->bind_result($shared_username);
        $stmt3->fetch();
        $stmt3->close();

        $sharing[] = [
            'username' => htmlspecialchars($shared_username),
            'status' => $status,
            'owner' => false
        ];
    }

    //If the request did not come from someone ACCID was shared with or the owner.
    if (!$allowed && !$owner) {
        $conn->close();
        die(json_encode(['status' => 'error', 'message' => 'You do not have access to this account.', 'account' => [], 'sharing' => []]));
    } else { //The request was valid.
        $conn->close();
        die(json_encode(['status' => 'success', 'account' => $account, 'sharing' => $sharing]));
    }
} catch (Exception $e) {
    $conn->close();
    die(json_encode(['status' => 'error', 'message' => 'An internal error has occurred.', 'account' => [], 'sharing' => []]));
}