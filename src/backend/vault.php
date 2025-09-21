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
    die(json_encode(['status' => 'error', 'message' => 'Database connection failed', 'accounts' => []]));
}

//Get the input.
$data = json_decode(file_get_contents('php://input'), true);
$id = isset($data['id']) ? $data['id'] : '';

if (empty($id)) {
    $conn->close();
    die(json_encode(['status' => 'error', 'message' => 'Invalid User ID', 'accounts' => []]));
}

//Authenticate the user via the security function.
if (!authorize_user($id, $conn)) {
    $conn->close();
    die(json_encode(['status' => 'failure', 'message' => 'Unauthorized access detected', 'accounts' => []]));

}

try {
    //Accounts table has fields: ID (accid), USER_ID, USERNAME, WEBSITE, PASSWORD, ICON_PATH, CREATED_AT, and UPDATED_AT
    $stmt = $conn->prepare("SELECT ID, USERNAME, WEBSITE, PASSWORD, ICON_PATH FROM accounts WHERE USER_ID = ?");
    $stmt->bind_param("i", $id);
    $stmt->execute();
    $result = $stmt->get_result();
    $accounts = [];
    while ($row = $result->fetch_assoc()) {
        $accounts[] = [
            'accplatform' => htmlspecialchars($row['WEBSITE']),
            'accusername' => htmlspecialchars($row['USERNAME']),
            'iconpath' => $row['ICON_PATH'],
            'accpassword' => htmlspecialchars($row['PASSWORD']),
            'accid' => $row['ID']
        ];
    }

    //Now to read for accounts which have been SHARED with this user to add them to the Vault page...
    $stmt2 = $conn->prepare("SELECT SHARE_ID, ACCID FROM invites WHERE SHARED_WITH = ? AND STATUS = 1");
    $stmt2->bind_param("i", $id);
    $stmt2->execute();
    $result2 = $stmt2->get_result();

    while ($row2 = $result2->fetch_assoc()) {
        $accid = $row2['ACCID'];

        //Fetch the account information for ACCID.
        $stmt3 = $conn->prepare("SELECT USERNAME, WEBSITE, ICON_PATH, PASSWORD FROM accounts WHERE ID = ?");
        $stmt3->bind_param("i", $accid);
        $stmt3->execute();
        $stmt3->bind_result($accusername, $accplatform, $iconpath, $password);
        $stmt3->fetch();
        $stmt3->close();


        //Build the array entry.
        $accounts[] = [
            'accplatform' => htmlspecialchars($accplatform),
            'accusername' => htmlspecialchars($accusername),
            'iconpath' => $iconpath,
            'accpassword' => htmlspecialchars($password),
            'accid' => $accid,
        ];
    }

    if (count($accounts) > 0) {
        $conn->close();
        die(json_encode(['status' => 'success', 'accounts' => $accounts]));
    } else {
        $conn->close();
        die(json_encode(['status' => 'success', 'accounts' => []]));
    }
} catch (Exception $e) {
    echo json_encode(['status' => 'error', 'message' => 'An internal error occurred', 'accounts' => []]);
} finally {
    // Close the database connection
    $conn->close();
}
?>