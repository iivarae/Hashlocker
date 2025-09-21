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
$searchTerm = isset($data['searchTerm']) ? $data['searchTerm'] : '';

//Get database connection using credentials from credentials.txt
$conn = new mysqli($db_host, $db_user, $db_pass, $db_name);

//Check for connection error
if ($conn->connect_error) {
    $conn->close();
    die(json_encode(['status' => 'error', 'message' => 'Database connection failed', 'accounts' => []]));
}



if (empty($id)) {
    $conn->close();
    die(json_encode(['status' => 'error', 'message' => 'Missing required ID field', 'accounts' => []]));
}



if (!authorize_user($id, $conn)){
    $conn->close();
    die(json_encode(['status' => 'failure', 'message' => 'Unauthorized access.', 'accounts' => []]));
}

if (empty($searchTerm)) {
    $conn->close();
    die(json_encode(['status' => 'success', 'accounts' => []]));
}

$sql = "SELECT ID, USERNAME, WEBSITE, PASSWORD, ICON_PATH FROM accounts WHERE USER_ID = ? AND WEBSITE LIKE ?";
$stmt = $conn->prepare($sql);
$likeTerm = "%$searchTerm%";
$stmt->bind_param("is", $id, $likeTerm);
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
$stmt->close();

//Now to read for accounts which have been SHARED with this user to add them to the search results if relevant...
$stmt2 = $conn->prepare("SELECT SHARE_ID, ACCID FROM invites WHERE SHARED_WITH = ? AND STATUS = 1");
$stmt2->bind_param("i", $id);
$stmt2->execute();
$result2 = $stmt2->get_result();

while ($row2 = $result2->fetch_assoc()) {
    $accid = $row2['ACCID'];

    // Fetch the account information for ACCID from the accounts table.
    $stmt3 = $conn->prepare("SELECT USERNAME, WEBSITE, ICON_PATH, PASSWORD FROM accounts WHERE ID = ? AND WEBSITE LIKE ?");
    $likeTerm = "%$searchTerm%";
    $stmt3->bind_param("is", $accid, $likeTerm);
    $stmt3->execute();
    $result3 = $stmt3->get_result();

    // Loop through all results for the given ACCID.
    while ($row3 = $result3->fetch_assoc()) {
        if (!empty($row3['WEBSITE'])) {
            $accounts[] = [
                'accplatform' => htmlspecialchars($row3['WEBSITE']),
                'accusername' => htmlspecialchars($row3['USERNAME']),
                'iconpath' => $row3['ICON_PATH'],
                'accpassword' => htmlspecialchars($row3['PASSWORD']),
                'accid' => $accid,
            ];
        }
    }

    $stmt3->close();
}

$stmt2->close();
$conn->close();

echo json_encode(['status' => 'success', 'accounts' => $accounts]);
?>