<?php
require 'security.php';

header("Access-Control-Allow-Origin:  {$_SERVER['HTTP_ORIGIN']}");
header("Access-Control-Allow-Methods: *");
header("Access-Control-Allow-Headers: Content-Type, X-CSRF-Token");
header("Access-Control-Allow-Credentials: true");

$credentials = parse_ini_file('credentials.txt');
$db_host = $credentials['DB_HOST'];
$db_name = $credentials['DB_NAME'];
$db_user = $credentials['DB_USER'];
$db_pass = $credentials['DB_PASS'];
$key = $credentials['CSRF_SECRET_KEY'];

//Get database connection using credentials from credentials.txt
$conn = new mysqli($db_host, $db_user, $db_pass, $db_name);

//Check for connection error
if ($conn->connect_error) {
    die(json_encode(['status' => 'failure', 'message' => 'Database connection failed.']));
}

//Check for json data.
if (!isset($_POST['json'])) {
    $conn->close();
    die(json_encode(['status' => 'failure', 'message' => 'Missing JSON data.']));
}

//Decode data.
$data = json_decode($_POST['json'], true);
if (!$data) {
    $conn->close();
    die(json_encode(['status' => 'failure', 'message' => 'Invalid JSON format.']));
}

//Get id and accid.
$id = isset($data['id']) ? trim($data['id']) : null;
$accid = isset($data['accid']) ? trim($data['accid']) : null;

//Check for empty id or accid.
if (empty($id) || empty($accid)) {
    $conn->close();
    die(json_encode(['status' => 'failure', 'message' => 'Missing required fields.']));
}

//Check if the request is coming from a logged-in user.
if (!authorize_user($id, $conn)){
    $conn->close();
    die(json_encode(['status' => 'failure', 'message' => 'Unauthorized access.']));
}

$read_id =  null;
$website = null;
$username = null;
$password = null;
$iconpath = null;

//Access the information of the account the user is updating the image for.
try {
    $stmt = $conn->prepare("SELECT USER_ID, USERNAME, WEBSITE, PASSWORD, ICON_PATH FROM accounts WHERE ID = ?");
    $stmt->bind_param("i", $accid);
    $stmt->execute();
    $result = $stmt->get_result();
    $row = $result->fetch_assoc();

    if ($result->num_rows == 0){
        $conn->close();
        die(json_encode(['status' => 'failure', 'message' => 'No account found with this ACCID.']));
    }

    $read_id = $row['USER_ID'];
    $website = htmlspecialchars($row['WEBSITE']);
    $username = htmlspecialchars($row['USERNAME']);
    $password = htmlspecialchars($row['PASSWORD']);
    $iconpath = $row['ICON_PATH'];


    if ($read_id != $id){
        $conn->close();
        die(json_encode(['status' => 'failure', 'message' => 'Invalid account to update.']));
    }
    $stmt->close();

} catch (Exception $e) {
    $conn->close();
    die(json_encode(['status' => 'error', 'message' => 'An internal error occurred']));
}

//If there is no file.
if (empty($_FILES['fileToUpload']) || $_FILES['fileToUpload']['error'] != UPLOAD_ERR_OK) {
    $conn->close();
    die(json_encode(['status' => 'failure', 'message' => 'Missing image file.']));
}

//Get file information.
$file = $_FILES['fileToUpload'];
$fileTmpPath = $file['tmp_name'];
$fileName = $file['name'];
$fileSize = $file['size'];
$fileType = $file['type'];

//If the file type is not jpeg or png.
$allowedTypes = ['image/jpeg', 'image/png'];
if (!in_array($fileType, $allowedTypes)) {
    $conn->close();
    die(json_encode(['status' => 'failure', 'message' => 'Error in image update: Invalid file type to upload.']));
}


//Move the image to the server.
$imageDir = realpath(__DIR__ . '/../../images');
if (!is_dir($imageDir)) {
    die(json_encode(['status' => 'failure', 'message' => 'Failed find images directory.']));
}

// Generate file path
$ext = pathinfo($fileName, PATHINFO_EXTENSION);
$iconPath = "/images/path{$accid}.{$ext}";
$destination = $imageDir . "/path{$accid}.{$ext}";

//Make sure the database is updated.
try {
    $stmt = $conn->prepare("UPDATE accounts SET ICON_PATH = ?, UPDATED_AT = NOW() WHERE ID = ?");
    $stmt->bind_param("si", $iconPath, $accid);
    $stmt->execute();
    $stmt->close();
} catch (Exception $e) {
    die(json_encode(['status' => 'failure', 'message' => 'Database update error.']));
}
$conn->close();

// Move file to server
if (!move_uploaded_file($fileTmpPath, $destination)) {
    die(json_encode(['status' => 'failure', 'message' => 'File upload failed']));
}
chmod($destination, 0666);
$account = ['accplatform' => $website, 'accusername' => $username, 'iconpath' => $iconPath,'accpassword' => $password, 'accid' => $accid];

echo json_encode([
    'status' => 'success',
    'account' =>  $account,
]);