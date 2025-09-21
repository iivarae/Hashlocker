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

// Check for connection error
if ($conn->connect_error) {
    die(json_encode(['status' => 'failure', 'message' => 'Database connection failed']));
}

//Check for json data.
if (!isset($_POST['json'])) {
    die(json_encode(['status' => 'failure', 'message' => 'Missing JSON data']));
}

$data = json_decode($_POST['json'], true);
if (!$data) {
    die(json_encode(['status' => 'failure', 'message' => 'Invalid JSON format']));
}


$id = isset($data['id']) ? trim($data['id']) : null;
$accplatform = isset($data['accplatform']) ? trim($data['accplatform']) : null;
$accusername = isset($data['accusername']) ? trim($data['accusername']) : null;
$accpassword = isset($data['accpassword']) ? trim($data['accpassword']) : null;

// Check for empty values
if (empty($id) || empty($accplatform) || empty($accusername) || empty($accpassword)) {
    die(json_encode(['status' => 'failure', 'message' => 'Missing required fields']));
}

if (!authorize_user($id, $conn)){
    die(json_encode(['status' => 'failure', 'message' => 'Unauthorized access']));
}

$defaultPath = "/images/default.jpg";
$stmt = $conn->prepare("INSERT INTO accounts (USER_ID, USERNAME, WEBSITE, PASSWORD, ICON_PATH, CREATED_AT, UPDATED_AT) VALUES (?, ?, ?, ?, ?, NOW(), NOW())");
$stmt->bind_param("issss", $id, $accusername, $accplatform, $accpassword, $defaultPath);
if (!$stmt->execute()) {
    die(json_encode(['status' => 'failure', 'message' => 'Database insertion failed']));
}


$accountID = $stmt->insert_id;
$stmt->close();


$iconPath = "/images/default.jpg";

if (!empty($_FILES['fileToUpload']) && $_FILES['fileToUpload']['error'] === UPLOAD_ERR_OK) {
    $file = $_FILES['fileToUpload'];
    $fileTmpPath = $file['tmp_name'];
    $fileName = $file['name'];
    $fileSize = $file['size'];
    $fileType = $file['type'];

    // Validate file type
    $allowedTypes = ['image/jpeg', 'image/png'];
    if (!in_array($fileType, $allowedTypes)) {
        die(json_encode(['status' => 'failure', 'message' => 'Invalid file type']));
    }

    $imageDir = realpath(__DIR__ . '/../../images');
    if (!is_dir($imageDir)) {
        die(json_encode(['status' => 'failure', 'message' => 'Failed find images directory.']));
    }

    // Generate file path
    $ext = pathinfo($fileName, PATHINFO_EXTENSION);
    $iconPath = "/images/path{$accountID}.{$ext}";
    $destination = $imageDir . "/path{$accountID}.{$ext}";

    // Move file to server
    if (!move_uploaded_file($fileTmpPath, $destination)) {
        die(json_encode(['status' => 'failure', 'message' => 'File upload failed']));
    }
    chmod($destination, 0666);

    $stmt = $conn->prepare("UPDATE accounts SET ICON_PATH = ?, UPDATED_AT = NOW() WHERE ID = ?");
    $stmt->bind_param("si", $iconPath, $accountID);
    $stmt->execute();
    $stmt->close();
}

echo json_encode([
    'status' => 'success',
    'message' => 'Account successfully added',
    'iconpath' => $iconPath,
    'accid' => $accountID
]);


$conn->close();
?>