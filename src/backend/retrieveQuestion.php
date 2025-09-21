<?php
//Kill CORS error once and for all
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: *");
header("Access-Control-Allow-Headers: Content-Type");

//Database connection credentials.
$credentials = parse_ini_file('credentials.txt');
$db_host = $credentials['DB_HOST'];
$db_name = $credentials['DB_NAME'];
$db_user = $credentials['DB_USER'];
$db_pass = $credentials['DB_PASS'];

//Get database connection using credentials from credentials.txt
$conn = new mysqli($db_host, $db_user, $db_pass, $db_name);

// Check for connection error
if ($conn->connect_error) {
    die(json_encode(['status' => 'error', 'message' => 'Database connection failed', 'user_data' => ['username' => '']]));
}

//Get the input.
$data = json_decode(file_get_contents('php://input'), true);
$username = isset($data['username']) ? $data['username'] : '';

// Return failure for empty username
if (empty($username)) {
    $username = htmlspecialchars($username);
    echo json_encode(['status' => 'failure', 'message' => 'Invalid Username', 'user_data' => ['username' => $username]]);
    exit;
}

try {
    //Query database for the user.
    //Bind param to prevent SQL injection vulnerability.
    $stmt = $conn->prepare("SELECT SECURITY_QUESTION, ID FROM user WHERE USERNAME = ? LIMIT 1");
    $stmt->bind_param("s", $username); // "s" indicates that the parameter is a string
    $stmt->execute();
    $result = $stmt->get_result();

    //Check if the user exists
    if ($user = $result->fetch_assoc()) {
        $username = htmlspecialchars($username);
        echo json_encode(['status' => 'success', 'question' => $user['SECURITY_QUESTION'], 'user_data' => ['id' => $user['ID'], 'username' => $username]]);

    } else {
        $username = htmlspecialchars($username);
        echo json_encode(['status' => 'failure', 'message' => 'Invalid Username', 'user_data' => ['username' => $username]]);
    }
} catch (Exception $e) {
    // Handle errors
    echo json_encode(['status' => 'error', 'message' => 'An internal error occurred']);
} finally {
    // Close the database connection
    $conn->close();
}
?>
