<?php
//New security function.
function authorize_user($id, $conn) {
    $credentials = parse_ini_file('credentials.txt');
    $key = $credentials['CSRF_SECRET_KEY'];
    if (!isset($_COOKIE['session_token'])) {
        return false;
    }

    // Read session token from cookie
    $sessionToken = $_COOKIE['session_token'];

    // Verify session token in database
    $stmt = $conn->prepare("SELECT ID FROM user WHERE ID = ? AND SESSION = ?");
    $stmt->bind_param("is", $id, $sessionToken);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows === 0) {
        return false; // Invalid session.
    }

    // Verify CSRF token.
    if (!isset($_COOKIE['csrf_token']) || !isset($_SERVER['HTTP_X_CSRF_TOKEN'])) {
        return false;
    }

    $csrfCookie = $_COOKIE['csrf_token'];
    $csrfHeader = $_SERVER['HTTP_X_CSRF_TOKEN'];
    $hashedCsrfHeader = hash_hmac('sha256', $csrfHeader, $key);

    return hash_equals($csrfCookie, $hashedCsrfHeader);

}
