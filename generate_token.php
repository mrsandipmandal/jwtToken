<?php
require './jwt/helper.php';
// Login 
$username = "admin";
$password = "123";

$data = $_REQUEST;
if ($data && $data['username'] === $username && $data['password'] === $password) {
    $payload = [
        "id" => 1,
        "username" => $data['username']
    ];

    $jwt_token = generateToken($payload);

    echo json_encode([
        "message" => "JWT Token generated.",
        "token" => $jwt_token
    ]);

} else {
    http_response_code(401);
    echo json_encode(["message" => "Invalid username or password."]);
}
?>