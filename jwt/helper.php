<?php
require 'vendor/autoload.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

$secret_key = "3b46be39f414db85e46985d405c4c29092e1a8203c09340c63e591d4f142374f";

function generateToken($payload_data, $expiry_seconds = 3600)  // 3600 SEC = 1 Hrs
{
    global $secret_key;

    $issuedat_claim = time();
    $expire_claim = $issuedat_claim + $expiry_seconds;

    $token = [
        "iat" => $issuedat_claim,
        "exp" => $expire_claim,
        "data" => $payload_data
    ];

    return JWT::encode($token, $secret_key, 'HS256');
}

function Authorization()
{
    global $secret_key;

    // Get Authorization header (case-insensitive)
    $headers = getallheaders();
    $authHeader = $headers['Authorization'] ?? $headers['authorization'] ?? '';

    if (!$authHeader) {
        http_response_code(401);
        echo json_encode(["message" => "Authorization header missing."]);
        exit;
    }

    if (preg_match('/Bearer\s(\S+)/', $authHeader, $matches)) {
        $jwt_token = $matches[1];

        try {
            $decoded = JWT::decode($jwt_token, new Key($secret_key, 'HS256'));
            return $decoded->data;
        } catch (Exception $e) {
            http_response_code(401);
            echo json_encode([
                "message" => "Token validation failed.",
                "error" => $e->getMessage()
            ]);
            exit;
        }
    } else {
        http_response_code(400);
        echo json_encode(["message" => "Invalid Authorization header format.", "error" => false]);
        exit;
    }
}
