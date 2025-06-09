<?php
/**
 * @author Sandip Mandal
 */
require 'vendor/autoload.php';
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

$secret_key = "3b46be39f414db85e46985d405c4c29092e1a8203c09340c63e591d4f142374f";

function generateToken($payload_data, $access_expiry = 3600, $refresh_expiry = 604800) // 1 hour, 7 days
{
    global $secret_key;

    $issued_at = time();
    $access_exp = $issued_at + $access_expiry;
    $refresh_exp = $issued_at + $refresh_expiry;

    $access_token_payload = [
        "iat" => $issued_at,
        "exp" => $access_exp,
        "type" => "access",
        "data" => $payload_data
    ];

    $refresh_token_payload = [
        "iat" => $issued_at,
        "exp" => $refresh_exp,
        "type" => "refresh",
        "data" => $payload_data
    ];

    return [
        "access_token" => JWT::encode($access_token_payload, $secret_key, 'HS256'),
        "refresh_token" => JWT::encode($refresh_token_payload, $secret_key, 'HS256')
    ];
}

function refreshAccessToken($refresh_token)
{
    global $secret_key;

    try {
        $decoded = JWT::decode($refresh_token, new Key($secret_key, 'HS256'));

        // Ensure token is actually a refresh token
        if ($decoded->type !== "refresh") {
            http_response_code(400);
            echo json_encode(["message" => "Invalid token type."]);
            exit;
        }

        // Create a new access token
        $new_access_token = generateToken((array)$decoded->data);

        echo json_encode([
            "access_token" => $new_access_token
        ]);
    } catch (Exception $e) {
        http_response_code(401);
        echo json_encode([
            "message" => "Refresh token invalid or expired.",
            "error" => $e->getMessage()
        ]);
        exit;
    }
}

function Authorization()
{
    global $secret_key;

    // Get Authorization header (case-insensitive)
    $headers = getallheaders();
    $authHeader = $headers['Authorization'] ?? $headers['authorization'] ?? '';

    if (!$authHeader) {
        http_response_code(401);
        echo json_encode(["message" => "Authorization missing."]);
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