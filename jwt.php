<?php

ini_set('display_errors', 1);
error_reporting(E_ALL);

// No need these 3 lines for Laravel, tested with Laravel 8
require_once './vendor/firebase/php-jwt/src/JWT.php';
require_once './vendor/firebase/php-jwt/src/JWK.php';
require_once './vendor/firebase/php-jwt/src/Key.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

// Download the certificate -> https://www.apple.com/certificateauthority/AppleRootCA-G3.cer
// Convert it to .PEM file, run on macOS terminal ->  ```bash openssl x509 -in AppleRootCA-G3.cer -out apple_root.pem```

$pem = file_get_contents('apple_root.pem');

$data = file_get_contents('notification.json');  // replace with file_get_contents('php://input');
$json = json_decode($data);

$header_payload_secret = explode('.', $json->signedPayload);

//------------------------------------------
// Header
//------------------------------------------
$header = json_decode(base64_decode($header_payload_secret[0]));
$algorithm = $header->alg;
$x5c = $header->x5c; // array
$certificate = $x5c[0];
$intermediate_certificate = $x5c[1];
$root_certificate = $x5c[2];

$certificate =
      "-----BEGIN CERTIFICATE-----\n"
    . $certificate
    . "\n-----END CERTIFICATE-----";

$intermediate_certificate =
      "-----BEGIN CERTIFICATE-----\n"
    . $intermediate_certificate
    . "\n-----END CERTIFICATE-----";

$root_certificate =
      "-----BEGIN CERTIFICATE-----\n"
    . $root_certificate
    . "\n-----END CERTIFICATE-----";

//------------------------------------------
// Verify the notification request   
//------------------------------------------

if (openssl_x509_verify($intermediate_certificate, $root_certificate) != 1){ 
    echo 'Intermediate and Root certificate do not match';
    exit;
}

// Verify again with Apple root certificate
if (openssl_x509_verify($root_certificate, $pem) == 1){
    $cert_object = openssl_x509_read($certificate);
    $pkey_object = openssl_pkey_get_public($cert_object);
    $pkey_array = openssl_pkey_get_details($pkey_object);
    $publicKey = $pkey_array['key'];

    //------------------------------------------
    // Payload
    //------------------------------------------
    $payload = json_decode(base64_decode($header_payload_secret[1]));
    $notificationType = $payload->notificationType;

    //if ($notificationType == "EXPIRED" || $notificationType == "REFUND") {
        $transactionInfo = $payload->data->signedTransactionInfo;
        $signedRenewalInfo = $payload->data->signedRenewalInfo;

        $transactionDecodedData = JWT::decode($transactionInfo, new Key($publicKey, $algorithm));
        var_dump($transactionDecodedData->originalTransactionId);
        echo "========================================";
        $signedRenewalDecodedData = JWT::decode($signedRenewalInfo, new Key($publicKey, $algorithm));
        var_dump($signedRenewalDecodedData);
    //}

} else {
    echo 'Header is not valid';
    exit;
}