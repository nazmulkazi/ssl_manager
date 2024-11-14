<?php
// Global Variables
$HOST = "domain.com"
$USERNAME = "user"
$TOKEN = "<token>"

// Reject all non-secure http requests
if (empty($_SERVER["HTTPS"]) || $_SERVER["HTTPS"] === "off") {
    header("HTTP/1.0 503 Service Unavailable");
    exit();
}

// Authenticate request
$token = "<token>";
if(!isset($_SERVER['HTTP_AUTHORIZATION']) || $_SERVER['HTTP_AUTHORIZATION'] !== $token){
    header("HTTP/1.0 401 Unauthorized");
    if(isset($_SERVER['HTTP_AUTHORIZATION'])){
        echo("ValueError: Invalid Token.");
    }
    exit();
}

// Request must include the `req` parameter
if(!isset($_GET["req"]) || $_GET["req"] == ""){
    header("HTTP/1.0 400 Bad Request");
    echo("Error: Required parameter `req` is missing which denotes the requested action.");
    exit();
}

// Fetch SSL certificate from cPanel using cURL
function fetch_ssl_for_domain($domain) {
    global $HOST, $USERNAME, $TOKEN
    
    // Initialize cURL session
    $ch = curl_init();

    // Set cURL options
    curl_setopt($ch, CURLOPT_URL, "https://{$HOST}:2083/execute/SSL/fetch_best_for_domain?domain={$domain}");
    curl_setopt($ch, CURLOPT_HTTPHEADER, array("Authorization: cpanel {$USERNAME}:{$TOKEN}", "Accept: application/json"));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

    // Execute cURL request
    $res = curl_exec($ch);

    // Check for errors
    if(curl_errno($ch)) {
        echo(curl_error($ch));
        exit();
    }

    // Close cURL session
    curl_close($ch);
    
    // Parse response as JSON
    $data = json_decode($res, True);
    
    // Print response and exit, if cURL returned any errors
    if(!is_null($data['errors'])){
        echo($res);
        exit();
    }
    
    // Build a new dict with necessary values
    $out = [
        "domain" => $data["data"]["domain"],
        "crt" => $data["data"]["crt"],
        "cab" => $data["data"]["cab"],
        "key" => $data["data"]["key"]
    ];
    
    // Extract validation period and and to out
    $crt = openssl_x509_read($out["crt"]);
    $crt_data = openssl_x509_parse($crt);
    $out["valid_from"] = $crt_data['validFrom_time_t'];
    $out["valid_to"] = $crt_data['validTo_time_t'];
    
    // Calculate fingerprint and add to out
    $out["fingerprint"] = openssl_x509_fingerprint($crt);
    
    return json_encode($out);
}

// Execute the requested action. Response with an error if the requested function (req) is not implemented
if($_GET["req"] == "ssl_certificate"){
    echo fetch_ssl_for_domain($_GET["domain"]);
} else {
    header("HTTP/1.0 501 Not Implemented");
    exit();
}
?>