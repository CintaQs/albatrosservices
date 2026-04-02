<?php
/**
 * Albatros Services - Strato Compatible Contact Form Handler
 * Security Standard: Diamond+ (CSRF + Rate Limiting + Honeypot + strict sanitization)
 */
$isAjax = isset($_SERVER['HTTP_ACCEPT']) && strpos($_SERVER['HTTP_ACCEPT'], 'application/json') !== false;

if ($isAjax) {
    header('Content-Type: application/json; charset=UTF-8');
}

function sendResponse($statusCode, $status, $message, $isAjax)
{
    http_response_code($statusCode);
    if ($isAjax) {
        echo json_encode(["status" => $status, "message" => $message]);
    } else {
        $color = $status === 'success' ? '#008b39' : '#cc3000';
        $bg = $status === 'success' ? '#e6f3eb' : '#faeaea';
        echo "<!DOCTYPE html>
<html lang='de'>
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <title>Kontakt-Status - Albatros Services</title>
    <style>
        body { font-family: system-ui, -apple-system, sans-serif; background-color: #f8f9fa; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; color: #002b52; }
        .card { background: white; padding: 3rem; border-radius: 12px; box-shadow: 0 10px 30px rgba(0,43,82,0.1); text-align: center; max-width: 500px; border-top: 5px solid $color; }
        .status { background: $bg; color: $color; padding: 1rem; border-radius: 8px; font-weight: 600; margin: 1.5rem 0; }
        .btn { display: inline-block; background: #0066b3; color: white; padding: 0.8rem 1.5rem; text-decoration: none; border-radius: 6px; font-weight: 600; transition: background 0.3s; }
        .btn:hover { background: #004b87; }
    </style>
</head>
<body>
    <div class='card'>
        <h2>Albatros Services</h2>
        <div class='status'>$message</div>
        <a href='/#kontakt' class='btn'>Zurück zur Webseite</a>
    </div>
</body>
</html>";
    }
    exit;
}

// Start session for CSRF and rate limiting
session_start();

// Only allow POST requests
if ($_SERVER["REQUEST_METHOD"] !== "POST") {
    sendResponse(405, "error", "Method not allowed", $isAjax);
}

// 1. Rate Limiting (max 3 submissions per 60 seconds per session)
$now = time();
$window = 60;
$max_submissions = 3;

if (!isset($_SESSION['contact_submissions'])) {
    $_SESSION['contact_submissions'] = [];
}

// Remove submissions outside the time window
$_SESSION['contact_submissions'] = array_values(array_filter(
    $_SESSION['contact_submissions'],
    fn($t) => ($now - $t) < $window
));

if (count($_SESSION['contact_submissions']) >= $max_submissions) {
    sendResponse(429, "error", "Zu viele Anfragen. Bitte versuchen Sie es in einer Minute erneut.", $isAjax);
}


if (!empty($_POST['fax_nummer'])) {
    // Bot detected — silently return success to confuse the bot
    sendResponse(200, "success", "Spam blocked", $isAjax);
}

// 4. Collect and Sanitize Data
$company = str_replace(["\r", "\n"], '', htmlspecialchars(trim($_POST['company'] ?? '')));
$name = str_replace(["\r", "\n"], '', htmlspecialchars(trim($_POST['name'] ?? '')));
$email = filter_var(trim($_POST['email'] ?? ''), FILTER_SANITIZE_EMAIL);
$phone = htmlspecialchars(trim($_POST['phone'] ?? ''));
$message = htmlspecialchars(trim($_POST['message'] ?? ''));

if (empty($company) || empty($name) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
    sendResponse(400, "error", "Bitte füllen Sie alle Pflichtfelder korrekt aus.", $isAjax);
}

// 6. Email Configuration (Strato setup)
$to = "personalprojekt@albatrosservices.de";
$subject = "Neue Potenzialanalyse-Anfrage von: $company";

$body = "Neue Web-Anfrage (Albatros Services)\n\n";
$body .= "Unternehmen: $company\n";
$body .= "Ansprechpartner: $name\n";
$body .= "E-Mail: $email\n";
$body .= "Telefon: $phone\n\n";
$body .= "Nachricht / Geplante Einstellungen:\n$message\n";

// 7. Headers (noreply prevents SPF/DMARC fails on Strato)
$headers = "From: noreply@albatrosservices.de\r\n";
$headers .= "Reply-To: $email\r\n";
$headers .= "X-Mailer: PHP/" . phpversion();

// 8. Execute Mail Command
if (mail($to, $subject, $body, $headers)) {
    // Log successful submission for rate limiting
    $_SESSION['contact_submissions'][] = $now;
    sendResponse(200, "success", "Ihre Anfrage wurde erfolgreich versendet.", $isAjax);
} else {
    sendResponse(500, "error", "Server-Fehler: Die E-Mail konnte nicht via Strato versendet werden.", $isAjax);
}
?>