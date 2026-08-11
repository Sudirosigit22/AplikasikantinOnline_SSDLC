<?php
$halaman = $_POST['file'] ?? '';

$allowed = [
    'login.html',
    'register.html',
    'datakantin.html',
    'etalase.html',
    'checkout.html',
    'final.html',
    'lupa_password.html',
    'reset_password.html'
];

if (in_array($halaman, $allowed)) {
    $path = __DIR__ . "/halaman/" . $halaman;

    if (file_exists($path)) {
        echo file_get_contents($path);
    } else {
        echo file_get_contents("404.html");
    }
} else {
    echo file_get_contents("403.html");
}
