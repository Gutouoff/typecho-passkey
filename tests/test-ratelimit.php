<?php
// Simulate the enforceRateLimit file-backed sliding-window logic
$file = sys_get_temp_dir() . '/passkey_rl_' . md5('unit|scope|1.2.3.4') . '.json';
@unlink($file);

function simulateLimit(string $file, int $window, int $max): ?string {
    $now = time();
    $data = ['count' => 0, 'window' => $now];
    if (is_file($file)) {
        $raw = @file_get_contents($file);
        $parsed = json_decode((string) $raw, true);
        if (is_array($parsed)) {
            $data = $parsed;
            if ((int) ($data['window'] ?? 0) < $now - $window) {
                $data = ['count' => 0, 'window' => $now];
            }
        }
    }
    $data['count'] = (int) ($data['count'] ?? 0) + 1;
    @file_put_contents($file, json_encode($data));
    return $data['count'] > $max ? 'BLOCKED' : 'OK';
}

$window = 60;
$max = 5;
$blockedAt = null;
for ($i = 1; $i <= 8; $i++) {
    $r = simulateLimit($file, $window, $max);
    if ($r === 'BLOCKED' && $blockedAt === null) $blockedAt = $i;
}
echo "Blocked at request #$blockedAt (expected 6)\n";
echo ($blockedAt === 6 ? "[OK] limit triggers at threshold+1\n" : "[FAIL] wrong threshold\n");

// Window expiry resets counter (simulate by aging the file)
$data = json_decode(file_get_contents($file), true);
$data['window'] = time() - 61;
file_put_contents($file, json_encode($data));
$r = simulateLimit($file, $window, $max);
echo "After window expiry: $r (expected OK — counter reset)\n";
echo ($r === 'OK' ? "[OK] window reset works\n" : "[FAIL] window reset broken\n");

// Non-blocking until threshold
$r = simulateLimit($file, $window, $max);
echo "Second request in new window: $r (expected OK)\n";
@unlink($file);
echo ($r === 'OK' ? "[OK] within-window counting works\n" : "[FAIL]\n");
