<?php
// Shared CBOR helpers for attack scripts

function cborInt(int $v): string {
    if ($v >= 0) {
        if ($v < 24) return chr(0x00 + $v);
        if ($v < 256) return "\x18" . chr($v);
        if ($v < 65536) return "\x19" . pack('n', $v);
        return "\x1a" . pack('N', $v);
    }
    $n = -1 - $v;
    if ($n < 24) return chr(0x20 + $n);
    if ($n < 256) return "\x38" . chr($n);
    return "\x39" . pack('n', $n);
}

function cborBytes(string $data): string {
    $len = strlen($data);
    if ($len < 24) return chr(0x40 + $len) . $data;
    if ($len < 256) return "\x58" . chr($len) . $data;
    if ($len < 65536) return "\x59" . pack('n', $len) . $data;
    return "\x5a" . pack('N', $len) . $data;
}

function cborText(string $data): string {
    $len = strlen($data);
    if ($len < 24) return chr(0x60 + $len) . $data;
    if ($len < 256) return "\x78" . chr($len) . $data;
    if ($len < 65536) return "\x79" . pack('n', $len) . $data;
    return "\x7a" . pack('N', $len) . $data;
}

function cborMap(array $items): string {
    $count = count($items);
    if ($count < 24) $out = chr(0xa0 + $count);
    else $out = "\xb8" . chr($count);
    foreach ($items as $k => $v) {
        if (is_int($k)) {
            $out .= cborInt($k) . $v;
        } else {
            $out .= cborText((string) $k) . $v;
        }
    }
    return $out;
}
