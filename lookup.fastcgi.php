<?php
/*
phpGSB - PHP Google Safe Browsing Implementation
Released under New BSD License (see LICENSE)
Copyright (c) 2010-2012, Sam Cleaver (Beaver6813, Beaver6813.com)
All rights reserved.

LOOKUP EXAMPLES - via Nginx Fastcgi on localhost:
//Should return false (not phishing or malware)
http://localhost/phpGSB/lookup.fastcgi.php?domain=http://www.google.com
{"status":"success","data":{}}

//Should return true, malicious URL
http://localhost/phpGSB/lookup.fastcgi.php?domain=http://www.gumblar.cn
{"status":"success","data":{"list_name":"gsb"}}

Feel free to throw in some more details into the output JSON!

*/
require("phpgsb.class.php");
$phpgsb = new phpGSB("DATABASE_NAME","DATABASE_USERNAME","DATABASE_PASSWORD");
//Obtain an API key from: http://code.google.com/apis/safebrowsing/key_signup.html
$phpgsb->apikey = "API_KEY_HERE";
$phpgsb->usinglists = array('googpub-phish-shavar','goog-malware-shavar');
$url = $_GET["domain"];

if ( $parts = parse_url($url) ) {
   if ( !isset($parts["scheme"]) )
   {
       $url = "http://$url";
   }
}

$result['status'] = "fail";
$result['data'] = (object) null;
if ($url === null || $url === "" || !filter_var($url, FILTER_VALIDATE_URL)) {
    http_response_code(400);
    print json_encode($result);
    return;
}

$checkres = $phpgsb->doLookup($url);
if ($checkres === true) {
    $result['status'] ="success";
    $list["list_name"] = "gsb";
    $result['data'] = $list;
} else if ($checkres === false) {
    $result['status'] ="success";
    $result['data'] = (object) null;
}
print json_encode($result);
$phpgsb->close();
?>
