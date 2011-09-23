<pre>
<?php
include('VirusTotal.php');

function outputResult($header, $result) {
    echo '<h2>' . $header . '</h2>';
    print_r($result);
}
/* Initialize the class */
$virusTotal = new VirusTotal('YOUR-API-KEY');

/* Scan a file */
$fileScan = $virusTotal->scanFile('RELATIVE-PATH-TO-THE-FILE');
outputResult('scanFile', $fileScan);
/* Get a file scan report */
$fileReport = $virusTotal->getScanReport('A-HASH-TO-THE-FILE');
outputResult('getScanReport', $fileReport);
/* Create a comment on a file report */
$createFileComment = $virusTotal->createComment('A-HASH-TO-THE-FILE', 'A-COMMENT', array('TAGS', 'GO', 'HERE'));
outputResult('getScanReport', $createFileComment);

/* Scan a URL */
$urlScan = $virusTotal->scanURL('A-URL-TO-SCAN');
outputResult('scanURL', $urlScan);
/* Get a URL report */
$urlReport = $virusTotal->getURLReport('A-URL-OR-PERMALINK-IDENTIFIER');
outputResult('getURLReport', $urlReport);
/* Create a comment on a URL report */
$createUrlComment = $virusTotal->createComment('THE-URL-SCANNED', 'A-COMMENT', array('TAGS', 'GO', 'HERE'), VirusTotal::URL);
outputResult('createComment', $createUrlComment);
?>