<?php

/**
 * VirusTotal API PHP
 * API Documentation: https://www.virustotal.com/advanced.html#publicapi
 *
 * @author Thomas Stig Jacobsen
 * @since 20-09-2011
 * @date 22-09-2011
 * @copyright Thomas Stig Jacobsen
 * @version 1.0
 * @license BSD http://www.opensource.org/licenses/bsd-license.php
 */
class VirusTotal {
    const OBJECT = 'object';
    const JSON = 'json';

    const FILE = 'file';
    const URL = 'url';

    const API_URL = 'https://www.virustotal.com/api/';

    const VERSION = '0.1';

    /**
     * The API-key
     *
     * @var string
     */
	private $_apiKey;

    /**
     * The default return format
     *
     * @var VirusTotal::OBJECT or VirusTotal::JSON
     */
    private $_format;

    /**
     * The available return formats
     *
     * @var array
     */
    private $_formatsArray = array(VirusTotal::OBJECT, VirusTotal::JSON);

    /**
     * The available types
     *
     * @var array
     */
    private $_typesArray = array(VirusTotal::FILE, VirusTotal::URL);

    /**
     * Default constructor
     *
     * @param string $apiKey                            API-key from VirusTotal
     * @param const[optional] $defaultFormat            Default return format
     */
    public function __construct($apiKey, $defaultFormat = VirusTotal::OBJECT) {
        $this->setApiKey($apiKey);
        $this->setFormat($defaultFormat);
    }

    /**
     * Send and scan a file
     *
     * @param string $filePath                          Relative path to the file
     * @param const[optional] $format                   Return format for this function
     *
     * @return VirusTotal::OBJECT or VirusTotal::JSON
     */
    public function scanFile($filePath, $format = null) {
        if ( ! file_exists($filePath)) {
            return false;
        }
        $realPath = realpath($filePath);
        $pathInfo = pathinfo($realPath);
        $finfo = finfo_open(FILEINFO_MIME_TYPE);

        $postData = array('file' => '@' . $realPath . ';type=' . finfo_file($finfo, $filePath) . ';filename=' . $pathInfo['basename']);
        $response = $this->_makeCall('scan_file.json', $postData, $format);

        return $response;
    }

    /**
     * Retrieve a file scan report
     *
     * @param string $resource                          Hash of the file (MD5, SHA1 or SHA256)
     * @param const[optional] $format                   Return format for this function
     *
     * @return VirusTotal::OBJECT or VirusTotal::JSON
     */
    public function getScanReport($resource, $format = null) {
        $postData = array('resource' => $resource);
        $response = $this->_makeCall('get_file_report.json', $postData, $format);

        return $response;
    }

    /**
     * Retrieve a URL scan report
     *
     * @param string $resource                          URL of the site
     * @param const[optional] $format                   Return format for this function
     *
     * @return VirusTotal::OBJECT or VirusTotal::JSON
     */
    public function scanURL($url, $format = null) {
        $postData = array('url' => $url);
        $response = $this->_makeCall('scan_url.json', $postData, $format);

        return $response;
    }

    /**
     * Retrieve a URL scan report
     *
     * @param string $resource                          URL of the site or permalink identifier (md5-timestamp)
     * @param bool $scan                                Scan the URL if not found in database (will return the scan_id)
     * @param const[optional] $format                   Return format for this function
     *
     * @return VirusTotal::OBJECT or VirusTotal::JSON
     */
    public function getURLReport($resource, $scan = false, $format = null) {
        $postData = array('resource' => $resource, 'scan' => (int) $scan);
        $response = $this->_makeCall('get_url_report.json', $postData, $format);

        return $response;
    }

    /**
     * Make comments on files and URLs
     *
     * @param string $resource                          Hash of the file (MD5, SHA1 or SHA256) or URL
     * @param string $comment                           The comment to the file or URL
     * @param array[optional] $tags                     List of standard file or URL tags (see API documentation for updates)
     *                                                  The standard file tags are: goodware, malware, spamattachmentorlink, p2pdownload, impropagating, networkworm, drivebydownload.
     *                                                  The standard URL tags are: malicious, benign, malwaredownload, phishingsite, browserexploit, spamlink.
     * @param const[optional] $type                     Type of hash or URL: VirusTotal::FILE or VirusTotal::URL
     * @param const[optional] $format                   Return format for this function
     *
     * @return VirusTotal::OBJECT or VirusTotal::JSON
     */
    public function createComment($resource, $comment, array $tags = array(), $type = VirusTotal::FILE, $format = null) {
        $typeName = (in_array($type, $this->_typesArray)) ? $type : VirusTotal::FILE;

        $postData = array($typeName => $resource, 'comment' => $comment);
        if (count($tags) > 0) {
            $postData['tags'] = implode($tags, ';');
        }

        $response = $this->_makeCall('make_comment.json', $postData, $format);

        return $response;
    }

    /**
     * Setter for the API-key
     *
     * @param string $apiKey    API-key
     */
    public function setApiKey($apiKey) {
        $this->_apiKey = (string) $apiKey;
    }

    /**
     * Getter for the API-key
     *
     * @return string API-key
     */
    public function getApiKey() {
        return $this->_apiKey;
    }

    /**
     * Setter for the default return format
     *
     * @param const $format
     */
    public function setFormat($format) {
        if(in_array($format, $this->_formatsArray)) {
            $this->_format = $format;
        } else {
            $this->_format = VirusTotal::OBJECT;
        }
    }

    /**
     * Getter for the default return format
     *
     * @return const
     */
    public function getFormat() {
        return $this->_format;
    }

    /**
     * Makes the call to the API
     *
     * @param string $function                          API specific function name for in the URL
     * @param array $post                               The POST data to send to the API
     * @param const $format                             Return format for this function
     *
     * @return VirusTotal::OBJECT or VirusTotal::JSON
     */
    private function _makeCall($function, array $post = array(), $format) {
        $format = ( ! empty($format) && in_array($format, $this->_formatsArray)) ? $format : $this->getFormat();

        $postData = array('key' => $this->_apiKey);
        $postData = array_merge($post, $postData);

        $ch = curl_init(VirusTotal::API_URL . $function);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array('Expect:'));
        curl_setopt($ch, CURLOPT_FORBID_REUSE, 1);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 0);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $postData);

        $response = curl_exec($ch);
        curl_close($ch);

        if ($format == VirusTotal::OBJECT) {
            $response = json_decode($response);
        }

        return $response;
	}
}
?>