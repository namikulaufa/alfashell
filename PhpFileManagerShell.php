<?php
//{"lang":"","fm_root":"","timezone":"","date_format":"Y\/m\/d H:i","auth_pass":"d41d8cd98f00b204e9800998ecf8427e","error_reporting":1}
/*-------------------------------------------------
| PHP FILE MANAGER
+--------------------------------------------------
| phpFileManager 1.7.9
| By Fabricio Seger Kolling
| Copyright (c) 2004-2020 Fabrício Seger Kolling
| E-mail: dulldusk@gmail.com
| URL: http://phpfm.sf.net
| Last Changed: 2020-04-28
+--------------------------------------------------
| It is the AUTHOR'S REQUEST that you keep intact the above header information
| and notify it only if you conceive any BUGFIXES or IMPROVEMENTS to this program.
+--------------------------------------------------
| LICENSE
+--------------------------------------------------
| Licensed under the terms of any of the following licenses at your choice:
| - GNU General Public License Version 2 or later (the "GPL");
| - GNU Lesser General Public License Version 2.1 or later (the "LGPL");
| - Mozilla Public License Version 1.1 or later (the "MPL").
| You are not required to, but if you want to explicitly declare the license
| you have chosen to be bound to when using, reproducing, modifying and
| distributing this software, just include a text file titled "LICENSE" in your version
| of this software, indicating your license choice. In any case, your choice will not
| restrict any recipient of your version of this software to use, reproduce, modify
| and distribute this software under any of the above licenses.
+--------------------------------------------------
| CONFIGURATION AND INSTALATION NOTES
+--------------------------------------------------
| This program does not include any instalation or configuration
| notes because it simply does not require them.
| Just throw this file anywhere in your webserver and enjoy !!
+--------------------------------------------------*/
// +--------------------------------------------------
// | Config
// +--------------------------------------------------
$version = '1.7.9';
$charset = 'UTF-8';
$debug_mode = false;
$max_php_recursion = 200;
$resolve_ids = 0;
$quota_mb = 0;
$upload_ext_filter = array();
$download_ext_filter = array();
$cookie_cache_time = 60*60*24*30; // 30 Days
$fm_color = array();
$fm_color['Bg'] = "EEEEEE";
$fm_color['Text'] = "000000";
$fm_color['Link'] = "0A77F7";
$fm_color['Entry'] = "FFFFFF";
$fm_color['Over'] = "C0EBFD";
$fm_color['Mark'] = "A7D2E4";
// https://pt.wikipedia.org/wiki/Lista_de_portas_dos_protocolos_TCP_e_UDP
$services = array();
//$services['13:UDP'] = "DAYTIME";
$services['21'] = "FTP";
$services['22'] = "SSH";
$services['23'] = "TELNET";
$services['25'] = "SMTP";
//$services['53:UDP'] = "DNS";
//$services['67:UDP'] = "DHCP";
//$services['68:UDP'] = "BOOTP";
//$services['69:UDP'] = "TFTP";
$services['80'] = "HTTPD";
$services['110'] = "POP3";
//$services['123:UDP'] = "NTP";
//$services['137:UDP'] = "NETBIOS-NS";
//$services['138:UDP'] = "NETBIOS-DATA";
$services['139'] = "NETBIOS-SESSION";
$services['143'] = "IMAP";
$services['161'] = "SNMP";
$services['389'] = "LDAP";
$services['445'] = "SMB-AD";
//$services['445:UDP'] = "SMB-FS";
$services['465'] = "SMTPS-SSL";
$services['512'] = "RPC";
$services['514'] = "RSH";
//$services['514:UDP'] = "SYSLOG";
$services['515'] = "LPD-PRINTER";
//$services['520:UDP'] = "RIP-ROUTER";
$services['530'] = "RPC";
$services['540'] = "UUCP";
$services['544'] = "KSHELL";
$services['556'] = "REMOTE-FS";
$services['587'] = "SMTPS-TLS";
$services['593'] = "HTTP-RPC";
$services['631'] = "IPP";
$services['636'] = "LDAPS";
$services['993'] = "IMAPS";
$services['995'] = "POP3S";
$services['990'] = "FTPS";
$services['992'] = "TELNETS";
$services['1433'] = "MSSQL";
$services['1521'] = "ORACLE";
$services['3306'] = "MYSQL/MARIADB";
$services['3389'] = "RDESKTOP";
$services['5900'] = "VNC";
$services['7778'] = "KLOXO-ADMIN";
$services['8080'] = "HTTPD-ALT";
$services['8200'] = "GOTOMYPC";
$services['10000'] = "VIRTUALMIN-ADMIN";
$services['27017'] = "MONGODB";
$services['50000'] = "DB2";
// +--------------------------------------------------
// | Header and Globals
// +--------------------------------------------------
@ob_start(); // For ChromePhp Debug and JSONRPC to Work!
function getmicrotime(){
   list($usec, $sec) = explode(" ", microtime());
   return ((float)$usec + (float)$sec);
}
$script_init_time = getmicrotime();
function log_script_time(){
    global $script_init_time;
    fb_log(number_format((getmicrotime()-$script_init_time), 3, '.', '')."s");
}
$is_windows = (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN');
$max_php_recursion_counter = 0;
if(!isset($_SERVER['PATH_INFO']) && isset($_SERVER['ORIG_PATH_INFO'])) {
    $_SERVER['PATH_INFO'] = $_SERVER['ORIG_PATH_INFO'];
}
function fix_directory_separator($str){
    global $is_windows;
    if ($is_windows) $str = str_replace('/',DIRECTORY_SEPARATOR,$str);
    else $str = str_replace('\\',DIRECTORY_SEPARATOR,$str);
    return $str;
}
if(!isset($_SERVER['DOCUMENT_ROOT'])) {
    if (isset($_SERVER['SCRIPT_FILENAME'])) $path = $_SERVER['SCRIPT_FILENAME'];
    elseif (isset($_SERVER['PATH_TRANSLATED'])) $path = str_replace('\\\\', '\\', $_SERVER['PATH_TRANSLATED']);
    $_SERVER['DOCUMENT_ROOT'] = substr($path, 0, 0-strlen($_SERVER['PHP_SELF']));
}
$_SERVER['DOCUMENT_ROOT'] = fix_directory_separator($_SERVER['DOCUMENT_ROOT']);
if (@get_magic_quotes_gpc()) {
    function stripslashes_deep($value){
        return is_array($value)? array_map('stripslashes_deep', $value):$value;
    }
    $_POST = array_map('stripslashes_deep', $_POST);
    $_GET = array_map('stripslashes_deep', $_GET);
    $_COOKIE = array_map('stripslashes_deep', $_COOKIE);
}
// Register Globals (its an old script..)
$blockKeys = array('_SERVER','_SESSION','_GET','_POST','_COOKIE');
foreach ($_GET as $key => $val) if (array_search($key,$blockKeys) === false) $$key=$val;
foreach ($_POST as $key => $val) if (array_search($key,$blockKeys) === false) $$key=$val;
foreach ($_COOKIE as $key => $val) if (array_search($key,$blockKeys) === false && $key != 'fm_current_dir' && $key != 'ace_wrap') $$key=$val;
// PHP_VERSION_ID is available as of PHP 5.2.7, if our version is lower than that, then emulate it
if (!defined('PHP_VERSION_ID')) {
    $php_version = explode('.', PHP_VERSION);
    define('PHP_VERSION_ID', ($php_version[0] * 10000 + $php_version[1] * 100 + $php_version[2]));
    if (PHP_VERSION_ID < 50207) {
        define('PHP_MAJOR_VERSION',   $php_version[0]);
        define('PHP_MINOR_VERSION',   $php_version[1]);
        define('PHP_RELEASE_VERSION', $php_version[2]);
    }
}
// Server Vars
function curl_server_online_check(){
    if (function_exists('curl_init')){
        @$ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, "http://phpfm.sf.net");
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_HEADER, 0);
        @curl_exec($ch);
        $errnum = curl_errno($ch);
        @curl_close($ch);
    }
    return ($errnum == "0");
}
function socket_get_lan_ip($dest='64.0.0.0', $port=80) {
    $addr = '';
    if (function_exists('socket_create')){
        $socket = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
        socket_connect($socket, $dest, $port);
        socket_getsockname($socket, $addr, $port);
        socket_close($socket);
    }
    return $addr;
}
function get_client_ip() {
    $ipaddress = '';
    if ($_SERVER['HTTP_CLIENT_IP']) $ipaddress = $_SERVER['HTTP_CLIENT_IP'];
    else if($_SERVER['HTTP_X_FORWARDED_FOR']) $ipaddress = $_SERVER['HTTP_X_FORWARDED_FOR'];
    else if($_SERVER['HTTP_X_FORWARDED']) $ipaddress = $_SERVER['HTTP_X_FORWARDED'];
    else if($_SERVER['HTTP_FORWARDED_FOR']) $ipaddress = $_SERVER['HTTP_FORWARDED_FOR'];
    else if($_SERVER['HTTP_FORWARDED']) $ipaddress = $_SERVER['HTTP_FORWARDED'];
    else if($_SERVER['HTTP_X_REAL_IP']) $ipaddress = $_SERVER['HTTP_X_REAL_IP'];
    else if($_SERVER['REMOTE_ADDR']) $ipaddress = $_SERVER['REMOTE_ADDR'];
    // proxy transparente não esconde o IP local, colocando ele após o IP da rede, separado por vírgula
    if (strpos($ipaddress, ',') !== false) {
        $ips = explode(',', $ipaddress);
        $ipaddress = trim($ips[0]);
    }
    if ($ipaddress == '::1' || $ipaddress == '127.0.0.1') $ipaddress = 'localhost';
    return $ipaddress;
}
$ip = @get_client_ip();
$lan_ip = @socket_get_lan_ip();
function getServerURL() {
    $url = (lowercase($_SERVER['HTTPS']) == "on")?"https://":"http://";
    if (strlen($_SERVER['SERVER_NAME'])) $url .= $_SERVER['SERVER_NAME'];
    elseif (strlen($_SERVER['HTTP_HOST'])) $url .= $_SERVER['HTTP_HOST'];
    if ($_SERVER['SERVER_PORT'] != "80" && $_SERVER['SERVER_PORT'] != "443") $url .= ":".$_SERVER['SERVER_PORT'];
    return $url;
}
function getCompleteURL() {
    return getServerURL().$_SERVER['REQUEST_URI'];
}
$url = @getCompleteURL();
$url_info = parse_url($url);
$doc_root = rtrim($_SERVER['DOCUMENT_ROOT'],DIRECTORY_SEPARATOR); // ex: 'C:/htdocs'
$url_root = rtrim(@getServerURL(),'/'); // ex. 'http://www.site.com'
$fm_file = __FILE__;
$fm_url = $url_root.$_SERVER['PHP_SELF'];
$fm_path_info = pathinfo($fm_file);
$open_basedir_ini = trim(@ini_get("open_basedir"));
$open_basedirs = array();
if (strlen($open_basedir_ini)) {
    $dirs = array($open_basedir_ini);
    if ($is_windows) {
        if (strpos($open_basedir_ini,';') !== false) {
            $dirs = explode(';',$open_basedir_ini);
        }
        $dirs = array_map('ucfirst',$dirs);
    } else {
        if (strpos($open_basedir_ini,':') !== false) {
            $dirs = explode(':',$open_basedir_ini);
        }
    }
    foreach ($dirs as $dir) {
        $dir = rtrim($dir,DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR; // fm_root must have trailing slash
        if (is_dir($dir)) $open_basedirs[] = $dir;
    }
}
$sys_lang = strtolower(substr($_SERVER['HTTP_ACCEPT_LANGUAGE'], 0, 2));
if (!function_exists('mb_strtolower') || !function_exists('mb_strtoupper')) {
    die('PHP File Manager<br>Error: Please enable "mbstring" php module.<br>http://php.net/manual/en/book.mbstring.php');
}
// +--------------------------------------------------
// | Config Class
// +--------------------------------------------------
function object_to_array( $var ) {
    if( !is_object( $var ) && !is_array( $var ) ) {
        return $var;
    }
    if( is_object( $var ) ) {
        $var = get_object_vars( $var );
    }
    return array_map( 'object_to_array', $var );
}
function array_to_object( $var ) {
    if( !is_object( $var ) && !is_array( $var ) ) {
        return $var;
    }
    $obj = new stdClass();
    foreach ($var as $key => $value) {
        if (strlen($key)) $obj->{$key} = array_to_object( $value );
    }
    return $obj;
}
class config {
    var $data;
    function __construct(){
        $this->data = array(
            'lang'=>'',
            'fm_root'=>'',
            'timezone'=>'',
            'date_format'=>'Y/m/d H:i',
            'auth_pass'=>md5(''),
            'error_reporting'=>1
        );
    }
    function save(){
        global $fm_file;
        $config_string = "<?php".chr(13).chr(10)."//".json_encode($this->data).chr(13).chr(10);
        if (is_file($fm_file)){
            $lines = file($fm_file);
            $script_start_line = 1;
            if (strpos($lines[0],'<?php') === 0 && strpos($lines[1],'//{"') === 0) $script_start_line = 2;
            if ($fh = @fopen($fm_file, "w")){
                @fputs($fh,$config_string,strlen($config_string));
                for ($x=$script_start_line;$x<count($lines);$x++) @fputs($fh,$lines[$x],strlen($lines[$x]));
                @fclose($fh);
            }
        }
    }
    function load(){
        global $fm_file;
        $data = false;
        if (is_file($fm_file)){
            $fh = fopen($fm_file, 'r');
            $line1 = fgets($fh);
            $line2 = fgets($fh);
            $line3 = fgets($fh);
            fclose($fh);
            if (strpos($line1,'<?php') === 0 && strpos($line2,'//{"') === 0){
                $config_string = trim(substr($line2,2));
                if (strlen($config_string)) $data = object_to_array(json_decode($config_string));
            }
        }
        if (is_array($data) && count($data)) $this->data = $data;
        foreach ($this->data as $key => $val) $GLOBALS[$key] = $val;
    }
}
// +--------------------------------------------------
// | Config Load
// +--------------------------------------------------
$cfg = new config();
$cfg->load();
if (strlen($timezone)) @date_default_timezone_set($timezone);
//@setlocale(LC_CTYPE, 'C');
//@ini_set('default_charset', $charset);
@mb_internal_encoding($charset);
@ini_set('mbstring.substitute_character','none'); // That will strip invalid characters from UTF-8 strings
@ini_set("allow_url_fopen",1);
@error_reporting(0);
@ini_set("display_errors",0);
if ($error_reporting > 0){
    error_reporting(E_ERROR | E_PARSE | E_COMPILE_ERROR); @ini_set("display_errors",1);
}
function fb_log(){
    global $error_reporting;
    if ($error_reporting < 2) return;
    if (!class_exists('ChromePhp')) return;
    $arguments = func_get_args();
    if (func_num_args() > 1 && is_string($arguments[0])) {
        ChromePhp::log($arguments[0].': ',$arguments[1]);
    } else {
        ChromePhp::log($arguments[0]);
    }
}
if (!strlen($fm_current_root)) {
    if ($is_windows) {
        if (strpos($doc_root,":") !== false) $fm_current_root = ucfirst(substr($doc_root,0,strpos($doc_root,":")+1).DIRECTORY_SEPARATOR); // If doc_root has ":" take the drive letter
        $fm_current_root = ucfirst($doc_root.DIRECTORY_SEPARATOR);
    } else {
        $fm_current_root = "/"; // Linux default show root
    }
} else {
    if ($is_windows) $fm_current_root = ucfirst($fm_current_root);
}
if (strlen($fm_root)){
    $fm_current_root = $fm_root;
}
if (count($open_basedirs)){
    $fm_current_root_ok = false;
    foreach ($open_basedirs as $open_basedir) {
        if (strpos($fm_current_root,$open_basedir) !== false) {
            $fm_current_root_ok = true;
            break;
        }
    }
    if (!$fm_current_root_ok) {
        $fm_path = rtrim($fm_path_info['dirname'],DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR;
        foreach ($open_basedirs as $open_basedir) {
            if (strpos($fm_path,$open_basedir) !== false) {
                $fm_current_root = $open_basedir;
                $fm_current_root_ok = true;
                break;
            }
        }
    }
    if (!$fm_current_root_ok){
        $fm_current_root = $open_basedirs[0];
    }
}
if (!isset($fm_current_dir)){
    $fm_path = rtrim($fm_path_info['dirname'],DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR;
    if (strpos($fm_path,$fm_current_root) !== false) {
        $fm_current_dir = $fm_path;
    } else {
        $fm_current_dir = $fm_current_root;
    }
    if ($is_windows) $fm_current_dir = ucfirst($fm_current_dir);
    if (strlen($_COOKIE['fm_current_dir'])) {
        $fm_current_dir = $_COOKIE['fm_current_dir'];
    }
}
$fm_current_root = rtrim($fm_current_root,DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR;
$fm_current_dir = rtrim($fm_current_dir,DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR;
@chdir($fm_current_dir); // Note: So is_link(), is_file(), is_dir() and other functions work with relative paths too.
//fb_log('fm_root',$fm_root);
//fb_log('fm_current_root',$fm_current_root);
//fb_log('fm_current_dir',$fm_current_dir);
if (isset($set_resolve_ids)){
    $resolve_ids=intval($set_resolve_ids);
    setcookie("resolve_ids", $resolve_ids, time()+$cookie_cache_time, "/");
}
// +--------------------------------------------------
// | User/Group Functions
// +--------------------------------------------------
$passwd_array = false;
function get_user_name($uid) {
    global $is_windows, $passwd_array;
    if ($is_windows) return $uid;
    if ($passwd_array === false){
        @system_exec_cmd("cat /etc/passwd",$passwd_file);
        $passwd_array = explode(chr(10),$passwd_file);
    }
    foreach ($passwd_array as $line) {
        $mat = explode(":",$line);
        if ($mat[2] == $uid){
            return $mat[0];
        }
    }
    if (function_exists('posix_getpwuid')) {
        $info = posix_getpwuid($uid);
        return $info['name'];
    }
    return $uid;
}
$group_array = false;
function get_group_name($gid) {
    global $is_windows, $group_array;
    if ($is_windows) return $gid;
    if ($group_array === false){
        @system_exec_cmd("cat /etc/group",$group_file);
        $group_array = explode(chr(10),$group_file);
    }
    foreach ($group_array as $line) {
        $mat = explode(":",$line);
        if ($mat[2] == $gid){
            return $mat[0];
        }
    }
    if (function_exists('posix_getgrgid')) {
        $info = posix_getgrgid($gid);
        return $info['name'];
    }
    return $gid;
}
function get_user_groups($user_name) {
    global $is_windows, $group_array;
    if ($is_windows) return array();
    if ($group_array === false){
        @system_exec_cmd("cat /etc/group",$group_file);
        $group_array = explode(chr(10),$group_file);
    }
    $resul = array();
    $resul['ids'] = array();
    $resul['names'] = array();
    foreach ($group_array as $line) {
        $mat = explode(":",$line);
        $user_names = explode(",",$mat[3]);
        if (array_search($user_name,$user_names) !== false){
            $resul['ids'][] = $mat[2];
            $resul['names'][] = $mat[0];
        }
    }
    return $resul;
}
function is_rwx_phpfm($file,$what='r'){
    global $is_windows;
    // Note: You can only change the uid/euid of the current process when one of the two is currently set to 0 (root).
    // groupadd gteste
    // usermod -a -G gteste www-data
    // gpasswd -d www-data gteste
    if (!is_array($GLOBALS['script_info'])) {
        $GLOBALS['script_info'] = array();
        $GLOBALS['script_info']['sys_uname'] = function_exists('posix_uname') ? @posix_uname() : '';
        $GLOBALS['script_info']['sys_hostname'] = function_exists('gethostname') ? @gethostname() : '';
        if (!strlen($GLOBALS['script_info']['sys_hostname'])){
            $GLOBALS['script_info']['sys_hostname'] = @getenv('COMPUTERNAME');
        }
        $GLOBALS['script_info']['script_user_id'] = function_exists('posix_getuid') ? @posix_getuid() : '';
        $GLOBALS['script_info']['script_user_name'] = $GLOBALS['script_info']['script_user_id'];
        $GLOBALS['script_info']['script_user_home'] = '';
        $GLOBALS['script_info']['script_user_shell'] = '';
        $GLOBALS['script_info']['script_user_group_id'] = '';
        $GLOBALS['script_info']['script_user_group_name'] = '';
        $GLOBALS['script_info']['script_user_group_ids'] = array();
        $GLOBALS['script_info']['script_user_group_names'] = array();
        $GLOBALS['script_info']['script_group_id'] = function_exists('posix_getgid') ? @posix_getgid() : '';
        $GLOBALS['script_info']['script_group_name'] = $GLOBALS['script_info']['script_group_id'];
        $GLOBALS['script_info']['script_group_members'] = '';
        if ($GLOBALS['script_info']['script_user_id'] && function_exists('posix_getpwuid')) {
            $info = posix_getpwuid($GLOBALS['script_info']['script_user_id']);
            $GLOBALS['script_info']['script_user_home'] = $info['dir'];
            $GLOBALS['script_info']['script_user_shell'] = $info['shell'];
            $GLOBALS['script_info']['script_user_name'] = $info['name'];
            $GLOBALS['script_info']['script_user_group_id'] = $info['gid'];
            if (function_exists('posix_getgrgid')) {
                $info = posix_getgrgid($GLOBALS['script_info']['script_user_group_id']);
                $GLOBALS['script_info']['script_user_group_name'] = $info['name'];
            }
            $info = get_user_groups($GLOBALS['script_info']['script_user_name']);
            $GLOBALS['script_info']['script_user_group_ids'] = $info['ids'];
            $GLOBALS['script_info']['script_user_group_names'] = $info['names'];
            array_unshift($GLOBALS['script_info']['script_user_group_ids'], $GLOBALS['script_info']['script_user_group_id']);
            array_unshift($GLOBALS['script_info']['script_user_group_names'], $GLOBALS['script_info']['script_user_group_name']);

        }
        if (!strlen($GLOBALS['script_info']['script_user_name'])) {
            if (!system_exec_cmd('whoami',$GLOBALS['script_info']['script_user_name'])) {
                $GLOBALS['script_info']['script_user_name'] = '';
            }
        }
        if (!strlen($GLOBALS['script_info']['script_user_name']) && function_exists('get_current_user')) {
            $GLOBALS['script_info']['script_user_name'] = get_current_user();
        }
        if (!strlen($GLOBALS['script_info']['script_user_name'])){
            $GLOBALS['script_info']['script_user_name'] = @getenv('USERNAME') ? : @getenv('USER');
        }
        if ($is_windows && strpos($GLOBALS['script_info']['script_user_name'],'\\') !== false){
            $GLOBALS['script_info']['script_user_name'] = ucfirst(substr($GLOBALS['script_info']['script_user_name'],strpos($GLOBALS['script_info']['script_user_name'],'\\')+1));
        }
        if (function_exists('posix_getgrgid')) {
            $info = posix_getgrgid($GLOBALS['script_info']['script_group_id']);
            $GLOBALS['script_info']['script_group_name'] = $info['name'];
            $GLOBALS['script_info']['script_group_members'] = $info['members'];
        }
        fb_log($GLOBALS['script_info']);
    }
    $file_info = array();
    $file_info['name'] = $file;
    $file_stat = stat($file);
    $file_info['nlinks'] = $file_stat['nlink'];
    $file_info['perms'] = fileperms($file);
    $file_info['owner'] = fileowner($file);
    $file_info['group'] = filegroup($file);
    $file_info['is_owner_readable'] = ($file_info['perms'] & 0x0100);
    $file_info['is_group_readable'] = ($file_info['perms'] & 0x0020);
    $file_info['is_world_readable'] = ($file_info['perms'] & 0x0004);
    $file_info['is_readable'] = false;
    if ($file_info['is_world_readable']) {
        $file_info['is_readable'] = true;
    }
    if ($file_info['is_group_readable']) {
        foreach ($GLOBALS['script_info']['script_user_group_ids'] as $gid) {
            if ($file_info['group'] == $gid) {
                $file_info['is_readable'] = true;
                break;
            }
        }
    }
    if ($file_info['is_owner_readable'] && $file_info['owner'] == $GLOBALS['script_info']['script_user_id']) {
        $file_info['is_readable'] = true;
    }
    $file_info['is_owner_writable'] = ($file_info['perms'] & 0x0080);
    $file_info['is_group_writable'] = ($file_info['perms'] & 0x0010);
    $file_info['is_world_writable'] = ($file_info['perms'] & 0x0002);
    $file_info['is_writable'] = false;
    if ($file_info['is_world_writable']) {
        $file_info['is_writable'] = true;
    }
    if ($file_info['is_group_writable']) {
        foreach ($GLOBALS['script_info']['script_user_group_ids'] as $gid) {
            if ($file_info['group'] == $gid) {
                $file_info['is_writable'] = true;
                break;
            }
        }
    }
    if ($file_info['is_owner_writable'] && $file_info['owner'] == $GLOBALS['script_info']['script_user_id']) {
        $file_info['is_writable'] = true;
    }
    $file_info['is_owner_executable'] = ($file_info['perms'] & 0x0040);
    $file_info['is_group_executable'] = ($file_info['perms'] & 0x0400);
    $file_info['is_world_executable'] = ($file_info['perms'] & 0x0001);
    $file_info['is_executable'] = false;
    if ($file_info['is_world_executable']) {
        $file_info['is_executable'] = true;
    }
    if ($file_info['is_group_executable']) {
        foreach ($GLOBALS['script_info']['script_user_group_ids'] as $gid) {
            if ($file_info['group'] == $gid) {
                $file_info['is_executable'] = true;
                break;
            }
        }
    }
    if ($file_info['is_owner_executable'] && $file_info['owner'] == $GLOBALS['script_info']['script_user_id']) {
        $file_info['is_executable'] = true;
    }
    if ($what == 'r') return $file_info['is_readable'];
    if ($what == 'w') return $file_info['is_writable'];
    if ($what == 'x') return $file_info['is_executable'];
    return false;
}
function is_readable_phpfm($file){
    return is_rwx_phpfm($file,'r');
}
function is_writable_phpfm($file){
    return is_rwx_phpfm($file,'w');
}
function is_executable_phpfm($file){
    return is_rwx_phpfm($file,'x');
}
// +--------------------------------------------------
// | File Manager Actions
// +--------------------------------------------------
if ($action != '99') {
    header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
    header("Cache-Control: post-check=0, pre-check=0", false);
    header("Pragma: no-cache");
    header("Content-Type: text/html; charset=".$charset);
}
if ($auth_pass == md5('') || $loggedon==$auth_pass){
    switch ($frame){
        case 1: break; // Empty Frame
        case 2: frame2(); break;
        case 3: frame3(); break;
        default:
            switch($action){
                case 1: logout(); break;
                case 2: config_form(); break;
                case 3: download(); break;
                case 4: view_form(); break;
                case 5: server_info_form(); break;
                case 6: break;
                case 7: edit_file_form(); break;
                case 8: chmod_form(); break;
                case 9: shell_form(); break;
                case 10: upload_form(); break;
                case 11: system_exec_file(); break;
                case 12: portscan_form(); break;
                case 14: dir_list_update_total_size(); break;
                case 99: get_base64_file(); break;
                default:
                    if ($noscript) login_form();
                    else frameset();
            }
    }
} elseif (strlen($pass)) {
    login();
} else {
    login_form();
}
// +--------------------------------------------------
// | File System
// +--------------------------------------------------
function symlink_phpfm($target,$link){
    global $is_windows;
    $ok = false;
    if (!$is_windows){ // symlink() function not available on windows
        if (function_exists('symlink')) {
            $ok = symlink($target,$link);
        } else {
            $GLOBALS['dir_list_warn_message'] .= 'Error: php symlink() function is disabled.<br>';
        }
    }
    if (!$ok){
        $cmd = '';
        if ($is_windows){
            //$runas = 'runas /noprofile /user:Administrator ';
            if (is_dir($target)) $cmd = $runas.'mklink /D '.escapeshellarg($link).' '.escapeshellarg($target);
            else $cmd = $runas.'mklink '.escapeshellarg($link).' '.escapeshellarg($target);
        } else {
            $cmd = 'ln -s '.escapeshellarg($target).' '.escapeshellarg($link);
        }
        $output = '';
        $ok = system_exec_cmd($cmd,$output);
        if (!$ok) {
            $GLOBALS['dir_list_warn_message'] .= 'CMD: '.$cmd.'<br>';
            $GLOBALS['dir_list_warn_message'] .= $output.'<br>';
        }
        // link() function is available on windows (Vista, Server 2008 or greater)
        // if everything failed, try to create a hardlink to the file instead
        if (!$ok && !is_dir($target) && $is_windows) {
            if (function_exists('link')) {
                $ok = link($target,$link);
            } else {
                $GLOBALS['dir_list_warn_message'] .= 'Error: php link() function is disabled.<br>';
            }
        }
    }
    return $ok;
}
function link_phpfm($target,$link){
    global $is_windows;
    if (is_dir($target)) {
        // hardlinks to directories are not allowed, create symlink instead
        // https://askubuntu.com/questions/210741/why-are-hard-links-not-allowed-for-directories
        return symlink_phpfm($target,$link);
    }
    $ok = false;
    if (function_exists('link')) { // link() function is available on windows (Vista, Server 2008 or greater)
        $ok = link($target,$link);
    } else {
        $GLOBALS['dir_list_warn_message'] .= 'Error: php link() function is disabled.<br>';
    }
    if (!$ok){
        $cmd = '';
        if ($is_windows){
            //$runas = 'runas /noprofile /user:Administrator ';
            $cmd = $runas.'mklink /H '.escapeshellarg($link).' '.escapeshellarg($target);
        } else {
            $cmd = 'ln '.escapeshellarg($target).' '.escapeshellarg($link);
        }
        $output = '';
        $ok = system_exec_cmd($cmd,$output);
        if (!$ok) {
            $GLOBALS['dir_list_warn_message'] .= 'CMD: '.$cmd.'<br>';
            $GLOBALS['dir_list_warn_message'] .= $output.'<br>';
        }
    }
    return $ok;
}
function phpfm_get_total_size($path){
    $total_size = false;
    $dir_cookiename = 'dir_'.md5(fix_cookie_name($path));
    if (strlen($_COOKIE[$dir_cookiename])) {
        $total_size = $_COOKIE[$dir_cookiename];
        if ($total_size != 'error'){
            return intval($total_size);
        }
        return $total_size;
    }
    $total_size = system_get_total_size($path);
    if ($total_size !== false) {
        setcookie((string)$dir_cookiename, (string)$total_size, 0 , "/");
    }
    return $total_size;
}
function dir_list_update_total_size(){
    global $fm_current_dir, $dirname;
    $path = rtrim($fm_current_dir,DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR.$dirname;
    $total_size = system_get_total_size($path);
    if ($total_size === false) {
        $total_size = php_get_total_size($path);
    }
    if ($total_size === false) {
        $total_size = 'error';
    }
    $dir_cookiename = 'dir_'.md5(fix_cookie_name($fm_current_dir.$dirname));
    setcookie((string)$dir_cookiename, (string)$total_size, 0 , "/");
    echo $total_size;
    die();
}
// INFO: php filesize() returns ZERO for files over 4Gb
function phpfm_filesize($file){
    $filesize = intval(filesize($file));
    if ($filesize <= 0) $filesize = system_get_total_size($file);
    return $filesize;
}
function system_get_total_size($path){
    global $is_windows;
    $total_size = false;
    if ($is_windows){
        if (class_exists('COM')) {
            $fsobj = new COM('Scripting.FileSystemObject');
            if (is_object($fsobj)) {
                try {
                    if (is_dir($path)) $ref = $fsobj->GetFolder($path);
                    else $ref = $fsobj->GetFile($path);
                    if (is_object($ref)) {
                        $total_size = floatval($ref->size);
                        $fsobj = null;
                        unset($fsobj);
                    }
                } catch (Exception $e) {
                }
            }
        }
        if ($total_size === false) {
            if (is_file($path)){
                $output = '';
                if (system_exec_cmd('for %I in ('.$path.') do @echo %~zI',$output)){
                    $total_size = floatval($output);
                }
            }
        }
    } else {
        $output = '';
        if (system_exec_cmd('du -sb '.$path,$output)){
            $total_size = floatval(substr($output,0,strpos($output,"\t")));
        }
    }
    if ($total_size === false) fb_log('system_get_total_size("'.$path.'") = FALSE');
    else fb_log('system_get_total_size("'.$path.'") = '.format_size($total_size));
    return $total_size;
}
function php_get_total_size($path) {
    global $debug_mode,$max_php_recursion_counter;
    $max_php_recursion_counter = 0;
    $total_size = php_get_total_size_execute($path);
    if ($total_size === false) fb_log('php_get_total_size("'.$path.'") = false'.' (recursion: '.$max_php_recursion_counter.')');
    else fb_log('php_get_total_size("'.$path.'") = '.format_size($total_size).' (recursion: '.$max_php_recursion_counter.')');
    return $total_size;
}
function php_get_total_size_execute($path) {
    global $debug_mode,$max_php_recursion,$max_php_recursion_counter;
    fb_log('php_get_total_size_execute',$path);
    if ($debug_mode) return 0;
    $total_size = 0;
    if (is_dir($path)) {
        $entry_list = scandir(fs_encode($path));
        foreach ($entry_list as $entry) {
            if ($entry == "." || $entry == "..") continue;
            if (is_dir($path.DIRECTORY_SEPARATOR.$entry)) {
                if ($max_php_recursion_counter >= $max_php_recursion) {
                    return false;
                }
                $max_php_recursion_counter++;
                $size = php_get_total_size_execute($path.DIRECTORY_SEPARATOR.$entry);
                if ($size === false) {
                    return false;
                }
                $total_size += $size;
            } else {
                $total_size += phpfm_filesize($path.DIRECTORY_SEPARATOR.$entry);
            }
        }
    } else {
        $total_size = phpfm_filesize($path);
    }
    return $total_size;
}
function php_shred($filepath) {
    // Based on https://github.com/DanielRuf/secure-shred (MIT license)
    // https://www.aldeid.com/wiki/Secure-delete-files
    // TODO: test write each pass, and rename the file before delete.
    try {
        // clear stat cache to avoid falsely reported file status
        // use $filepath parameter to possibly improve performance
        clearstatcache(true, $filepath);
        if (is_file($filepath) && is_readable($filepath) && is_writable($filepath)) {
            $read = new \SplFileObject($filepath, 'r');
            $write = new \SplFileObject($filepath, 'r+');
            while (!$read->eof()) {
                $line_pos = $read->ftell();
                $line_content = $read->fgets();
                $line_length = strlen($line_content);
                if ($line_length === 0) continue;
                for ($n=0;$n<3;$n++) { // does 3 overwrites per line
                    $write->fseek($line_pos);
                    $write->fwrite(random_bytes($line_length));
                    $write->fflush();
                }
            }
            $write->ftruncate(0);
            $read = $write = null;
            return unlink($filepath);
        }
    } catch(\Exception $e) {
        fb_log($e->getMessage().' ('.$e->getCode().')');
    }
    return false;
}
function total_delete($path,$followlinks=false,$checkhardlinks=true) {
    global $debug_mode;
    fb_log('total_delete',$path);
    if ($debug_mode) return;
    // TODO: $checkhardlinks will not allow to delete anything that has other links on the system, using stat() to avoid creating brokenlinks. Add a warning and complete action;.
    if (file_exists($path)) {
        @chmod($path,0755);
        if (is_dir($path)) {
            $entry_list = scandir(fs_encode($path));
            foreach ($entry_list as $entry) {
                if ($entry == "." || $entry == "..") continue;
                if ($followlinks == false && is_link(rtrim($path,DIRECTORY_SEPARATOR))) continue;
                total_delete($path.DIRECTORY_SEPARATOR.$entry,$followlinks,$checkhardlinks);
            }
            if (is_link($path)) @unlink($path);
            else @rmdir($path);
        } else {
            @unlink($path);
        }
    } elseif (is_link($path)) {
        @unlink($path); // Broken links must be removed
    }
}
function total_copy($orig,$dest,$copylinks=true,$followlinks=false) {
    global $debug_mode;
    fb_log('total_copy',$orig.' => '.$dest);
    if ($debug_mode) return;
    $ok = true;
    if (file_exists($orig) || is_link($orig)) {
        if ($copylinks == true && is_link($orig)){
            $ok = link_phpfm(readlink($orig), $dest);
            if (!$ok) $ok = link_phpfm($orig, $dest); // Allow copy of broken links, but rather copy the link to the target, as the link was.
        } elseif (is_dir($orig)) {
            $ok = mkdir(fs_encode($dest),0755);
            if ($ok) {
                $entry_list = scandir(fs_encode($orig));
                foreach ($entry_list as $entry) {
                    if ($entry == "." || $entry == "..") continue;
                    if ($followlinks == false && is_link(rtrim($orig,DIRECTORY_SEPARATOR))){
                        $ok = link_phpfm(readlink($orig.DIRECTORY_SEPARATOR.$entry), $dest.DIRECTORY_SEPARATOR.$entry);
                    } else {
                        $ok = total_copy($orig.DIRECTORY_SEPARATOR.$entry, $dest.DIRECTORY_SEPARATOR.$entry, $copylinks, $followlinks);
                    }
                    if (!$ok) break;
                }
            }
        } else {
            $ok = copy((string)$orig,(string)$dest);
        }
    }
    return $ok;
}
function total_move($orig,$dest) {
    global $debug_mode;
    fb_log('total_move',$orig.' => '.$dest);
    if ($debug_mode) return;
    // Just why doesn't it has a MOVE alias?!
    return rename((string)$orig,(string)$dest);
}
function download(){
    global $fm_current_dir,$filename,$debug_mode;
    $file = $fm_current_dir.$filename;
    fb_log('download',$file);
    if ($debug_mode) return;
    if(file_exists($file)){
        $is_denied = false;
        foreach($download_ext_filter as $key=>$ext){
            if (eregi($ext,$filename)){
                $is_denied = true;
                break;
            }
        }
        if (!$is_denied){
            $size = phpfm_filesize($file);
            header("Content-Type: application/save");
            header("Content-Length: $size");
            header("Content-Disposition: attachment; filename=\"".$filename."\"");
            header("Content-Transfer-Encoding: binary");
            if ($fh = fopen("$file", "rb")){
                ob_get_flush(); // Flush the output buffer and turn off output buffering, to allow direct download of big files
                fpassthru($fh);
                fclose($fh);
            } else alert(et('ReadDenied').": ".$file);
        } else alert(et('ReadDenied').": ".$file);
    } else alert(et('FileNotFound').": ".$file);
}
// Returns the full path of the current PHP executable
function linux_get_proc_name(){
    $output = '';
    $ok = system_exec_cmd("readlink -f /proc/".posix_getpid()."/exe",$output);
    if (!$ok) return false;
    return $output;
}
function system_exec_file(){
    global $fm_current_dir,$filename,$debug_mode,$is_windows;
    fb_log('system_exec_file',$filename);
    if ($debug_mode) return;
    header("Content-type: text/plain");
    $file = $fm_current_dir.$filename;
    if(file_exists($file)){
        if (!is_executable($file)) @chmod($file,0755);
        if (is_executable($file)) {
            $fm_current_dir = get_absolute_path($fm_current_dir);
            $cmd_line = '';
            if ($is_windows) {
                $cmd_line .= "cd /D ".$fm_current_dir." && ";
            } else {
                $cmd_line .= "cd ".$fm_current_dir." && ";
            }
            // TODO: verificar e usar interpretador correto
            // php -f /script.php
            // bash /script.sh
            // sh /script.sh
            // python /script.py
            // perl /script.pl
            $cmd_line .= $file;
            echo "# ".$cmd_line."\n";
            system_exec_cmd($cmd_line, $output);
            echo $output;
        } else echo('Error: '.$file.' is not executable...');
    } else echo(et('FileNotFound').": ".$file);
}
function save_upload($temp_file,$filename,$dir_dest) {
    global $upload_ext_filter,$debug_mode,$is_windows;
    fb_log('save_upload',$temp_file.' => '.$dir_dest.$filename);
    if ($debug_mode) return;
    $filename = remove_special_chars($filename);
    $file = $dir_dest.$filename;
    $filesize = phpfm_filesize($temp_file);
    $is_denied = false;
    foreach($upload_ext_filter as $key=>$ext){
        if (eregi($ext,$filename)){
            $is_denied = true;
            break;
        }
    }
    if (!$is_denied){
        if (!check_limit($filesize)){
            if (file_exists($file)){
                if (unlink($file)){
                    if (copy($temp_file,$file)){
                        // https://stackoverflow.com/questions/23851821/setting-file-permissions-in-windows-with-php
                        if ($is_windows) system_exec_cmd('icacls "'.$file.'" /q /c /reset');
                        else @chmod($file,0644);
                        $out = 6;
                    } else $out = 2;
                } else $out = 5;
            } else {
                if (copy($temp_file,$file)){
                    if ($is_windows) system_exec_cmd('icacls "'.$file.'" /q /c /reset');
                    else @chmod($file,0644);
                    $out = 1;
                } else $out = 2;
            }
        } else $out = 3;
    } else $out = 4;
    return $out;
}
// Note: readlink() may return a relative path, with or without ./, and that is not good for is_file() is_dir() and broken link evaluation, because we can´t always chdir() to the link basepath.
function readlink_absolute_path($path){
    global $is_windows;
    if (!is_link($path)) return $path;
    $target = readlink($path);
    if (strpos($target,'.'.DIRECTORY_SEPARATOR) === 0){
        $target = substr($target,2); // remove ./
    }
    if (($is_windows && substr($target,2,1) != ':') || (!$is_windows && substr($target,0,1) != DIRECTORY_SEPARATOR)){ // check if does not start with C: or / = relative path
        $target = substr($path,0,strrpos($path,DIRECTORY_SEPARATOR)+1).$target; // complete the target using origin path
    }
    return $target;
}
// +--------------------------------------------------
// | Data Formating
// +--------------------------------------------------
function fix_cookie_name($str){
    $str = remove_acentos(trim($str));
    $str = str_replace('\\', '_', $str);
    $str = str_replace('/', '_', $str);
    $str = str_replace(':', '_', $str);
    $str = str_replace('*', '_', $str);
    $str = str_replace('?', '_', $str);
    $str = str_replace('"', '_', $str);
    $str = str_replace('<', '_', $str);
    $str = str_replace('>', '_', $str);
    $str = str_replace('|', '_', $str);
    $str = str_replace(' ', '_', $str);
    $str = str_strip($str,"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_-0123456789");
    $str = replace_double('_', $str);
    $str = trim($str,'_');
    return $str;
}
// http://www.ietf.org/rfc/rfc1738.txt
// The characters ";", "/", "?", ":", "@", "=" and "&" are the characters which may be reserved for special meaning within a scheme. No other characters may be reserved within a scheme.
// Thus, only alphanumerics, the special characters "$-_.+!*'(),", and reserved characters used for their reserved purposes may be used unencoded within a URL.
function fix_url($str) {
    // Remove acentos
    $str = remove_acentos($str);
    // Substitui caracteres reservados
    $str = str_replace(';', '-', $str);
    $str = str_replace('/', '-', $str);
    $str = str_replace('?', '-', $str);
    $str = str_replace(':', '-', $str);
    $str = str_replace('@', '-', $str);
    $str = str_replace('=', '-', $str);
    $str = str_replace('&', '-', $str);
    // Caracteres adicionais
    $str = str_replace('(', '-', $str);
    $str = str_replace(')', '-', $str);
    $str = str_replace('.', '-', $str);
    $str = str_replace('_', '-', $str);
    $str = str_replace(' ', '-', $str);
    // Apenas caracteres válidos
    $str = str_strip($str, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890.-");
    $str = replace_double('-', $str);
    $str = trim($str,'-');
    return $str;
}
function fix_filename($str,$allowSpaces=false){ // no filesystem não podemos ter acentos
    $str = remove_acentos(trim($str));
    // Substitui caracteres reservados
    $str = str_replace('\\', '_', $str);
    $str = str_replace('/', '_', $str);
    $str = str_replace(':', '_', $str);
    $str = str_replace('*', '_', $str);
    $str = str_replace('?', '_', $str);
    $str = str_replace('"', '_', $str);
    $str = str_replace('<', '_', $str);
    $str = str_replace('>', '_', $str);
    $str = str_replace('|', '_', $str);
    if ($allowSpaces){
        // Apenas caracteres válidos
        $str = str_strip($str,"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_-0123456789.()[]& ");
        $str = replace_double(' ', $str);
        $str = trim($str);
    } else {
        $str = str_replace(' ', '_', $str);
        // Apenas caracteres válidos
        $str = str_strip($str,"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_-0123456789.()[]&");
    }
    $str = replace_double('_', $str);
    $str = trim($str,'_');
    return $str;
}
function fix_filename_download($str){ // no download podemos ter acentos
    $str = trim($str);
    // Substitui caracteres reservados
    $str = str_replace('\\', ' ', $str);
    $str = str_replace('/', ' ', $str);
    $str = str_replace(':', ' ', $str);
    $str = str_replace('*', ' ', $str);
    $str = str_replace('?', ' ', $str);
    $str = str_replace('"', ' ', $str);
    $str = str_replace('<', ' ', $str);
    $str = str_replace('>', ' ', $str);
    $str = str_replace('|', ' ', $str);
    // Apenas caracteres válidos
    $str = str_strip($str,"ÁÀÃÂÉÊÈËÍÓÔÕÒÚÜÇÑáàãâéêèëíóõôòúüçñABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_-0123456789.()[] ");
    $str = replace_double(' ', $str);
    $str = trim($str);
    return $str;
}
function add_http($str){
    if (mb_strlen($str) > 0 && mb_strpos($str, 'http://') === false && mb_strpos($str, 'https://') === false) return 'http://'.$str;
    else return $str;
}
function remove_sinais($str){
    $sinais = "./\\-,:;'`~?!\"<>{}[]@#\$%^&*()_+=|";
    $str = str_replace(str_split($sinais),"",$str);
    return replace_double(" ",$str);
}
function remove_acentos($string) {
    if ( !preg_match('/[\x80-\xff]/', $string) ) return $string;
    $chars = array(
    // Decompositions for Latin-1 Supplement
    chr(195).chr(128) => 'A', chr(195).chr(129) => 'A',
    chr(195).chr(130) => 'A', chr(195).chr(131) => 'A',
    chr(195).chr(132) => 'A', chr(195).chr(133) => 'A',
    chr(195).chr(135) => 'C', chr(195).chr(136) => 'E',
    chr(195).chr(137) => 'E', chr(195).chr(138) => 'E',
    chr(195).chr(139) => 'E', chr(195).chr(140) => 'I',
    chr(195).chr(141) => 'I', chr(195).chr(142) => 'I',
    chr(195).chr(143) => 'I', chr(195).chr(145) => 'N',
    chr(195).chr(146) => 'O', chr(195).chr(147) => 'O',
    chr(195).chr(148) => 'O', chr(195).chr(149) => 'O',
    chr(195).chr(150) => 'O', chr(195).chr(153) => 'U',
    chr(195).chr(154) => 'U', chr(195).chr(155) => 'U',
    chr(195).chr(156) => 'U', chr(195).chr(157) => 'Y',
    chr(195).chr(159) => 's', chr(195).chr(160) => 'a',
    chr(195).chr(161) => 'a', chr(195).chr(162) => 'a',
    chr(195).chr(163) => 'a', chr(195).chr(164) => 'a',
    chr(195).chr(165) => 'a', chr(195).chr(167) => 'c',
    chr(195).chr(168) => 'e', chr(195).chr(169) => 'e',
    chr(195).chr(170) => 'e', chr(195).chr(171) => 'e',
    chr(195).chr(172) => 'i', chr(195).chr(173) => 'i',
    chr(195).chr(174) => 'i', chr(195).chr(175) => 'i',
    chr(195).chr(177) => 'n', chr(195).chr(178) => 'o',
    chr(195).chr(179) => 'o', chr(195).chr(180) => 'o',
    chr(195).chr(181) => 'o', chr(195).chr(182) => 'o',
    chr(195).chr(182) => 'o', chr(195).chr(185) => 'u',
    chr(195).chr(186) => 'u', chr(195).chr(187) => 'u',
    chr(195).chr(188) => 'u', chr(195).chr(189) => 'y',
    chr(195).chr(191) => 'y',
    // Decompositions for Latin Extended-A
    chr(196).chr(128) => 'A', chr(196).chr(129) => 'a',
    chr(196).chr(130) => 'A', chr(196).chr(131) => 'a',
    chr(196).chr(132) => 'A', chr(196).chr(133) => 'a',
    chr(196).chr(134) => 'C', chr(196).chr(135) => 'c',
    chr(196).chr(136) => 'C', chr(196).chr(137) => 'c',
    chr(196).chr(138) => 'C', chr(196).chr(139) => 'c',
    chr(196).chr(140) => 'C', chr(196).chr(141) => 'c',
    chr(196).chr(142) => 'D', chr(196).chr(143) => 'd',
    chr(196).chr(144) => 'D', chr(196).chr(145) => 'd',
    chr(196).chr(146) => 'E', chr(196).chr(147) => 'e',
    chr(196).chr(148) => 'E', chr(196).chr(149) => 'e',
    chr(196).chr(150) => 'E', chr(196).chr(151) => 'e',
    chr(196).chr(152) => 'E', chr(196).chr(153) => 'e',
    chr(196).chr(154) => 'E', chr(196).chr(155) => 'e',
    chr(196).chr(156) => 'G', chr(196).chr(157) => 'g',
    chr(196).chr(158) => 'G', chr(196).chr(159) => 'g',
    chr(196).chr(160) => 'G', chr(196).chr(161) => 'g',
    chr(196).chr(162) => 'G', chr(196).chr(163) => 'g',
    chr(196).chr(164) => 'H', chr(196).chr(165) => 'h',
    chr(196).chr(166) => 'H', chr(196).chr(167) => 'h',
    chr(196).chr(168) => 'I', chr(196).chr(169) => 'i',
    chr(196).chr(170) => 'I', chr(196).chr(171) => 'i',
    chr(196).chr(172) => 'I', chr(196).chr(173) => 'i',
    chr(196).chr(174) => 'I', chr(196).chr(175) => 'i',
    chr(196).chr(176) => 'I', chr(196).chr(177) => 'i',
    chr(196).chr(178) => 'IJ',chr(196).chr(179) => 'ij',
    chr(196).chr(180) => 'J', chr(196).chr(181) => 'j',
    chr(196).chr(182) => 'K', chr(196).chr(183) => 'k',
    chr(196).chr(184) => 'k', chr(196).chr(185) => 'L',
    chr(196).chr(186) => 'l', chr(196).chr(187) => 'L',
    chr(196).chr(188) => 'l', chr(196).chr(189) => 'L',
    chr(196).chr(190) => 'l', chr(196).chr(191) => 'L',
    chr(197).chr(128) => 'l', chr(197).chr(129) => 'L',
    chr(197).chr(130) => 'l', chr(197).chr(131) => 'N',
    chr(197).chr(132) => 'n', chr(197).chr(133) => 'N',
    chr(197).chr(134) => 'n', chr(197).chr(135) => 'N',
    chr(197).chr(136) => 'n', chr(197).chr(137) => 'N',
    chr(197).chr(138) => 'n', chr(197).chr(139) => 'N',
    chr(197).chr(140) => 'O', chr(197).chr(141) => 'o',
    chr(197).chr(142) => 'O', chr(197).chr(143) => 'o',
    chr(197).chr(144) => 'O', chr(197).chr(145) => 'o',
    chr(197).chr(146) => 'OE',chr(197).chr(147) => 'oe',
    chr(197).chr(148) => 'R',chr(197).chr(149) => 'r',
    chr(197).chr(150) => 'R',chr(197).chr(151) => 'r',
    chr(197).chr(152) => 'R',chr(197).chr(153) => 'r',
    chr(197).chr(154) => 'S',chr(197).chr(155) => 's',
    chr(197).chr(156) => 'S',chr(197).chr(157) => 's',
    chr(197).chr(158) => 'S',chr(197).chr(159) => 's',
    chr(197).chr(160) => 'S', chr(197).chr(161) => 's',
    chr(197).chr(162) => 'T', chr(197).chr(163) => 't',
    chr(197).chr(164) => 'T', chr(197).chr(165) => 't',
    chr(197).chr(166) => 'T', chr(197).chr(167) => 't',
    chr(197).chr(168) => 'U', chr(197).chr(169) => 'u',
    chr(197).chr(170) => 'U', chr(197).chr(171) => 'u',
    chr(197).chr(172) => 'U', chr(197).chr(173) => 'u',
    chr(197).chr(174) => 'U', chr(197).chr(175) => 'u',
    chr(197).chr(176) => 'U', chr(197).chr(177) => 'u',
    chr(197).chr(178) => 'U', chr(197).chr(179) => 'u',
    chr(197).chr(180) => 'W', chr(197).chr(181) => 'w',
    chr(197).chr(182) => 'Y', chr(197).chr(183) => 'y',
    chr(197).chr(184) => 'Y', chr(197).chr(185) => 'Z',
    chr(197).chr(186) => 'z', chr(197).chr(187) => 'Z',
    chr(197).chr(188) => 'z', chr(197).chr(189) => 'Z',
    chr(197).chr(190) => 'z', chr(197).chr(191) => 's'
    );
    $string = strtr($string, $chars);
    return $string;
}
function retifica_aspas($str){
    //return $str;
    $quotes = array(
        "\xC2\xAB"     => '"', // « (U+00AB) in UTF-8
        "\xC2\xBB"     => '"', // » (U+00BB) in UTF-8
        "\xE2\x80\x98" => "'", // ‘ (U+2018) in UTF-8
        "\xE2\x80\x99" => "'", // ’ (U+2019) in UTF-8
        "\xE2\x80\x9A" => "'", // ‚ (U+201A) in UTF-8
        "\xE2\x80\x9B" => "'", // ‛ (U+201B) in UTF-8
        "\xE2\x80\x9C" => '"', // “ (U+201C) in UTF-8
        "\xE2\x80\x9D" => '"', // ” (U+201D) in UTF-8
        "\xE2\x80\x9E" => '"', // „ (U+201E) in UTF-8
        "\xE2\x80\x9F" => '"', // ‟ (U+201F) in UTF-8
        "\xE2\x80\xB9" => "'", // ‹ (U+2039) in UTF-8
        "\xE2\x80\xBA" => "'", // › (U+203A) in UTF-8
    );
    return strtr($str, $quotes);
    // replace Microsoft Word version of single  and double quotations marks (“ ” ‘ ’) with  regular quotes (' and ")
    //return iconv('UTF-8', 'ASCII//TRANSLIT', $str);
}
function html_encode($str){
    global $charset;
    $str = preg_replace(array('/&/', '/</', '/>/', '/"/'), array('&amp;', '&lt;', '&gt;', '&quot;'), $str);  // Bypass PHP to allow any charset!!
    if (version_compare(PHP_VERSION, '5.2.3', '>=')) {
        $str = htmlentities($str, ENT_QUOTES, $charset, false);
    } else {
        $str = htmlentities($str, ENT_QUOTES, $charset);
    }
    return $str;
}
function rep($x,$y){
    if ($x) {
        $aux = "";
        for ($a=1;$a<=$x;$a++) $aux .= $y;
        return $aux;
    } else return "";
}
function str_zero($arg1,$arg2){
    if (strstr($arg1,"-") == false){
        $aux = intval($arg2) - strlen($arg1);
        if ($aux) return rep($aux,"0").$arg1;
        else return $arg1;
    } else {
        return "[$arg1]";
    }
}
function replace_double($sub,$str){
    $out=str_replace($sub.$sub,$sub,$str);
    while ( strlen($out) != strlen($str) ){
        $str=$out;
        $out=str_replace($sub.$sub,$sub,$str);
    }
    return $out;
}
function remove_special_chars($str){
    $str = trim($str);
    $str = strtr($str,"¥µÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖØÙÚÛÜÝßàáâãäåæçèéêëìíîïðñòóôõöøùúûüýÿ!@#%&*()[]{}+=?",
                      "YuAAAAAAACEEEEIIIIDNOOOOOOUUUUYsaaaaaaaceeeeiiiionoooooouuuuyy_______________");
    $str = str_replace("..","",str_replace("/","",str_replace("\\","",str_replace("\$","",$str))));
    return $str;
}
function array_csort() {
    $args = func_get_args();
    $marray = array_shift($args);
    $msortline = "return(array_multisort(";
    foreach ($args as $arg) {
        $i++;
        if (is_string($arg)) {
            foreach ($marray as $row) {
                $sortarr[$i][] = $row[$arg];
            }
        } else {
            $sortarr[$i] = $arg;
        }
        $msortline .= "\$sortarr[".$i."],";
    }
    $msortline .= "\$marray));";
    eval($msortline);
    return $marray;
}
function show_perms($P) {
    $sP = "<b>";
    if($P & 0x1000) $sP .= 'p';            // FIFO pipe
    elseif($P & 0x2000) $sP .= 'c';        // Character special
    elseif($P & 0x4000) $sP .= 'd';        // Directory
    elseif($P & 0x6000) $sP .= 'b';        // Block special
    elseif($P & 0x8000) $sP .= '&minus;';  // Regular
    elseif($P & 0xA000) $sP .= 'l';        // Symbolic Link
    elseif($P & 0xC000) $sP .= 's';        // Socket
    else $sP .= 'u';                       // UNKNOWN
    $sP .= "</b>";
    // owner - group - others
    $sP .= (($P & 0x0100) ? 'r' : '&minus;') . (($P & 0x0080) ? 'w' : '&minus;') . (($P & 0x0040) ? (($P & 0x0800) ? 's' : 'x' ) : (($P & 0x0800) ? 'S' : '&minus;'));
    $sP .= (($P & 0x0020) ? 'r' : '&minus;') . (($P & 0x0010) ? 'w' : '&minus;') . (($P & 0x0008) ? (($P & 0x0400) ? 's' : 'x' ) : (($P & 0x0400) ? 'S' : '&minus;'));
    $sP .= (($P & 0x0004) ? 'r' : '&minus;') . (($P & 0x0002) ? 'w' : '&minus;') . (($P & 0x0001) ? (($P & 0x0200) ? 't' : 'x' ) : (($P & 0x0200) ? 'T' : '&minus;'));
    return $sP;
}
function format_size($arg) {
    if ($arg>0){
        $j = 0;
        $ext = array(" bytes"," Kb"," Mb"," Gb"," Tb");
        while ($arg >= pow(1024,$j)) ++$j;
        return round($arg / pow(1024,$j-1) * 100) / 100 . $ext[$j-1];
    } else return "0 bytes";
}
function check_limit($new_filesize=0) {
    global $fm_current_root;
    global $quota_mb;
    if($quota_mb){
        $total = intval(phpfm_get_total_size($fm_current_root));
        if (floor(($total+$new_filesize)/(1024*1024)) > $quota_mb) return true;
    }
    return false;
}
function uppercase($str){
    global $charset;
    return mb_strtoupper($str, $charset);
}
function lowercase($str){
    global $charset;
    return mb_strtolower($str, $charset);
}
function word_count($theString) {
    $theString = html_decode(strip_tags($theString));
    $char_count = mb_strlen($theString);
    $fullStr = $theString." ";
    $initial_whitespace_rExp = "^[[:alnum:]]$";

    $left_trimmedStr = ereg_replace($initial_whitespace_rExp,"",$fullStr);
    $non_alphanumerics_rExp = "^[[:alnum:]]$";
    $cleanedStr = ereg_replace($non_alphanumerics_rExp," ",$left_trimmedStr);
    $splitString = explode(" ",$cleanedStr);

    $word_count = count($splitString)-1;
    if(mb_strlen($fullStr)<2)$word_count=0;

    return $word_count;
}
function str_strip($str,$valid_chars){
    $out = "";
    for ($i=0;$i<mb_strlen($str);$i++){
        $mb_char = mb_substr($str,$i,1);
        if (mb_strpos($valid_chars,$mb_char) !== false){
            $out .= $mb_char;
        }
    }
    return $out;
}
function mb_str_ireplace($co, $naCo, $wCzym) {
    $wCzymM = mb_strtolower($wCzym);
    $coM    = mb_strtolower($co);
    $offset = 0;
    while(!is_bool($poz = mb_strpos($wCzymM, $coM, $offset))) {
        $offset = $poz + mb_strlen($naCo);
        $wCzym = mb_substr($wCzym, 0, $poz). $naCo .mb_substr($wCzym, $poz+mb_strlen($co));
        $wCzymM = mb_strtolower($wCzym);
    }
    return $wCzym;
}
// +--------------------------------------------------
// | Interface
// +--------------------------------------------------
// Fix for the demo at https://phpfm-demo.000webhostapp.com
function demo_fix(){
    global $url_root;
    if (strpos($url_root,'phpfm-demo.000webhostapp.com') !== false) {
        echo "
        <script language=\"Javascript\" type=\"text/javascript\">
            if (window.jQuery){
                setTimeout(function(){
                    $('div:has(a:has(img[alt=\"www.000webhost.com\"]))').remove();
                },1000);
            }
        </script>";
    }
}
function html_header($header=""){
    global $charset,$fm_color,$fm_path_info,$cookie_cache_time;
    echo "
    <!DOCTYPE HTML PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\" \"//www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">
    <html xmlns=\"//www.w3.org/1999/xhtml\">
    <head>
    <meta http-equiv=\"content-type\" content=\"text/html; charset=".$charset."\" />
    <link rel=\"shortcut icon\" href=\"".$fm_path_info['basename']."?action=99&filename=favicon.ico\" type=\"image/x-icon\">
    <title>".et('FileMan')."</title>
    <style>
        .fm-title { margin: 0; font-weight: 500; line-height: 1.2; font-size: 1.5rem; }
        .float-left { float: left }
        .float-right { float: right }
        .noselect {
            -webkit-touch-callout: none; /* iOS Safari */
            -webkit-user-select: none; /* Safari */
            -khtml-user-select: none; /* Konqueror HTML */
            -moz-user-select: none; /* Firefox */
            -ms-user-select: none; /* Internet Explorer/Edge */
            user-select: none; /* Non-prefixed version */
        }
        .btn {
            display: inline-block;
            text-align: center;
            white-space: nowrap;
            vertical-align: middle;
            user-select: none;
            padding: 0 .4rem .05rem .2rem;
            line-height: 1.6;
            cursor: pointer;
        }
        .noIcon {
            padding: 0 .4rem .05rem .4rem;
        }
        i.bdc-link {
            font-style: normal;
            padding: 0 1px;
        }
        .fm-disk-info span {
            display: inline-block;
            margin: 2px 0;
            font-weight: 700;
        }
        .table {
            width: 100%;
            margin-bottom: 1rem;
            border-collapse: collapse;
        }
        .table .thead-light th {
            color: #495057;
            background-color: #e9ecef;
            border-color: #dee2e6;
            vertical-align: bottom;
            border-bottom: 2px solid #dee2e6;
            border-bottom-width: 2px;
        }
        .table td, .table th {
            padding: .3rem .4rem;
            border: 1px solid #dee2e6;
        }
        .table th {
            text-align: left;
        }
        .table td.lg {
            width: 400px;
        }
        .table td.sm {
            width: 10px;
            padding: .3rem .6rem;
            white-space: nowrap;
        }
        table.entry_name_table {
            width: 100%;
        }
        table.entry_name_table td {
            border: none;
            white-space: nowrap;
            padding: 0;
        }
        table.entry_name_table td.entry_name {
            padding-right: 60px;
            padding-top: 3px;
        }
        table.entry_name_table td .fa {
            margin-top: 0;
            margin-left: -6px;
            margin-right: 3px;
        }
        .form-signin {
            max-width: 350px;
            padding: 20px 20px 25px 20px;
            /*margin: 0 auto;*/
            background-color: #fff;
            border: 1px solid #ccc;
        }
        .form-signin-heading {
            margin-top: 0;
            margin-bottom: 18px;
            white-space: nowrap;
        }
        .form-control {
            display: block;
            width: 100%;
            margin-top: 1px;
            padding: 4px 10px;
            color: #495057;
            background-color: #fff;
            background-clip: padding-box;
            border: 1px solid #ced4da;
        }
        .form-signin input[type=\"password\"] {
            max-width: calc(100% - 80px);
            float: left;
        }
        .alert {
            position: relative;
            padding: 5px 10px;
            border: 1px solid transparent;
            clear: both;
        }
        .alert-danger {
            color: #721c24;
            background-color: #f8d7da;
            border-color: #f5c6cb;
        }
        .mt-3 { margin-top: 1rem!important; }
        .mt-5 { margin-top: 3rem!important; }
        .icon_loading {
            background:url('".$fm_path_info['basename']."?action=99&filename=throbber.gif') 0 0 no-repeat;
            width: 16px;
            height: 16px;
            line-height: 16px;
            display: inline-block;
            vertical-align: text-bottom;
        }
        .fa {
            background:url('".$fm_path_info['basename']."?action=99&filename=file_sprite.png') 0 0 no-repeat;
            width: 18px;
            height: 18px;
            line-height: 18px;
            display: inline-block;
            vertical-align: text-bottom;
            margin-top: 3px;
        }
        .fa.fa-code { background-position: -126px 0; }
        .fa.fa-code-o { background-position: -143px 0; }
        .fa.fa-php { background-position: -108px -18px; }
        .fa.fa-picture { background-position: -125px -18px; }
        .fa.fa-file-text-o { background-position: -254px -18px; }
        .fa-file-archive-o { background-position: -180px 0; }
        .fa.fa-html { background-position: -434px -18px; }
        .fa.fa-file-excel-o { background-position: -361px 0; }
        .fa.fa-music { background-position: -108px 0; }
        .fa.fa-video { background-position: -90px 0; }
        .fa.fa-file-aspx { background-position: -236px 0; }
        .fa.fa-database { background-position: -272px 0; }
        .fa.fa-file-word { background-position: -361px -18px; }
        .fa.fa-file-powerpoint { background-position: -144px -18px; }
        .fa.fa-font { background-position: -415px 0; }
        .fa.file-pdf { background-position: -18px 0; }
        .fa.file-image-o { background-position: -398px 0; }
        .fa.fa-gear { background-position: -434px 0; }
        .fa.fa-download { background-position: -162px -18px; }
        .fa.fa-settings { background-position: -398px -18px; }
        .fa.fa-refresh { background-position: -236px -18px; }
        .fa.fa-lunix { background-position: -290px -18px; }
        .fa.fa-folder { background-position: -506px -18px; }
        .fa.fa-add-file { background-position: -54px 0; }
        .fa.fa-upload { background-position: -453px 0; }
        .fa.fa-file-go { background-position: -470px 0; }
        .fa.fa-link { background-position: -488px -18px; }
        .fa.fa-find { background-position: -380px 0; }
        .fa.fa-file-light { background-position: -470px -18px; }
        .fa.fa-file-remove { background-position: -290px 0; }
        .fa.fa-file-config { background-position: -308px 0; }
        .fa.fa-resolve { background-position: -272px 0; }
        .fa.fa-perms { background-position: -344px 0; }
        .fa.fa-copy { background-position: -198px 0; }
        .fa.fa-copy-o { background-position: -198px -18px; }
        .fa.fa-edit { background-position: -326px 0; }
        .fa.fa-rename { background-position: -454px -18px; }
        .fa.fa-glob { background-position: -380px -18px; }
        .fa.fa-vs { background-position: -326px -18px; }
        .fa.fa-search { background-position: 0 -18px; }
    </style>
    <script language=\"Javascript\" type=\"text/javascript\">
    <!--
        function Is(){
            this.appname = navigator.appName;
            this.appversion = navigator.appVersion;
            this.platform = navigator.platform;
            this.useragent = navigator.userAgent.toLowerCase();
            this.ie = ( this.appname == 'Microsoft Internet Explorer' );
            if (( this.useragent.indexOf( 'mac' ) != -1 ) || ( this.platform.indexOf( 'mac' ) != -1 )){
                this.sisop = 'mac';
            } else if (( this.useragent.indexOf( 'windows' ) != -1 ) || ( this.platform.indexOf( 'win32' ) != -1 )){
                this.sisop = 'windows';
            } else if (( this.useragent.indexOf( 'inux' ) != -1 ) || ( this.platform.indexOf( 'linux' ) != -1 )){
                this.sisop = 'linux';
            }
        }
        var is = new Is();
        function enterSubmit(keypressEvent,submitFunc){
            var kCode = (is.ie) ? keypressEvent.keyCode : keypressEvent.which
            if( kCode == 13) eval(submitFunc);
        }
        function getCookieVal(offset) {
            var endstr = document.cookie.indexOf (';', offset);
            if (endstr == -1) endstr = document.cookie.length;
            return decodeURIComponent(document.cookie.substring(offset, endstr));
        }
        function getCookie(name) {
            var arg = name + '=';
            var alen = arg.length;
            var clen = document.cookie.length;
            var i = 0;
            while (i < clen) {
                var j = i + alen;
                if (document.cookie.substring(i, j) == arg) return getCookieVal (j);
                i = document.cookie.indexOf(' ', i) + 1;
                if (i == 0) break;
            }
            return null;
        }
        function setCookie(name, value) {
            var argv = setCookie.arguments;
            var argc = setCookie.arguments.length;
            var expires = (argc > 2) ? argv[2] : null;
            var path = (argc > 3) ? argv[3] : null;
            var domain = (argc > 4) ? argv[4] : null;
            var secure = (argc > 5) ? argv[5] : false;
            document.cookie = name + '=' + encodeURIComponent(value) +
            ((expires == null) ? '' : ('; expires=' + expires.toGMTString())) +
            ((path == null) ? '' : ('; path=' + path)) +
            ((domain == null) ? '' : ('; domain=' + domain)) +
            ((secure == true) ? '; secure' : '');
        }
        function delCookie(name) {
            var exp = new Date();
            exp.setTime (exp.getTime() - 1);
            var cval = getCookie (name);
            document.cookie = name + '=' + cval + '; expires=' + exp.toGMTString();
        }
        function setCookiePersistent(name, value){
            var exp = new Date();
            exp.setTime(exp.getTime()+".$cookie_cache_time.");
            setCookie(name,value,exp);
        }
        var frameWidth, frameHeight;
        function getFrameSize(){
            if (self.innerWidth){
                frameWidth = self.innerWidth;
                frameHeight = self.innerHeight;
            }else if (document.documentElement && document.documentElement.clientWidth){
                frameWidth = document.documentElement.clientWidth;
                frameHeight = document.documentElement.clientHeight;
            }else if (document.body){
                frameWidth = document.body.clientWidth;
                frameHeight = document.body.clientHeight;
            }else return false;
            return true;
        }
        getFrameSize();
        function str_replace (search, replace, subject, count) {
            var i = 0,
                j = 0,
                temp = '',
                repl = '',
                sl = 0,
                fl = 0,
                f = [].concat(search),
                r = [].concat(replace),
                s = subject,
                ra = Object.prototype.toString.call(r) === '[object Array]',
                sa = Object.prototype.toString.call(s) === '[object Array]';
            s = [].concat(s);
            if (count) {
                this.window[count] = 0;
            }

            for (i = 0, sl = s.length; i < sl; i++) {
                if (s[i] === '') {
                    continue;
                }
                for (j = 0, fl = f.length; j < fl; j++) {
                    temp = s[i] + '';
                    repl = ra ? (r[j] !== undefined ? r[j] : '') : r[0];
                    s[i] = (temp).split(f[j]).join(repl);
                    if (count && s[i] !== temp) {
                        this.window[count] += (temp.length - s[i].length) / f[j].length;
                    }
                }
            }
            return sa ? s : s[0];
        }
        function rep(str,i){
            str = String(str);
            i = parseInt(i);
            if (i > 0) {
                var out = '';
                for (var ii=1;ii<=i;ii++) out += str;
                return out;
            } else return '';
        }
    //-->
    </script>
    <style type=\"text/css\">
    html {
        width: 100%;
        margin-left: 0 !important;
    }
    body {
        font-family : Arial;
        font-size: 14px;
        font-weight : normal;
        color: #".$fm_color['Text'].";
        background-color: #".$fm_color['Bg'].";
    }
    table {
        font-family : Arial;
        font-size: 14px;
        font-weight : normal;
        color: #".$fm_color['Text'].";
        cursor: default;
    }
    input {
        font-family : Arial;
        font-size: 14px;
        font-weight : normal;
        color: #".$fm_color['Text'].";
    }
    textarea {
        font-family : Courier;
        font-size: 12px;
        font-weight : normal;
        color: #".$fm_color['Text'].";
    }
    a {
        font-family : Arial;
        font-size : 14px;
        font-weight : bold;
        text-decoration: none;
        color: #".$fm_color['Text'].";
    }
    a:link {
        color: #".$fm_color['Text'].";
    }
    a:visited {
        color: #".$fm_color['Text'].";
    }
    a:hover {
        color: #".$fm_color['Link'].";
    }
    a:active {
        color: #".$fm_color['Text'].";
    }
    tr.entryUnselected {
        background-color: #".$fm_color['Entry'].";
    }
    tr.entryUnselected:hover {
        background-color: #".$fm_color['Over'].";
    }
    tr.entrySelected {
        background-color: #".$fm_color['Mark'].";
    }
    </style>
    ".$header."
    </head>
    ";
}
function reloadframe($ref,$frame_number,$plus=""){
    global $fm_current_dir,$fm_path_info;
    echo "
    <script language=\"Javascript\" type=\"text/javascript\">
    <!--
        ".$ref.".frame".$frame_number.".location.href='".$fm_path_info['basename']."?frame=".$frame_number."&fm_current_dir=".rawurlencode($fm_current_dir.$plus)."';
    //-->
    </script>
    ";
}
function alert($arg){
    echo "
    <script language=\"Javascript\" type=\"text/javascript\">
    <!--
        alert('$arg');
    //-->
    </script>
    ";
}
define('UTF32_BIG_ENDIAN_BOM'   , chr(0x00).chr(0x00).chr(0xFE).chr(0xFF));
define('UTF32_LITTLE_ENDIAN_BOM', chr(0xFF).chr(0xFE).chr(0x00).chr(0x00));
define('UTF16_BIG_ENDIAN_BOM'   , chr(0xFE).chr(0xFF));
define('UTF16_LITTLE_ENDIAN_BOM', chr(0xFF).chr(0xFE));
define('UTF8_BOM'               , chr(0xEF).chr(0xBB).chr(0xBF));
function get_encoding($text){
    $first2 = mb_substr($text, 0, 2);
    $first3 = mb_substr($text, 0, 3);
    $first4 = mb_substr($text, 0, 4);
    if ($first3 == UTF8_BOM) return 'UTF-8'; // WITH BOM
    elseif ($first4 == UTF32_BIG_ENDIAN_BOM) return 'UTF-32BE';
    elseif ($first4 == UTF32_LITTLE_ENDIAN_BOM) return 'UTF-32LE';
    elseif ($first2 == UTF16_BIG_ENDIAN_BOM) return 'UTF-16BE';
    elseif ($first2 == UTF16_LITTLE_ENDIAN_BOM) return 'UTF-16LE';
    elseif (mb_detect_encoding($text, 'UTF-8', true) == true) return 'UTF-8'; // WITHOUT BOM
    elseif (mb_detect_encoding($text, 'ISO-8859-1', true) == true) return 'ISO-8859-1';
    else return mb_detect_encoding($text);
}
function utf8_convert($str){
    if (extension_loaded('mbstring') && extension_loaded('iconv')) {
        $str_chatset = get_encoding($str);
        if ($str_chatset == "UTF-8") return $str;
        return iconv($str_chatset, "UTF-8//TRANSLIT", $str);
    } else return utf8_encode($str);
}
function convert_charset($str,$charset){
    $str_chatset = get_encoding($str);
    if ($str_chatset == $charset) return $str;
    else return iconv($str_chatset, $charset."//TRANSLIT", $str);
}
function fs_encode($str){
    global $is_windows;
    if ($is_windows) {
        if (extension_loaded('mbstring') && extension_loaded('iconv')) {
            $str = convert_charset($str,'ISO-8859-1');
        }
    }
    return $str;
}
class tree_fs {
    protected $base = null;
    public function __construct($base) {
        $this->base = $this->real($base);
        if(!$this->base) { fb_log('Base directory does not exist'); }
    }
    protected function real($path) {
        if (is_link($path)) $temp = get_absolute_path(fs_encode($path));
        else $temp = realpath(fs_encode($path));
        if(!$temp) { fb_log('Path does not exist: ' . $path); }
        if($this->base && strlen($this->base)) {
            if(strpos($temp, $this->base) !== 0) { fb_log('Path is not inside base ('.$this->base.'): ' . $temp); }
        }
        return $temp;
    }
    protected function path($id) {
        global $is_windows;
        $path = str_replace('/', DIRECTORY_SEPARATOR, $id);
        $path = $this->real($this->base.DIRECTORY_SEPARATOR.$path);
        $path = rtrim($path, DIRECTORY_SEPARATOR);
        if (!$is_windows) {
            $path = DIRECTORY_SEPARATOR.$path;
        }
        $path = replace_double(DIRECTORY_SEPARATOR,$path);
        //fb_log('path()',$id.' => '.$path);
        return $path;
    }
    protected function id($path) {
        global $is_windows;
        $id = $this->real($path);
        $id = substr($id, strlen($this->base));
        $id = str_replace(DIRECTORY_SEPARATOR, '/', $id);
        $id = '/'.rtrim($id, '/');
        $id = replace_double('/',$id);
        //fb_log('id()',$path.' => '.$id);
        return $id;
    }
    public function lst($id, $with_root=false) {
        $path = $this->path($id);
        $lst = scandir(fs_encode($path));
        if(!$lst) { fb_log('Could not list path: '.$path); }
        $res = array();
        foreach($lst as $item) {
            if ($item == '.' || $item == '..' || $item === null) { continue; }
            $item_path = rtrim($path,DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR.$item;
            if (is_dir($item_path)) {
                if (is_link($item_path)) $item .= ' (L)';
                $res[] = array('text' => utf8_convert($item), 'children' => true,  'id' => utf8_convert($this->id($item_path)), 'icon' => 'folder');
            } elseif (is_link($item_path) && !is_file($item_path)) {
                // Add &#8202; Invisible char to change color to RED using Jquery https://stackoverflow.com/questions/17978720/invisible-characters-ascii
                // TODO: Find a better way to show RED broken folder links, using jsTree API
                if (is_link($item_path)) $item .= ' (L*)';
                $res[] = array('text' => utf8_convert($item), 'children' => true,  'id' => utf8_convert($this->id($item_path)), 'icon' => 'folder');
            }
        }
        if($with_root && $this->id($path) == '/') {
            $res = array(array('text' => utf8_convert($this->base), 'children' => $res, 'id' => '/', 'icon'=>'folder', 'state' => array('opened' => true, 'disabled' => false)));
        }
        return $res;
    }
    public function data($id) {
        if(strpos($id, ":")) {
            $id = array_map(array($this, 'id'), explode(':', $id));
            return array('type'=>'multiple', 'content'=> 'Multiple selected: ' . implode(' ', $id));
        }
        $path = $this->path($id);
        if(is_dir($path)) {
            return array('type'=>'folder', 'content'=> $id);
        }
        fb_log('Not a valid selection: '.$path);
    }
}
function frame2(){
    global $fm_root,$fm_current_root,$fm_path_info,$setflag,$is_windows,$cookie_cache_time,$fm_current_dir,$auth_pass,$open_basedirs;
    if(isset($_GET['operation'])) {
        $tree_fs = new tree_fs($fm_current_root);
        try {
            $resul = null;
            switch($_GET['operation']) {
                case 'get_node':
                    $node = (strlen($_GET['id']) && $_GET['id'] !== '#') ? $_GET['id'] : '/';
                    $with_root = true;
                    $resul = $tree_fs->lst($node, $with_root);
                    break;
                default:
                    fb_log('Unsupported operation: '.$_GET['operation']);
                    break;
            }
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode($resul);
        }
        catch (Exception $e) {
            header($_SERVER['SERVER_PROTOCOL'] . ' 500 Server Error');
            header('Status:  500 Server Error');
            echo $e->getMessage();
        }
        die();
    }
    html_header("
    <script language=\"Javascript\" type=\"text/javascript\">
    <!--
        function saveFrameSize(){
            if (getFrameSize()){
                var exp = new Date();
                exp.setTime(exp.getTime()+".$cookie_cache_time.");
                setCookie('leftFrameWidth',frameWidth,exp);
            }
        }
        window.onresize = saveFrameSize;
    //-->
    </script>");
    echo "<body marginwidth=\"0\" marginheight=\"0\">
    <script language=\"Javascript\" type=\"text/javascript\">
    <!--
        // Disable text selection, binding the onmousedown, but not for some elements, it must work.
        function disableTextSelection(e){
            var type = String(e.target.type);
            return (type.indexOf('select') != -1 || type.indexOf('button') != -1 || type.indexOf('input') != -1 || type.indexOf('radio') != -1);
        }
        function enableTextSelection(){return true}
        if (is.ie) document.onselectstart=new Function('return false')
        else {
            document.body.onmousedown=disableTextSelection
            document.body.onclick=enableTextSelection
        }
        var flag = ".(($setflag)?"true":"false")."
        function set_flag(arg) {
            flag = arg;
        }
        function go_tree(arg) {
            if (flag) {
                parent.frame3.set_dir_dest(arg+'".addslashes(DIRECTORY_SEPARATOR)."');
                flag = false;
            } else {
                parent.frame3.location.href='".addslashes($fm_path_info['basename'])."?frame=3&fm_current_root=".rawurlencode($fm_current_root)."&fm_current_dir='+encodeURIComponent(arg)+'".rawurlencode(DIRECTORY_SEPARATOR)."';
            }
        }
        function set_fm_current_root(arg){
            document.location.href='".addslashes($fm_path_info['basename'])."?frame=2&fm_current_root='+encodeURIComponent(arg);
        }
        function refresh_tree(){
            document.location.href='".addslashes($fm_path_info['basename'])."?frame=2&fm_current_root=".rawurlencode($fm_current_root)."';
        }
        function logout(){
            document.location.href='".addslashes($fm_path_info['basename'])."?action=1';
        }
    //-->
    </script>
    ";
    echo "<table width=\"100%\" height=\"100%\" border=0 cellspacing=0 cellpadding=5>\n";
    echo "<tr valign=top height=10 bgcolor=\"#DDDDDD\" style=\"border-bottom: 2px solid #eaeaea;\"><td style=\"padding: 6px 6px 1px; 6px;\">";
    echo "<form style=\"display:inline-block;\" action=\"".$fm_path_info['basename']."\" method=\"post\" target=\"_parent\">";
        $fm_root_opts=array();
        if (strlen($fm_root) == 0) {
            if (count($open_basedirs)>1){
                foreach ($open_basedirs as $dir) {
                    $is_sel=(strpos($fm_current_root,$dir) !== false)?"selected":"";
                    $fm_root_opts[] = "<option ".$is_sel." value=\"".$dir."\">".html_encode($dir)."</option>";
                }
            } elseif ($is_windows){
                $drives=array();
                $aux="ABCDEFGHIJKLMNOPQRSTUVWXYZ";
                for($x=0;$x<strlen($aux);$x++){
                    $dir = $aux[$x].":".DIRECTORY_SEPARATOR;
                    if ($handle = @opendir($dir)){
                        @closedir($handle);
                        $is_sel=(strpos(uppercase($fm_current_root),$dir) !== false)?"selected":"";
                        $fm_root_opts[] = "<option ".$is_sel." value=\"".$dir."\">".html_encode($dir)."</option>";
                    }
                }
            }
        }
        if (count($fm_root_opts)>1) echo "<select name=drive onchange=\"set_fm_current_root(this.value)\" style=\"float:left; margin:1px 0 5px 0; margin-right:5px; padding:5px;\">".implode("\n",$fm_root_opts)."</select>";
        echo "<button type=\"button\" style=\"margin-bottom: 5px;\" class=\"btn\" onclick=\"refresh_tree()\" value=\"".et('Refresh')."\"><i class=\"fa fa-refresh\"></i> ".et('Refresh')."</button>";
        if ($auth_pass != md5('')) echo "&nbsp;<button type=\"button\" style=\"margin-bottom: 5px;\" class=\"btn \" onclick=\"logout()\" value=\"".et('Leave')."\"><i class=\"fa fa-file-go\"></i> ".et('Leave')."</button>";
    echo "</form>";
    echo "</td></tr>";
    echo "<tr valign=top><td>";
    ?>
        <script type="text/javascript" src="<?php echo $fm_path_info['basename']; ?>?action=99&filename=jquery-1.11.1.min.js"></script>
        <script type="text/javascript" src="<?php echo $fm_path_info['basename']; ?>?action=99&filename=jstree.min.js"></script>
        <link rel="stylesheet" type="text/css" href="<?php echo $fm_path_info['basename']; ?>?action=99&filename=jstree.style.min.css" media="screen" />
        <style>
            #tree { float:left; overflow:auto; padding:0; margin-bottom: 20px;}
            #tree .folder { background:url('<?php echo $fm_path_info['basename']; ?>?action=99&filename=file_sprite.png') right bottom no-repeat; }
            #tree .file { background:url('<?php echo $fm_path_info['basename']; ?>?action=99&filename=file_sprite.png') 0 0 no-repeat; }
            #tree .file-pdf { background-position: -32px 0 }
            #tree .file-as { background-position: -36px 0 }
            #tree .file-c { background-position: -72px -0px }
            #tree .file-iso { background-position: -108px -0px }
            #tree .file-htm, #tree .file-html, #tree .file-xml, #tree .file-xsl { background-position: -126px -0px }
            #tree .file-cf { background-position: -162px -0px }
            #tree .file-cpp { background-position: -216px -0px }
            #tree .file-cs { background-position: -236px -0px }
            #tree .file-sql { background-position: -272px -0px }
            #tree .file-xls, #tree .file-xlsx { background-position: -362px -0px }
            #tree .file-h { background-position: -488px -0px }
            #tree .file-crt, #tree .file-pem, #tree .file-cer { background-position: -452px -18px }
            #tree .file-php { background-position: -108px -18px }
            #tree .file-jpg, #tree .file-jpeg, #tree .file-png, #tree .file-gif, #tree .file-bmp { background-position: -126px -18px }
            #tree .file-ppt, #tree .file-pptx { background-position: -144px -18px }
            #tree .file-rb { background-position: -180px -18px }
            #tree .file-text, #tree .file-txt, #tree .file-md, #tree .file-log, #tree .file-htaccess { background-position: -254px -18px }
            #tree .file-doc, #tree .file-docx { background-position: -362px -18px }
            #tree .file-zip, #tree .file-gz, #tree .file-tar, #tree .file-rar { background-position: -416px -18px }
            #tree .file-js { background-position: -434px -18px }
            #tree .file-css { background-position: -144px -0px }
            #tree .file-fla { background-position: -398px -0px }
        </style>
        <div id="container" role="main">
            <div id="tree"></div>
        </div>
        <?php
            $tree_auto_load_nodes = substr($fm_current_dir,strlen($fm_current_root));
            $tree_auto_load_nodes = trim($tree_auto_load_nodes,DIRECTORY_SEPARATOR);
            $tree_auto_load_nodes = explode(DIRECTORY_SEPARATOR,$tree_auto_load_nodes);
        ?>
        <script>
        var tree_loaded = false;
        var tree_auto_load_nodes = <?php echo json_encode($tree_auto_load_nodes); ?>;
        var tree_auto_load_node_curr = 0;
        //console.log(tree_auto_load_nodes);
        function highlight_broken_links(){
            $("#tree a:contains('(L*)')").css({'color':'red'});
            var str = $("#tree a:contains('(L*)')").html();
            $("#tree a:contains('(L*)')").html(String(str).replace('(L*)','(L)'));
        }
        function tree_auto_load(){
            if (tree_auto_load_node_curr > tree_auto_load_nodes.length) return;
            var node_id = '/'+tree_auto_load_nodes.slice(0, tree_auto_load_node_curr+1).join('/');
            var node = $('#tree').find("[id='"+node_id+"']:eq(0)");
            tree_auto_load_node_curr++;
            //console.log('tree_auto_load() '+tree_auto_load_node_curr);
            //console.log('node_id: '+node_id);
            //console.log(node);
            if (tree_auto_load_node_curr == tree_auto_load_nodes.length) {
                if (node.length) {
                    $("#tree").jstree(true).open_node(node, function(){
                        highlight_broken_links();
                        $('#tree').jstree(true).select_node(node,true);
                        tree_loaded = true;
                    }, false);
                } else {
                    tree_loaded = true;
                }
            } else {
                if (node.length) {
                    $("#tree").jstree(true).open_node(node, tree_auto_load, false);
                } else {
                    tree_auto_load();
                }
            }
            highlight_broken_links();
        }
        $(function () {
            $('#tree')
                .jstree({
                    'core' : {
                        'data' : {
                            'url' : '?frame=2&fm_current_root=<?php echo rawurlencode($fm_current_root) ?>&operation=get_node',
                            'data' : function (node) {
                                return { 'id' : node.id };
                            }
                        },
                        'check_callback' : function(o, n, p, i, m) {
                            if(m && m.dnd && m.pos !== 'i') { return false; }
                            if(o === "move_node" || o === "copy_node") {
                                if(this.get_node(n).parent === this.get_node(p).id) { return false; }
                            }
                            return true;
                        },
                        'force_text' : true,
                        'themes' : {
                            'responsive' : false,
                            'variant' : 'small',
                            'stripes' : false
                        },
                        'expand_selected_onload' : true
                    },
                    'sort' : function(a, b) {
                        return this.get_type(a) === this.get_type(b) ? (this.get_text(a) > this.get_text(b) ? 1 : -1) : (this.get_type(a) >= this.get_type(b) ? 1 : -1);
                    },
                    'types' : {
                        'default' : { 'icon' : 'folder' },
                        'file' : { 'valid_children' : [], 'icon' : 'file' },
                        'broken_link': { 'icon' : 'folder' }
                    },
                    'unique' : {
                        'duplicate' : function (name, counter) {
                            return name + ' ' + counter;
                        }
                    },
                    'massload' : {
                        'url' : '?frame=2&fm_current_root=<?php echo rawurlencode($fm_current_root) ?>&operation=get_node',
                        'data' : function (nodes) {
                            return { 'ids' : nodes.join(',') };
                        }
                    },
                    'plugins' : ['sort','types','unique'] // 'state', 'massload'
                })
            //.on('changed.jstree', function (e, data) {
            .on('select_node.jstree', function (e, data) {
                if (!tree_loaded) return;
                if (data && data.selected && data.selected.length) {
                    //console.log('select_node.jstree()');
                    var path = String(data.selected[0]);
                    path = path.replace(/\//g,'<?php echo addslashes(DIRECTORY_SEPARATOR); ?>');
                    go_tree('<?php echo addslashes(rtrim($fm_current_root,DIRECTORY_SEPARATOR)); ?>'+path);
                }
            })
            .on('loaded.jstree', function (e, data) {
                //console.log('loaded.jstree()');
                //console.log(e);
                //console.log(data);
                tree_auto_load();
            });
            //$('#tree').jstree(true).clear_state();
        });
        </script>
    <?php
    echo "</td></tr>";
    echo "</table>\n";
    echo "</body>\n</html>";
}
function is_binary($file){
    //https://stackoverflow.com/questions/1765311/how-to-view-files-in-binary-from-bash
    //http://php.net/manual/pt_BR/function.bin2hex.php
    if (!is_file($file)) return false;
    $mime = mime_content_type($file);
    fb_log($file,$mime);
    if (strpos($mime,'text') === false && strpos($mime,'x-empty') === false) return true;
    return false;
}
function is_textfile($file){
    if (!is_file($file)) return false;
    $mime = mime_content_type($file);
    fb_log($file,$mime);
    if (strpos($mime,'text') === 0 || strpos($mime,'x-empty') !== false) return true;
    return false;
}
function dir_list_form() {
    global $script_init_time,$fm_current_root,$fm_current_dir,$quota_mb,$resolve_ids,$order_dir_list_by,$is_windows,$cmd_name,$ip,$lan_ip,$fm_path_info,$version,$date_format;
    clearstatcache();
    $out = "<style>
        #modalIframeWrapper {
            background: #FFF;
            border: 1px solid #ccc;
            margin: -2px;
            position: absolute;
            top: 22px;
            left: 5px;
            width: calc(100% - 10px);
            height: calc(100% - 50px);
            transform: translate(0,22px);
            z-index: 32000;
            display: none;
        }
        #modalIframe {
            display: block;
            background: #FFF;
            border: 1px solid #ccc;
            width: 100%;
            height: 100%;
            overflow-y: scroll;
            overflow-x: auto;
        }
        #modalIframeWrapperTitle {
            padding-left: 5px;
        }
    </style>
    <div id=\"modalIframeWrapper\">
        <table border=0 cellspacing=1 cellpadding=4 width=\"100%\" height=\"100%\">
            <tr style=\"height:20px;\">
                <td id=\"modalIframeWrapperTitle\" style=\"font-weight:bold;\">Title</td>
                <td align=right width=10><button type=\"button\" class=\"btn\" onclick=\"closeModalWindow()\" value=\"".et('Close')."\"><i class=\"fa fa-file-go\"></i> ".et('Close')."</button></td>
            </tr>
            <tr style=\"height:100%\">
                <td colspan=2 style=\"padding-top:0;\"><iframe id=\"modalIframe\" src=\"\" scrolling=\"yes\" frameborder=\"0\"></iframe></td>
            </tr>
        </table>
    </div>
    <script language=\"Javascript\" type=\"text/javascript\">
    <!--
        var modalWindowReloadOnClose = false;
        var modalWindowCurrSrc = '';
        function toogleModalWindow(url,title,reloadOnClose){
            if (document.getElementById(\"modalIframeWrapper\").style.display == '' || modalWindowCurrSrc != url){
                openModalWindow(url,title,reloadOnClose);
            } else {
                modalWindowReloadOnClose = false;
                closeModalWindow();
            }
        }
        function openModalWindow(url,title,reloadOnClose){
            cancel_copy_move();
            if (typeof(title) == 'undefined') title = '';
            if (typeof(reloadOnClose) != 'undefined') modalWindowReloadOnClose = reloadOnClose;
            if (modalWindowCurrSrc != url) {
                document.getElementById(\"modalIframe\").src = url;
            }
            modalWindowCurrSrc = url;
            document.getElementById(\"modalIframeWrapper\").style.display = 'block';
            document.getElementById(\"modalIframeWrapperTitle\").innerHTML = title;
            document.getElementById(\"modalIframe\").focus();
            document.body.style.overflow = 'hidden';
            window.scrollTo(0,0);
        }
        function closeModalWindow(){
            document.getElementById(\"modalIframeWrapper\").style.display = '';
            document.body.style.overflow = 'auto';
            if (modalWindowReloadOnClose) {
                window.parent.frame3.location.href='".$fm_path_info['basename']."?frame=3&fm_current_dir=".rawurlencode($fm_current_dir)."';
            }
        }
    -->
    </script>";
    $io_error = true;
    if ($opdir = @opendir(fs_encode($fm_current_dir))) {
        $io_error = false;
        $has_files = false;
        $entry_count = 0;
        $total_size = 0;
        $entry_list = array();
        while (($entry = readdir($opdir)) !== false) {
            if ($entry == "." || $entry == "..") continue;
            $entry_list[$entry_count]['name'] = $entry;
            $entry_list[$entry_count]['namet'] = $entry;
            $entry_list[$entry_count]['size'] = 0;
            $entry_list[$entry_count]['sizet'] = 0;
            $entry_list[$entry_count]['type'] = "none";
            $entry_list[$entry_count]['date'] = date("Ymd", filemtime($fm_current_dir.$entry));
            $entry_list[$entry_count]['time'] = date("His", filemtime($fm_current_dir.$entry));
            $entry_list[$entry_count]['datet'] = date($date_format, filemtime($fm_current_dir.$entry));
            $entry_list[$entry_count]['p'] = substr(sprintf('%o', fileperms($fm_current_dir.$entry)), -4);
            $entry_list[$entry_count]['u'] = fileowner($fm_current_dir.$entry);
            $entry_list[$entry_count]['g'] = filegroup($fm_current_dir.$entry);
            if ($resolve_ids){
                $entry_list[$entry_count]['p'] = show_perms(fileperms($fm_current_dir.$entry));
                if (!$is_windows){
                    $entry_list[$entry_count]['u'] = get_user_name(fileowner($fm_current_dir.$entry));
                    $entry_list[$entry_count]['g'] = get_group_name(filegroup($fm_current_dir.$entry));
                }
            }
            if (is_link($fm_current_dir.$entry)){
                $entry_list[$entry_count]['type'] = "link";
                $entry_list[$entry_count]['target'] = readlink($fm_current_dir.$entry);
                $entry_list[$entry_count]['target_absolute_path'] = readlink_absolute_path($fm_current_dir.$entry);
                if (is_dir($entry_list[$entry_count]['target_absolute_path'])) {
                    $entry_list[$entry_count]['type'] = "dir";
                    $dirsize = phpfm_get_total_size($fm_current_dir.$entry);
                    $entry_list[$entry_count]['size'] = intval($dirsize);
                    if ($dirsize === false) {
                        $sizet = et('GetSize').'..';
                    } elseif ($dirsize === 'error'){
                        $sizet = '<span title="error: too much recursion">'.et('Error').' &#x21bb</span>';
                    } else {
                        $sizet = format_size($entry_list[$entry_count]['size']).' &#x21bb';
                    }
                    $entry_list[$entry_count]['sizet'] = "<a onmousedown=\"if(event)event.stopPropagation();\" href=\"javascript:dir_list_update_total_size('".addslashes($entry)."','dir".$entry_count."size')\"><span id=\"dir".$entry_count."size\">".$sizet."</span></a>";
                } elseif (is_file($entry_list[$entry_count]['target_absolute_path'])) {
                    $entry_list[$entry_count]['type'] = "file";
                    $entry_list[$entry_count]['size'] = phpfm_filesize($fm_current_dir.$entry);
                    $entry_list[$entry_count]['sizet'] = format_size($entry_list[$entry_count]['size']);
                    $has_files = true;
                } else {
                    $entry_list[$entry_count]['type'] = "broken_link";
                    $entry_list[$entry_count]['date'] = '';
                    $entry_list[$entry_count]['time'] = '';
                    $entry_list[$entry_count]['datet'] = '';
                    $entry_list[$entry_count]['size'] = 0;
                    $entry_list[$entry_count]['sizet'] = '';
                    $entry_list[$entry_count]['p'] = '';
                }
                $entry_list[$entry_count]['linkt'] = '<span style="float:right; margin-top:3px; font-weight:bold;" title="symlink to '.$entry_list[$entry_count]['target'].'">(L)</span>';
                $ext = lowercase(strrchr($entry,"."));
                if (strstr($ext,".")){
                    $entry_list[$entry_count]['ext'] = $ext;
                    $entry_list[$entry_count]['extt'] = $ext;
                } else {
                    $entry_list[$entry_count]['ext'] = "";
                    $entry_list[$entry_count]['extt'] = "&nbsp;";
                }
            } elseif (is_file($fm_current_dir.$entry)){
                $ext = lowercase(strrchr($entry,"."));
                $entry_list[$entry_count]['type'] = "file";
                $entry_list[$entry_count]['size'] = phpfm_filesize($fm_current_dir.$entry);
                $entry_list[$entry_count]['sizet'] = format_size($entry_list[$entry_count]['size']);
                if (strstr($ext,".")){
                    $entry_list[$entry_count]['ext'] = $ext;
                    $entry_list[$entry_count]['extt'] = $ext;
                } else {
                    $entry_list[$entry_count]['ext'] = "";
                    $entry_list[$entry_count]['extt'] = "&nbsp;";
                }
                $has_files = true;
            } elseif (is_dir($fm_current_dir.$entry)) {
                $entry_list[$entry_count]['type'] = "dir";
                $dirsize = phpfm_get_total_size($fm_current_dir.$entry);
                $entry_list[$entry_count]['size'] = intval($dirsize);
                if ($dirsize === false){
                    $sizet = et('GetSize').'..';
                } elseif ($dirsize === 'error') {
                    $sizet = '<span title="error: too much recursion">'.et('Error').' &#x21bb</span>';
                } else {
                    $sizet = format_size($entry_list[$entry_count]['size']).' &#x21bb';
                }
                $entry_list[$entry_count]['sizet'] = "<a onmousedown=\"if(event)event.stopPropagation();\" href=\"javascript:dir_list_update_total_size('".addslashes($entry)."','dir".$entry_count."size')\"><span id=\"dir".$entry_count."size\">".$sizet."</span></a>";
            }
            $total_size += $entry_list[$entry_count]['size'];
            $entry_count++;
        }
        @closedir($opdir);
    }
    if($entry_count){
        $or1="1A";
        $or2="2D";
        $or3="3A";
        $or4="4A";
        $or5="5A";
        $or6="6D";
        $or7="7D";
        switch($order_dir_list_by){
            case "1A": $entry_list = array_csort($entry_list,"type",SORT_STRING,SORT_ASC,"name",SORT_STRING,SORT_ASC); $or1="1D"; break;
            case "1D": $entry_list = array_csort($entry_list,"type",SORT_STRING,SORT_ASC,"name",SORT_STRING,SORT_DESC); $or1="1A"; break;
            case "2A": $entry_list = array_csort($entry_list,"type",SORT_STRING,SORT_ASC,"p",SORT_STRING,SORT_ASC,"g",SORT_STRING,SORT_ASC,"u",SORT_STRING,SORT_ASC); $or2="2D"; break;
            case "2D": $entry_list = array_csort($entry_list,"type",SORT_STRING,SORT_ASC,"p",SORT_STRING,SORT_DESC,"g",SORT_STRING,SORT_ASC,"u",SORT_STRING,SORT_ASC); $or2="2A"; break;
            case "3A": $entry_list = array_csort($entry_list,"type",SORT_STRING,SORT_ASC,"u",SORT_STRING,SORT_ASC,"g",SORT_STRING,SORT_ASC); $or3="3D"; break;
            case "3D": $entry_list = array_csort($entry_list,"type",SORT_STRING,SORT_ASC,"u",SORT_STRING,SORT_DESC,"g",SORT_STRING,SORT_ASC); $or3="3A"; break;
            case "4A": $entry_list = array_csort($entry_list,"type",SORT_STRING,SORT_ASC,"g",SORT_STRING,SORT_ASC,"u",SORT_STRING,SORT_DESC); $or4="4D"; break;
            case "4D": $entry_list = array_csort($entry_list,"type",SORT_STRING,SORT_ASC,"g",SORT_STRING,SORT_DESC,"u",SORT_STRING,SORT_DESC); $or4="4A"; break;
            case "5A": $entry_list = array_csort($entry_list,"type",SORT_STRING,SORT_ASC,"size",SORT_NUMERIC,SORT_ASC); $or5="5D"; break;
            case "5D": $entry_list = array_csort($entry_list,"type",SORT_STRING,SORT_ASC,"size",SORT_NUMERIC,SORT_DESC); $or5="5A"; break;
            case "6A": $entry_list = array_csort($entry_list,"type",SORT_STRING,SORT_ASC,"date",SORT_STRING,SORT_ASC,"time",SORT_STRING,SORT_ASC,"name",SORT_STRING,SORT_ASC); $or6="6D"; break;
            case "6D": $entry_list = array_csort($entry_list,"type",SORT_STRING,SORT_ASC,"date",SORT_STRING,SORT_DESC,"time",SORT_STRING,SORT_DESC,"name",SORT_STRING,SORT_ASC); $or6="6A"; break;
            case "7A": $entry_list = array_csort($entry_list,"type",SORT_STRING,SORT_ASC,"ext",SORT_STRING,SORT_ASC,"name",SORT_STRING,SORT_ASC); $or7="7D"; break;
            case "7D": $entry_list = array_csort($entry_list,"type",SORT_STRING,SORT_ASC,"ext",SORT_STRING,SORT_DESC,"name",SORT_STRING,SORT_ASC); $or7="7A"; break;
        }
    }
    $out .= "
    <script language=\"Javascript\" type=\"text/javascript\">
    <!--
    function go_dir_list(arg) {
        document.location.href='".addslashes($fm_path_info['basename'])."?frame=3&fm_current_dir=".rawurlencode($fm_current_dir)."'+encodeURIComponent(arg)+'".addslashes(DIRECTORY_SEPARATOR)."';
    }
    function resolve_ids() {
        document.location.href='".addslashes($fm_path_info['basename'])."?frame=3&set_resolve_ids=".($resolve_ids?'0':'1')."&fm_current_dir=".rawurlencode($fm_current_dir)."';
    }
    var entry_list = new Array();
    // Custom object constructor
    function entry(name, type, perms, size, selected){
        this.name = name;
        this.type = type;
        this.perms = perms;
        this.size = size;
        this.selected = false;
    }
    // Declare entry_list for selection procedures";
    foreach ($entry_list as $i=>$data){
        $out .= "\n\tentry_list['entry$i'] = new entry('".addslashes($data['name'])."', '".$data['type']."', '".$data['p']."', '".$data['size']."', false);";
    }
    $out .= "
    function dir_list_update_total_size(dirname,id){
        var el = document.getElementById(id);
        if (el) {
            el.innerHTML = '<div class=\"icon_loading\"></div>';
        }
        $.ajax({
            type: 'GET',
            url: '".$fm_path_info['basename']."?action=14&dirname='+encodeURIComponent(dirname)+'&fm_current_dir=".rawurlencode($fm_current_dir)."',
            dataType: 'text',
            crossDomain: false,
            success: function (data){
                dir_list_update_total_size_callback(dirname,id,data);
            },
            error: function (err){
                console.log(err);
            }
        });
    }
    function dir_list_update_total_size_callback(dirname,id,dirsize){
        for(var x=0;x<".(integer)count($entry_list).";x++){
            if(entry_list['entry'+x].name == dirname){
                entry_list['entry'+x].size = parseInt(dirsize);
                break;
            }
        }
        var el = document.getElementById(id);
        if (el) {
            if (dirsize == 'error') el.innerHTML = '<span title=\"error: too much recursion\">".et('Error')." &#x21bb</span>';
            else el.innerHTML = format_size(dirsize)+' &#x21bb';
        }
        update_footer_status();
    }
    // Select/Unselect Rows OnClick/OnMouseOver
    var lastRows = new Array(null,null);
    function selectEntry(Row, Action){
        if (multipleSelection){
            // Avoid repeated onmouseover events from same Row ( cell transition )
            if (Row != lastRows[0]){
                if (Action == 'over') {
                    if (entry_list[Row.id].selected){
                        if (unselect(entry_list[Row.id])) {
                            Row.className = 'entryUnselected';
                        }
                        // Change the last Row when you change the movement orientation
                        if (lastRows[0] != null && lastRows[1] != null){
                            var LastRowID = lastRows[0].id;
                            if (Row.id == lastRows[1].id){
                                if (unselect(entry_list[LastRowID])) {
                                    lastRows[0].className = 'entryUnselected';
                                }
                            }
                        }
                    } else {
                        if (select(entry_list[Row.id])){
                            Row.className = 'entrySelected';
                        }
                        // Change the last Row when you change the movement orientation
                        if (lastRows[0] != null && lastRows[1] != null){
                            var LastRowID = lastRows[0].id;
                            if (Row.id == lastRows[1].id){
                                if (select(entry_list[LastRowID])) {
                                    lastRows[0].className = 'entrySelected';
                                }
                            }
                        }
                    }
                    lastRows[1] = lastRows[0];
                    lastRows[0] = Row;
                }
            }
        } else {
            if (Action == 'click') {
                var newClassName = null;
                if (entry_list[Row.id].selected){
                    if (unselect(entry_list[Row.id])) newClassName = 'entryUnselected';
                } else {
                    if (select(entry_list[Row.id])) newClassName = 'entrySelected';
                }
                if (newClassName) {
                    lastRows[0] = lastRows[1] = Row;
                    Row.className = newClassName;
                }
            }
        }
        return true;
    }
    // Disable text selection and bind multiple selection flag
    var multipleSelection = false;
    if (is.ie) {
        document.onselectstart=new Function('return false');
        document.onmousedown=switch_flag_on;
        document.onmouseup=switch_flag_off;
        // Event mouseup is not generated over scrollbar.. curiously, mousedown is.. go figure.
        window.onscroll=new Function('multipleSelection=false');
        window.onresize=new Function('multipleSelection=false');
    } else {
        if (document.layers) window.captureEvents(Event.MOUSEDOWN);
        if (document.layers) window.captureEvents(Event.MOUSEUP);
        window.onmousedown=switch_flag_on;
        window.onmouseup=switch_flag_off;
    }
    // Using same function and a ternary operator couses bug on double click
    function switch_flag_on(e) {
        if (is.ie){
            multipleSelection = (event.button == 1);
        } else {
            multipleSelection = (e.which == 1);
        }
        return false;
        //var type = String(e.target.type);
        //return (type.indexOf('select') != -1 || type.indexOf('button') != -1 || type.indexOf('input') != -1 || type.indexOf('radio') != -1);
    }
    function switch_flag_off(e) {
        if (is.ie){
            multipleSelection = (event.button != 1);
        } else {
            multipleSelection = (e.which != 1);
        }
        lastRows[0] = lastRows[1] = null;
        update_footer_selection_total_status();
        return false;
    }
    var total_dirs = 0;
    var total_files = 0;
    var total_size = 0;
    var total_dirs_selected = 0;
    var total_files_selected = 0;
    var total_size_selected = 0;
    var last_entry_selected = '';
    function select(Entry){
        if(Entry.selected) return false;
        Entry.selected = true;
        last_entry_selected = Entry.name;
        document.form_action.chmod_arg.value = Entry.perms;
        update_footer_selection_total_status();
        return true;
    }
    function unselect(Entry){
        if (!Entry.selected) return false;
        Entry.selected = false;
        update_footer_selection_total_status();
        return true;
    }
    function is_anything_selected(){
        var selected_dir_list = new Array();
        var selected_file_list = new Array();
        for(var x=0;x<".(integer)count($entry_list).";x++){
            if(entry_list['entry'+x].selected){
                if(entry_list['entry'+x].type == 'dir') selected_dir_list.push(entry_list['entry'+x].name);
                else selected_file_list.push(entry_list['entry'+x].name);
            }
        }
        document.form_action.selected_dir_list.value = selected_dir_list.join('<|*|>');
        document.form_action.selected_file_list.value = selected_file_list.join('<|*|>');
        return (total_dirs_selected>0 || total_files_selected>0);
    }
    function format_size(arg) {
        var resul = '';
        if (arg>0){
            var j = 0;
            var ext = new Array(' bytes',' Kb',' Mb',' Gb',' Tb');
            while (arg >= Math.pow(1024,j)) ++j;
            resul = (Math.round(arg/Math.pow(1024,j-1)*100)/100) + ext[j-1];
        } else resul = '0 bytes';
        return resul;
    }
    function update_footer_status(){
        update_footer_total_status();
        update_footer_selection_total_status();
    }
    function update_footer_total_status(){
        total_size = 0;
        total_dirs = 0;
        total_files = 0;
        for(var x=0;x<".(integer)count($entry_list).";x++){
            if(entry_list['entry'+x].type == 'dir'){
                total_dirs++;
            } else {
                total_files++;
            }
            total_size += parseInt(entry_list['entry'+x].size);
        }
        var total_size_status = '';
        if (total_dirs) {
            total_size_status += total_dirs+' ".et('Dir_s')."';
        }
        if (total_files) {
            if (total_dirs) total_size_status += ' ".et('And')." ';
            total_size_status += total_files+' ".et('File_s')."';
        }
        if (total_size_status != '') {
            if (total_size) total_size_status += ' = '+format_size(total_size);
        }
        var el = document.getElementById('total_size_status');
        if (el) {
            el.innerHTML = '<span>'+total_size_status+'</span><br />';
            if (total_size_status != '') el.style.display='';
            else el.style.display='none';
        }
    }
    function update_footer_selection_total_status(){
        total_size_selected = 0;
        total_dirs_selected = 0;
        total_files_selected = 0;
        for(var x=0;x<".(integer)count($entry_list).";x++){
            if(entry_list['entry'+x].selected){
                if(entry_list['entry'+x].type == 'dir'){
                    total_dirs_selected++;
                } else {
                    total_files_selected++;
                }
                total_size_selected += parseInt(entry_list['entry'+x].size);
            }
        }
        var selection_total_size_status = '';
        if (total_dirs_selected) {
            selection_total_size_status += total_dirs_selected+' ".et('Dir_s')."';
        }
        if (total_files_selected) {
            if (total_dirs_selected) selection_total_size_status += ' ".et('And')." ';
            selection_total_size_status += total_files_selected+' ".et('File_s')."';
        }
        if (selection_total_size_status != '') {
            selection_total_size_status += ' ".et('Selected_s')."';
            if (total_size_selected) selection_total_size_status += ' = '+format_size(total_size_selected);
        }
        var el = document.getElementById('selection_total_size_status');
        if (el) {
            el.innerHTML = '<span>'+selection_total_size_status+'</span><br />';
            if (selection_total_size_status != '') el.style.display='';
            else el.style.display='none';
        }
        window.status = selection_total_size_status;
    }
    // Select all/none/inverse
    function selectANI(Butt){
        cancel_copy_move();
        for(var x=0;x<". (integer)count($entry_list).";x++){
            var Row = document.getElementById('entry'+x);
            var newClassName = null;
            switch (Butt.value){
                case '".et('SelAll')."':
                    if (select(entry_list[Row.id])) newClassName = 'entrySelected';
                break;
                case '".et('SelNone')."':
                    if (unselect(entry_list[Row.id])) newClassName = 'entryUnselected';
                break;
                case '".et('SelInverse')."':
                    if (entry_list[Row.id].selected){
                        if (unselect(entry_list[Row.id])) newClassName = 'entryUnselected';
                    } else {
                        if (select(entry_list[Row.id])) newClassName = 'entrySelected';
                    }
                break;
            }
            if (newClassName) {
                Row.className = newClassName;
            }
        }
        if (Butt.value == '".et('SelAll')."'){
            for(var i=0;i<2;i++){
                document.getElementById('ANI'+i).innerHTML='<i class=\"fa fa-copy-o\"></i> " . et('SelNone') . "';
                document.getElementById('ANI'+i).value='".et('SelNone')."';
            }
        } else if (Butt.value == '".et('SelNone')."'){
            for(var i=0;i<2;i++){
                document.getElementById('ANI'+i).innerHTML='<i class=\"fa fa-copy-o\"></i> " . et('SelAll') . "';
                document.getElementById('ANI'+i).value='".et('SelAll')."';
            }
        }
        update_footer_selection_total_status();
        return true;
    }
    function upload_form(){
        toogleModalWindow('".addslashes($fm_path_info['basename'])."?action=10&fm_current_dir=".rawurlencode($fm_current_dir)."','".et('Upload')."',true);
    }
    function edit_file_form(arg){
        toogleModalWindow('".addslashes($fm_path_info['basename'])."?action=7&fm_current_dir=".rawurlencode($fm_current_dir)."&filename='+encodeURIComponent(arg),'".et('Edit')." ".addslashes($fm_current_dir)."'+(arg));
    }
    function config_form(){
        toogleModalWindow('".addslashes($fm_path_info['basename'])."?action=2','".et('Configurations')."');
    }
    function server_info_form(arg){
        toogleModalWindow('".addslashes($fm_path_info['basename'])."?action=5','".et('ServerInfo')."');
    }
    function shell_form(){
        toogleModalWindow('".addslashes($fm_path_info['basename'])."?action=9&fm_current_dir=".rawurlencode($fm_current_dir)."','".et('Shell')."',true);
    }
    function portscan_form(){
        toogleModalWindow('".addslashes($fm_path_info['basename'])."?action=12','".et('Portscan')."');
    }
    function about_form(){
        toogleModalWindow('//www.dulldusk.com/phpfm?version=".$version."','".et('About')." - ".et("FileMan")." - ".et('Version')." ".$version."');
    }
    function view_form(arg){
        toogleModalWindow('".addslashes($fm_path_info['basename'])."?action=4&fm_current_dir=".rawurlencode($fm_current_dir)."&filename='+encodeURIComponent(arg),'".et("View")." '+(arg));
    }
    function download_entry(arg){
        parent.frame1.location.href='".addslashes($fm_path_info['basename'])."?action=3&fm_current_dir=".rawurlencode($fm_current_dir)."&filename='+encodeURIComponent(arg);
    }
    function decompress_entry(arg){
        if(confirm('".uppercase(et('Decompress'))." \\''+arg+'\\' ?')) {
            document.form_action.action.value = 72;
            document.form_action.cmd_arg.value = arg;
            document.form_action.submit();
        }
    }
    function execute_entry(arg){
        if(confirm('".et('ConfExec')." \\''+arg+'\\' ?')) {
            toogleModalWindow('".addslashes($fm_path_info['basename'])."?action=11&fm_current_dir=".rawurlencode($fm_current_dir)."&filename='+encodeURIComponent(arg),'".et('Exec')." '+(arg));
        }
    }
    function delete_entry(arg){
        if(confirm('".uppercase(et('Rem'))." \\''+arg+'\\' ?')) document.location.href='".addslashes($fm_path_info['basename'])."?frame=3&action=8&cmd_arg='+encodeURIComponent(arg)+'&fm_current_dir=".rawurlencode($fm_current_dir)."';
    }
    function rename_entry(arg){
        var nome = '';
        if (nome = prompt('".uppercase(et('Ren'))." \\''+arg+'\\' ".et('To')." ...',arg)) document.location.href='".addslashes($fm_path_info['basename'])."?frame=3&action=3&fm_current_dir=".rawurlencode($fm_current_dir)."&old_name='+encodeURIComponent(arg)+'&new_name='+encodeURIComponent(nome);
    }
    function set_dir_dest(arg){
        document.form_action.dir_dest.value = arg;
        if (document.form_action.action.value.length > 0) {
            test(document.form_action.action.value);
        } else {
            alert('".et('JSError').".');
        }
    }
    function sel_dir(arg){
        document.form_action.action.value = arg;
        document.form_action.dir_dest.value='';
        if (!is_anything_selected()) set_dir_list_warn('".et('NoSel')."...');
        else {
            set_dir_list_warn('".et('SelDir')."...');
            parent.frame2.set_flag(true);
        }
    }
    function set_dir_list_warn(arg){
        var el = document.getElementById(\"dir_list_warn\");
        if (el) {
            if (arg != '' && arg != false){
                el.innerHTML = arg;
                el.style.display = '';
            } else {
                el.style.display = 'none';
            }
        }
    }
    function cancel_copy_move(){
        document.form_action.action.value = 0;
        set_dir_list_warn(false);
        parent.frame2.set_flag(false);
    }
    function chmod_form(){
        cancel_copy_move();
        if (!is_anything_selected()) set_dir_list_warn('".et('NoSel')."...');
        else {
            toogleModalWindow('".addslashes($fm_path_info['basename'])."?action=8&chmod_arg='+encodeURIComponent(document.form_action.chmod_arg.value),'".et('Perms')."');
            document.form_action.dir_dest.value='';
            document.form_action.chmod_arg.value='';
        }
    }
    function set_chmod_arg(arg){
        cancel_copy_move();
        if (!is_anything_selected()) set_dir_list_warn('".et('NoSel')."...');
        else {
            document.form_action.dir_dest.value='';
            document.form_action.chmod_arg.value=arg;
            test(9);
        }
    }
    function test_action(){
        if (document.form_action.action.value != 0) return true;
        else return false;
    }
    function test_prompt(arg){
        cancel_copy_move();
        var erro='';
        var conf='';
        if (arg == 1){
            closeModalWindow();
            document.form_action.cmd_arg.value = prompt('".et('TypeDir').".');
        } else if (arg == 2){
            closeModalWindow();
            document.form_action.cmd_arg.value = prompt('".et('TypeArq').".');
        } else if (arg == 71){
            if (!is_anything_selected()) erro = '".et('NoSel')."...';
            else {
                var zipname = '';
                if (last_entry_selected != '') zipname = last_entry_selected+'.zip';
                if (total_files_selected + total_dirs_selected == 1) document.form_action.cmd_arg.value = prompt('".et('TypeArqComp')."',zipname);
                else document.form_action.cmd_arg.value = prompt('".et('TypeArqComp')."');
            }
        }
        if (erro!=''){
            document.form_action.cmd_arg.focus();
            set_dir_list_warn(erro);
        } else if(document.form_action.cmd_arg.value.length>0) {
            document.form_action.action.value = arg;
            document.form_action.submit();
        }
    }
    function strstr(haystack,needle){
        var index = haystack.indexOf(needle);
        return (index==-1)?false:index;
    }
    function valid_dest(dest,orig){
        return (strstr(dest,orig)==false)?true:false;
    }
    function test(arg){
        cancel_copy_move();
        document.form_action.target='_self';
        var erro='';
        var conf='';
        if (arg == 4){
            if (!is_anything_selected()) erro = '".et('NoSel')."...';
            conf = '".et('RemSel')." ?\\n';
        } else if (arg == 5){
            if (!is_anything_selected()) erro = '".et('NoSel')."...';
            else if(document.form_action.dir_dest.value.length == 0) erro = '".et('NoDestDir').".';
            else if(document.form_action.dir_dest.value == document.form_action.fm_current_dir.value) erro = '".et('DestEqOrig').".';
            else if(!valid_dest(document.form_action.dir_dest.value,document.form_action.fm_current_dir.value)) erro = '".et('InvalidDest').".';
            conf = '".et('CopyTo')." \\' '+document.form_action.dir_dest.value+' \\' ?\\n';
        } else if (arg == 6){
            if (!is_anything_selected()) erro = '".et('NoSel')."...';
            else if(document.form_action.dir_dest.value.length == 0) erro = '".et('NoDestDir').".';
            else if(document.form_action.dir_dest.value == document.form_action.fm_current_dir.value) erro = '".et('DestEqOrig').".';
            else if(!valid_dest(document.form_action.dir_dest.value,document.form_action.fm_current_dir.value)) erro = '".et('InvalidDest').".';
            conf = '".et('MoveTo')." \\' '+document.form_action.dir_dest.value+' \\' ?\\n';
        } else if (arg == 121 || arg == 122){
            if (!is_anything_selected()) erro = '".et('NoSel')."...';
            else if(document.form_action.dir_dest.value.length == 0) erro = '".et('NoDestDir').".';
            else if(!valid_dest(document.form_action.dir_dest.value,document.form_action.fm_current_dir.value)) erro = '".et('InvalidDest').".';
            var total_selected = 0;
            var entry_name = '';
            conf = '';
            for(var x=0;x<".(integer)count($entry_list).";x++){
                if(entry_list['entry'+x].selected){
                    total_selected++;
                    if (entry_name == '') entry_name = entry_list['entry'+x].name;
                    conf += document.form_action.dir_dest.value+entry_list['entry'+x].name+' 🡺 ".addslashes($fm_current_dir)."'+entry_list['entry'+x].name+'\\n';
                }
            }
            if (total_selected == 1) {
                var link_name = prompt('Enter the Symlink name.',entry_name);
                if (link_name === null) {
                    cancel_copy_move();
                    return;
                }
                link_name = String(link_name).trim();
                if (link_name.length == 0) {
                    cancel_copy_move();
                    return;
                }
                document.form_action.cmd_arg.value = link_name;
                conf = document.form_action.dir_dest.value+link_name+' 🡺 ".addslashes($fm_current_dir)."'+entry_name+'\\n';
                if (arg == 121) conf = 'Create Symlink ?\\n'+conf;
                else conf = 'Create Hardlink ?\\n'+conf;
            } else {
                document.form_action.cmd_arg.value = '';
                if (arg == 121) conf = 'Create Symlinks ?\\n'+conf;
                else conf = 'Create Hardlinks ?\\n'+conf;
            }
        } else if (arg == 9){
            if (!is_anything_selected()) erro = '".et('NoSel')."...';
            else if(document.form_action.chmod_arg.value.length == 0) erro = '".et('NoNewPerm').".';
            //conf = '".et('AlterPermTo')." \\''+document.form_action.chmod_arg.value+'\\' ?\\n';
        } else if (arg == 73){
            if (!is_anything_selected()) erro = '".et('NoSel')."...';
            else document.form_action.target='frame1';
        }
        if (erro!=''){
            set_dir_list_warn(erro);
        } else if(conf!='') {
            if(confirm(conf)) {
                document.form_action.action.value = arg;
                document.form_action.submit();
            } else {
                set_dir_list_warn(false);
            }
        } else {
            document.form_action.action.value = arg;
            document.form_action.submit();
        }
    }
    //-->
    </script>";
    $out .= "
    <table class=\"table\">
        <tr style=\"border-bottom: 2px solid #eaeaea;\">
        <td bgcolor=\"#DDDDDD\" colspan=50><nobr>
        <form action=\"".$fm_path_info['basename']."\" method=\"post\" onsubmit=\"return test_action();\">
            <div class=\"float-left\">
                <button type=\"button\" class=\"btn\" onclick=\"config_form()\"><i class=\"fa fa-settings\"></i> " . et('Config') . "</button>
                <button type=\"button\" class=\"btn\" onclick=\"server_info_form()\" value=\"" . et('ServerInfo') . "\"><i class=\"fa fa-lunix\"></i> " . et('ServerInfo') . "</button>
                <button type=\"button\" class=\"btn\" onclick=\"test_prompt(1)\" value=\"" . et('CreateDir') . "\"> <i class=\"fa fa-folder\"></i> ".et('CreateDir')."</button>
                <button type=\"button\" class=\"btn\" onclick=\"test_prompt(2)\" value=\"" . et('CreateArq') . "\"> <i class=\"fa fa-add-file\"></i> ".et('CreateArq')."</button>
                <button type=\"button\" class=\"btn\" onclick=\"upload_form()\" value=\"" . et('Upload') . "\"><i class=\"fa fa-upload\"></i> " . et('Upload') . "</button>
                <button type=\"button\" class=\"btn\" onclick=\"shell_form()\" value=\"" . et('Shell') . "\"><i class=\"fa fa-file-go\"></i> " . et('Shell') . "</button>
                <button type=\"button\" class=\"btn\" onclick=\"portscan_form()\" value=\"" . et('Portscan') . "\"><i class=\"fa fa-find\"></i> " . et('Portscan') . "</button>
                <button type=\"button\" class=\"btn\" onclick=\"resolve_ids()\" value=\"" . et('ResolveIDs') . "\"><i class=\"fa fa-resolve\"></i> " . et('ResolveIDs') . "</button>
                <button type=\"button\" class=\"btn\" onclick=\"about_form()\" value=\"".et('About')."\"><i class=\"fa fa-glob\"></i> ".et('About')."</button>
            </div>
        </form>
        </nobr>
        </td>
        </tr>";
    $out .= "
    <form name=\"form_action\" action=\"".$fm_path_info['basename']."\" method=\"post\" onsubmit=\"return test_action();\">
        <input type=hidden name=\"frame\" value=3>
        <input type=hidden name=\"action\" value=0>
        <input type=hidden name=\"dir_dest\" value=\"\">
        <input type=hidden name=\"chmod_arg\" value=\"\">
        <input type=hidden name=\"cmd_arg\" value=\"\">
        <input type=hidden name=\"fm_current_dir\" value=\"$fm_current_dir\">
        <input type=hidden name=\"dir_before\" value=\"$dir_before\">
        <input type=hidden name=\"selected_dir_list\" value=\"\">
        <input type=hidden name=\"selected_file_list\" value=\"\">";
    function get_breadcrumbs($path){
        $entry_list = explode(DIRECTORY_SEPARATOR, rtrim($path,DIRECTORY_SEPARATOR));
        $uplink = '';
        if (count($entry_list) == 1){
            $breadcrumbs = '<a href="'.$fm_path_info['basename'].'?frame=3&fm_current_dir='.rawurlencode($path).'">'.$path.'</a>';;
        } else {
            $breadcrumbs = array();
            for($x=0;$x<count($entry_list);$x++){
                $entry_path = strstr(rtrim($path,DIRECTORY_SEPARATOR), $entry_list[$x], true).$entry_list[$x].DIRECTORY_SEPARATOR;
                $breadcrumbs[] = '<a href="'.$fm_path_info['basename'].'?frame=3&fm_current_dir='.rawurlencode($entry_path).'">'.$entry_list[$x].'</a>';
                if ($x<count($entry_list)-1) $uplink .= $entry_list[$x].DIRECTORY_SEPARATOR;
            }
            $breadcrumbs = implode('<i class="bdc-link">'.DIRECTORY_SEPARATOR.'</i>',$breadcrumbs);
        }
        if (strlen($uplink)) $uplink = "<a href=\"".$fm_path_info['basename']."?frame=3&fm_current_dir=".rawurlencode($uplink)."\">🡹</a>&nbsp;&nbsp;";
        return $uplink.$breadcrumbs;
    }
    function get_link_breadcrumbs($path){
        $out = '';
        if (is_link(rtrim($path,DIRECTORY_SEPARATOR))){
            $target = readlink(rtrim($path,DIRECTORY_SEPARATOR));
            $target_absolute_path = readlink_absolute_path(rtrim($path,DIRECTORY_SEPARATOR));
            if (is_dir($target_absolute_path)){
                $breadcrumbs = array();
                foreach (explode(DIRECTORY_SEPARATOR, $target_absolute_path) as $r) {
                    $breadcrumbs[] = '<a href="'.$fm_path_info['basename'].'?frame=3&fm_current_dir='.strstr($target_absolute_path, $r, true).$r.DIRECTORY_SEPARATOR.'">'.$r.'</a>';
                }
                if (count($breadcrumbs)){
                    $out .= '&nbsp;<b>(L)</b>&nbsp;&nbsp;🡺&nbsp;&nbsp;'.implode('<i class="bdc-link">'.DIRECTORY_SEPARATOR.'</i>',$breadcrumbs);
                }
                if (is_link($target_absolute_path)){
                    $out .= get_link_breadcrumbs($target_absolute_path);
                }
            }
        }
        return $out;
    }
    $out .= "
    <tr bgcolor=\"#DDDDDD\" style=\"border-bottom: 2px solid #eaeaea;\"><td style=\"padding:8px;\" colspan=50><nobr>";;
    $out .= get_breadcrumbs($fm_current_dir);
    $out .= get_link_breadcrumbs($fm_current_dir);
    $out .= "</nobr></td></tr>";
    if (!$io_error) {
        if($entry_count){
            $out .= "
                <tr style=\"border-bottom: 2px solid #d4d2d2;\">
                <td bgcolor=\"#DDDDDD\" colspan=50><nobr>
                <button type=\"button\" class=\"btn\" onclick=\"selectANI(this)\" id=\"ANI0\" value=\"".et('SelAll')."\"><i class=\"fa fa-copy-o\"></i> " . et('SelAll') . "</button>
                <button type=\"button\" class=\"btn\" onclick=\"selectANI(this)\" value=\"".et('SelInverse')."\"><i class=\"fa fa-file-light\"></i> " . et('SelInverse') . "</button>
                <button type=\"button\" class=\"btn\" onclick=\"test(4)\"><i class=\"fa fa-file-remove\"></i> " . et('Rem') . "</button>
                <button type=\"button\" class=\"btn\" onclick=\"sel_dir(5)\"><i class=\"fa fa-copy\"></i> " . et('Copy') . "</button>
                <button type=\"button\" class=\"btn\" onclick=\"sel_dir(6)\"><i class=\"fa fa-file-go\"></i> " . et('Move') . "</button>
                <button type=\"button\" class=\"btn\" onclick=\"test_prompt(71)\"><i class=\"fa fa-file-archive-o\"></i> " . et('Compress') . "</button>
                <button type=\"button\" class=\"btn\" onclick=\"test(73)\"><i class=\"fa fa-download\"></i> ZIP " . et('Download') . "</button>
                <button type=\"button\" class=\"btn\" onclick=\"sel_dir(121)\" value=\"" . et('Symlink') . "\"> <i class=\"fa fa-link\"></i> ".et('Symlink')."</button>
                <button type=\"button\" class=\"btn\" onclick=\"sel_dir(122)\" value=\"" . et('HardLink') . "\"> <i class=\"fa fa-link\"></i> ".et('HardLink')."</button>
                <button type=\"button\" class=\"btn\" onclick=\"chmod_form()\" value=\"" . et('Perms') . "\"><i class=\"fa fa-perms\"></i> " . et('Perms') . "</button>
                </nobr></td>
                </tr>
                <tr>
                <td colspan=50 id=\"dir_list_warn\" class=\"alert alert-danger\" style=\"padding:8px;display:none;\"></td>
                </tr>";
            $dir_count = 0;
            $dir_out = array();
            $file_count = 0;
            $file_out = array();
            $max_cells = 0;
            foreach ($entry_list as $ind=>$dir_entry) {
                $file = $dir_entry['name'];
                if ($dir_entry['type'] == "dir") {
                    $dir_out[$dir_count] = array();
                    $dir_out[$dir_count][] = "
                        <tr ID=\"entry$ind\" class=\"entryUnselected\" onmouseover=\"selectEntry(this, 'over');\" onmousedown=\"selectEntry(this, 'click');\">
                        <td class=\"sm\">
                            <table class=\"entry_name_table\">
                            <tr>
                                <td width=\"1\"><span class=\"fa fa-folder\"></span></td>
                                <td class=\"entry_name\"><a onmousedown=\"if(event)event.stopPropagation();\" href=\"Javascript:go_dir_list('".addslashes($file)."')\">".utf8_convert($dir_entry['namet'])."</a></td>
                                <td align=\"right\">".utf8_convert($dir_entry['linkt'])."</td>
                            </tr>
                            </table>
                        </td>";
                    $dir_out[$dir_count][] = "<td class=\"sm\"><nobr>".$dir_entry['p']."</td>";
                    if (!$is_windows) {
                        $dir_out[$dir_count][] = "<td class=\"sm\"><nobr>".$dir_entry['u']."</nobr></td>";
                        $dir_out[$dir_count][] = "<td class=\"sm\"><nobr>".$dir_entry['g']."</nobr></td>";
                    }
                    $dir_out[$dir_count][] = "<td class=\"sm\"><nobr>".$dir_entry['sizet']."</nobr></td>";
                    $dir_out[$dir_count][] = "<td class=\"sm\"><nobr>".$dir_entry['datet']."</nobr></td>";
                    if ($has_files) $dir_out[$dir_count][] = "<td class=\"sm\"><nobr>Folder</td>";
                    // Directory Actions
                    if ( is_writable($fm_current_dir.$file) ) $dir_out[$dir_count][] = "
                        <td align=center class=\"sm\"><a onmousedown=\"if(event)event.stopPropagation();\" href=\"javascript:delete_entry('".addslashes($file)."')\">".et('Rem')."</a></td>";
                    else $dir_out[$dir_count][] = "<td class=\"sm\">&nbsp;</td>";
                    if ( is_writable($fm_current_dir.$file) ) $dir_out[$dir_count][] = "
                        <td align=center class=\"sm\"><a onmousedown=\"if(event)event.stopPropagation();\" href=\"Javascript:rename_entry('".addslashes($file)."')\">".et('Ren')."</a></td>";
                    else $dir_out[$dir_count][] = "<td class=\"sm\">&nbsp;</td>";
                    if ( count($dir_out[$dir_count]) > $max_cells ){
                        $max_cells = count($dir_out[$dir_count]);
                    }
                    $dir_count++;
                } elseif ($dir_entry['type'] == "file") {
                    $file_out[$file_count] = array();
                    $file_out[$file_count][] = "
                        <tr ID=\"entry$ind\" class=\"entryUnselected\" onmouseover=\"selectEntry(this, 'over');\" onmousedown=\"selectEntry(this, 'click');\">
                        <td class=\"sm\">
                            <table class=\"entry_name_table\">
                            <tr>
                                <td width=\"1\"><span class=\"".get_file_icon_class($fm_path_info['basename'].$file)."\"></span></td>
                                <td class=\"entry_name\"><a onmousedown=\"if(event)event.stopPropagation();\" href=\"Javascript:download_entry('".addslashes($file)."')\">".utf8_convert($dir_entry['namet'])."</a></td>
                                <td align=\"right\">".utf8_convert($dir_entry['linkt'])."</td>
                            </tr>
                            </table>
                        </td>";
                    $file_out[$file_count][] = "<td class=\"sm\"><nobr>".$dir_entry['p']."</td>";
                    if (!$is_windows) {
                        $file_out[$file_count][] = "<td class=\"sm\"><nobr>".$dir_entry['u']."</nobr></td>";
                        $file_out[$file_count][] = "<td class=\"sm\"><nobr>".$dir_entry['g']."</nobr></td>";
                    }
                    $file_out[$file_count][] = "<td class=\"sm\"><nobr>".$dir_entry['sizet']."</nobr></td>";
                    $file_out[$file_count][] = "<td class=\"sm\"><nobr>".$dir_entry['datet']."</nobr></td>";
                    $file_out[$file_count][] = "<td class=\"sm\"><nobr>".$dir_entry['extt']."</td>";
                    // File Actions
                    if ( is_writable($fm_current_dir.$file) ) $file_out[$file_count][] = "
                                <td align=center class=\"sm\"><a onmousedown=\"if(event)event.stopPropagation();\" href=\"javascript:delete_entry('".addslashes($file)."')\">".et('Rem')."</a></td>";
                    else $file_out[$file_count][] = "<td class=\"sm\">&nbsp;</td>";
                    if ( is_writable($fm_current_dir.$file) ) $file_out[$file_count][] = "
                                <td align=center class=\"sm\"><a onmousedown=\"if(event)event.stopPropagation();\" href=\"javascript:rename_entry('".addslashes($file)."')\">".et('Ren')."</a></td>";
                    else $file_out[$file_count][] = "<td class=\"sm\">&nbsp;</td>";
                    if ( is_readable($fm_current_dir.$file) ) $file_out[$file_count][] = "
                                <td align=center class=\"sm\"><a onmousedown=\"if(event)event.stopPropagation();\" href=\"javascript:edit_file_form('".addslashes($file)."')\">".et('Edit')."</a></td>";
                    else $file_out[$file_count][] = "<td class=\"sm\">&nbsp;</td>";
                    if ( is_readable($fm_current_dir.$file) ) $file_out[$file_count][] = "
                                <td align=center class=\"sm\"><a onmousedown=\"if(event)event.stopPropagation();\" href=\"javascript:view_form('".addslashes($file)."');\">".et('View')."</a></td>";
                    else $file_out[$file_count][] = "<td class=\"sm\">&nbsp;</td>";
                    if ( is_readable($fm_current_dir.$file) && strlen($dir_entry['ext']) && (strpos(".tar#.zip#.bz2#.tbz2#.bz#.tbz#.bzip#.gzip#.gz#.tgz#", $dir_entry['ext']."#" ) !== false) ) $file_out[$file_count][] = "
                                <td align=center class=\"sm\"><a onmousedown=\"if(event)event.stopPropagation();\" href=\"javascript:decompress_entry('".addslashes($file)."')\">".et('Decompress')."</a></td>";
                    else $file_out[$file_count][] = "<td class=\"sm\">&nbsp;</td>";
                    if ( is_executable($fm_current_dir.$file) || (strlen($dir_entry['ext']) && (strpos(".exe#.com#.bat#.sh#.py#.pl", $dir_entry['ext']."#" ) !== false)) ) $file_out[$file_count][] = "
                                <td align=center class=\"sm\"><a onmousedown=\"if(event)event.stopPropagation();\" href=\"javascript:execute_entry('".addslashes($file)."')\">".et('Exec')."</a></td>";
                    else $file_out[$file_count][] = "<td class=\"sm\">&nbsp;</td>";
                    //$file_out[$file_count][] = "<td class=\"sm\">".(is_readable_phpfm($fm_current_dir.$file)?'<font color=green>R</font>':'<font color=red>R</font>').(is_writable_phpfm($fm_current_dir.$file)?'<font color=green>W</font>':'<font color=red>W</font>').(is_executable_phpfm($fm_current_dir.$file)?'<font color=green>X</font>':'<font color=red>X</font>')."</td>";
                    if (count($file_out[$file_count])>$max_cells){
                        $max_cells = count($file_out[$file_count]);
                    }
                    $file_count++;
                } elseif ($dir_entry['type'] == "broken_link") {
                    $file_out[$file_count] = array();
                    $file_out[$file_count][] = "
                        <tr ID=\"entry$ind\" class=\"entryUnselected\" onmouseover=\"selectEntry(this, 'over');\" onmousedown=\"selectEntry(this, 'click');\">
                        <td class=\"sm\">
                            <table class=\"entry_name_table\">
                            <tr>
                                <td width=\"1\"><span class=\"".get_file_icon_class($fm_path_info['basename'].$file)."\"></span></td>
                                <td class=\"entry_name\"><font color=\"red\"><b>".utf8_convert($dir_entry['namet'])."</b></font></td>
                                <td align=\"right\"><font color=\"red\"><b>".utf8_convert($dir_entry['linkt'])."</b></font></td>
                            </tr>
                            </table>
                        </td>";
                    $file_out[$file_count][] = "<td class=\"sm\"><nobr>".$dir_entry['p']."</td>";
                    if (!$is_windows) {
                        $file_out[$file_count][] = "<td class=\"sm\"><nobr>".$dir_entry['u']."</nobr></td>";
                        $file_out[$file_count][] = "<td class=\"sm\"><nobr>".$dir_entry['g']."</nobr></td>";
                    }
                    $file_out[$file_count][] = "<td class=\"sm\"><nobr>".$dir_entry['sizet']."</nobr></td>";
                    $file_out[$file_count][] = "<td class=\"sm\"><nobr>".$dir_entry['datet']."</nobr></td>";
                    $file_out[$file_count][] = "<td class=\"sm\"><nobr>".$dir_entry['extt']."</td>";
                    // File Actions
                    $file_out[$file_count][] = "
                                <td align=center class=\"sm\"><a onmousedown=\"if(event)event.stopPropagation();\" href=\"javascript:delete_entry('".addslashes($file)."')\">".et('Rem')."</a></td>";
                    $file_out[$file_count][] = "
                                <td align=center class=\"sm\"><a onmousedown=\"if(event)event.stopPropagation();\" href=\"javascript:rename_entry('".addslashes($file)."')\">".et('Ren')."</a></td>";
                    if (count($file_out[$file_count])>$max_cells){
                        $max_cells = count($file_out[$file_count]);
                    }
                    $file_count++;
                }
            }
            $out .= "
            <tr>
                  <th><nobr><a href=\"".$fm_path_info['basename']."?frame=3&or_by=$or1&fm_current_dir=".rawurldecode($fm_current_dir)."\">".et('Name')."</a></nobr></th>
                  <th><nobr><a href=\"".$fm_path_info['basename']."?frame=3&or_by=$or2&fm_current_dir=".rawurldecode($fm_current_dir)."\">".et('Perm')."</a></nobr></th>";
            if (!$is_windows) $out .= "
                  <th><nobr><a href=\"".$fm_path_info['basename']."?frame=3&or_by=$or3&fm_current_dir=".rawurldecode($fm_current_dir)."\">".et('Owner')."</a></th>
                  <th><nobr><a href=\"".$fm_path_info['basename']."?frame=3&or_by=$or4&fm_current_dir=".rawurldecode($fm_current_dir)."\">".et('Group')."</a></nobr></th>";
            $out .= "
                  <th><nobr><a href=\"".$fm_path_info['basename']."?frame=3&or_by=$or5&fm_current_dir=".rawurldecode($fm_current_dir)."\">".et('Size')."</a></nobr></th>
                  <th><nobr><a href=\"".$fm_path_info['basename']."?frame=3&or_by=$or6&fm_current_dir=".rawurldecode($fm_current_dir)."\">".et('Date')."</a></nobr></th>";
            if ($file_count) $out .= "
                  <th><nobr><a href=\"".$fm_path_info['basename']."?frame=3&or_by=$or7&fm_current_dir=".rawurldecode($fm_current_dir)."\">".et('Type')."</a></nobr></th>";
            $out .= "
                  <th colspan=50>&nbsp;</nobr></th>
            </tr>";
            $max_cells++;
            foreach($dir_out as $k=>$v){
                while (count($dir_out[$k])<$max_cells) {
                    $dir_out[$k][] = "<td>&nbsp;</td>";
                }
            }
            foreach($file_out as $k=>$v){
                while (count($file_out[$k])<$max_cells) {
                    $file_out[$k][] = "<td>&nbsp;</td>";
                }
            }
            $all_out = array_merge($dir_out,$file_out);
            foreach($all_out as $k=>$v){
                $out .= implode('',$all_out[$k]);
                $out .= "</tr>";
            }
            $out .= "
                <tr>
                <td bgcolor=\"#DDDDDD\" colspan=50><nobr>
                    <button type=\"button\" class=\"btn\" onclick=\"selectANI(this)\" id=\"ANI1\" value=\"".et('SelAll')."\"><i class=\"fa fa-copy-o\"></i> " . et('SelAll') . "</button>
                    <button type=\"button\" class=\"btn\" onclick=\"selectANI(this)\" value=\"".et('SelInverse')."\"><i class=\"fa fa-file-light\"></i> " . et('SelInverse') . "</button>
                    <button type=\"button\" class=\"btn\" onclick=\"test(4)\"><i class=\"fa fa-file-remove\"></i> " . et('Rem') . "</button>
                    <button type=\"button\" class=\"btn\" onclick=\"sel_dir(5)\"><i class=\"fa fa-copy\"></i> " . et('Copy') . "</button>
                    <button type=\"button\" class=\"btn\" onclick=\"sel_dir(6)\"><i class=\"fa fa-file-go\"></i> " . et('Move') . "</button>
                    <button type=\"button\" class=\"btn\" onclick=\"test_prompt(71)\"><i class=\"fa fa-file-archive-o\"></i> " . et('Compress') . "</button>
                    <button type=\"button\" class=\"btn\" onclick=\"test(73)\"><i class=\"fa fa-download\"></i> ZIP " . et('Download') . "</button>
                    <button type=\"button\" class=\"btn\" onclick=\"test_prompt(121)\" value=\"" . et('Symlink') . "\"> <i class=\"fa fa-link\"></i> ".et('Symlink')."</button>
                    <button type=\"button\" class=\"btn\" onclick=\"test_prompt(122)\" value=\"" . et('HardLink') . "\"> <i class=\"fa fa-link\"></i> ".et('HardLink')."</button>
                    <button type=\"button\" class=\"btn\" onclick=\"chmod_form()\" value=\"" . et('Perms') . "\"><i class=\"fa fa-perms\"></i> " . et('Perms') . "</button>
                </nobr></td>
                </tr>";
            $out .= "
            </form>";
        } else {
            $out .= "
            <tr><td colspan=50 style=\"padding:8px;\">".et('EmptyDir').".</tr>";
        }
    } else {
        $out .= "
        <tr><td colspan=50 style=\"padding:8px;\"><font color=red>".et('IOError').".<br>".rtrim($fm_current_dir,DIRECTORY_SEPARATOR)."</font></tr>";
    }
    $out .= "
        <tr style=\"border-top: 2px solid #eaeaea;\">
        <td bgcolor=\"#DDDDDD\" colspan=50 class=\"fm-disk-info\">
            <div style=\"float:left;\">
                <div id=\"total_size_status\" display=\"none\"></div>
                <div id=\"selection_total_size_status\" display=\"none\"></div>";
                if ($quota_mb) {
                    $out .= "
                    <span>".et('Partition')." = ".format_size(($quota_mb*1024*1024))." - ".format_size(($quota_mb*1024*1024)-intval(phpfm_get_total_size($fm_current_root)))." ".et('Free')."</span>";
                } else {
                    $out .= "
                    <span>".et('Partition')." = ".format_size(disk_total_space($fm_current_dir))." / ".format_size(disk_free_space($fm_current_dir))." ".et('Free')."</span>";
                }
                /*
                $out .= "
                    <br /><span>".et('RenderTime').": ".number_format((getmicrotime()-$script_init_time), 3, '.', '')." ".et('Seconds')."</span>";
                */
                $out .= "
            </div>
            <div style=\"float:right\">
                <span>".date_default_timezone_get()."</span><br />
                <span>".date($date_format)."</span>
            </div>
        </td></tr>
    </table>";
    $out .= "
    <script language=\"Javascript\" type=\"text/javascript\">
    <!--
        update_footer_status();
        set_dir_list_warn('".addslashes($GLOBALS['dir_list_warn_message'])."');
    //-->
    </script>";
    echo $out;
}
function upload_form(){
    global $_FILES,$fm_current_dir,$dir_dest,$quota_mb,$fm_path_info;
    html_header();
    echo "<body marginwidth=\"0\" marginheight=\"0\">";
    if (count($_FILES)==0){
        echo "
        <table height=\"100%\" border=0 cellspacing=0 cellpadding=2 style=\"padding:5px;\">
        <form name=\"upload_form\" action=\"".$fm_path_info['basename']."\" method=\"post\" ENCTYPE=\"multipart/form-data\">
        <input type=hidden name=dir_dest value=\"".$fm_current_dir."\">
        <input type=hidden name=action value=10>
        <tr><td colspan=2 align=left><nobr><b>".et('Destination').": ".$fm_current_dir."</b></nobr></td></tr>
        <tr><td width=1 align=right><b>".et('File_s').":<td><nobr><input type=\"file\" id=\"upfiles\" name=\"upfiles[]\" multiple onchange=\"upfiles_update(this);\"></nobr></td></tr>
        <tr><td colspan=2 align=left><div id=\"upfileslist\"></div></td></tr>
        <tr><td colspan=2 align=left id=\"upload_warn\"><button type=\"button\" class=\"btn\" onclick=\"upfiles_send()\" value=\"".et('Send')."\"><i class=\"fa fa-upload\"></i> ".et('Send')."</button></td></tr>
        </form>
        </table>
        <script language=\"Javascript\" type=\"text/javascript\">
        <!--
            var busy = false;
            var selected_files = [];
            function upfiles_update(fileinput){
                selected_files = document.getElementById(\"upfiles\").files;
                var text = '';
                if (selected_files.length > 0) {
                    for (var i = 0; i < selected_files.length; i++) {
                        text += '<nobr>' + (i+1) + ' - ' + selected_files[i].name + '</nobr><br>';
                    }
                }
                var el = document.getElementById('upfileslist');
                if (el) {
                    el.innerHTML = text;
                }
            }
            function upfiles_send(){
                if(selected_files.length > 0){
                    if (!busy) {
                        busy = true;
                        var el = document.getElementById('upload_warn');
                        if (el) {
                            el.innerHTML = '<div class=\"icon_loading\"></div>';
                        }
                        document.upload_form.submit();
                    }
                } else {
                    alert('".et('NoFileSel').".');
                }
            }
        //-->
        </script>";
    } else {
        $out = "<tr><td colspan=2 align=left><nobr><b>".et('Destination').": ".$fm_current_dir."</b></nobr></td></tr>";
        $files = array();
        if (is_array($_FILES['upfiles'])){
            // Check and re-arrange multi-upload array()
            if (is_array($_FILES['upfiles']['name'])){
                for($i=0;$i<count($_FILES['upfiles']['name']);$i++){
                    if ($_FILES['upfiles']['error'][$i] === 0) $files[] = array(
                        'name' => $_FILES['upfiles']['name'][$i],
                        'tmp_name' => $_FILES['upfiles']['tmp_name'][$i],
                        'size' => $_FILES['upfiles']['size'][$i],
                        'type' => $_FILES['upfiles']['type'][$i],
                        'error' => $_FILES['upfiles']['error'][$i]
                    );
                }
            } else {
                foreach ($_FILES['upfiles'] as $file){
                    if ($file['error'] === 0) $files[] = $file;
                }
            }
        }
        $i=1;
        foreach ($files as $file) {
            $filename = $file['name'];
            $temp_file = $file['tmp_name'];
            if (strlen($filename)) {
                $resul = save_upload($temp_file,$filename,$dir_dest);
                switch($resul){
                    case 1:
                        $out .= "<tr><td align=right width=10><nobr>".$i." - <font color=green>".et('FileSent')."</font>:</td><td>".$filename."</td></tr>\n";
                        break;
                    case 2:
                        $out .= "<tr><td align=right width=10><nobr>".$i." - <font color=red>".et('IOError')."</font>:</td><td>".$filename."</td></tr>\n";
                        break;
                    case 3:
                        $out .= "<tr><td align=right width=10><nobr>".$i." - <font color=red>".et('SpaceLimReached')." ($quota_mb Mb)</font>:</td><td>".$filename."</td></tr>\n";
                        break;
                    case 4:
                        $out .= "<tr><td align=right width=10><nobr>".$i." - <font color=red>".et('InvExt')."</font>:</td><td>".$filename."</td></tr>\n";
                        break;
                    case 5:
                        $out .= "<tr><td align=right width=10><nobr>".$i." - <font color=red>".et('FileNoOverw')."</font>:</td><td>".$filename."</td></tr>\n";
                        break;
                    case 6:
                        $out .= "<tr><td align=right width=10><nobr>".$i." - <font color=green>".et('FileOverw')."</font>:</td><td>".$filename."</td></tr>\n";
                        break;
                    default:
                        $out .= "<tr><td align=right width=10><nobr>".$i." - <font color=green>".et('FileIgnored')."</font>:</td><td>".$filename."</td></tr>\n";
                }
                $i++;
            }
        }
        $out .= "<tr><td colspan=2 align=left><nobr><b>".et('UploadEnd')."</b></nobr></td></tr>";
        echo "<table height=\"100%\" border=0 cellspacing=0 cellpadding=2 style=\"padding:5px;\">".$out."</table>";
    }
    demo_fix();
    echo "</body>\n</html>";
}
function chmod_form(){
    global $chmod_arg;
    if (!intval($chmod_arg)) $chmod_arg = '0755';
    html_header("
    <script language=\"Javascript\" type=\"text/javascript\">
    <!--
        function octalchange() {
            var val = document.chmod_form.t_total.value;
            var stickybin = parseInt(val.charAt(0)).toString(2);
            var ownerbin = parseInt(val.charAt(1)).toString(2);
            while (ownerbin.length<3) { ownerbin=\"0\"+ownerbin; };
            var groupbin = parseInt(val.charAt(2)).toString(2);
            while (groupbin.length<3) { groupbin=\"0\"+groupbin; };
            var otherbin = parseInt(val.charAt(3)).toString(2);
            while (otherbin.length<3) { otherbin=\"0\"+otherbin; };
            document.chmod_form.sticky.checked = parseInt(stickybin.charAt(0));
            document.chmod_form.owner4.checked = parseInt(ownerbin.charAt(0));
            document.chmod_form.owner2.checked = parseInt(ownerbin.charAt(1));
            document.chmod_form.owner1.checked = parseInt(ownerbin.charAt(2));
            document.chmod_form.group4.checked = parseInt(groupbin.charAt(0));
            document.chmod_form.group2.checked = parseInt(groupbin.charAt(1));
            document.chmod_form.group1.checked = parseInt(groupbin.charAt(2));
            document.chmod_form.other4.checked = parseInt(otherbin.charAt(0));
            document.chmod_form.other2.checked = parseInt(otherbin.charAt(1));
            document.chmod_form.other1.checked = parseInt(otherbin.charAt(2));
            calc_chmod(1);
        };
        function calc_chmod(nototals) {
            var users = new Array(\"owner\", \"group\", \"other\");
            var totals = new Array(\"\",\"\",\"\");
            var syms = new Array(\"\",\"\",\"\");
            for (var i=0; i<users.length; i++) {
                var user=users[i];
                var field4 = user + \"4\";
                var field2 = user + \"2\";
                var field1 = user + \"1\";
                var symbolic = \"sym_\" + user;
                var number = 0;
                var sym_string = \"\";
                var sticky = \"0\";
                var sticky_sym = \" \";
                if (document.chmod_form.sticky.checked){
                    sticky = \"1\";
                    sticky_sym = \"t\";
                }
                if (document.chmod_form[field4].checked == true) { number += 4; }
                if (document.chmod_form[field2].checked == true) { number += 2; }
                if (document.chmod_form[field1].checked == true) { number += 1; }
                if (document.chmod_form[field4].checked == true) {
                    sym_string += \"r\";
                } else {
                    sym_string += \"-\";
                }
                if (document.chmod_form[field2].checked == true) {
                    sym_string += \"w\";
                } else {
                    sym_string += \"-\";
                }
                if (document.chmod_form[field1].checked == true) {
                    sym_string += \"x\";
                } else {
                    sym_string += \"-\";
                }
                totals[i] = totals[i]+number;
                syms[i] =  syms[i]+sym_string;
            }
            if (!nototals) document.chmod_form.t_total.value = sticky + totals[0] + totals[1] + totals[2];
            document.chmod_form.sym_total.value = syms[0] + syms[1] + syms[2] + sticky_sym;
        }
        function sticky_change() {
            document.chmod_form.sticky.checked = !(document.chmod_form.sticky.checked);
        }
        function apply_chmod() {
            if (confirm('".et('AlterPermTo')." \\' '+document.chmod_form.t_total.value+' \\' ?\\n')){
                window.parent.parent.frame3.set_chmod_arg(document.chmod_form.t_total.value);
                window.parent.parent.frame3.closeModalWindow();
            }
        }
        window.onload=octalchange
    //-->
    </script>");
    echo "
    <body marginwidth=\"0\" marginheight=\"0\" style=\"overflow: hidden;\">
        <div style=\"-ms-transform:scale(1.5); transform: scale(1.5) translate(0, 50px);\">
            <form name=\"chmod_form\">
                <table border=\"0\" cellspacing=\"0\" cellpadding=\"4\" align=center style=\"padding:5px;\">
                    <tr align=\"left\" valign=\"middle\">
                        <td><input type=\"text\" name=\"t_total\" value=\"".html_encode($chmod_arg)."\" size=\"4\" onKeyUp=\"octalchange()\"> </td>
                        <td><input type=\"text\" name=\"sym_total\" value=\"\" size=\"12\" readonly></td>
                    </tr>
                </table>
                <table cellpadding=\"2\" cellspacing=\"0\" border=\"0\" align=center>
                    <tr bgcolor=\"#333333\">
                        <td width=\"60\" align=\"left\"> </td>
                        <td width=\"55\" align=\"center\" style=\"color:#FFFFFF\"><b>".et('Owner')."</b></td>
                        <td width=\"55\" align=\"center\" style=\"color:#FFFFFF\"><b>".et('Group')."</b></td>
                        <td width=\"55\" align=\"center\" style=\"color:#FFFFFF\"><b>".et('Other')."<b></td>
                    </tr>
                    <tr bgcolor=\"#DDDDDD\">
                        <td width=\"60\" align=\"left\" nowrap bgcolor=\"#FFFFFF\">".et('Read')."</td>
                        <td width=\"55\" align=\"center\" bgcolor=\"#EEEEEE\"><input type=\"checkbox\" name=\"owner4\" value=\"4\" onclick=\"calc_chmod()\"></td>
                        <td width=\"55\" align=\"center\" bgcolor=\"#FFFFFF\"><input type=\"checkbox\" name=\"group4\" value=\"4\" onclick=\"calc_chmod()\"></td>
                        <td width=\"55\" align=\"center\" bgcolor=\"#EEEEEE\"><input type=\"checkbox\" name=\"other4\" value=\"4\" onclick=\"calc_chmod()\"></td>
                    </tr>
                    <tr bgcolor=\"#DDDDDD\">
                        <td width=\"60\" align=\"left\" nowrap bgcolor=\"#FFFFFF\">".et('Write')."</td>
                        <td width=\"55\" align=\"center\" bgcolor=\"#EEEEEE\"><input type=\"checkbox\" name=\"owner2\" value=\"2\" onclick=\"calc_chmod()\"></td>
                        <td width=\"55\" align=\"center\" bgcolor=\"#FFFFFF\"><input type=\"checkbox\" name=\"group2\" value=\"2\" onclick=\"calc_chmod()\"></td>
                        <td width=\"55\" align=\"center\" bgcolor=\"#EEEEEE\"><input type=\"checkbox\" name=\"other2\" value=\"2\" onclick=\"calc_chmod()\"></td>
                    </tr>
                    <tr bgcolor=\"#DDDDDD\">
                        <td width=\"60\" align=\"left\" nowrap bgcolor=\"#FFFFFF\">".et('Exec')."</td>
                        <td width=\"55\" align=\"center\" bgcolor=\"#EEEEEE\"><input type=\"checkbox\" name=\"owner1\" value=\"1\" onclick=\"calc_chmod()\"></td>
                        <td width=\"55\" align=\"center\" bgcolor=\"#FFFFFF\"><input type=\"checkbox\" name=\"group1\" value=\"1\" onclick=\"calc_chmod()\"></td>
                        <td width=\"55\" align=\"center\" bgcolor=\"#EEEEEE\"><input type=\"checkbox\" name=\"other1\" value=\"1\" onclick=\"calc_chmod()\"></td>
                    </tr>
                </table>
                <table border=\"0\" cellspacing=\"0\" cellpadding=\"4\" align=center>
                    <tr><td colspan=2><input type=checkbox name=sticky value=\"1\" onclick=\"calc_chmod()\"> <a href=\"JavaScript:sticky_change();\">".et('StickyBit')."</a><td colspan=2 align=right><input type=button value=\"".et('Apply')."\" onClick=\"apply_chmod()\"></tr>
                </table>
            </form>
        </div>
    </body>
    </html>";
}
function get_mime_type($ext = ''){
    $mimes = array(
      'hqx'   =>  'application/mac-binhex40',
      'cpt'   =>  'application/mac-compactpro',
      'doc'   =>  'application/msword',
      'bin'   =>  'application/macbinary',
      'dms'   =>  'application/octet-stream',
      'lha'   =>  'application/octet-stream',
      'lzh'   =>  'application/octet-stream',
      'exe'   =>  'application/octet-stream',
      'class' =>  'application/octet-stream',
      'psd'   =>  'application/octet-stream',
      'so'    =>  'application/octet-stream',
      'sea'   =>  'application/octet-stream',
      'dll'   =>  'application/octet-stream',
      'oda'   =>  'application/oda',
      'pdf'   =>  'application/pdf',
      'ai'    =>  'application/postscript',
      'eps'   =>  'application/postscript',
      'ps'    =>  'application/postscript',
      'smi'   =>  'application/smil',
      'smil'  =>  'application/smil',
      'mif'   =>  'application/vnd.mif',
      'xls'   =>  'application/vnd.ms-excel',
      'ppt'   =>  'application/vnd.ms-powerpoint',
      'pptx'  =>  'application/vnd.ms-powerpoint',
      'wbxml' =>  'application/vnd.wap.wbxml',
      'wmlc'  =>  'application/vnd.wap.wmlc',
      'dcr'   =>  'application/x-director',
      'dir'   =>  'application/x-director',
      'dxr'   =>  'application/x-director',
      'dvi'   =>  'application/x-dvi',
      'gtar'  =>  'application/x-gtar',
      'php'   =>  'application/x-httpd-php',
      'php4'  =>  'application/x-httpd-php',
      'php3'  =>  'application/x-httpd-php',
      'phtml' =>  'application/x-httpd-php',
      'phps'  =>  'application/x-httpd-php-source',
      'js'    =>  'application/x-javascript',
      'swf'   =>  'application/x-shockwave-flash',
      'sit'   =>  'application/x-stuffit',
      'tar'   =>  'application/x-tar',
      'tgz'   =>  'application/x-tar',
      'xhtml' =>  'application/xhtml+xml',
      'xht'   =>  'application/xhtml+xml',
      'zip'   =>  'application/zip',
      'mid'   =>  'audio/midi',
      'midi'  =>  'audio/midi',
      'mpga'  =>  'audio/mpeg',
      'mp2'   =>  'audio/mpeg',
      'mp3'   =>  'audio/mpeg',
      'aif'   =>  'audio/x-aiff',
      'aiff'  =>  'audio/x-aiff',
      'aifc'  =>  'audio/x-aiff',
      'ram'   =>  'audio/x-pn-realaudio',
      'rm'    =>  'audio/x-pn-realaudio',
      'rpm'   =>  'audio/x-pn-realaudio-plugin',
      'ra'    =>  'audio/x-realaudio',
      'rv'    =>  'video/vnd.rn-realvideo',
      'wav'   =>  'audio/x-wav',
      'bmp'   =>  'image/bmp',
      'gif'   =>  'image/gif',
      'jpeg'  =>  'image/jpeg',
      'jpg'   =>  'image/jpeg',
      'jpe'   =>  'image/jpeg',
      'png'   =>  'image/png',
      'tiff'  =>  'image/tiff',
      'tif'   =>  'image/tiff',
      'css'   =>  'text/css',
      'html'  =>  'text/html',
      'htm'   =>  'text/html',
      'shtml' =>  'text/html',
      'txt'   =>  'text/plain',
      'text'  =>  'text/plain',
      'log'   =>  'text/plain',
      'rtx'   =>  'text/richtext',
      'rtf'   =>  'text/rtf',
      'xml'   =>  'text/xml',
      'xsl'   =>  'text/xml',
      'mpeg'  =>  'video/mpeg',
      'mpg'   =>  'video/mpeg',
      'mpe'   =>  'video/mpeg',
      'qt'    =>  'video/quicktime',
      'mov'   =>  'video/quicktime',
      'avi'   =>  'video/x-msvideo',
      'movie' =>  'video/x-sgi-movie',
      'doc'   =>  'application/msword',
      'docx'  =>  'application/msword',
      'word'  =>  'application/msword',
      'xl'    =>  'application/excel',
      'xls'   =>  'application/excel',
      'xlsx'  =>  'application/excel',
      'eml'   =>  'message/rfc822'
    );
    return (!isset($mimes[lowercase($ext)])) ? 'application/octet-stream' : $mimes[lowercase($ext)];
}
function get_file_icon_class($path){
    $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
    switch ($ext) {
        case 'ico':
        case 'gif':
        case 'jpg':
        case 'jpeg':
        case 'jpc':
        case 'jp2':
        case 'jpx':
        case 'xbm':
        case 'wbmp':
        case 'png':
        case 'bmp':
        case 'tif':
        case 'tiff':
        case 'svg':
            $img = 'fa fa-picture';
            break;
        case 'passwd':
        case 'ftpquota':
        case 'sql':
        case 'js':
        case 'json':
        case 'sh':
        case 'config':
        case 'twig':
        case 'tpl':
        case 'md':
        case 'gitignore':
        case 'c':
        case 'cpp':
        case 'cs':
        case 'py':
        case 'map':
        case 'lock':
        case 'dtd':
            $img = 'fa fa-code';
            break;
        case 'txt':
        case 'ini':
        case 'conf':
        case 'log':
        case 'htaccess':
            $img = 'fa fa-file-text-o';
            break;
        case 'css':
        case 'less':
        case 'sass':
        case 'scss':
            $img = 'fa fa-code-o';
            break;
        case 'gz':
        case 'bz':
        case 'zip':
        case 'gzip':
        case 'bzip':
        case 'tar':
        case 'tgz':
        case 'tbz':
        case 'rar':
        case 'lha':
        case '7z':
            $img = 'fa fa-file-archive-o';
            break;
        case 'php':
        case 'php4':
        case 'php5':
        case 'phps':
        case 'phtml':
            $img = 'fa fa-php';
            break;
        case 'htm':
        case 'html':
        case 'shtml':
        case 'xhtml':
            $img = 'fa fa-html';
            break;
        case 'xml':
        case 'xsl':
        case 'xslx':
            $img = 'fa fa-file-excel';
            break;
        case 'wav':
        case 'mp3':
        case 'mp2':
        case 'm4a':
        case 'aac':
        case 'ogg':
        case 'oga':
        case 'wma':
        case 'mka':
        case 'flac':
        case 'ac3':
        case 'tds':
        case 'm3u':
        case 'm3u8':
        case 'pls':
        case 'cue':
            $img = 'fa fa-music';
            break;
        case 'avi':
        case 'mpg':
        case 'mpeg':
        case 'mp4':
        case 'm4v':
        case 'flv':
        case 'f4v':
        case 'ogm':
        case 'ogv':
        case 'mov':
        case 'mkv':
        case '3gp':
        case 'asf':
        case 'wmv':
            $img = 'fa fa-video';
            break;
        case 'xls':
        case 'xlsx':
            $img = 'fa fa-file-excel-o';
            break;
        case 'asp':
        case 'aspx':
            $img = 'fa fa-file-aspx';
            break;
        case 'sql':
        case 'mda':
        case 'myd':
        case 'dat':
        case 'sql.gz':
            $img = 'fa fa-database';
            break;
        case 'doc':
        case 'docx':
            $img = 'fa fa-file-word';
            break;
        case 'ppt':
        case 'pptx':
            $img = 'fa fa-file-powerpoint';
            break;
        case 'ttf':
        case 'ttc':
        case 'otf':
        case 'woff':
        case 'woff2':
        case 'eot':
        case 'fon':
            $img = 'fa fa-font';
            break;
        case 'pdf':
            $img = 'fa fa-file-pdf';
            break;
        case 'psd':
        case 'ai':
        case 'eps':
        case 'fla':
        case 'swf':
            $img = 'fa fa-file-image-o';
            break;
        case 'exe':
        case 'msi':
            $img = 'fa fa-file-o';
            break;
        default:
            $img = 'fa fa-file';
    }
    return $img;
}
function view_form(){
    global $doc_root,$fm_path_info,$url_info,$fm_current_dir,$is_windows,$filename,$passthru;
    if (intval($passthru)){
        $file = $fm_current_dir.$filename;
        if(file_exists($file)){
            $is_denied = false;
            foreach($download_ext_filter as $key=>$ext){
                if (eregi($ext,$filename)){
                    $is_denied = true;
                    break;
                }
            }
            if (!$is_denied){
                if ($fh = fopen("$file", "rb")){
                    fclose($fh);
                    $ext = pathinfo($file, PATHINFO_EXTENSION);
                    $ctype = get_mime_type($ext);
                    if (strpos($ctype,"application/") !== false) $ctype = "text/plain";
                    header("Pragma: public");
                    header("Expires: 0");
                    header("Cache-Control: must-revalidate, post-check=0, pre-check=0");
                    header("Cache-Control: public");
                    header("Content-Type: ".$ctype);
                    header("Content-Disposition: inline; filename=\"".pathinfo($file, PATHINFO_BASENAME)."\";");
                    header("Content-Transfer-Encoding: binary");
                    header("Content-Length: ".phpfm_filesize($file));
                    @readfile($file);
                    exit();
                } else echo(et('ReadDenied').": ".$file);
            } else echo(et('ReadDenied').": ".$file);
        } else echo(et('FileNotFound').": ".$file);
    } else {
        html_header();
        echo "<body marginwidth=\"0\" marginheight=\"0\" style=\"height:100%; background-color:#fff;\">";
        $title = et("View").' '.addslashes($filename);
        $is_reachable_thru_webserver = (stristr($fm_current_dir,$doc_root)!==false);
        if ($is_reachable_thru_webserver){
            $url  = $url_info['scheme']."://".$url_info['host'];
            if (strlen($url_info['port'])) $url .= ":".$url_info['port'];
            $url .= str_replace(DIRECTORY_SEPARATOR,'/',str_replace($doc_root,'',$fm_current_dir));
            $url .= $filename;
            $title = et("View").' '.$url;
        } else {
            $url  = addslashes($fm_path_info['basename']);
            $url .= "?action=4&fm_current_dir=".rawurlencode($fm_current_dir)."&filename=".rawurldecode($filename)."&passthru=1";
            $title = et("View").' '.addslashes($fm_current_dir.$filename);
        }
        //fb_log('url',$url);
        echo "
        <script language=\"Javascript\" type=\"text/javascript\">
        <!--
            var el = window.parent.document.getElementById(\"modalIframeWrapperTitle\");
            if (el) el.innerHTML = \"".html_encode($title)."\";
            document.location.href = '".$url."';
        //-->
        </script>";
        demo_fix();
        echo "
        </body>\n</html>";
    }
}
function ace_mode_autodetect($file){
    $mode = 'plain_text';
    $extension = strtolower(pathinfo($file, PATHINFO_EXTENSION));
    switch ($extension){
        case 'html':
        case 'htm':
            $mode = 'html';
        break;
        case 'css':
            $mode = 'css';
        break;
        case 'php':
        case 'php3':
        case 'php4':
        case 'php5':
        case 'php6':
        case 'php7':
        case 'phps':
            $mode = 'php';
        break;
        case 'js':
            $mode = 'javascript';
        break;
        case 'sh':
        case 'bash':
            $mode = 'batchfile';
        break;
        case 'py':
            $mode = 'python';
        break;
        case 'c':
        case 'cpp':
            $mode = 'c_cpp';
        break;
        case 'jsp':
        case 'java':
            $mode = 'jsp';
        break;
        case 'sql':
            $mode = 'sql';
        break;
        case 'ini':
            $mode = 'ini';
        break;
        case 'json':
            $mode = 'json';
        break;
    }
    return $mode;
}
function edit_file_form(){
    global $fm_current_dir,$filename,$file_data,$save_file,$fm_path_info,$curr_row,$curr_col,$ace_mode,$ace_wrap,$cookie_cache_time;
    $file = $fm_current_dir.$filename;
    $ace_mode_opts = array();
    $ace_mode_opts[] = array('HTML','html');
    $ace_mode_opts[] = array('CSS','css');
    $ace_mode_opts[] = array('PHP','php');
    $ace_mode_opts[] = array('JAVASCRIPT','javascript');
    $ace_mode_opts[] = array('BATCH SCRIPT','batchfile');
    $ace_mode_opts[] = array('PYTHON','python');
    $ace_mode_opts[] = array('C/C++','c_cpp');
    $ace_mode_opts[] = array('JSP/JAVA','jsp');
    $ace_mode_opts[] = array('SQL','sql');
    $ace_mode_opts[] = array('INI','ini');
    $ace_mode_opts[] = array('JSON','json');
    $ace_mode_opts[] = array('PLAIN TEXT','plain_text');
    $ace_mode_curr = ace_mode_autodetect($file);
    $file_ace_mode_cookiename = 'ace_'.md5(fix_cookie_name('ace_mode_'.$file));
    if (strlen($_COOKIE[$file_ace_mode_cookiename])) $ace_mode_curr = $_COOKIE[$file_ace_mode_cookiename];
    if (strlen($ace_mode)) $ace_mode_curr = $ace_mode;
    setcookie($file_ace_mode_cookiename, $ace_mode_curr, time()+$cookie_cache_time, "/");
    $ace_wrap_curr = 0;
    if (strlen($_COOKIE['ace_wrap'])) $ace_wrap_curr = intval($_COOKIE['ace_wrap']);
    if (strlen($ace_wrap)) $ace_wrap_curr = intval($ace_wrap);
    setcookie('ace_wrap', $ace_wrap_curr, time()+$cookie_cache_time, "/");
    $curr_row = intval($curr_row);
    $curr_col = intval($curr_col);
    $save_msg = '';
    $reload = false;
    if ($save_file){
        if (is_binary($file)){
            $file_data = base64_decode($file_data);
            //$file_data = hex2bin($file_data);
        }
        if (file_put_contents($file,$file_data,FILE_BINARY)){
            $save_msg = et("FileSaved")."!";
            $reload = true;
        } else $save_msg = et("FileSaveError")."...";
    }
    clearstatcache();
    $file_data = file_get_contents($file,FILE_BINARY);
    if (is_binary($file)){
        $file_data = base64_encode($file_data);
        //$file_data = bin2hex($file_data);
        //$file_data = chunk_split($file_data,2,"\\x");
        //$file_data = "\\x".substr($file_data,0,-2);
    }
    //<link rel=\"stylesheet\" type=\"text/css\" href=\"".$fm_path_info['basename']."?action=99&filename=prism.css\" media=\"screen\" />
    html_header("
        <script type=\"text/javascript\" src=\"".$fm_path_info['basename']."?action=99&filename=jquery-1.11.1.min.js\"></script>
        <script type=\"text/javascript\" src=\"".$fm_path_info['basename']."?action=99&filename=ace.js\"></script>
    ");
    echo "<body marginwidth=\"0\" marginheight=\"0\">
    <form name=\"edit_form\" action=\"".$fm_path_info['basename']."\" method=\"post\">
        <input type=hidden name=\"action\" value=\"7\">
        <input type=hidden name=\"fm_current_dir\" value=\"".$fm_current_dir."\">
        <input type=hidden name=\"filename\" value=\"".$filename."\">
        <input type=hidden name=\"file_data\" id=\"file_data\" value=\"\">
        <input type=hidden name=\"curr_row\" id=\"curr_row\" value=\"0\">
        <input type=hidden name=\"curr_col\" id=\"curr_col\" value=\"0\">
        <input type=hidden name=\"ace_mode\" id=\"ace_mode\" value=\"\">
        <input type=hidden name=\"ace_wrap\" id=\"ace_wrap\" value=\"\">
        <input type=hidden name=\"save_file\" value=\"0\">
    </form>
    <style>
        html, body {
            width: 100%;
            height: 100%;
            margin: 0 !important;
            overflow: hidden;
        }
        #div_toolbar {
            position: relative;
            display: block;
            height: 30px;
            padding: 6px;
        }
        #div_toolbar button, #div_toolbar select {
            display: inline-block;
            float: left;
            margin-right: 6px;
        }
        #div_toolbar .ace_wrap_select {
            display: inline-block;
            float: left;
            border: 1px solid #aaa;
            background-color: #ddd;
            padding: 3px 6px 4px 3px;
            margin-right: 6px;
            margin-top: 1px;
        }
        #div_toolbar .ace_wrap_select input, #div_toolbar .ace_wrap_select label {
            cursor: pointer;
        }
        #div_toolbar .save_msg {
            display: inline-block;
            float: left;
            font-weight: bold;
            border: 1px solid #aaa;
            padding: 5px 6px;
            margin-right: 6px;
            margin-top: 1px;
        }
        #div_ace_editor {
            position: relative;
            display: block;
            height: calc(100% - 43px);
            border-top: 1px solid #ccc;
        }
    </style>";
    echo "
    <div id=\"div_toolbar\">
        <button type=\"button\" class=\"btn\" onclick=\"refreshFile()\" value=\"".et('Refresh')."\"><i class=\"fa fa-refresh\"></i> ".et('Refresh')." (Ctrl+r)</button>
        <button type=\"button\" class=\"btn\" onclick=\"saveFile()\" value=\"".et('SaveFile')."\"><i class=\"fa fa-add-file\"></i> ".et('SaveFile')." (Ctrl+s)</button>
        <select name=\"ace_mode_select\" id=\"ace_mode_select\" onchange=\"changeHighlightMode()\" style=\"width:300px; margin-top:1px; padding:6px 5px 5px 5px;\">";
            foreach ($ace_mode_opts as $opt) {
                echo "
                <option value='".$opt[1]."'>Mode: ".$opt[0];
            }
        echo "
        </select>
        <div class=\"ace_wrap_select\"><input type=\"checkbox\" name=\"ace_wrap_select\" id=\"ace_wrap_select\" value=\"1\"".($ace_wrap_curr?' checked':'')." onclick=\"changeWrapMode()\"><label for=\"ace_wrap_select\" class=\"noselect\">&nbsp;Wrap</label></div>";
        if (strlen($save_msg)) echo "
        <div class=\"save_msg\">".$save_msg."</div>";
    echo "
    </div>
    <div id=\"div_ace_editor\">".html_encode($file_data)."</div>
    <script language=\"Javascript\" type=\"text/javascript\">
    <!--
        ace.config.set('basePath', '".$fm_path_info['basename']."?action=99&filename=');
        ace.require(\"ace/ext/whitespace\");
        var editor = ace.edit('div_ace_editor');
        editor.setOptions({
            theme: 'ace/theme/monokai',
            mode: 'ace/mode/".$ace_mode_curr."',
            useWorker: false, // boolean: true if use web worker for loading scripts
            useSoftTabs: true, // boolean: true if we want to use spaces than tabs
            tabSize: 4,
            wrap: ".($ace_wrap_curr?'true':'false').",
            indentedSoftWrap: false,
            fixedWidthGutter: true,
            showPrintMargin: false,
            printMarginColumn: 80,
            //scrollSpeed: 2,
            fontFamily: 'Courier New',
            fontSize: '10pt'
        });
        editor.commands.addCommand({
            name: 'refreshFile',
            bindKey: {win: 'Ctrl-r', mac: 'Command-r'},
            exec: function(editor) {
                refreshFile();
            }
        });
        editor.commands.addCommand({
            name: 'saveFile',
            bindKey: {win: 'Ctrl-s', mac: 'Command-s'},
            exec: function(editor) {
                saveFile();
            }
        });
        function changeHighlightMode(){
            var mode = $('#ace_mode_select').val();
            if (mode.length > 0) mode = 'ace/mode/'+mode;
            editor.getSession().setMode(mode);
        }
        function changeWrapMode(){
            var mode = $('#ace_wrap_select').prop('checked');
            editor.getSession().setOption('wrap', mode);
        }
        function refreshFile(){
            document.edit_form.save_file.value=0;
            document.edit_form.file_data.value='';
            $('#curr_row').val(editor.getSelectionRange().start.row);
            $('#curr_col').val(editor.getSelectionRange().start.column);
            $('#ace_mode').val($('#ace_mode_select').val());
            $('#ace_wrap').val($('#ace_wrap_select').prop('checked')?1:0);
            document.edit_form.submit();
        }
        function saveFile(){
            document.edit_form.save_file.value=1;
            $('#file_data').val(editor.getSession().getValue());
            $('#curr_row').val(editor.getSelectionRange().start.row);
            $('#curr_col').val(editor.getSelectionRange().start.column);
            $('#ace_mode').val($('#ace_mode_select').val());
            $('#ace_wrap').val($('#ace_wrap_select').prop('checked')?1:0);
        ";
        if (is_writable($file)) echo "
            document.edit_form.submit();";
        else echo "
            if(confirm('".et('ConfTrySave')." ?')) document.edit_form.submit();";
        echo "
        }
        $('#ace_mode_select').val('".$ace_mode_curr."');
        window.parent.modalWindowReloadOnClose = ".($reload?'true':'false').";
        window.focus();
        editor.gotoLine(".($curr_row+1).",".($curr_col).");
        editor.focus();
    //-->
    </script>";
    demo_fix();
    echo "
    </body>\n</html>";
}
function config_form(){
    global $cfg;
    global $fm_current_dir,$fm_file,$doc_root,$fm_path_info,$fm_current_root,$sys_lang,$open_basedirs,$version;
    global $lang,$fm_root,$timezone,$date_format,$error_reporting;
    global $config_action,$newlang,$newfmroot,$newtimezone,$newdateformat,$newerror,$newpass;
    $reload = false;
    switch ($config_action){
        case 1:
            if ($cfg->data['lang'] != $newlang){
                $cfg->data['lang'] = $newlang;
                $lang = $newlang;
            }
            if ($cfg->data['fm_root'] != $newfmroot){
                $cfg->data['fm_root'] = $newfmroot;
                $fm_root = $newfmroot;
            }
            if ($cfg->data['timezone'] != $newtimezone){
                $cfg->data['timezone'] = $newtimezone;
                $timezone = $newtimezone;
            }
            if ($cfg->data['date_format'] != $newdateformat){
                $cfg->data['date_format'] = $newdateformat;
                $date_format = $newdateformat;
            }
            if ($cfg->data['error_reporting'] != $newerror){
                $cfg->data['error_reporting'] = $newerror;
                $error_reporting = $newerror;
            }
            if ($cfg->data['auth_pass'] != $newpass){
                $cfg->data['auth_pass'] = md5($newpass);
                setcookie("loggedon", $cfg->data['auth_pass'], 0 , "/");
            }
            $cfg->save();
            $reload = true;
        break;
    }
    html_header('<script type="text/javascript" src="'.$fm_path_info['basename'].'?action=99&filename=jquery-1.11.1.min.js"></script>');
    echo "<body marginwidth=\"0\" marginheight=\"0\">\n";
    if ($reload){
        echo "
        <script language=\"Javascript\" type=\"text/javascript\">
        <!--
            window.setTimeout(function(){
                window.parent.parent.document.location.href='".$fm_path_info['basename']."?fm_current_dir=".rawurlencode($fm_current_dir)."';
            },500);
        //-->
        </script>";
    } else {
        $timezone_opts = json_decode('[
            ["(GMT-12:00) Pacific\/Wake","Pacific\/Wake"],
            ["(GMT-11:00) Pacific\/Apia","Pacific\/Apia"],
            ["(GMT-10:00) Pacific\/Honolulu","Pacific\/Honolulu"],
            ["(GMT-09:00) America\/Anchorage","America\/Anchorage"],
            ["(GMT-08:00) America\/Los_Angeles","America\/Los_Angeles"],
            ["(GMT-07:00) America\/Chihuahua","America\/Chihuahua"],
            ["(GMT-07:00) America\/Denver","America\/Denver"],
            ["(GMT-07:00) America\/Phoenix","America\/Phoenix"],
            ["(GMT-06:00) America\/Chicago","America\/Chicago"],
            ["(GMT-06:00) America\/Managua","America\/Managua"],
            ["(GMT-06:00) America\/Mexico_City","America\/Mexico_City"],
            ["(GMT-06:00) America\/Regina","America\/Regina"],
            ["(GMT-05:00) America\/Bogota","America\/Bogota"],
            ["(GMT-05:00) America\/Indiana\/Indianapolis","America\/Indiana\/Indianapolis"],
            ["(GMT-05:00) America\/New_York","America\/New_York"],
            ["(GMT-04:00) America\/Caracas","America\/Caracas"],
            ["(GMT-04:00) America\/Halifax","America\/Halifax"],
            ["(GMT-04:00) America\/Santiago","America\/Santiago"],
            ["(GMT-03:30) America\/St_Johns","America\/St_Johns"],
            ["(GMT-03:00) America\/Argentina\/Buenos_Aires","America\/Argentina\/Buenos_Aires"],
            ["(GMT-03:00) America\/Godthab","America\/Godthab"],
            ["(GMT-03:00) America\/Sao_Paulo","America\/Sao_Paulo"],
            ["(GMT-02:00) America\/Noronha","America\/Noronha"],
            ["(GMT-01:00) Atlantic\/Azores","Atlantic\/Azores"],
            ["(GMT-01:00) Atlantic\/Cape_Verde","Atlantic\/Cape_Verde"],
            ["(GMT 00:00) Africa\/Casablanca","\/Casablanca"],
            ["(GMT 00:00) Europe\/London","\/London"],
            ["(GMT+01:00) Africa\/Lagos","Africa\/Lagos"],
            ["(GMT+01:00) Europe\/Belgrade","Europe\/Belgrade"],
            ["(GMT+01:00) Europe\/Berlin","Europe\/Berlin"],
            ["(GMT+01:00) Europe\/Paris","Europe\/Paris"],
            ["(GMT+01:00) Europe\/Sarajevo","Europe\/Sarajevo"],
            ["(GMT+02:00) Africa\/Cairo","Africa\/Cairo"],
            ["(GMT+02:00) Africa\/Johannesburg","Africa\/Johannesburg"],
            ["(GMT+02:00) Asia\/Jerusalem","Asia\/Jerusalem"],
            ["(GMT+02:00) Europe\/Istanbul","Europe\/Istanbul"],
            ["(GMT+02:00) Europe\/Bucharest","Europe\/Bucharest"],
            ["(GMT+02:00) Europe\/Helsinki","Europe\/Helsinki"],
            ["(GMT+03:00) Africa\/Nairobi","Africa\/Nairobi"],
            ["(GMT+03:00) Asia\/Baghdad","Asia\/Baghdad"],
            ["(GMT+03:00) Asia\/Riyadh","Asia\/Riyadh"],
            ["(GMT+03:00) Europe\/Moscow","Europe\/Moscow"],
            ["(GMT+03:30) Asia\/Tehran","Asia\/Tehran"],
            ["(GMT+04:00) Asia\/Muscat","Asia\/Muscat"],
            ["(GMT+04:00) Asia\/Tbilisi","Asia\/Tbilisi"],
            ["(GMT+04:30) Asia\/Kabul","Asia\/Kabul"],
            ["(GMT+05:00) Asia\/Karachi","Asia\/Karachi"],
            ["(GMT+05:00) Asia\/Yekaterinburg","Asia\/Yekaterinburg"],
            ["(GMT+05:30) Asia\/Calcutta","Asia\/Calcutta"],
            ["(GMT+05:45) Asia\/Katmandu","Asia\/Katmandu"],
            ["(GMT+06:00) Asia\/Dhaka","Asia\/Dhaka"],
            ["(GMT+06:00) Asia\/Colombo","Asia\/Colombo"],
            ["(GMT+06:00) Asia\/Novosibirsk","Asia\/Novosibirsk"],
            ["(GMT+06:30) Asia\/Rangoon","Asia\/Rangoon"],
            ["(GMT+07:00) Asia\/Bangkok","Asia\/Bangkok"],
            ["(GMT+07:00) Asia\/Krasnoyarsk","Asia\/Krasnoyarsk"],
            ["(GMT+08:00) Asia\/Hong_Kong","Asia\/Hong_Kong"],
            ["(GMT+08:00) Asia\/Irkutsk","Asia\/Irkutsk"],
            ["(GMT+08:00) Asia\/Singapore","Asia\/Singapore"],
            ["(GMT+08:00) Asia\/Taipei","Asia\/Taipei"],
            ["(GMT+08:00) Asia\/Irkutsk","Asia\/Irkutsk"],
            ["(GMT+08:00) Australia\/Perth","Australia\/Perth"],
            ["(GMT+09:00) Asia\/Tokyo","Asia\/Tokyo"],
            ["(GMT+09:00) Asia\/Seoul","Asia\/Seoul"],
            ["(GMT+09:00) Asia\/Yakutsk","Asia\/Yakutsk"],
            ["(GMT+09:30) Australia\/Adelaide","Australia\/Adelaide"],
            ["(GMT+09:30) Australia\/Darwin","Australia\/Darwin"],
            ["(GMT+10:00) Australia\/Brisbane","Australia\/Brisbane"],
            ["(GMT+10:00) Australia\/Hobart","Australia\/Hobart"],
            ["(GMT+10:00) Australia\/Sydney","Australia\/Sydney"],
            ["(GMT+10:00) Asia\/Vladivostok","Asia\/Vladivostok"],
            ["(GMT+10:00) Pacific\/Guam","Pacific\/Guam"],
            ["(GMT+11:00) Asia\/Magadan","Asia\/Magadan"],
            ["(GMT+12:00) Pacific\/Auckland","Pacific\/Auckland"],
            ["(GMT+12:00) Pacific\/Fiji","Pacific\/Fiji"],
            ["(GMT+13:00) Pacific\/Tongatapu","Pacific\/Tongatapu"]
        ]');
        echo "
        <table border=0 cellspacing=0 cellpadding=5 align=left style=\"padding:5px;\">
        <form name=\"config_form\" action=\"".$fm_path_info['basename']."\" method=\"post\" autocomplete=\"off\">
        <input type=hidden name=action value=2>
        <input type=hidden name=config_action value=0>
        <tr><td align=right width=1>".et('FileMan').":<td>".et('Version')." ".$version." (".format_size(phpfm_filesize($fm_file)).")</td></tr>
        <tr><td align=right width=1><nobr>".et('DocRoot').":</nobr><td>".$doc_root."</td></tr>
        <tr><td align=right width=1><nobr>".et('PHPOpenBasedir').":</nobr><td>".(count($open_basedirs)?implode("<br>\n",$open_basedirs):et('PHPOpenBasedirFullAccess'))."</td></tr>
        <tr><td align=right width=1>".et('FMRoot').":<td><input type=\"text\" style=\"width:392px; padding:5px 8px;\" id=\"newfmroot\" name=\"newfmroot\" readonly autocomplete=\"off\" value=\"".html_encode($fm_root)."\" onkeypress=\"enterSubmit(event,'test_config_form(1)')\"></td></tr>
        <tr><td align=right>".et('Timezone').":<td>
            <select name=newtimezone id=newtimezone style=\"width:410px; padding:5px;\">
                <option value=''>System Default";
                foreach ($timezone_opts as $opt) {
                    echo "
                    <option value='".$opt[1]."'>".$opt[0];
                }
            echo "
            </select>
        </td></tr>
        <tr><td align=right width=1>".et('DateFormat').":<td><input type=\"text\" style=\"width:392px; padding:5px 8px;\" id=\"newdateformat\" name=\"newdateformat\" readonly autocomplete=\"off\" value=\"".html_encode($date_format)."\" onkeypress=\"enterSubmit(event,'test_config_form(1)')\"></td></tr>
        <tr><td align=right>".et('Lang').":<td>
            <select name=newlang id=newlang style=\"width:410px; padding:5px;\">
                <option value=''>System Default</option>
                <option value='ca'>Catalan - by Pere Borràs AKA @Norl</option>
                <option value='cn'>Chinese - by Wen.Xin</option>
                <option value='nl'>Dutch - by Leon Buijs</option>
                <option value='en'>English - by Fabricio Seger Kolling</option>
                <option value='fr'>French - by Jean Bilwes</option>
                <option value='de'>German - by Guido Ogrzal</option>
                <option value='it'>Italian - by Valerio Capello</option>
                <option value='ko'>Korean - by Airplanez</option>
                <option value='fa'>Persian/Dari - by Opensecure, Max Base</option>
                <option value='pt'>Portuguese - by Fabricio Seger Kolling</option>
                <option value='pl'>Polish - by Jakub Kocój</option>
                <option value='sr'>Serbian - by Miroljub Sunajko</option>
                <option value='es'>Spanish - by Sh Studios</option>
                <option value='ru'>Russian - by Евгений Рашев, Алексей Гаврюшин</option>
                <option value='tr'>Turkish - by Necdet Yazilimlari</option>
                <option value='ua'>Ukrainian - by Андрій Литвин</option>
            </select>
        </td></tr>
        <tr><td align=right>".et('ErrorReport').":<td>
            <select name=newerror id=newerror style=\"width:410px; padding:5px;\">
                <option value=\"0\">Disabled
                <option value=\"1\">Show PHP Errors
                <option value=\"2\">Show PHP Errors + ChromePhp Debug
            </select>
        </td></tr>";
        $show_pass = '';
        if ($cfg->data['auth_pass'] != md5('')) $show_pass = $cfg->data['auth_pass'];
        echo "
        <tr><td align=right>".et('Pass').":<td>
            <input type=\"password\" style=\"width:392px; padding:5px 8px;\" name=\"newpass\" id=\"newpass\" readonly autocomplete=\"off\" value=\"".html_encode($show_pass)."\" onkeypress=\"enterSubmit(event,'test_config_form(1)')\">
        </td></tr>
        <tr><td>&nbsp;<td align=right><input type=button class=\"btn noIcon\" value=\"".et('SaveConfig')."\" onclick=\"test_config_form(1)\"></td></tr>
        </form>
        </table>
        <script language=\"Javascript\" type=\"text/javascript\">
        <!--
            $('#newlang').val('".$cfg->data['lang']."');
            $('#newtimezone').val('".$cfg->data['timezone']."');
            $('#newerror').val('".$cfg->data['error_reporting']."');
            function test_config_form(arg){
                document.config_form.config_action.value = arg;
                document.config_form.submit();
            }
            // To avoid autofill, because autocomplete=off simply does not work..
            window.setTimeout(function(){
                $('#newfmroot').removeAttr('readonly');
                $('#newdateformat').removeAttr('readonly');
                $('#newpass').removeAttr('readonly');
            },250);
        //-->
        </script>";
        demo_fix();
    }
    echo "
    </body>\n</html>";
}
function phpfm_host2ip($host_or_ip){
    if (filter_var($host_or_ip, FILTER_VALIDATE_IP)) return $host_or_ip;
    else return gethostbyname($host_or_ip);
}
function phpfm_ping($host_or_ip,&$output) {
    if (!function_exists("socket_create")) {
        $output = "Function socket_create() not available";
        return false;
    }
    $timeout = 1;
    $ip = phpfm_host2ip($host_or_ip);
    $socket = socket_create(AF_INET, SOCK_RAW, getprotobyname('icmp'));
    socket_set_option($socket, SOL_SOCKET, SO_RCVTIMEO, array('sec' => $timeout, 'usec' => 0));
    socket_connect($socket, $ip, 0);
    $ping_ok = false;
    $ping_tries = 2;
    for ($i=0;$i<$ping_tries;$i++) {
        $time_start = microtime(true);
        $package  = "\x08\x00\x19\x2f\x00\x00\x00\x00\x70\x69\x6e\x67";
        socket_send($socket, $package, strlen($package), 0);
        if (socket_read($socket, 255)) {
            $ping_ok = true;
        }
        $time_stop = microtime(true);
        $ms = ($time_stop - $time_start) * 1000;
        if ($ping_ok) break;
    }
    socket_close($socket);
    if ($ping_ok) $output = number_format((float)$ms, 2, '.', '').'ms';
    elseif ($ms > $timeout * 1000) $output = 'Timeout';
    else $output = 'No response';
    if ($ip != $host_or_ip) $output .= ' ('.$ip.')';
    return $ping_ok;
}
function phpfm_portscan($ip,$port,&$output){
    global $services;
    if (!function_exists("fsockopen")) {
        return "Function fsockopen() not available";
    }
    $timeout = 1;
    $proto_ip = $ip;
    if (stripos($port,'udp') !== false) $proto_ip = 'udp://'.$ip;
    $port_nr = str_strip($port,'1234567890');
    $port_open = false;
    $fp = @fsockopen($proto_ip, $port_nr, $errno, $errstr, $timeout);
    $fb_out = '';
    if($fp){
        // TODO: UDP port scan needs more testing..
        if (stripos($port,'udp') !== false) {
            stream_set_timeout($fp, 3);
            stream_set_write_buffer($fp, 0);
            stream_set_read_buffer($fp, 0);
            stream_set_blocking($fp, true);
            if (fwrite($fp,"test\n") !== falze){
                $fb_out = trim(stream_get_contents($fp));
                $info = stream_get_meta_data($fp);
                if (!$info['timed_out'] && $fb_out !== false) {
                    if (strlen($fb_out)){
                        $port_open = true;
                    }
                }
            }
        } else {
            $port_open = true;
        }
        fclose($fp);
    }
    if ($port_open) {
        $output = '│ <font color="green">Port: '.$port.(isset($services[$port])?' = '.$services[$port]:'').'</font><br>';
    } else {
        $output = '│ <font color="brown">Port: '.$port.(isset($services[$port])?' = '.$services[$port]:'').'</font><br>'; // '.$errstr.' ('.$errno.')
    }
    return $port_open;
}
/*
https://www.ricardoarrigoni.com.br/tabela-ascii-completa/
┌─────────┐
│ XXXXXXX │
├───-─────┘
├─► xxxxxxx
└─► xxxxxxx
╔═════════╗
║ XXXXXXX ║
╠═════════╝
╟► xxxxxxx
╙► xxxxxxx
*/
function portscan_form(){
    global $cfg;
    global $fm_current_dir,$fm_file,$doc_root,$fm_path_info,$fm_current_root;
    global $ip,$lan_ip;
    global $portscan_action,$portscan_ip,$portscan_ips,$portscan_port,$portscan_ports,$services,$portscan_ignore_ping;
    $services_inverted = array_flip($services);
    $default_portscan_services = explode(",","DAYTIME,FTP,SSH,TELNET,DNS,DHCP,NETBIOS-SESSION,SNMP,LDAP,SMB-AD,MSSQL,ORACLE,MYSQL/MARIADB,RDESKTOP,VNC,HTTPD-ALT");
    $default_portscan_ports = array();
    foreach ($default_portscan_services as $name) {
        if (isset($services_inverted[$name])) $default_portscan_ports[] = $services_inverted[$name];
    }
    $default_portscan_ports = implode(",",$default_portscan_ports);
    switch ($portscan_action){
        case 2: // Do Ping
            @ini_set("max_execution_time",30);
            header("Content-type: text/plain");
            $output = '';
            $ping_ok = phpfm_ping($portscan_ip,$output);
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode(array($ping_ok,$output));
            die();
        break;
        case 3: // Scan Port
            @ini_set("max_execution_time",30);
            $output = '';
            $portscan_ip = phpfm_host2ip($portscan_ip);
            $port_open = phpfm_portscan($portscan_ip,$portscan_port,$output);
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode(array($port_open,$output));
            die();
        break;
        case 4: // Scan Multiple Ports
            @ini_set("max_execution_time",120);
            $portscan_ip = phpfm_host2ip($portscan_ip);
            $portscan_ports = explode(',',$portscan_ports);
            $resul = array();
            foreach ($portscan_ports as $portscan_port) {
                $output = '';
                $port_open = phpfm_portscan($portscan_ip,$portscan_port,$output);
                $resul[] = array($port_open,$output);
            }
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode($resul);
            die();
        break;
    }
    html_header('<script type="text/javascript" src="'.$fm_path_info['basename'].'?action=99&filename=jquery-1.11.1.min.js"></script>');
    $m = explode(".",$lan_ip);
    $inet = $m[0].".".$m[1].".".$m[2].".";
    if (!strlen($portscan_ip_range)) $portscan_ip_range = $inet."1-254";
    //if (!strlen($portscan_port_range)) $portscan_port_range = implode(",",array_keys($services));
    if (strlen($_COOKIE['portscan_ip_range'])) $portscan_ip_range = $_COOKIE['portscan_ip_range'];
    if (!strlen($portscan_port_range)) $portscan_port_range = $default_portscan_ports;
    if (strlen($_COOKIE['portscan_port_range'])) $portscan_port_range = $_COOKIE['portscan_port_range'];
    echo "<body marginwidth=\"0\" marginheight=\"0\">
    <style>
        html, body {
            width: 100%;
            height: 100%;
            margin: 0 !important;
            overflow: hidden;
        }
        #div_toolbar {
            position: relative;
            display: block;
            height: 130px;
            padding: 6px;
        }
        #div_toolbar button, #div_toolbar .save_msg {
            display: inline-block;
            float: left;
            margin-right: 6px;
        }
        #div_toolbar .portscan_ignore_ping {
            display: inline-block;
            float: left;
            border: 1px solid #aaa;
            background-color: #ddd;
            padding: 3px 6px 4px 3px;
            margin-right: 6px;
            margin-top: 1px;
        }
        #div_toolbar .portscan_ignore_ping input, #div_toolbar .portscan_ignore_ping label {
            cursor: pointer;
        }
        #portscanIframe {
            position: relative;
            display: block;
            background: #000;
            color: #fff;
            width: 100%;
            height: calc(100% - 143px);
            overflow-y: scroll;
            overflow-x: auto;
            border-top: 1px solid #ccc;
        }
    </style>
    <div id=\"div_toolbar\">
        <table border=0 cellspacing=0 cellpadding=5 align=center width=\"100%\" height=\"100%\">
        <form name=\"portscan_form\" action=\"".$fm_path_info['basename']."\" method=\"get\" target=\"portscanIframe\">
            <input type=hidden name=action value=12>
            <input type=hidden name=portscan_action value=0>
            <tr><td valign=top width=1>
                <table border=0 cellspacing=0 cellpadding=5>
                <tr><td align=right width=1><nobr>Hosts:</nobr><td><input type=\"text\" style=\"width:430px; padding:5px 8px;\" name=\"portscan_ip_range\" value=\"".html_encode($portscan_ip_range)."\"></td></tr>
                <tr><td align=right width=1><nobr>Scan Ports:</nobr><td><input type=\"text\" style=\"width:430px; padding:5px 8px;\" name=\"portscan_port_range\" value=\"".html_encode($portscan_port_range)."\"></td></tr>
                <tr><td>&nbsp;</td><td>
                <div class=\"portscan_ignore_ping\"><input type=\"checkbox\" name=\"portscan_ignore_ping\" id=\"portscan_ignore_ping\" value=\"1\"".($portscan_ignore_ping?' checked':'')." onclick=\"set_ping_cookie()\"><label for=\"portscan_ignore_ping\" class=\"noselect\">&nbsp;Ignore Ping</label></div>
                <button type=\"button\" class=\"btn\" onclick=\"execute_portscan()\" value=\"".et('Exec')."\"><i class=\"fa fa-refresh\"></i> ".et('Exec')."</button>
                <button type=\"button\" class=\"btn\" onclick=\"stop_portscan()\" value=\"".et('Stop')."\"><i class=\"fa fa-delete\"></i> ".et('Stop')."</button>
                </td></tr>
                </table>
            </td><td valign=top>
                <table border=0 cellspacing=0 cellpadding=5>
                <tr><td align=right width=1><nobr>Your IP:</nobr><td><input type=\"text\" name=\"your_ip\" value=\"".$ip."\" style=\"width:150px; background-color:#ccc; padding:5px 8px;\" readonly></td></tr>";
                if (strlen($lan_ip)) echo "<tr><td align=right width=1><nobr>Server Lan IP:</nobr><td><input type=\"text\" name=\"your_ip\" value=\"".$lan_ip."\" style=\"width:150px; background-color:#ccc; padding:5px 8px;\" readonly></td></tr>";
                echo "
                </form>
                </table>
            </td></tr>
        </form>
        </table>
    </div>
    <iframe id=\"portscanIframe\" name=\"portscanIframe\" src=\"\" scrolling=\"yes\" frameborder=\"0\"></iframe>
    ";
    $ports_reference = array();
    foreach ($services as $port => $service){
        $ports_reference[] = "$port = $service";
    }
    echo "
    <script language=\"Javascript\" type=\"text/javascript\">
    <!--
        var iframe_text = '';
        var portscan_ips, portscan_ports;
        var portscan_curr_ip, portscan_curr_port;
        var all_ports_one_request = false;
        var portscan_ignore_ping = ".($portscan_ignore_ping?'true':'false').";
        var portscan_execute_flag = false;
        var all_service_ports = ".json_encode(array_keys($services)).";
        var portscan_ports_failed = 0;
        function get_boxed_text(str){
            str = String(str);
            var br = '<br>';
            var arr = str.split(br);
            var max_str_length = 0;
            for(var i=0;i<arr.length;i++){
                line_strip_tags = String(arr[i]).replace(/<\/?[^>]+(>|$)/g, \"\");
                if (line_strip_tags.length > max_str_length) max_str_length = line_strip_tags.length;
            }
            var out = '';
            out += '<nobr>┌'+rep('─',max_str_length+2)+'┐<nobr>'+br;
            for(var i=0;i<arr.length;i++){
                line_strip_tags = String(arr[i]).replace(/<\/?[^>]+(>|$)/g, \"\");
                out += '<nobr>│ '+arr[i]+rep('&nbsp;',(max_str_length-line_strip_tags.length))+' │<nobr>';
                if (i<arr.length) out += br;
            }
            out += '<nobr>└'+rep('─',max_str_length+2)+'┘<nobr>'+br;
            return out;
        }
        function write_to_iframe(str){
            iframe_text += str;
            var iframe_body = document.getElementById('portscanIframe').contentWindow.document;
            iframe_body.open();
            iframe_body.write('<style>body { margin:5px; background-color:#000; color:#fff; } </style><div style=\"width:100%; height:100%; font-family:Courier New; font-size:10pt; font-weight:normal; color:#aaa;\">'+iframe_text+'</div>');
            iframe_body.close();
        }
        function iframe_scroll_down(){
            var iframe_window = document.getElementById('portscanIframe').contentWindow;
            iframe_window.scrollTo( 0, 999999 );
        }
        write_to_iframe(get_boxed_text('PHP File Manager - Portscan<br><br><b>Hosts examples:</b><br>Single: phpfm.sf.net<br>Single: 192.168.0.1<br>Range: 192.168.0.1-254<br>Multiple: phpfm.sf.net,192.168.0.1,192.168.0.2'));
        write_to_iframe(get_boxed_text('<b>Ports reference:</b><br>* = ALL<br>".implode('<br>',$ports_reference)."'));
        function stop_portscan(){
            portscan_execute_flag = false;
        }
        function set_ping_cookie(){
            portscan_ignore_ping = $('#portscan_ignore_ping').prop('checked');
            var value = portscan_ignore_ping?1:0;
            setCookiePersistent('portscan_ignore_ping',value);
        }
        function execute_portscan(){
            iframe_text = '';
            portscan_ip_range = String(document.portscan_form.portscan_ip_range.value).trim();
            portscan_port_range = String(document.portscan_form.portscan_port_range.value).trim();
            setCookie('portscan_ip_range',portscan_ip_range);
            setCookie('portscan_port_range',portscan_port_range);
            var portscan_command_str = '';
            portscan_command_str += 'PHP File Manager - Portscan<br><br>';
            portscan_command_str += 'Hosts: '+portscan_ip_range+'<br>';
            portscan_command_str += 'Scan Ports: '+portscan_port_range+'<br>';
            portscan_command_str += 'Ignore Ping: '+(portscan_ignore_ping?'Yes':'No');
            portscan_ips = [];
            portscan_ports = [];
            if (portscan_port_range.length > 0) {
                if (portscan_port_range == '*') portscan_ports = all_service_ports;
                else portscan_ports = portscan_port_range.split(',');
            }
            if (portscan_ip_range.length > 0) {
                if (portscan_ip_range.indexOf('-') != -1){
                    portscan_ip_range = portscan_ip_range.split('-');
                    portscan_inet = portscan_ip_range[0].substr(0,portscan_ip_range[0].lastIndexOf('.')+1);
                    portscan_start = parseInt(portscan_ip_range[0].substr(portscan_ip_range[0].lastIndexOf('.')+1));
                    portscan_end = parseInt(portscan_ip_range[1]);
                    for(var i=portscan_start;i<=portscan_end;i++){
                        portscan_ips.push(portscan_inet+i);
                    }
                } else if (portscan_ip_range.indexOf(',') != -1){
                    portscan_ips = portscan_ip_range.split(',');
                } else {
                    portscan_ips.push(portscan_ip_range);
                }
            }
            write_to_iframe(get_boxed_text(portscan_command_str));
            portscan_curr_ip = 0;
            portscan_execute_flag = true;
            do_ping();
        }
        function do_ping(){
            if (portscan_execute_flag) {
                if (portscan_curr_ip<portscan_ips.length){
                    ip = portscan_ips[portscan_curr_ip];
                    write_to_iframe('│ Ping: '+ip+' = ');
                    iframe_scroll_down();
                    $.ajax({
                        type: 'POST',
                        url: '".$fm_path_info['basename']."',
                        dataType: 'json',
                        crossDomain: false,
                        data: {
                            action : 12,
                            portscan_action: 2,
                            portscan_ip : ip
                        },
                        success: function (data){
                            if (data[0]) {
                                write_to_iframe('<font color=\"green\">'+data[1]+'</font><br>');
                            } else {
                                write_to_iframe('<font color=\"brown\">'+data[1]+'</font><br>');
                            }
                            iframe_scroll_down();
                            if ((data[0] || portscan_ignore_ping) && portscan_ports.length > 0) {
                                portscan_curr_port = 0;
                                portscan_ports_failed = 0
                                do_scan();
                            } else {
                                portscan_curr_ip++;
                                do_ping();
                            }
                        },
                        error: function (err){
                            write_to_iframe('<font color=\"#777\">Server error</font><br>');
                        }
                    })
                } else {
                    write_to_iframe(get_boxed_text('Portscan finished'));
                    iframe_scroll_down();
                }
            } else {
                write_to_iframe(get_boxed_text('Portscan stopped'));
                iframe_scroll_down();
            }
        }
        function do_scan(){
            ip = portscan_ips[portscan_curr_ip];
            if (all_ports_one_request){
                $.get(
                    '".$fm_path_info['basename']."',
                    {
                        action : 12,
                        portscan_action: 4,
                        portscan_ip : ip,
                        portscan_ports : portscan_ports.join(',')
                    },
                    function (data){
                        data = String(data).trim();
                        if (data.length > 0) {
                            write_to_iframe(data);
                            iframe_scroll_down();
                        }
                        portscan_curr_ip++;
                        do_ping();
                    }
                )
            } else {
                if (portscan_curr_port<portscan_ports.length && portscan_execute_flag){
                    port = portscan_ports[portscan_curr_port];
                    iframe_scroll_down();
                    $.ajax({
                        type: 'POST',
                        url: '".$fm_path_info['basename']."',
                        dataType: 'json',
                        crossDomain: false,
                        data: {
                            action : 12,
                            portscan_action: 3,
                            portscan_ip : ip,
                            portscan_port : port
                        },
                        success: function (data){
                            if (data[0]) {
                                if (portscan_ports_failed > 0) write_to_iframe('<br>');
                                write_to_iframe(data[1]);
                                iframe_scroll_down();
                                portscan_ports_failed = 0;
                            } else {
                                if (portscan_ports_failed == 0) write_to_iframe('│ ');
                                write_to_iframe('<font color=\"brown\">.</font>');
                                portscan_ports_failed++;
                            }
                            portscan_curr_port++;
                            do_scan();
                        },
                        error: function (err){
                            write_to_iframe('<font color=\"brown\">.</font>');
                            portscan_ports_failed++;
                            portscan_curr_port++;
                            do_scan();
                        }
                    })
                } else {
                    if (portscan_ports_failed > 0) write_to_iframe('<br>');
                    portscan_curr_ip++;
                    do_ping();
                }
            }
        }
    //-->
    </script>
    ";
    demo_fix();
    echo "</body>\n</html>";
}
// +--------------------------------------------------
// | Shell Form Functions
// +--------------------------------------------------
function error_handler($err, $message, $file, $line) {
    global $stop;
    $stop = true;
    $content = explode("\n", file_get_contents($file));
    header('Content-Type: application/json');
    $id = extract_id(); // don't need to parse
    ob_end_clean();
    echo response(null, $id, array(
       "code" => 100,
       "message" => "Server error",
       "error" => array(
          "name" => "PHPError",
          "code" => $err,
          "message" => $message,
          "file" => $file,
          "at" => $line,
          "line" => $content[$line-1]))
    );
    exit();
}
class JsonRpcExeption extends Exception {
    function __construct($code, $message) {
        $this->code = $code;
        Exception::__construct($message);
    }
    function code() {
        return $this->code;
    }
}
function json_error() {
    switch (json_last_error()) {
    case JSON_ERROR_NONE:
        return 'No error has occurred';
    case JSON_ERROR_DEPTH:
        return 'The maximum stack depth has been exceeded';
    case JSON_ERROR_CTRL_CHAR:
        return 'Control character error, possibly incorrectly encoded';
    case JSON_ERROR_SYNTAX:
        return 'Syntax error';
    case JSON_ERROR_UTF8:
        return 'Malformed UTF-8 characters, possibly incorrectly encoded';
    }
}
function get_raw_post_data() {
    if (isset($GLOBALS['HTTP_RAW_POST_DATA'])) {
        return $GLOBALS['HTTP_RAW_POST_DATA'];
    } else {
        return file_get_contents('php://input');
    }
}
function has_field($object, $field) {
    return array_key_exists($field, get_object_vars($object));
}
function get_field($object, $field, $default) {
    $array = get_object_vars($object);
    if (isset($array[$field])) {
        return $array[$field];
    } else {
        return $default;
    }
}
function extract_id() {
    $regex = '/[\'"]id[\'"] *: *([0-9]*)/';
    $raw_data = get_raw_post_data();
    if (preg_match($regex, $raw_data, $m)) {
        return $m[1];
    } else {
        return null;
    }
}
function currentURL() {
    $pageURL = 'http';
    if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] == "on") {
        $pageURL .= "s";
    }
    $pageURL .= "://";
    if ($_SERVER['SERVER_PORT'] != "80") {
        $pageURL .= $_SERVER['SERVER_NAME'].":".$_SERVER['SERVER_PORT'].$_SERVER['REQUEST_URI'];
    } else {
        $pageURL .= $_SERVER['SERVER_NAME'].$_SERVER['REQUEST_URI'];
    }
    return $pageURL;
}
function service_description($object) {
    $class_name = get_class($object);
    $methods = get_class_methods($class_name);
    $service = array("sdversion" => "1.0",
                     "name" => "ShellService",
                     "address" => currentURL(),
                     "id" => "urn:md5:" . md5(currentURL()));
    $static = get_class_vars($class_name);
    foreach ($methods as $method_name) {
        $proc = array("name" => $method_name);
        $method = new ReflectionMethod($class_name, $method_name);
        $params = array();
        foreach ($method->getParameters() as $param) {
            $params[] = $param->name;
        }
        $proc['params'] = $params;
        $help_str_name = $method_name . "_documentation";
        if (array_key_exists($help_str_name, $static)) {
            $proc['help'] = $static[$help_str_name];
        }
        $service['procs'][] = $proc;
    }
    return $service;
}
function get_json_request() {
    $request = get_raw_post_data();
    if ($request == "") {
        throw new JsonRpcExeption(101, "Parse Error: no data");
    }
    $encoding = mb_detect_encoding($request, 'auto');
    //convert to unicode
    if ($encoding != 'UTF-8') {
        $request = iconv($encoding, 'UTF-8', $request);
    }
    $request = json_decode($request);
    if ($request == NULL) { // parse error
        $error = json_error();
        throw new JsonRpcExeption(101, "Parse Error: $error");
    }
    return $request;
}
function get_absolute_path($path) {
    global $is_windows;
    $path = str_replace(array('/', '\\'), DIRECTORY_SEPARATOR, $path);
    $parts = array_filter(explode(DIRECTORY_SEPARATOR, $path), 'strlen');
    $absolutes = array();
    foreach ($parts as $part) {
        if ('.' == $part) continue;
        if ('..' == $part) {
            array_pop($absolutes);
        } else {
            $absolutes[] = $part;
        }
    }
    $path = '';
    if (count($absolutes)) $path = implode(DIRECTORY_SEPARATOR, $absolutes).DIRECTORY_SEPARATOR;
    if (!$is_windows) $path = DIRECTORY_SEPARATOR.$path;
    return $path;
}
function cmd_proc_open_exec($cmd, &$stdout, &$stderr) {
    $tmp_dir = ini_get('session.save_path') ? ini_get('session.save_path') : sys_get_temp_dir();
    $outfile = tempnam($tmp_dir,"cmd");
    $errfile = tempnam($tmp_dir,"cmd");
    $descriptorspec = array(
        0 => array("pipe", "r"),
        1 => array("file", $outfile, "w"),
        2 => array("file", $errfile, "w")
    );
    $proc = proc_open($cmd, $descriptorspec, $pipes);
    if (!is_resource($proc)) return 255;
    fclose($pipes[0]);    //Don't really want to give any input
    $exit = proc_close($proc);
    $stdout = file_get_contents($outfile);
    $stderr = file_get_contents($errfile);
    @unlink($outfile);
    @unlink($errfile);
    return $exit;
}
function cmd_popen_exec($cmd, &$output){
    if ($handle = popen($cmd,"r")){
        while (!feof($handle)) {
            $output .= fgets($handle, 4096);
        }
        pclose($handle);
        return true;
    }
    return false;
}
if($is_windows && !function_exists('pcntl_exec') && class_exists('COM')){
    function pcntl_exec($path, $args=array()){
        if(is_string($args)) $args = array($args);
        if(count($args)) $path = '"'.$path.'"';
        $shell = new COM('WScript.Shell');
        if ($shell->run($path.(count($args) ? ' '.implode(' ',$args) : ''),0,true)) return NULL;
        else return false;
    }
}
function cmd_pcntl_exec($cmd, $args=array()){ // Does not provide output, could throw it to a file!
    if(is_string($args)) $args = array($args);
    $envs = array();
    if (pcntl_exec($cmd, $args, $envs) === NULL) return true;
    return false;
}
function system_exec_cmd($cmd, &$output){
    fb_log('system_exec_cmd: '.$cmd);
    $exec_ok = false;
    if (strlen($cmd)) {
        if (function_exists('proc_open')) {
            $stdout = $stderr = '';
            $exitCode = cmd_proc_open_exec($cmd, $stdout, $stderr);
            $exec_ok = (intval($exitCode) == 0); // 0 = success
            $output = trim($stdout);
            if (strlen($stderr)) {
                if (strlen($output)) $output .= "\n";
                $output .= trim($stderr);
            }
        } else {
            if (strpos($cmd,'2>&1') === false) {
                $cmd .= ' 2>&1';
            }
            if (function_exists('exec')) {
                $outputArr = array();
                $exitCode = 1;
                @exec($cmd, $outputArr, $exitCode);
                $exec_ok = (intval($exitCode) == 0); // 0 = success
                $output = trim(implode("\n",$outputArr));
            } elseif (function_exists('shell_exec')) {
                // The backtick operator is disabled when safe mode is enabled or shell_exec() is disabled.
                $output = @shell_exec($cmd);
                if ($output === NULL){
                    $output = '';
                    $exec_ok = false;
                } else {
                    $exec_ok = true;
                }
            } elseif (function_exists('system')) {
                @ob_clean();
                $last_output_line = @system($cmd,$exitCode);
                $output = @ob_get_contents();
                @ob_clean();
                $exec_ok = ($last_output_line !== false);
                $exec_ok = (intval($exitCode) == 0); // 0 = success
            } elseif (function_exists('passthru')) {
                @ob_clean();
                @passthru($cmd, $exitCode);
                $output = @ob_get_contents();
                @ob_clean();
                $exec_ok = (intval($exitCode) == 0); // 0 = success
            } elseif (function_exists('popen')) {
                $exec_ok = cmd_popen_exec($cmd, $output);
            } else {
                $output = "Error: PHP system exec functions are disabled.";
            }
        }
    }
    $output = trim($output);
    return $exec_ok;
}
function handle_json_rpc() {
    global $fm_current_dir,$cmd_line,$is_windows;
    @set_error_handler('error_handler');
    try {
        $input = get_json_request();
        header('Content-Type: application/json');
        $method = get_field($input, 'method', null);
        $params = get_field($input, 'params', null);
        $id = get_field($input, 'id', null);
        // json rpc error
        if (!($method && $id)) {
            if (!$id) {
                $id = extract_id();
            }
            if (!$method) {
                $error = "no method";
            } else if (!$id) {
                $error = "no id";
            } else {
                $error = "unknown reason";
            }
            throw new JsonRpcExeption(103,"Invalid Request: $error");
            //": " . $GLOBALS['HTTP_RAW_POST_DATA']));
        }
        // fix params (if params is null set it to empty array)
        if (!$params) {
            $params = array();
        }
        // if params is object change it to array
        if (is_object($params)) {
            if (count(get_object_vars($params)) == 0) {
                $params = array();
            } else {
                $params = get_object_vars($params);
            }
        }
        $fm_current_dir = get_absolute_path($fm_current_dir);
        $cmd_line = '';
        if ($is_windows) {
            $cmd_line .= "cd /D ".$fm_current_dir." && ";
        } else {
            $cmd_line .= "cd ".$fm_current_dir." && ";
        }
        $cmd_line .= $method." ".implode(" ", $params);
        if ($is_windows && strlen($method) == 2 && count($params) == 0){
            $drive = uppercase($method[0]);
            if (strpos($method,':') === 1 && strpos("ABCDEFGHIJKLMNOPQRSTUVWXYZ",$drive) !== false){
                $fm_current_dir = get_absolute_path($drive.':');
                $cmd_line = '';
            }
        } elseif (lowercase($method) == 'cd' && count($params) > 0){
            $arg = implode(' ',$params);
            if (strlen($arg)){
                if ($is_windows){
                    $drive = uppercase($arg[0]);
                    if (strpos($arg,':') === 1 && strpos("ABCDEFGHIJKLMNOPQRSTUVWXYZ",$drive) !== false){
                        $fm_current_dir = get_absolute_path($drive.':'.DIRECTORY_SEPARATOR.substr($arg,2));
                    } else {
                        $fm_current_dir = get_absolute_path($fm_current_dir.DIRECTORY_SEPARATOR.$arg);
                    }
                } else {
                    if (strpos($arg,'/') === 0){
                        $fm_current_dir = $arg;
                    } else {
                        $fm_current_dir = get_absolute_path($fm_current_dir.DIRECTORY_SEPARATOR.$arg);
                    }
                }
                $cmd_line = '';
            }
        }
        $output = '';
        $exec_ok = system_exec_cmd($cmd_line, $output);
        echo response($output, $id, null);
    } catch (JsonRpcExeption $e) {
        // exteption with error code
        $msg = $e->getMessage();
        $code = $e->code();
        if ($code = 101) { // parse error;
            $id = extract_id();
        }
        echo response(null, $id, array("name"=>"JSONRPCError", "code"=>$code, "message"=>$msg));
    } catch (Exception $e) {
        //catch all exeption from user code
        $msg = $e->getMessage();
        echo response(null, $id, array("name"=>"JSONRPCError", "code"=>200, "message"=>$msg));
    }
}
function response($result, $id, $error) {
    global $fm_current_dir,$cmd_line,$is_windows;
    // Se o path não é raiz no linux ou raiz de drive no windows, remove o ultimo separador da direita
    if ($is_windows){
        if (strlen($fm_current_dir) > 3){
            $fm_current_dir = rtrim($fm_current_dir,DIRECTORY_SEPARATOR);
        }
    } elseif (strlen($fm_current_dir) > 1) {
        $fm_current_dir = rtrim($fm_current_dir,DIRECTORY_SEPARATOR);
    }
    return json_encode(array('cmd_line' => $cmd_line,
                             'fm_current_dir' => $fm_current_dir,
                             'result' => $result,
                             'jsonrpc' => '2.0',
                             'id' => $id,
                             'error'=> $error));
}
function shell_form(){
    global $fm_current_dir,$shell_form,$cmd_arg,$fm_path_info,$is_windows;
    switch ($shell_form){
        case 1:
            handle_json_rpc();
            exit();
        break;
        default:
            html_header("
                <script type=\"text/javascript\" src=\"".$fm_path_info['basename']."?action=99&filename=jquery-1.11.1.min.js\"></script>
                <script type=\"text/javascript\" src=\"".$fm_path_info['basename']."?action=99&filename=jquery.terminal.min.js\"></script>
                <link rel=\"stylesheet\" type=\"text/css\" href=\"".$fm_path_info['basename']."?action=99&filename=jquery.terminal.min.css\" media=\"screen\" />
            ");
            is_rwx_phpfm(__FILE__); // Init $GLOBALS['script_info']
            $username = $GLOBALS['script_info']['script_user_name'];
            $groupname = $GLOBALS['script_info']['script_group_name'];
            $hostname = $GLOBALS['script_info']['sys_hostname'];
            $ugh = '';
            if (strlen($username)) $ugh .= $username;
            if (strlen($groupname)) $ugh .= ':'.$groupname;
            if (strlen($hostname)) $ugh .= '@'.$hostname;
            $prompt_start = '[';
            if ($username == 'root') $prompt_end .= ']# ';
            else $prompt_end .= ']$ ';
            $greetings = array();
            $greetings[] = 'PHP File Manager - Shell Terminal Emulator';
            $greetings[] = '';
            if (strlen($username)) $greetings[] = 'User: '.$username;
            if (strlen($groupname)) $greetings[] = 'Group: '.$groupname;
            if (strlen($hostname)) $greetings[] = 'Host: '.$hostname;
            $exec_functions = array('proc_open','exec','shell_exec','system','passthru','popen');
            $is_exec_disabled = true;
            foreach ($exec_functions as $f) {
                if (function_exists($f)) {
                    $is_exec_disabled = false;
                    break;
                }
            }
            if ($is_exec_disabled) {
                $greetings[] = '';
                $greetings[] = 'Warning: All PHP system exec functions are disabled.';
                $greetings[] = implode('(),',$exec_functions).'()';
            }
            $shell_current_dir = $fm_current_dir;
            if (strlen($_COOKIE['shell_current_dir'])) $shell_current_dir = $_COOKIE['shell_current_dir'];
            ?>
            <body marginwidth="0" marginheight="0">
                <style>
                    .cmd, .cmd div, .cmd span, .terminal, .terminal span, .terminal-output span {
                        font-family: Courier New !important;
                        font-size: 10pt !important;
                    }
                </style>
                <script>
                    function get_boxed_text(str){
                        str = String(str);
                        var br = String.fromCharCode(10);
                        var arr = str.split(br);
                        var max_str_length = 0;
                        for(var i=0;i<arr.length;i++){
                            arr[i] = String(arr[i]);
                            if (arr[i].length > max_str_length) max_str_length = arr[i].length;
                        }
                        var out = '';
                        out += '┌'+rep('─',max_str_length+2)+'┐'+br;
                        for(var i=0;i<arr.length;i++){
                            out += '│ '+arr[i]+rep('&nbsp;',(max_str_length-arr[i].length))+' │';
                            if (i<arr.length) out += br;
                        }
                        out += '└'+rep('─',max_str_length+2)+'┘'+br;
                        return out;
                    }
                    var shell_current_dir = '<?php echo addslashes(rtrim($shell_current_dir,DIRECTORY_SEPARATOR)); ?>';
                    jQuery(document).ready(function($) {
                        $('body').terminal(
                            function(command, term) {
                                if (command){
                                    term.pause();
                                    var params = String(command).split(' ');
                                    var method = params.shift();
                                    var timestamp = new Date().getTime();
                                    $.ajax({
                                        type: 'POST',
                                        url: '<?php echo $fm_path_info['basename']; ?>?action=9&shell_form=1&fm_current_dir='+shell_current_dir,
                                        dataType: 'json',
                                        crossDomain: false,
                                        data: JSON.stringify(
                                            {
                                                jsonrpc: '2.0',
                                                method: method,
                                                params: params,
                                                id: timestamp
                                            }
                                        ),
                                        success: function (data){
                                            if (data.error !== null){
                                                if (data.error.code == 100) term.echo(data.error.error.name+': '+data.error.error.message).resume(); // Server Error
                                                else term.echo(data.error.name+': '+data.error.message).resume();
                                            } else {
                                                shell_current_dir = data.fm_current_dir;
                                                setCookie('shell_current_dir',shell_current_dir);
                                                term.echo(data.result).resume();
                                            }
                                        },
                                        error: function (err){
                                            term.echo(err).resume();
                                        }
                                    });
                                }
                            },
                            {
                                greetings: get_boxed_text('<?php echo implode('\n',$greetings)?>'),
                                prompt: function(callback) {
                                    //console.log(shell_current_dir);
                                    callback('<?php echo $prompt_start; ?>'+shell_current_dir+'<?php echo $prompt_end; ?>');
                                },
                                name: 'shell',
                                tabcompletion: true,
                                login: false,
                                exit: false,
                                history: true,
                                convertLinks: false,
                                completion: function(terminal, command, callback) {
                                    callback(['Sorry, no tab completion...']);
                                },
                                onBlur: function() {
                                    // the height of the body is only 2 lines initialy
                                    return false;
                                }
                            }
                        );
                    });
                </script>
            <?php
            demo_fix();
            echo "</body>\n</html>";
        break;
    }
}
function server_info_form(){
    if (!@phpinfo()) echo et('NoPhpinfo')."...";
    echo "<br><br>";
        $a=ini_get_all();
        $output="<table border=1 cellspacing=0 cellpadding=4 align=center>";
        $output.="<tr><th colspan=2>ini_get_all()</td></tr>";
        while(list($key, $value)=each($a)) {
            list($k, $v)= each($a[$key]);
            $output.="<tr><td align=right>$key</td><td>$v</td></tr>";
        }
        $output.="</table>";
    echo $output;
    echo "<br><br>";
        $output="<table border=1 cellspacing=0 cellpadding=4 align=center>";
        $output.="<tr><th colspan=2>\$_SERVER</td></tr>";
        foreach ($_SERVER as $k=>$v) {
            $output.="<tr><td align=right>$k</td><td>$v</td></tr>";
        }
        $output.="</table>";
    echo $output;
    echo "<br><br>";
    echo "<table border=1 cellspacing=0 cellpadding=4 align=center>";
    $safe_mode=trim(ini_get("safe_mode"));
    if ((strlen($safe_mode)==0)||($safe_mode==0)) $safe_mode=false;
    else $safe_mode=true;
    $is_windows = (uppercase(substr(PHP_OS, 0, 3)) === 'WIN');
    echo "<tr><td colspan=2>".php_uname();
    echo "<tr><td>safe_mode<td>".($safe_mode?"on":"off");
    if ($is_windows) echo "<tr><td>sisop<td>Windows<br>";
    else echo "<tr><td>sisop<td>Linux<br>";
    echo "</table><br><br><table border=1 cellspacing=0 cellpadding=4 align=center>";
    $display_errors=ini_get("display_errors");
    $ignore_user_abort = ignore_user_abort();
    $max_execution_time = ini_get("max_execution_time");
    $upload_max_filesize = ini_get("upload_max_filesize");
    $memory_limit=ini_get("memory_limit");
    $output_buffering=ini_get("output_buffering");
    $default_socket_timeout=ini_get("default_socket_timeout");
    $allow_url_fopen = ini_get("allow_url_fopen");
    $magic_quotes_gpc = ini_get("magic_quotes_gpc");
    ignore_user_abort(true);
    ini_set("display_errors",0);
    ini_set("max_execution_time",0);
    ini_set("upload_max_filesize","10M");
    ini_set("memory_limit","20M");
    ini_set("output_buffering",0);
    ini_set("default_socket_timeout",30);
    ini_set("allow_url_fopen",1);
    ini_set("magic_quotes_gpc",0);
    echo "<tr><td colspan=4 align=center>Server Config Overwrite Test";
    echo "<tr><td> <td>Get<td>Set<td>Get";
    echo "<tr><td>display_errors<td>$display_errors<td>0<td>".ini_get("display_errors");
    echo "<tr><td>ignore_user_abort<td>".($ignore_user_abort?"on":"off")."<td>on<td>".(ignore_user_abort()?"on":"off");
    echo "<tr><td>max_execution_time<td>$max_execution_time<td>0<td>".ini_get("max_execution_time");
    echo "<tr><td>upload_max_filesize<td>$upload_max_filesize<td>10M<td>".ini_get("upload_max_filesize");
    echo "<tr><td>memory_limit<td>$memory_limit<td>20M<td>".ini_get("memory_limit");
    echo "<tr><td>output_buffering<td>$output_buffering<td>0<td>".ini_get("output_buffering");
    echo "<tr><td>default_socket_timeout<td>$default_socket_timeout<td>30<td>".ini_get("default_socket_timeout");
    echo "<tr><td>allow_url_fopen<td>$allow_url_fopen<td>1<td>".ini_get("allow_url_fopen");
    echo "<tr><td>magic_quotes_gpc<td>$magic_quotes_gpc<td>0<td>".ini_get("magic_quotes_gpc");
    echo "</table><br><br>";
    echo "</body>\n</html>";
}
// +--------------------------------------------------
// | Session
// +--------------------------------------------------
function logout(){
    global $fm_path_info;
    setcookie("loggedon",0,0,"/");
    echo "
    <script language=\"Javascript\" type=\"text/javascript\">
    <!--
        window.parent.document.location.href='".$fm_path_info['basename']."';
    //-->
    </script>";
}
function login(){
    global $pass,$auth_pass,$fm_path_info;
    if (md5(trim($pass)) == $auth_pass){
        setcookie("loggedon",$auth_pass,0,"/");
        header ("Location: ".$fm_path_info['basename']);
        return true;
    } else header ("Location: ".$fm_path_info['basename']."?erro=1");
    return false;
}
function login_form(){
    global $erro,$auth_pass,$loggedon,$fm_path_info,$noscript,$version;
    html_header();
    echo "
    <body>";
    if ($noscript && ($auth_pass == md5('') || $loggedon==$auth_pass)) {
        echo "
        <table border=0 cellspacing=0 cellpadding=5>
            <tr><td><font size=4>".et('FileMan')."</font></td></tr>
            <tr><td align=left><font color=red size=3>Error: No Javascript support...</font></td></tr>
        </table>
        <script language=\"Javascript\" type=\"text/javascript\">
        <!--
            window.parent.document.location.href='".$fm_path_info['basename']."';
        //-->
        </script>";
    } else {
        echo "
        <form class=\"form-signin noScriptHidden mt-4\" name=\"login_form\" action=\"" . $fm_path_info['basename'] . "\" method=\"post\">
            <h2 class=\"form-signin-heading text-center\">".et('FileMan')."</h2>
            <input type=\"password\" class=\"form-control\" name=\"pass\" placeholder=\"".et('Pass')."\" required=\"\"/>
            <button type=\"submit\" class=\"btn noIcon\" style=\"float:right\" value=\"".et('Login')."\">".et('Login')."</button>
            <div style=\"clear:both\"></div>";
        if (strlen($erro)) echo "
            <div class=\"alert alert-danger\" style=\"margin-top: 10px;\">".et('InvPass')."</div>";
        echo "
        </form>
        <script language=\"Javascript\" type=\"text/javascript\">
        <!--
            document.login_form.pass.focus();
        //-->
        </script>";
        echo "
        <noscript>
            <style>
                .noScriptHidden { display:none }
            </style>
            <table border=0 cellspacing=0 cellpadding=5>
                <tr><td><font size=4>".et('FileMan')."</font></td></tr>
                <tr><td align=left><font color=red size=3>Error: No Javascript support...</font></td></tr>
            </table>
        </noscript>";
    }
    echo "
    </body>
    </html>";
}
function frame3(){
    global $is_windows,$cmd_arg,$chmod_arg,$zip_dir,$fm_current_root,$cookie_cache_time;
    global $dir_dest,$fm_current_dir,$dir_before;
    global $selected_file_list,$selected_dir_list,$old_name,$new_name;
    global $action,$or_by,$order_dir_list_by;
    global $about_form_was_shown;
    // ZIP download
    if ($action == '73') {
        ignore_user_abort(true);
        ini_set("display_errors",0);
        ini_set("max_execution_time",0);
        $filename = trim(str_replace(DIRECTORY_SEPARATOR,'-',$fm_current_dir),'-');
        $filename = str_replace(':','-',$filename);
        $filename = replace_double('-',$filename);
        $filename = trim($filename,'-').'-'.date('Y.m.d-H\hi').'.zip';
        $file = new zip_file($filename);
        if ($file){
            $file->set_options(array('basedir'=>$fm_current_dir,'overwrite'=>1,'level'=>3,'inmemory'=>1));
            if (strlen($selected_file_list)){
                $selected_file_list = explode("<|*|>",$selected_file_list);
                if (count($selected_file_list)) {
                    for($x=0;$x<count($selected_file_list);$x++) {
                        $selected_file_list[$x] = trim($selected_file_list[$x]);
                        if (strlen($selected_file_list[$x])) $file->add_files($selected_file_list[$x]);
                    }
                }
            }
            if (strlen($selected_dir_list)){
                $selected_dir_list = explode("<|*|>",$selected_dir_list);
                if (count($selected_dir_list)) {
                    for($x=0;$x<count($selected_dir_list);$x++) {
                        $selected_dir_list[$x] = trim($selected_dir_list[$x]);
                        if (strlen($selected_dir_list[$x])) $file->add_files($selected_dir_list[$x]);
                    }
                }
            }
            $file->create_archive();
            $file->download_file();
            exit();
        }
    }
    $about_form_was_shown = intval($about_form_was_shown);
    if (!$about_form_was_shown){
        setcookie("about_form_was_shown", '1' , time()+$cookie_cache_time , "/");
    }
    if (!isset($order_dir_list_by)){
        $order_dir_list_by = "1A";
        setcookie("order_dir_list_by", $order_dir_list_by , time()+$cookie_cache_time , "/");
    } elseif (strlen($or_by)){
        $order_dir_list_by = $or_by;
        setcookie("order_dir_list_by", $or_by , time()+$cookie_cache_time , "/");
    }
    setcookie("fm_current_dir", $fm_current_dir, 0 , "/");
    html_header("
        <script type=\"text/javascript\" src=\"".$fm_path_info['basename']."?action=99&filename=jquery-1.11.1.min.js\"></script>
    ");
    echo "<body>\n";
    $GLOBALS['dir_list_warn_message'] = '';
    if ($action){
        switch ($action){
            case 1: // create dir
            $cmd_arg = fix_filename($cmd_arg);
            if (strlen($cmd_arg)){
                $cmd_arg = $fm_current_dir.$cmd_arg;
                if (!file_exists($cmd_arg)){
                    @mkdir(fs_encode($cmd_arg),0755,true);
                    @chmod(fs_encode($cmd_arg),0755);
                    reloadframe("parent",2,"&ec_dir=".$cmd_arg);
                } else alert(et('FileDirExists').".");
            }
            break;
            case 2: // create arq
            $cmd_arg = fix_filename($cmd_arg);
            if (strlen($cmd_arg)){
                $cmd_arg = $fm_current_dir.$cmd_arg;
                if (!file_exists($cmd_arg)){
                    @touch($cmd_arg);
                    @chmod($cmd_arg,0644);
                } else alert(et('FileDirExists').".");
            }
            break;
            case 3: // rename arq ou dir
            if ((strlen($old_name))&&(strlen($new_name))){
                rename($fm_current_dir.$old_name,$fm_current_dir.$new_name);
                if (is_dir($fm_current_dir.$new_name) || is_link($fm_current_dir.$new_name)) reloadframe("parent",2);
            }
            break;
            case 4: // delete sel
            if(strstr($fm_current_dir,$fm_current_root)){
                if (strlen($selected_file_list)){
                    $selected_file_list = explode("<|*|>",$selected_file_list);
                    if (count($selected_file_list)) {
                        for($x=0;$x<count($selected_file_list);$x++) {
                            $selected_file_list[$x] = trim($selected_file_list[$x]);
                            if (strlen($selected_file_list[$x])) total_delete($fm_current_dir.$selected_file_list[$x]);
                        }
                    }
                }
                if (strlen($selected_dir_list)){
                    $selected_dir_list = explode("<|*|>",$selected_dir_list);
                    if (count($selected_dir_list)) {
                        for($x=0;$x<count($selected_dir_list);$x++) {
                            $selected_dir_list[$x] = trim($selected_dir_list[$x]);
                            if (strlen($selected_dir_list[$x])) total_delete($fm_current_dir.$selected_dir_list[$x]);
                        }
                        reloadframe("parent",2);
                    }
                }
            }
            break;
            case 5: // copy sel
            if (strlen($dir_dest)){
                if(uppercase($dir_dest) != uppercase($fm_current_dir)){
                    if (strlen($selected_file_list)){
                        $selected_file_list = explode("<|*|>",$selected_file_list);
                        if (count($selected_file_list)) {
                            for($x=0;$x<count($selected_file_list);$x++) {
                                $selected_file_list[$x] = trim($selected_file_list[$x]);
                                if (strlen($selected_file_list[$x])) total_copy($fm_current_dir.$selected_file_list[$x],$dir_dest.$selected_file_list[$x]);
                            }
                        }
                    }
                    if (strlen($selected_dir_list)){
                        $selected_dir_list = explode("<|*|>",$selected_dir_list);
                        if (count($selected_dir_list)) {
                            for($x=0;$x<count($selected_dir_list);$x++) {
                                $selected_dir_list[$x] = trim($selected_dir_list[$x]);
                                if (strlen($selected_dir_list[$x])) total_copy($fm_current_dir.$selected_dir_list[$x],$dir_dest.$selected_dir_list[$x]);
                            }
                            reloadframe("parent",2);
                        }
                    }
                    $fm_current_dir = $dir_dest;
                }
            }
            break;
            case 6: // move sel
            if (strlen($dir_dest)){
                if(uppercase($dir_dest) != uppercase($fm_current_dir)){
                    if (strlen($selected_file_list)){
                        $selected_file_list = explode("<|*|>",$selected_file_list);
                        if (count($selected_file_list)) {
                            for($x=0;$x<count($selected_file_list);$x++) {
                                $selected_file_list[$x] = trim($selected_file_list[$x]);
                                if (strlen($selected_file_list[$x])) total_move($fm_current_dir.$selected_file_list[$x],$dir_dest.$selected_file_list[$x]);
                            }
                        }
                    }
                    if (strlen($selected_dir_list)){
                        $selected_dir_list = explode("<|*|>",$selected_dir_list);
                        if (count($selected_dir_list)) {
                            for($x=0;$x<count($selected_dir_list);$x++) {
                                $selected_dir_list[$x] = trim($selected_dir_list[$x]);
                                if (strlen($selected_dir_list[$x])) total_move($fm_current_dir.$selected_dir_list[$x],$dir_dest.$selected_dir_list[$x]);
                            }
                            reloadframe("parent",2);
                        }
                    }
                    $fm_current_dir = $dir_dest;
                }
            }
            break;
            case 71: // compress sel
            if (strlen($cmd_arg)){
                ignore_user_abort(true);
                ini_set("display_errors",0);
                ini_set("max_execution_time",0);
                $file = false;
                if (strstr($cmd_arg,".tar")) $file = new tar_file($cmd_arg);
                elseif (strstr($cmd_arg,".zip")) $file = new zip_file($cmd_arg);
                elseif (strstr($cmd_arg,".bzip")) $file = new bzip_file($cmd_arg);
                elseif (strstr($cmd_arg,".gzip")) $file = new gzip_file($cmd_arg);
                if ($file){
                    $file->set_options(array('basedir'=>$fm_current_dir,'overwrite'=>1,'level'=>3));
                    if (strlen($selected_file_list)){
                        $selected_file_list = explode("<|*|>",$selected_file_list);
                        if (count($selected_file_list)) {
                            for($x=0;$x<count($selected_file_list);$x++) {
                                $selected_file_list[$x] = trim($selected_file_list[$x]);
                                if (strlen($selected_file_list[$x])) $file->add_files($selected_file_list[$x]);
                            }
                        }
                    }
                    if (strlen($selected_dir_list)){
                        $selected_dir_list = explode("<|*|>",$selected_dir_list);
                        if (count($selected_dir_list)) {
                            for($x=0;$x<count($selected_dir_list);$x++) {
                                $selected_dir_list[$x] = trim($selected_dir_list[$x]);
                                if (strlen($selected_dir_list[$x])) $file->add_files($selected_dir_list[$x]);
                            }
                        }
                    }
                    $file->create_archive();
                }
                unset($file);
            }
            break;
            case 72: // decompress arq
            if (strlen($cmd_arg)){
                if (file_exists($fm_current_dir.$cmd_arg)){
                    if (strstr($cmd_arg,".zip") && class_exists('ZipArchive')) {
                        $zipArchive = new ZipArchive();
                        if ($zipArchive->open($cmd_arg) === true) {
                            $zipArchive->extractTo($fm_current_dir);
                            $zipArchive->close();
                        }
                    } else {
                        if (strstr($cmd_arg,".bzip")||strstr($cmd_arg,".bz2")||strstr($cmd_arg,".tbz2")||strstr($cmd_arg,".bz")||strstr($cmd_arg,".tbz")) $file = new bzip_file($cmd_arg);
                        elseif (strstr($cmd_arg,".gzip")||strstr($cmd_arg,".gz")||strstr($cmd_arg,".tgz")) $file = new gzip_file($cmd_arg);
                        elseif (strstr($cmd_arg,".tar")) $file = new tar_file($cmd_arg);
                        if ($file){
                            $file->set_options(array('basedir'=>$fm_current_dir,'overwrite'=>1));
                            $file->extract_files();
                        }
                        unset($file);
                    }
                    reloadframe("parent",2);
                }
            }
            break;
            case 8: // delete folder/file
            if (strlen($cmd_arg)){
                total_delete($fm_current_dir.$cmd_arg);
                reloadframe("parent",2);
            }
            break;
            case 9: // CHMOD
            if((strlen($chmod_arg) == 4)&&(strlen($fm_current_dir))){
                if ($chmod_arg[0]=="1") $chmod_arg = "0".$chmod_arg;
                else $chmod_arg = "0".substr($chmod_arg,strlen($chmod_arg)-3);
                $new_mod = octdec($chmod_arg);
                if (strlen($selected_file_list)){
                    $selected_file_list = explode("<|*|>",$selected_file_list);
                    if (count($selected_file_list)) {
                        for($x=0;$x<count($selected_file_list);$x++) {
                            $selected_file_list[$x] = trim($selected_file_list[$x]);
                            if (strlen($selected_file_list[$x])) @chmod($fm_current_dir.$selected_file_list[$x],$new_mod);
                        }
                    }
                }
                if (strlen($selected_dir_list)){
                    $selected_dir_list = explode("<|*|>",$selected_dir_list);
                    if (count($selected_dir_list)) {
                        for($x=0;$x<count($selected_dir_list);$x++) {
                            $selected_dir_list[$x] = trim($selected_dir_list[$x]);
                            if (strlen($selected_dir_list[$x])) @chmod($fm_current_dir.$selected_dir_list[$x],$new_mod);
                        }
                    }
                }
            }
            break;
            case 121: // Symlink
            case 122: // Hardlink
            $allow_links_to_links = true; // TODO: readlink() recursive
            $cmd_arg = fix_filename($cmd_arg);
            if (strlen($dir_dest)){
                if (strlen($selected_file_list)){
                    $selected_file_list = explode("<|*|>",$selected_file_list);
                    if (count($selected_file_list)) {
                        for($x=0;$x<count($selected_file_list);$x++) {
                            $selected_file_list[$x] = trim($selected_file_list[$x]);
                            if (strlen($selected_file_list[$x])) {
                                $link_name = rtrim($dir_dest.$selected_file_list[$x],DIRECTORY_SEPARATOR);
                                if (count($selected_file_list) == 1 && strlen($cmd_arg)) {
                                    $link_name = rtrim($dir_dest.$cmd_arg,DIRECTORY_SEPARATOR);
                                }
                                if ($action == '121') symlink_phpfm($fm_current_dir.$selected_file_list[$x], $link_name);
                                else link_phpfm($fm_current_dir.$selected_file_list[$x], $link_name);
                            }
                        }
                    }
                }
                if (strlen($selected_dir_list)){
                    $selected_dir_list = explode("<|*|>",$selected_dir_list);
                    if (count($selected_dir_list)) {
                        for($x=0;$x<count($selected_dir_list);$x++) {
                            $selected_dir_list[$x] = trim($selected_dir_list[$x]);
                            if (strlen($selected_dir_list[$x])) {
                                $link_name = rtrim($dir_dest.$selected_dir_list[$x],DIRECTORY_SEPARATOR);
                                if (count($selected_dir_list) == 1 && strlen($cmd_arg)) {
                                    $link_name = rtrim($dir_dest.$cmd_arg,DIRECTORY_SEPARATOR);
                                }
                                if ($action == '121') symlink_phpfm($fm_current_dir.$selected_dir_list[$x], $link_name);
                                else link_phpfm($fm_current_dir.$selected_dir_list[$x], $link_name);
                            }

                        }
                        reloadframe("parent",2);
                    }
                }
                $fm_current_dir = $dir_dest;
            }
            break;
        }
        if ($action != 10) {
            dir_list_form();
        }
    } else {
        dir_list_form();
    }
    if (!$about_form_was_shown) {
        echo "
        <script language=\"Javascript\" type=\"text/javascript\">
            about_form();
        </script>";
    }
    demo_fix();
    echo "
    </body>\n</html>";
}
function frameset(){
    global $fm_path_info,$leftFrameWidth;
    if (!isset($leftFrameWidth)) $leftFrameWidth = 300;
    html_header("
    <noscript>
        <meta http-equiv=\"refresh\" content=\"0;url=".$fm_path_info['basename']."?noscript=1\">
    </noscript>
    ");
    echo "
    <frameset cols=\"".$leftFrameWidth.",*\" framespacing=\"0\">
        <frameset rows=\"0,*\" framespacing=\"0\" frameborder=\"0\">
            <frame src=\"".$fm_path_info['basename']."?frame=1\" name=frame1 border=\"0\" marginwidth=\"0\" marginheight=\"0\" scrolling=\"no\">
            <frame src=\"".$fm_path_info['basename']."?frame=2\" name=frame2 border=\"0\" marginwidth=\"0\" marginheight=\"0\">
        </frameset>
        <frame src=\"".$fm_path_info['basename']."?frame=3\" name=frame3 border=\"0\" marginwidth=\"0\" marginheight=\"0\">
    </frameset>
    </html>";
}
// +--------------------------------------------------
// | Open Source Contributions
// +--------------------------------------------------
/*-------------------------------------------------
| TAR/GZIP/BZIP2/ZIP ARCHIVE CLASSES 2.1
| By Devin Doucette
| Copyright (c) 2005 Devin Doucette
| Email: darksnoopy@shaw.ca
+--------------------------------------------------
| Email bugs/suggestions to darksnoopy@shaw.ca
+--------------------------------------------------
| This script has been created and released under
| the GNU GPL and is free to use and redistribute
| only if this copyright statement is not removed
+--------------------------------------------------*/
class archive {
    function __construct($name) {
        $this->options   = array(
            'basedir' => ".",
            'name' => $name,
            'prepend' => "",
            'inmemory' => 0,
            'overwrite' => 0,
            'recurse' => 1,
            'storepaths' => 1,
            'followlinks' => 0,
            'level' => 3,
            'method' => 1,
            'sfx' => "",
            'type' => "",
            'comment' => ""
        );
        $this->files     = array();
        $this->exclude   = array();
        $this->storeonly = array();
        $this->error     = array();
    }
    function set_options($options) {
        foreach ($options as $key => $value)
            $this->options[$key] = $value;
        if (!empty($this->options['basedir'])) {
            $this->options['basedir'] = str_replace("\\", "/", $this->options['basedir']);
            $this->options['basedir'] = preg_replace("/\/+/", "/", $this->options['basedir']);
            $this->options['basedir'] = preg_replace("/\/$/", "", $this->options['basedir']);
        }
        if (!empty($this->options['name'])) {
            $this->options['name'] = str_replace("\\", "/", $this->options['name']);
            $this->options['name'] = preg_replace("/\/+/", "/", $this->options['name']);
        }
        if (!empty($this->options['prepend'])) {
            $this->options['prepend'] = str_replace("\\", "/", $this->options['prepend']);
            $this->options['prepend'] = preg_replace("/^(\.*\/+)+/", "", $this->options['prepend']);
            $this->options['prepend'] = preg_replace("/\/+/", "/", $this->options['prepend']);
            $this->options['prepend'] = preg_replace("/\/$/", "", $this->options['prepend']) . "/";
        }
    }
    function create_archive() {
        $this->make_list();
        if ($this->options['inmemory'] == 0) {
            $pwd = getcwd();
            chdir($this->options['basedir']);
            if ($this->options['overwrite'] == 0 && file_exists($this->options['name'])) {
                $this->error[] = "File {$this->options['name']} already exists.";
                chdir($pwd);
                return 0;
            } else if ($this->archive = @fopen($this->options['name'], "wb+")) {
                chdir($pwd);
            } else {
                $this->error[] = "Could not open {$this->options['name']} for writing.";
                chdir($pwd);
                return 0;
            }
        } else {
            $this->archive = "";
        }
        switch ($this->options['type']) {
            case "zip":
                if (!$this->create_zip()) {
                    $this->error[] = "Could not create zip file.";
                    return 0;
                }
                break;
            case "bzip":
                if (!$this->create_tar()) {
                    $this->error[] = "Could not create tar file.";
                    return 0;
                }
                if (!$this->create_bzip()) {
                    $this->error[] = "Could not create bzip2 file.";
                    return 0;
                }
                break;
            case "gzip":
                if (!$this->create_tar()) {
                    $this->error[] = "Could not create tar file.";
                    return 0;
                }
                if (!$this->create_gzip()) {
                    $this->error[] = "Could not create gzip file.";
                    return 0;
                }
                break;
            case "tar":
                if (!$this->create_tar()) {
                    $this->error[] = "Could not create tar file.";
                    return 0;
                }
        }
        if ($this->options['inmemory'] == 0) {
            fclose($this->archive);
        }
    }
    function add_data($data) {
        if ($this->options['inmemory'] == 0)
            fwrite($this->archive, $data);
        else
            $this->archive .= $data;
    }
    function make_list() {
        if (!empty($this->exclude))
            foreach ($this->files as $key => $value)
                foreach ($this->exclude as $current)
                    if ($value['name'] == $current['name'])
                        unset($this->files[$key]);
        if (!empty($this->storeonly))
            foreach ($this->files as $key => $value)
                foreach ($this->storeonly as $current)
                    if ($value['name'] == $current['name'])
                        $this->files[$key]['method'] = 0;
        unset($this->exclude, $this->storeonly);
    }
    function add_files($list) {
        $temp = $this->list_files($list);
        foreach ($temp as $current)
            $this->files[] = $current;
    }
    function exclude_files($list) {
        $temp = $this->list_files($list);
        foreach ($temp as $current)
            $this->exclude[] = $current;
    }
    function store_files($list) {
        $temp = $this->list_files($list);
        foreach ($temp as $current)
            $this->storeonly[] = $current;
    }
    function list_files($list) {
        if (!is_array($list)) {
            $temp = $list;
            $list = array(
                $temp
            );
            unset($temp);
        }
        $files = array();
        $pwd   = getcwd();
        chdir($this->options['basedir']);
        foreach ($list as $current) {
            $current = str_replace("\\", "/", $current);
            $current = preg_replace("/\/+/", "/", $current);
            $current = preg_replace("/\/$/", "", $current);
            if (strstr($current, "*")) {
                $regex = preg_replace("/([\\\^\$\.\[\]\|\(\)\?\+\{\}\/])/", "\\\\\\1", $current);
                $regex = str_replace("*", ".*", $regex);
                $dir   = strstr($current, "/") ? substr($current, 0, strrpos($current, "/")) : ".";
                $temp  = $this->parse_dir($dir);
                foreach ($temp as $current2)
                    if (preg_match("/^{$regex}$/i", $current2['name']))
                        $files[] = $current2;
                unset($regex, $dir, $temp, $current);
            } else if (@is_dir($current)) {
                $temp = $this->parse_dir($current);
                foreach ($temp as $file)
                    $files[] = $file;
                unset($temp, $file);
            } else if (@file_exists($current))
                $files[] = array(
                    'name' => $current,
                    'name2' => $this->options['prepend'] . preg_replace("/(\.+\/+)+/", "", ($this->options['storepaths'] == 0 && strstr($current, "/")) ? substr($current, strrpos($current, "/") + 1) : $current),
                    'type' => @is_link($current) && $this->options['followlinks'] == 0 ? 2 : 0,
                    'ext' => substr($current, strrpos($current, ".")),
                    'stat' => stat($current)
                );
        }
        chdir($pwd);
        unset($current, $pwd);
        usort($files, array(
            "archive",
            "sort_files"
        ));
        return $files;
    }
    function parse_dir($dirname) {
        $files = array();
        if ($this->options['storepaths'] == 1 && !preg_match("/^(\.+\/*)+$/", $dirname)) {
            $files = array(
                array(
                    'name' => $dirname,
                    'name2' => $this->options['prepend'] . preg_replace("/(\.+\/+)+/", "", ($this->options['storepaths'] == 0 && strstr($dirname, "/")) ? substr($dirname, strrpos($dirname, "/") + 1) : $dirname),
                    'type' => 5,
                    'stat' => stat($dirname)
                )
            );
        }
        if ($dir = @opendir($dirname)){
            while (($file = @readdir($dir)) !== false) {
                $fullname = $dirname . "/" . $file;
                if ($file == "." || $file == "..")
                    continue;
                else if (@is_dir($fullname)) {
                    if (empty($this->options['recurse']))
                        continue;
                    $temp = $this->parse_dir($fullname);
                    foreach ($temp as $file2)
                        $files[] = $file2;
                } else if (@file_exists($fullname))
                    $files[] = array(
                        'name' => $fullname,
                        'name2' => $this->options['prepend'] . preg_replace("/(\.+\/+)+/", "", ($this->options['storepaths'] == 0 && strstr($fullname, "/")) ? substr($fullname, strrpos($fullname, "/") + 1) : $fullname),
                        'type' => @is_link($fullname) && $this->options['followlinks'] == 0 ? 2 : 0,
                        'ext' => substr($file, strrpos($file, ".")),
                        'stat' => stat($fullname)
                    );
            }
            @closedir($dir);
        }
        return $files;
    }
    function sort_files($a, $b) {
        if ($a['type'] != $b['type'])
            if ($a['type'] == 5 || $b['type'] == 2)
                return -1;
            else if ($a['type'] == 2 || $b['type'] == 5)
                return 1;
            else if ($a['type'] == 5)
                return strcmp(strtolower($a['name']), strtolower($b['name']));
            else if ($a['ext'] != $b['ext'])
                return strcmp($a['ext'], $b['ext']);
            else if ($a['stat'][7] != $b['stat'][7])
                return $a['stat'][7] > $b['stat'][7] ? -1 : 1;
            else
                return strcmp(strtolower($a['name']), strtolower($b['name']));
        return 0;
    }
    function download_file() {
        if ($this->options['inmemory'] == 0) {
            $this->error[] = "Can only use download_file() if archive is in memory. Redirect to file otherwise, it is faster.";
            return;
        }
        switch ($this->options['type']) {
            case "zip":
                header("Content-Type: application/zip");
                break;
            case "bzip":
                header("Content-Type: application/x-bzip2");
                break;
            case "gzip":
                header("Content-Type: application/x-gzip");
                break;
            case "tar":
                header("Content-Type: application/x-tar");
        }
        $header = "Content-Disposition: attachment; filename=\"";
        $header .= strstr($this->options['name'], "/") ? substr($this->options['name'], strrpos($this->options['name'], "/") + 1) : $this->options['name'];
        $header .= "\"";
        header($header);
        header("Content-Length: ".strlen($this->archive));
        header("Content-Transfer-Encoding: binary");
        header("Cache-Control: no-cache, must-revalidate, max-age=60");
        header("Expires: Sat, 01 Jan 2000 12:00:00 GMT");
        print($this->archive);
        exit();
    }
}
class tar_file extends archive {
    function __construct($name) {
        parent::__construct($name);
        $this->options['type'] = "tar";
    }
    function create_tar() {
        $pwd = getcwd();
        chdir($this->options['basedir']);
        foreach ($this->files as $current) {
            if ($current['name'] == $this->options['name'])
                continue;
            if (strlen($current['name2']) > 99) {
                $path             = substr($current['name2'], 0, strpos($current['name2'], "/", strlen($current['name2']) - 100) + 1);
                $current['name2'] = substr($current['name2'], strlen($path));
                if (strlen($path) > 154 || strlen($current['name2']) > 99) {
                    $this->error[] = "Could not add {$path}{$current['name2']} to archive because the filename is too long.";
                    continue;
                }
            }
            $block    = pack("a100a8a8a8a12a12a8a1a100a6a2a32a32a8a8a155a12", $current['name2'], sprintf("%07o", $current['stat'][2]), sprintf("%07o", $current['stat'][4]), sprintf("%07o", $current['stat'][5]), sprintf("%011o", $current['type'] == 2 ? 0 : $current['stat'][7]), sprintf("%011o", $current['stat'][9]), "        ", $current['type'], $current['type'] == 2 ? @readlink($current['name']) : "", "ustar ", " ", "Unknown", "Unknown", "", "", !empty($path) ? $path : "", "");
            $checksum = 0;
            for ($i = 0; $i < 512; $i++)
                $checksum += ord(substr($block, $i, 1));
            $checksum = pack("a8", sprintf("%07o", $checksum));
            $block    = substr_replace($block, $checksum, 148, 8);
            if ($current['type'] == 2 || $current['stat'][7] == 0)
                $this->add_data($block);
            else if ($fp = @fopen($current['name'], "rb")) {
                $this->add_data($block);
                while ($temp = fread($fp, 1048576))
                    $this->add_data($temp);
                if ($current['stat'][7] % 512 > 0) {
                    $temp = "";
                    for ($i = 0; $i < 512 - $current['stat'][7] % 512; $i++)
                        $temp .= "\0";
                    $this->add_data($temp);
                }
                fclose($fp);
            } else
                $this->error[] = "Could not open file {$current['name']} for reading. It was not added.";
        }
        $this->add_data(pack("a1024", ""));
        chdir($pwd);
        return 1;
    }
    function extract_files() {
        $pwd = getcwd();
        chdir($this->options['basedir']);
        if ($fp = $this->open_archive()) {
            if ($this->options['inmemory'] == 1)
                $this->files = array();
            while ($block = fread($fp, 512)) {
                $temp = unpack("a100name/a8mode/a8uid/a8gid/a12size/a12mtime/a8checksum/a1type/a100symlink/a6magic/a2temp/a32temp/a32temp/a8temp/a8temp/a155prefix/a12temp", $block);
                $file = array(
                    'name' => $temp['prefix'] . $temp['name'],
                    'stat' => array(
                        2 => $temp['mode'],
                        4 => octdec($temp['uid']),
                        5 => octdec($temp['gid']),
                        7 => octdec($temp['size']),
                        9 => octdec($temp['mtime'])
                    ),
                    'checksum' => octdec($temp['checksum']),
                    'type' => $temp['type'],
                    'magic' => $temp['magic']
                );
                if ($file['checksum'] == 0x00000000)
                    break;
                else if (substr($file['magic'], 0, 5) != "ustar") {
                    $this->error[] = "This script does not support extracting this type of tar file.";
                    break;
                }
                $block    = substr_replace($block, "        ", 148, 8);
                $checksum = 0;
                for ($i = 0; $i < 512; $i++)
                    $checksum += ord(substr($block, $i, 1));
                if ($file['checksum'] != $checksum)
                    $this->error[] = "Could not extract from {$this->options['name']}, it is corrupt.";
                if ($this->options['inmemory'] == 1) {
                    $file['data'] = fread($fp, $file['stat'][7]);
                    fread($fp, (512 - $file['stat'][7] % 512) == 512 ? 0 : (512 - $file['stat'][7] % 512));
                    unset($file['checksum'], $file['magic']);
                    $this->files[] = $file;
                } else if ($file['type'] == 5) {
                    if (!is_dir($file['name']))
                        mkdir(fs_encode($file['name']), $file['stat'][2]);
                } else if ($this->options['overwrite'] == 0 && file_exists($file['name'])) {
                    $this->error[] = "{$file['name']} already exists.";
                    continue;
                } else if ($file['type'] == 2) {
                    symlink_phpfm($temp['symlink'], $file['name']);
                    chmod($file['name'], $file['stat'][2]);
                } else if ($new = @fopen($file['name'], "wb")) {
                    fwrite($new, fread($fp, $file['stat'][7]));
                    fread($fp, (512 - $file['stat'][7] % 512) == 512 ? 0 : (512 - $file['stat'][7] % 512));
                    fclose($new);
                    chmod($file['name'], $file['stat'][2]);
                } else {
                    $this->error[] = "Could not open {$file['name']} for writing.";
                    continue;
                }
                chown($file['name'], $file['stat'][4]);
                chgrp($file['name'], $file['stat'][5]);
                touch($file['name'], $file['stat'][9]);
                unset($file);
            }
        } else
            $this->error[] = "Could not open file {$this->options['name']}";
        chdir($pwd);
    }
    function open_archive() {
        return @fopen($this->options['name'], "rb");
    }
}
class gzip_file extends tar_file {
    function __construct($name) {
        parent::__construct($name);
        $this->options['type'] = "gzip";
    }
    function create_gzip() {
        if ($this->options['inmemory'] == 0) {
            $pwd = getcwd();
            chdir($this->options['basedir']);
            if ($fp = gzopen($this->options['name'], "wb{$this->options['level']}")) {
                fseek($this->archive, 0);
                while ($temp = fread($this->archive, 1048576))
                    gzwrite($fp, $temp);
                gzclose($fp);
                chdir($pwd);
            } else {
                $this->error[] = "Could not open {$this->options['name']} for writing.";
                chdir($pwd);
                return 0;
            }
        } else
            $this->archive = gzencode($this->archive, $this->options['level']);
        return 1;
    }
    function open_archive() {
        return @gzopen($this->options['name'], "rb");
    }
}
class bzip_file extends tar_file {
    function __construct($name) {
        parent::__construct($name);
        $this->options['type'] = "bzip";
    }
    function create_bzip() {
        if ($this->options['inmemory'] == 0) {
            $pwd = getcwd();
            chdir($this->options['basedir']);
            if ($fp = bzopen($this->options['name'], "wb")) {
                fseek($this->archive, 0);
                while ($temp = fread($this->archive, 1048576))
                    bzwrite($fp, $temp);
                bzclose($fp);
                chdir($pwd);
            } else {
                $this->error[] = "Could not open {$this->options['name']} for writing.";
                chdir($pwd);
                return 0;
            }
        } else
            $this->archive = bzcompress($this->archive, $this->options['level']);
        return 1;
    }
    function open_archive() {
        return @bzopen($this->options['name'], "rb");
    }
}
class zip_file extends archive {
    function __construct($name) {
        parent::__construct($name);
        $this->options['type'] = "zip";
    }
    function create_zip() {
        $files   = 0;
        $offset  = 0;
        $central = "";
        if (!empty($this->options['sfx']))
            if ($fp = @fopen($this->options['sfx'], "rb")) {
                $temp = fread($fp, phpfm_filesize($this->options['sfx']));
                fclose($fp);
                $this->add_data($temp);
                $offset += strlen($temp);
                unset($temp);
            } else
                $this->error[] = "Could not open sfx module from {$this->options['sfx']}.";
        $pwd = getcwd();
        chdir($this->options['basedir']);
        foreach ($this->files as $current) {
            if ($current['name'] == $this->options['name'])
                continue;
            $timedate = explode(" ", date("Y n j G i s", $current['stat'][9]));
            $timedate = ($timedate[0] - 1980 << 25) | ($timedate[1] << 21) | ($timedate[2] << 16) | ($timedate[3] << 11) | ($timedate[4] << 5) | ($timedate[5]);
            $block    = pack("VvvvV", 0x04034b50, 0x000A, 0x0000, (isset($current['method']) || $this->options['method'] == 0) ? 0x0000 : 0x0008, $timedate);
            if ($current['stat'][7] == 0 && $current['type'] == 5) {
                $block .= pack("VVVvv", 0x00000000, 0x00000000, 0x00000000, strlen($current['name2']) + 1, 0x0000);
                $block .= $current['name2'] . "/";
                $this->add_data($block);
                $central .= pack("VvvvvVVVVvvvvvVV", 0x02014b50, 0x0014, $this->options['method'] == 0 ? 0x0000 : 0x000A, 0x0000, (isset($current['method']) || $this->options['method'] == 0) ? 0x0000 : 0x0008, $timedate, 0x00000000, 0x00000000, 0x00000000, strlen($current['name2']) + 1, 0x0000, 0x0000, 0x0000, 0x0000, $current['type'] == 5 ? 0x00000010 : 0x00000000, $offset);
                $central .= $current['name2'] . "/";
                $files++;
                $offset += (31 + strlen($current['name2']));
            } else if ($current['stat'][7] == 0) {
                $block .= pack("VVVvv", 0x00000000, 0x00000000, 0x00000000, strlen($current['name2']), 0x0000);
                $block .= $current['name2'];
                $this->add_data($block);
                $central .= pack("VvvvvVVVVvvvvvVV", 0x02014b50, 0x0014, $this->options['method'] == 0 ? 0x0000 : 0x000A, 0x0000, (isset($current['method']) || $this->options['method'] == 0) ? 0x0000 : 0x0008, $timedate, 0x00000000, 0x00000000, 0x00000000, strlen($current['name2']), 0x0000, 0x0000, 0x0000, 0x0000, $current['type'] == 5 ? 0x00000010 : 0x00000000, $offset);
                $central .= $current['name2'];
                $files++;
                $offset += (30 + strlen($current['name2']));
            } else if ($fp = @fopen($current['name'], "rb")) {
                $temp = fread($fp, $current['stat'][7]);
                fclose($fp);
                $crc32 = crc32($temp);
                if (!isset($current['method']) && $this->options['method'] == 1) {
                    $temp = gzcompress($temp, $this->options['level']);
                    $size = strlen($temp) - 6;
                    $temp = substr($temp, 2, $size);
                } else
                    $size = strlen($temp);
                $block .= pack("VVVvv", $crc32, $size, $current['stat'][7], strlen($current['name2']), 0x0000);
                $block .= $current['name2'];
                $this->add_data($block);
                $this->add_data($temp);
                unset($temp);
                $central .= pack("VvvvvVVVVvvvvvVV", 0x02014b50, 0x0014, $this->options['method'] == 0 ? 0x0000 : 0x000A, 0x0000, (isset($current['method']) || $this->options['method'] == 0) ? 0x0000 : 0x0008, $timedate, $crc32, $size, $current['stat'][7], strlen($current['name2']), 0x0000, 0x0000, 0x0000, 0x0000, 0x00000000, $offset);
                $central .= $current['name2'];
                $files++;
                $offset += (30 + strlen($current['name2']) + $size);
            } else
                $this->error[] = "Could not open file {$current['name']} for reading. It was not added.";
        }
        $this->add_data($central);
        $this->add_data(pack("VvvvvVVv", 0x06054b50, 0x0000, 0x0000, $files, $files, strlen($central), $offset, !empty($this->options['comment']) ? strlen($this->options['comment']) : 0x0000));
        if (!empty($this->options['comment']))
            $this->add_data($this->options['comment']);
        chdir($pwd);
        return 1;
    }
}
/*-------------------------------------------------
| ChromePhp
| Server Side Chrome PHP debugger class
+--------------------------------------------------
| @author Craig Campbell <iamcraigcampbell@gmail.com>
+--------------------------------------------------
| Licensed under the Apache License, Version 2.0 (the "License")
| http://www.apache.org/licenses/LICENSE-2.0
+--------------------------------------------------*/
class ChromePhp {
    const VERSION = '4.1.0';
    const HEADER_NAME = 'X-ChromeLogger-Data';
    const BACKTRACE_LEVEL = 'backtrace_level';
    const LOG = 'log';
    const WARN = 'warn';
    const ERROR = 'error';
    const GROUP = 'group';
    const INFO = 'info';
    const GROUP_END = 'groupEnd';
    const GROUP_COLLAPSED = 'groupCollapsed';
    const TABLE = 'table';
    protected $_php_version;
    protected $_timestamp;
    protected $_json = array(
        'version' => self::VERSION,
        'columns' => array('log', 'backtrace', 'type'),
        'rows' => array()
    );
    protected $_backtraces = array();
    protected $_error_triggered = false;
    protected $_settings = array(
        self::BACKTRACE_LEVEL => 2
    );
    protected static $_instance;
    protected $_processed = array();
    private function __construct() {
        $this->_php_version = phpversion();
        $this->_timestamp = $this->_php_version >= 5.1 ? $_SERVER['REQUEST_TIME'] : time();
        $this->_json['request_uri'] = $_SERVER['REQUEST_URI'];
    }
    public static function getInstance() {
        if (self::$_instance === null) {
            self::$_instance = new self();
        }
        return self::$_instance;
    }
    public static function log() {
        $args = func_get_args();
        return self::_log('', $args);
    }
    public static function warn() {
        $args = func_get_args();
        return self::_log(self::WARN, $args);
    }
    public static function error() {
        $args = func_get_args();
        return self::_log(self::ERROR, $args);
    }
    public static function group() {
        $args = func_get_args();
        return self::_log(self::GROUP, $args);
    }
    public static function info() {
        $args = func_get_args();
        return self::_log(self::INFO, $args);
    }
    public static function groupCollapsed() {
        $args = func_get_args();
        return self::_log(self::GROUP_COLLAPSED, $args);
    }
    public static function groupEnd() {
        $args = func_get_args();
        return self::_log(self::GROUP_END, $args);
    }
    public static function table() {
        $args = func_get_args();
        return self::_log(self::TABLE, $args);
    }
    protected static function _log($type, array $args) {
        // nothing passed in, don't do anything
        if (count($args) == 0 && $type != self::GROUP_END) {
            return;
        }
        $logger = self::getInstance();
        $logger->_processed = array();
        $logs = array();
        foreach ($args as $arg) {
            $logs[] = $logger->_convert($arg);
        }
        $backtrace = debug_backtrace(false);
        $level = $logger->getSetting(self::BACKTRACE_LEVEL);
        $backtrace_message = 'unknown';
        if (isset($backtrace[$level]['file']) && isset($backtrace[$level]['line'])) {
            //$backtrace_message = trim($backtrace[$level]['file']).' '.trim($backtrace[$level]['line']);
            $backtrace_message = trim(basename($backtrace[$level]['file'])).':'.trim($backtrace[$level]['line']);
        }
        $logger->_addRow($logs, $backtrace_message, $type);
    }
    protected function _convert($object) {
        // if this isn't an object then just return it
        if (!is_object($object)) {
            return $object;
        }
        //Mark this object as processed so we don't convert it twice and it
        //Also avoid recursion when objects refer to each other
        $this->_processed[] = $object;
        $object_as_array = array();
        // first add the class name
        $object_as_array['___class_name'] = get_class($object);
        // loop through object vars
        $object_vars = get_object_vars($object);
        foreach ($object_vars as $key => $value) {
            // same instance as parent object
            if ($value === $object || in_array($value, $this->_processed, true)) {
                $value = 'recursion - parent object [' . get_class($value) . ']';
            }
            $object_as_array[$key] = $this->_convert($value);
        }
        $reflection = new ReflectionClass($object);
        // loop through the properties and add those
        foreach ($reflection->getProperties() as $property) {
            // if one of these properties was already added above then ignore it
            if (array_key_exists($property->getName(), $object_vars)) {
                continue;
            }
            $type = $this->_getPropertyKey($property);
            if ($this->_php_version >= 5.3) {
                $property->setAccessible(true);
            }
            try {
                $value = $property->getValue($object);
            } catch (ReflectionException $e) {
                $value = 'only PHP 5.3 can access private/protected properties';
            }
            // same instance as parent object
            if ($value === $object || in_array($value, $this->_processed, true)) {
                $value = 'recursion - parent object [' . get_class($value) . ']';
            }
            $object_as_array[$type] = $this->_convert($value);
        }
        return $object_as_array;
    }
    protected function _getPropertyKey(ReflectionProperty $property) {
        $static = $property->isStatic() ? ' static' : '';
        if ($property->isPublic()) {
            return 'public' . $static . ' ' . $property->getName();
        }
        if ($property->isProtected()) {
            return 'protected' . $static . ' ' . $property->getName();
        }
        if ($property->isPrivate()) {
            return 'private' . $static . ' ' . $property->getName();
        }
    }
    protected function _addRow(array $logs, $backtrace, $type) {
        // if this is logged on the same line for example in a loop, set it to null to save space
        if (in_array($backtrace, $this->_backtraces)) {
            $backtrace = null;
        }
        // for group, groupEnd, and groupCollapsed
        // take out the backtrace since it is not useful
        if ($type == self::GROUP || $type == self::GROUP_END || $type == self::GROUP_COLLAPSED) {
            $backtrace = null;
        }
        if ($backtrace !== null) {
            $this->_backtraces[] = $backtrace;
        }
        $row = array($logs, $backtrace, $type);
        $this->_json['rows'][] = $row;
        $this->_writeHeader($this->_json);
    }
    protected function _writeHeader($data) {
        $header = self::HEADER_NAME . ': ' . $this->_encode($data);
        // https://maxchadwick.xyz/blog/http-request-header-size-limits
        // Most web servers do limit size of headers they accept. Apache default limit is 8KB, in IIS it's 16KB.
        $limit = 7; //Kb
        if ($limit) {
            if (strlen($header) > $limit * 1024){
                $data['rows'] = array();
                $data['rows'][] = array(array('LOG Error: HTML Header too big = '.format_size(strlen($header))), '', self::ERROR);
                $header = self::HEADER_NAME . ': ' . $this->_encode($data);
            }
        }
        header($header);
    }
    protected function _encode($data) {
        return base64_encode(utf8_encode(json_encode($data)));
    }
    public function addSetting($key, $value) {
        $this->_settings[$key] = $value;
    }
    public function addSettings(array $settings) {
        foreach ($settings as $key => $value) {
            $this->addSetting($key, $value);
        }
    }
    public function getSetting($key) {
        if (!isset($this->_settings[$key])) {
            return null;
        }
        return $this->_settings[$key];
    }
}
// +--------------------------------------------------
// | Internationalization
// +--------------------------------------------------
function et($tag){
    global $lang,$sys_lang;

    // English - by Fabricio Seger Kolling
    $et['en']['Version'] = 'Version';
    $et['en']['DocRoot'] = 'Document Root';
    $et['en']['FMRoot'] = 'File Manager Root';
    $et['en']['DateFormat'] = 'Date Format';
    $et['en']['GetSize'] = 'Get size';
    $et['en']['Error'] = 'Error';
    $et['en']['Name'] = 'Name';
    $et['en']['And'] = 'and';
    $et['en']['Enter'] = 'Enter';
    $et['en']['Send'] = 'Send';
    $et['en']['Refresh'] = 'Refresh';
    $et['en']['SaveConfig'] = 'Save Configurations';
    //$et['en']['SavePass'] = 'Save Password';
    //$et['en']['TypePass'] = 'Enter the password';
    $et['en']['SaveFile'] = 'Save File';
    $et['en']['Save'] = 'Save';
    $et['en']['Leave'] = 'Leave';
    $et['en']['Edit'] = 'Edit';
    $et['en']['View'] = 'View';
    $et['en']['Config'] = 'Config';
    $et['en']['Ren'] = 'Rename';
    $et['en']['Rem'] = 'Delete';
    $et['en']['Compress'] = 'Compress';
    $et['en']['Decompress'] = 'Decompress';
    $et['en']['ResolveIDs'] = 'Resolve IDs';
    $et['en']['Move'] = 'Move';
    $et['en']['Copy'] = 'Copy';
    $et['en']['ServerInfo'] = 'Server Info';
    $et['en']['CreateDir'] = 'Create Directory';
    $et['en']['CreateArq'] = 'Create File';
    $et['en']['Symlink'] = 'Symlink';
    $et['en']['HardLink'] = 'Hardlink';
    $et['en']['ExecCmd'] = 'Execute Command';
    $et['en']['Upload'] = 'Upload';
    $et['en']['UploadEnd'] = 'Upload Finished';
    $et['en']['Perm'] = 'Perm';
    $et['en']['Perms'] = 'Permissions';
    $et['en']['Owner'] = 'Owner';
    $et['en']['Group'] = 'Group';
    $et['en']['Other'] = 'Other';
    $et['en']['Size'] = 'Size';
    $et['en']['Date'] = 'Date';
    $et['en']['Type'] = 'Type';
    $et['en']['Free'] = 'free';
    $et['en']['Shell'] = 'Shell';
    $et['en']['Read'] = 'Read';
    $et['en']['Write'] = 'Write';
    $et['en']['Exec'] = 'Execute';
    $et['en']['Apply'] = 'Apply';
    $et['en']['StickyBit'] = 'Sticky Bit';
    $et['en']['Pass'] = 'Password';
    $et['en']['Lang'] = 'Language';
    $et['en']['File'] = 'File';
    $et['en']['File_s'] = 'file(s)';
    $et['en']['Dir_s'] = 'directory(s)';
    $et['en']['To'] = 'to';
    $et['en']['Destination'] = 'Destination';
    $et['en']['Configurations'] = 'Configurations';
    $et['en']['JSError'] = 'JavaScript Error';
    $et['en']['NoSel'] = 'There are no selected items';
    $et['en']['SelDir'] = 'Select the destination directory on the left tree';
    $et['en']['TypeDir'] = 'Enter the directory name';
    $et['en']['TypeArq'] = 'Enter the file name';
    $et['en']['TypeCmd'] = 'Enter the command';
    $et['en']['TypeArqComp'] = 'Enter the file name.\\nThe extension will define the compression type.\\nEx:\\nnome.zip\\nnome.tar\\nnome.bzip\\nnome.gzip';
    $et['en']['RemSel'] = 'DELETE selected items';
    $et['en']['NoDestDir'] = 'There is no selected destination directory';
    $et['en']['DestEqOrig'] = 'Origin and destination directories are equal';
    $et['en']['InvalidDest'] = 'Destination directory is invalid';
    $et['en']['NoNewPerm'] = 'New permission not set';
    $et['en']['CopyTo'] = 'COPY to';
    $et['en']['MoveTo'] = 'MOVE to';
    $et['en']['AlterPermTo'] = 'CHANGE PERMISSIONS to';
    $et['en']['ConfExec'] = 'Confirm EXECUTE';
    $et['en']['ConfRem'] = 'Confirm DELETE';
    $et['en']['EmptyDir'] = 'Empty directory';
    $et['en']['IOError'] = 'I/O Error';
    $et['en']['FileMan'] = 'PHP File Manager';
    $et['en']['InvPass'] = 'Invalid Password';
    $et['en']['ReadDenied'] = 'Read Access Denied';
    $et['en']['FileNotFound'] = 'File not found';
    $et['en']['AutoClose'] = 'Close on Complete';
    $et['en']['OutDocRoot'] = 'File beyond DOCUMENT_ROOT';
    $et['en']['NoCmd'] = 'Error: Command not informed';
    $et['en']['ConfTrySave'] = 'File without write permisson.\\nTry to save anyway';
    $et['en']['ConfSaved'] = 'Configurations saved';
    $et['en']['PassSaved'] = 'Password saved';
    $et['en']['FileDirExists'] = 'File or directory already exists';
    $et['en']['NoPhpinfo'] = 'Function phpinfo disabled';
    $et['en']['NoReturn'] = 'no return';
    $et['en']['FileSent'] = 'File sent';
    $et['en']['SpaceLimReached'] = 'Space limit reached';
    $et['en']['InvExt'] = 'Invalid extension';
    $et['en']['FileNoOverw'] = 'File could not be overwritten';
    $et['en']['FileOverw'] = 'File overwritten';
    $et['en']['FileIgnored'] = 'File ignored';
    $et['en']['ChkVer'] = 'Check for new version';
    $et['en']['ChkVerAvailable'] = 'New version, click here to begin download!!';
    $et['en']['ChkVerNotAvailable'] = 'No new version available. :(';
    $et['en']['ChkVerError'] = 'Connection Error.';
    $et['en']['Website'] = 'Website';
    $et['en']['SendingForm'] = 'Sending files, please wait';
    $et['en']['NoFileSel'] = 'No file selected';
    $et['en']['SelAll'] = 'All';
    $et['en']['SelNone'] = 'None';
    $et['en']['SelInverse'] = 'Inverse';
    $et['en']['Selected_s'] = 'selected';
    $et['en']['Total'] = 'total';
    $et['en']['Partition'] = 'Partition';
    $et['en']['RenderTime'] = 'Time to render this page';
    $et['en']['Seconds'] = 'sec';
    $et['en']['ErrorReport'] = 'Error Reporting';
    $et['en']['Close'] = 'Close';
    $et['en']['SetPass'] = 'Set Password';
    $et['en']['ChangePass'] = 'Change Password';
    $et['en']['Portscan'] = 'Portscan';
    $et['en']['PHPOpenBasedir'] = 'PHP Open Basedir';
    $et['en']['PHPOpenBasedirFullAccess'] = '(unset) Full Access';
    $et['en']['About'] = 'About';
    $et['en']['FileSaved'] = 'File saved';
    $et['en']['FileSaveError'] = 'Error saving file';

    // Portuguese - by Fabricio Seger Kolling
    $et['pt']['Version'] = 'Versão';
    $et['pt']['DocRoot'] = 'Document Root';
    $et['pt']['FMRoot'] = 'File Manager Root';
    $et['pt']['DateFormat'] = 'Formato de Data';
    $et['pt']['GetSize'] = 'Ver tamanho';
    $et['pt']['Error'] = 'Erro';
    $et['pt']['Name'] = 'Nome';
    $et['pt']['And'] = 'e';
    $et['pt']['Enter'] = 'Entrar';
    $et['pt']['Send'] = 'Enviar';
    $et['pt']['Refresh'] = 'Atualizar';
    $et['pt']['SaveConfig'] = 'Salvar Configurações';
    //$et['pt']['SavePass'] = 'Salvar Senha';
    //$et['en']['TypePass'] = 'Digite a senha';
    $et['pt']['SaveFile'] = 'Salvar Arquivo';
    $et['pt']['Save'] = 'Salvar';
    $et['pt']['Leave'] = 'Sair';
    $et['pt']['Edit'] = 'Editar';
    $et['pt']['View'] = 'Visualizar';
    $et['pt']['Config'] = 'Config';
    $et['pt']['Ren'] = 'Renomear';
    $et['pt']['Rem'] = 'Apagar';
    $et['pt']['Compress'] = 'Compactar';
    $et['pt']['Decompress'] = 'Descompactar';
    $et['pt']['ResolveIDs'] = 'Resolver IDs';
    $et['pt']['Move'] = 'Mover';
    $et['pt']['Copy'] = 'Copiar';
    $et['pt']['ServerInfo'] = 'Server Info';
    $et['pt']['CreateDir'] = 'Criar Diretório';
    $et['pt']['CreateArq'] = 'Criar Arquivo';
    $et['pt']['ExecCmd'] = 'Executar Comando';
    $et['pt']['Upload'] = 'Upload';
    $et['pt']['UploadEnd'] = 'Upload Terminado';
    $et['pt']['Perm'] = 'Perm';
    $et['pt']['Perms'] = 'Permissões';
    $et['pt']['Owner'] = 'Dono';
    $et['pt']['Group'] = 'Grupo';
    $et['pt']['Other'] = 'Outros';
    $et['pt']['Size'] = 'Tamanho';
    $et['pt']['Date'] = 'Data';
    $et['pt']['Type'] = 'Tipo';
    $et['pt']['Free'] = 'livre';
    $et['pt']['Shell'] = 'Shell';
    $et['pt']['Read'] = 'Ler';
    $et['pt']['Write'] = 'Escrever';
    $et['pt']['Exec'] = 'Executar';
    $et['pt']['Apply'] = 'Aplicar';
    $et['pt']['StickyBit'] = 'Sticky Bit';
    $et['pt']['Pass'] = 'Senha';
    $et['pt']['Lang'] = 'Idioma';
    $et['pt']['File'] = 'Arquivo';
    $et['pt']['File_s'] = 'arquivo(s)';
    $et['pt']['Dir_s'] = 'diretorio(s)';
    $et['pt']['To'] = 'para';
    $et['pt']['Destination'] = 'Destino';
    $et['pt']['Configurations'] = 'Configurações';
    $et['pt']['JSError'] = 'Erro de JavaScript';
    $et['pt']['NoSel'] = 'Não há itens selecionados';
    $et['pt']['SelDir'] = 'Selecione o diretório de destino na árvore a esquerda';
    $et['pt']['TypeDir'] = 'Digite o nome do diretório';
    $et['pt']['TypeArq'] = 'Digite o nome do arquivo';
    $et['pt']['TypeCmd'] = 'Digite o commando';
    $et['pt']['TypeArqComp'] = 'Digite o nome do arquivo.\\nA extensão determina o tipo de compactação.\\nEx:\\nnome.zip\\nnome.tar\\nnome.bzip\\nnome.gzip';
    $et['pt']['RemSel'] = 'APAGAR itens selecionados';
    $et['pt']['NoDestDir'] = 'Não há um diretório de destino selecionado';
    $et['pt']['DestEqOrig'] = 'Diretório de origem e destino iguais';
    $et['pt']['InvalidDest'] = 'Diretório de destino inválido';
    $et['pt']['NoNewPerm'] = 'Nova permissão não foi setada';
    $et['pt']['CopyTo'] = 'COPIAR para';
    $et['pt']['MoveTo'] = 'MOVER para';
    $et['pt']['AlterPermTo'] = 'ALTERAR PERMISSÕES para';
    $et['pt']['ConfExec'] = 'Confirma EXECUTAR';
    $et['pt']['ConfRem'] = 'Confirma APAGAR';
    $et['pt']['EmptyDir'] = 'Diretório vazio';
    $et['pt']['IOError'] = 'Erro de E/S';
    $et['pt']['FileMan'] = 'PHP File Manager';
    $et['pt']['TypePass'] = 'Digite a senha';
    $et['pt']['InvPass'] = 'Senha Inválida';
    $et['pt']['ReadDenied'] = 'Acesso de leitura negado';
    $et['pt']['FileNotFound'] = 'Arquivo não encontrado';
    $et['pt']['AutoClose'] = 'Fechar Automaticamente';
    $et['pt']['OutDocRoot'] = 'Arquivo fora do DOCUMENT_ROOT';
    $et['pt']['NoCmd'] = 'Erro: Comando não informado';
    $et['pt']['ConfTrySave'] = 'Arquivo sem permissão de escrita.\\nTentar salvar assim mesmo';
    $et['pt']['ConfSaved'] = 'Configurações salvas';
    $et['pt']['PassSaved'] = 'Senha salva';
    $et['pt']['FileDirExists'] = 'Arquivo ou diretório já existe';
    $et['pt']['NoPhpinfo'] = 'Função phpinfo desabilitada';
    $et['pt']['NoReturn'] = 'sem retorno';
    $et['pt']['FileSent'] = 'Arquivo enviado';
    $et['pt']['SpaceLimReached'] = 'Limite de espaço alcançado';
    $et['pt']['InvExt'] = 'Extensão inválida';
    $et['pt']['FileNoOverw'] = 'Arquivo não pode ser sobreescrito';
    $et['pt']['FileOverw'] = 'Arquivo sobreescrito';
    $et['pt']['FileIgnored'] = 'Arquivo omitido';
    $et['pt']['ChkVer'] = 'Verificar por nova versão';
    $et['pt']['ChkVerAvailable'] = 'Nova versão, clique aqui para iniciar download!!';
    $et['pt']['ChkVerNotAvailable'] = 'Não há nova versão disponível. :(';
    $et['pt']['ChkVerError'] = 'Erro de conexão.';
    $et['pt']['Website'] = 'Website';
    $et['pt']['SendingForm'] = 'Enviando arquivos, aguarde';
    $et['pt']['NoFileSel'] = 'Nenhum arquivo selecionado';
    $et['pt']['SelAll'] = 'Tudo';
    $et['pt']['SelNone'] = 'Nada';
    $et['pt']['SelInverse'] = 'Inverso';
    $et['pt']['Selected_s'] = 'selecionado(s)';
    $et['pt']['Total'] = 'total';
    $et['pt']['Partition'] = 'Partição';
    $et['pt']['RenderTime'] = 'Tempo para gerar esta página';
    $et['pt']['Seconds'] = 'seg';
    $et['pt']['ErrorReport'] = 'Error Reporting';
    $et['pt']['Close'] = 'Fechar';
    $et['pt']['SetPass'] = 'Alterar Senha';
    $et['pt']['ChangePass'] = 'Alterar Senha';
    $et['pt']['Portscan'] = 'Portscan';
    $et['pt']['PHPOpenBasedir'] = 'PHP Open Basedir';
    $et['pt']['PHPOpenBasedirFullAccess'] = '(indefinido) Acesso Completo';
    $et['pt']['About'] = 'Sobre';
    $et['pt']['FileSaved'] = 'Arquivo salvo';
    $et['pt']['FileSaveError'] = 'Erro salvando arquivo';

    // Polish - by Jakub Kocój
    $et['pl']['Version'] = 'Wersja';
    $et['pl']['DocRoot'] = 'Document Root';
    $et['pl']['FMRoot'] = 'File Manager Root';
    $et['pl']['Name'] = 'Nazwa';
    $et['pl']['And'] = 'i';
    $et['pl']['Enter'] = 'Enter';
    $et['pl']['Send'] = 'Wyślij';
    $et['pl']['Refresh'] = 'Odśwież';
    $et['pl']['SaveConfig'] = 'Zapisz konfigurację';
    $et['pl']['SaveFile'] = 'Zapisz plik';
    $et['pl']['Save'] = 'Zapisz';
    $et['pl']['Leave'] = 'Wyjdź';
    $et['pl']['Edit'] = 'Edycja';
    $et['pl']['View'] = 'Pokaż';
    $et['pl']['Config'] = 'Konfiguracja';
    $et['pl']['Ren'] = 'Zmień nazwę';
    $et['pl']['Rem'] = 'Usuń';
    $et['pl']['Compress'] = 'Kompresuj';
    $et['pl']['Decompress'] = 'Dekompresuj';
    $et['pl']['ResolveIDs'] = 'Rozpoznaj ID';
    $et['pl']['Move'] = 'Przenieś';
    $et['pl']['Copy'] = 'Kopiuj';
    $et['pl']['ServerInfo'] = 'Informacje o serwerze';
    $et['pl']['CreateDir'] = 'Utwórz katalog';
    $et['pl']['CreateArq'] = 'Utówrz plik';
    $et['pl']['ExecCmd'] = 'Wykonaj polecenie';
    $et['pl']['Upload'] = 'Wgraj plik';
    $et['pl']['UploadEnd'] = 'Wgranie zakończone';
    $et['pl']['Perm'] = 'Prawa pliku';
    $et['pl']['Perms'] = 'Prawa dostępu';
    $et['pl']['Owner'] = 'Właściciel';
    $et['pl']['Group'] = 'Grupa';
    $et['pl']['Other'] = 'Inne';
    $et['pl']['Size'] = 'Rozmiar';
    $et['pl']['Date'] = 'Data';
    $et['pl']['Type'] = 'Typ';
    $et['pl']['Free'] = 'darmowe';
    $et['pl']['Shell'] = 'Shell';
    $et['pl']['Read'] = 'Odczyt';
    $et['pl']['Write'] = 'Zapis';
    $et['pl']['Exec'] = 'Wykonywanie';
    $et['pl']['Apply'] = 'Zastosuj';
    $et['pl']['StickyBit'] = 'Sticky Bit';
    $et['pl']['Pass'] = 'Hasło';
    $et['pl']['Lang'] = 'Język';
    $et['pl']['File'] = 'Plik';
    $et['pl']['File_s'] = 'Plik(i)';
    $et['pl']['Dir_s'] = 'katalog(i)';
    $et['pl']['To'] = 'do';
    $et['pl']['Destination'] = 'Cel';
    $et['pl']['Configurations'] = 'Konfiguracje';
    $et['pl']['JSError'] = 'Błąd JavaScript';
    $et['pl']['NoSel'] = 'Nie wybrano żadnych rekordów';
    $et['pl']['SelDir'] = 'Wybierz docelowy folder w drzewku po lewej';
    $et['pl']['TypeDir'] = 'Wpisz nazwę folderu';
    $et['pl']['TypeArq'] = 'Wpisz nazwę pliku';
    $et['pl']['TypeCmd'] = 'Wprowadź komendę';
    $et['pl']['TypeArqComp'] = 'Wprowadź nazwę pliku.\\nRozszerzenie definiuje kompresję pliku.\\nEx:\\nnome.zip\\nnome.tar\\nnome.bzip\\nnome.gzip';
    $et['pl']['RemSel'] = 'USUŃ zanzaczone rekordy';
    $et['pl']['NoDestDir'] = 'Nie wybrano folderu docelowego';
    $et['pl']['DestEqOrig'] = 'Folder docelowy jest równy bieżącemu folderowi';
    $et['pl']['InvalidDest'] = 'Folder docelowy jest niepoprawny';
    $et['pl']['NoNewPerm'] = 'Nie ustawiono uprawnień';
    $et['pl']['CopyTo'] = 'KOPIUJ do';
    $et['pl']['MoveTo'] = 'PRZENIEŚ do';
    $et['pl']['AlterPermTo'] = 'ZMIEŃ PRAWA DOSTĘPU do';
    $et['pl']['ConfExec'] = 'Potwierdź WYKONANIE POLECENIA';
    $et['pl']['ConfRem'] = 'Potwierdź USUNIĘCIE';
    $et['pl']['EmptyDir'] = 'Pusty folder';
    $et['pl']['IOError'] = 'Błąd wejścia/wyjścia';
    $et['pl']['FileMan'] = 'PHP Menadźer plików';
    $et['pl']['InvPass'] = 'Niepoprawne hasło';
    $et['pl']['ReadDenied'] = 'Czytanie dostęp zabroniony';
    $et['pl']['FileNotFound'] = 'Nie odnaleziono pliku';
    $et['pl']['AutoClose'] = 'Zamknij po zakończeniu';
    $et['pl']['OutDocRoot'] = 'Plik powyżej DOCUMENT_ROOT';
    $et['pl']['NoCmd'] = 'Błąd: Brak polecenia';
    $et['pl']['ConfTrySave'] = 'Plik bez możliwości zapisy.\\nSpróbój zapisać pomimo tego';
    $et['pl']['ConfSaved'] = 'Konfiguracja zapisana';
    $et['pl']['PassSaved'] = 'Hasło zapisane';
    $et['pl']['FileDirExists'] = 'Plik lub folder już istnieje';
    $et['pl']['NoPhpinfo'] = 'Funkcja phpinfo wyłączona';
    $et['pl']['NoReturn'] = 'bez powrotu';
    $et['pl']['FileSent'] = 'Plik wysłano';
    $et['pl']['SpaceLimReached'] = 'Osiągnięto limit miejsa';
    $et['pl']['InvExt'] = 'Niepoprawne rozszerzenie';
    $et['pl']['FileNoOverw'] = 'Plik nie może zostać nadpisany';
    $et['pl']['FileOverw'] = 'Nadpisano plik';
    $et['pl']['FileIgnored'] = 'Plik pominięte';
    $et['pl']['ChkVer'] = 'Sprawdź aktualizacje';
    $et['pl']['ChkVerAvailable'] = 'Jest nowa wersja, klikniu tutaj aby pobrać!!';
    $et['pl']['ChkVerNotAvailable'] = 'Brak nowszej wersji. :(';
    $et['pl']['ChkVerError'] = 'Błąd połączenia.';
    $et['pl']['Website'] = 'Strona';
    $et['pl']['SendingForm'] = 'Pliki są przesyłane, proszę czekać';
    $et['pl']['NoFileSel'] = 'Nie wybrano pliku';
    $et['pl']['SelAll'] = 'Wszystkie';
    $et['pl']['SelNone'] = 'Żadme';
    $et['pl']['SelInverse'] = 'Odwróć zaznaczenie';
    $et['pl']['Selected_s'] = 'zaznaczone';
    $et['pl']['Total'] = 'Wszystkie';
    $et['pl']['Partition'] = 'Partycja';
    $et['pl']['RenderTime'] = 'Czas do wyrenderowania tej strony';
    $et['pl']['Seconds'] = 'sec';
    $et['pl']['ErrorReport'] = 'Raportowanie błędów';
    $et['pl']['Close'] = 'Zamknij';
    $et['pl']['SetPass'] = 'Ustaw hasło';
    $et['pl']['ChangePass'] = 'Zmień hasło';
    $et['pl']['Portscan'] = 'Skan portów';

    // Spanish - by Sh Studios
    $et['es']['Version'] = 'Versión';
    $et['es']['DocRoot'] = 'Raiz del programa';
    $et['es']['FMRoot'] = 'Raiz del administrador de archivos';
    $et['es']['Name'] = 'Nombre';
    $et['es']['And'] = 'y';
    $et['es']['Enter'] = 'Enter';
    $et['es']['Send'] = 'Enviar';
    $et['es']['Refresh'] = 'Refrescar';
    $et['es']['SaveConfig'] = 'Guardar configuraciones';
    $et['es']['SavePass'] = 'Cuardar Contraseña';
    $et['es']['SaveFile'] = 'Guardar Archivo';
    $et['es']['Save'] = 'Guardar';
    $et['es']['Leave'] = 'Salir';
    $et['es']['Edit'] = 'Editar';
    $et['es']['View'] = 'Mirar';
    $et['es']['Config'] = 'Config.';
    $et['es']['Ren'] = 'Renombrar';
    $et['es']['Rem'] = 'Borrar';
    $et['es']['Compress'] = 'Comprimir';
    $et['es']['Decompress'] = 'Decomprimir';
    $et['es']['ResolveIDs'] = 'Resolver IDs';
    $et['es']['Move'] = 'Mover';
    $et['es']['Copy'] = 'Copiar';
    $et['es']['ServerInfo'] = 'Info del Server';
    $et['es']['CreateDir'] = 'Crear Directorio';
    $et['es']['CreateArq'] = 'Crear Archivo';
    $et['es']['ExecCmd'] = 'Ejecutar Comando';
    $et['es']['Upload'] = 'Subir';
    $et['es']['UploadEnd'] = 'Subida exitosa';
    $et['es']['Perm'] = 'Perm';
    $et['es']['Perms'] = 'Permisiones';
    $et['es']['Owner'] = 'Propietario';
    $et['es']['Group'] = 'Grupo';
    $et['es']['Other'] = 'Otro';
    $et['es']['Size'] = 'Tamaño';
    $et['es']['Date'] = 'Fecha';
    $et['es']['Type'] = 'Tipo';
    $et['es']['Free'] = 'libre';
    $et['es']['Shell'] = 'Ejecutar';
    $et['es']['Read'] = 'Leer';
    $et['es']['Write'] = 'Escribir';
    $et['es']['Exec'] = 'Ejecutar';
    $et['es']['Apply'] = 'Aplicar';
    $et['es']['StickyBit'] = 'Sticky Bit';
    $et['es']['Pass'] = 'Contraseña';
    $et['es']['Lang'] = 'Lenguage';
    $et['es']['File'] = 'Archivos';
    $et['es']['File_s'] = 'archivo(s)';
    $et['es']['Dir_s'] = 'directorio(s)';
    $et['es']['To'] = 'a';
    $et['es']['Destination'] = 'Destino';
    $et['es']['Configurations'] = 'Configuracion';
    $et['es']['JSError'] = 'Error de JavaScript';
    $et['es']['NoSel'] = 'No hay items seleccionados';
    $et['es']['SelDir'] = 'Seleccione el directorio de destino en el arbol derecho';
    $et['es']['TypeDir'] = 'Escriba el nombre del directorio';
    $et['es']['TypeArq'] = 'Escriba el nombre del archivo';
    $et['es']['TypeCmd'] = 'Escriba el comando';
    $et['es']['TypeArqComp'] = 'Escriba el nombre del directorio.\\nLa extension definira el tipo de compresion.\\nEj:\\nnome.zip\\nnome.tar\\nnome.bzip\\nnome.gzip';
    $et['es']['RemSel'] = 'BORRAR items seleccionados';
    $et['es']['NoDestDir'] = 'No se ha seleccionado el directorio de destino';
    $et['es']['DestEqOrig'] = 'El origen y el destino son iguales';
    $et['es']['InvalidDest'] = 'El destino del directorio es invalido';
    $et['es']['NoNewPerm'] = 'Las permisiones no se pudieron establecer';
    $et['es']['CopyTo'] = 'COPIAR a';
    $et['es']['MoveTo'] = 'MOVER a';
    $et['es']['AlterPermTo'] = 'CAMBIAR PERMISIONES a';
    $et['es']['ConfExec'] = 'Confirmar EJECUCION';
    $et['es']['ConfRem'] = 'Confirmar BORRADO';
    $et['es']['EmptyDir'] = 'Directorio Vacio';
    $et['es']['IOError'] = 'Error I/O';
    $et['es']['FileMan'] = 'PHP File Manager';
    $et['es']['TypePass'] = 'Escriba la contraseña';
    $et['es']['InvPass'] = 'Contraseña invalida';
    $et['es']['ReadDenied'] = 'Acceso de lectura denegado';
    $et['es']['FileNotFound'] = 'Archivo no encontrado';
    $et['es']['AutoClose'] = 'Cerrar al completar';
    $et['es']['OutDocRoot'] = 'Archivo antes de DOCUMENT_ROOT';
    $et['es']['NoCmd'] = 'Error: No se ha escrito ningun comando';
    $et['es']['ConfTrySave'] = 'Archivo sin permisos de escritura.\\nIntente guardar en otro lugar';
    $et['es']['ConfSaved'] = 'Configuracion Guardada';
    $et['es']['PassSaved'] = 'Contraseña guardada';
    $et['es']['FileDirExists'] = 'Archivo o directorio ya existente';
    $et['es']['NoPhpinfo'] = 'Funcion phpinfo() inhabilitada';
    $et['es']['NoReturn'] = 'sin retorno';
    $et['es']['FileSent'] = 'Archivo enviado';
    $et['es']['SpaceLimReached'] = 'Limite de espacio en disco alcanzado';
    $et['es']['InvExt'] = 'Extension inalida';
    $et['es']['FileNoOverw'] = 'El archivo no pudo ser sobreescrito';
    $et['es']['FileOverw'] = 'Archivo sobreescrito';
    $et['es']['FileIgnored'] = 'Archivo ignorado';
    $et['es']['ChkVer'] = 'Chequear las actualizaciones';
    $et['es']['ChkVerAvailable'] = 'Nueva version, haga click aqui para descargar!!';
    $et['es']['ChkVerNotAvailable'] = 'Su version es la mas reciente.';
    $et['es']['ChkVerError'] = 'Error de coneccion.';
    $et['es']['Website'] = 'Sitio Web';
    $et['es']['SendingForm'] = 'Enviando archivos, espere!';
    $et['es']['NoFileSel'] = 'Ningun archivo seleccionado';
    $et['es']['SelAll'] = 'Todos';
    $et['es']['SelNone'] = 'Ninguno';
    $et['es']['SelInverse'] = 'Inverso';
    $et['es']['Selected_s'] = 'seleccionado';
    $et['es']['Total'] = 'total';
    $et['es']['Partition'] = 'Particion';
    $et['es']['RenderTime'] = 'Generado en';
    $et['es']['Seconds'] = 'seg';
    $et['es']['ErrorReport'] = 'Reporte de error';

    // Korean - by Airplanez, totally revised by Quidn(S. Seo)
    $et['ko']['Version'] = '버전';
    $et['ko']['DocRoot'] = '호스트 루트 디렉토리';
    $et['ko']['FMRoot'] = '관리하려는 디렉토리';
    $et['ko']['DateFormat'] = '날짜 형식';
    $et['ko']['GetSize'] = '크기 계산';
    $et['ko']['Error'] = '오류';
    $et['ko']['Name'] = '이름';
    $et['ko']['And'] = '및';
    $et['ko']['Enter'] = '입력';
    $et['ko']['Send'] = '전송';
    $et['ko']['Refresh'] = '새로고침';
    $et['ko']['SaveConfig'] = '설정 저장';
    //$et['ko']['SavePass'] = '패스워드 저장';
    //$et['ko']['TypePass'] = '패스워드 입력';
    $et['ko']['SaveFile'] = '파일 저장';
    $et['ko']['Save'] = '저장';
    $et['ko']['Leave'] = '로그아웃';
    $et['ko']['Edit'] = '수정';
    $et['ko']['View'] = '보기';
    $et['ko']['Config'] = '설정';
    $et['ko']['Ren'] = '이름 변경';
    $et['ko']['Rem'] = '삭제';
    $et['ko']['Compress'] = '압축';
    $et['ko']['Decompress'] = '압축해제';
    $et['ko']['ResolveIDs'] = '소유자 ID 숫자↔문자';
    $et['ko']['Move'] = '이동';
    $et['ko']['Copy'] = '복사';
    $et['ko']['ServerInfo'] = '서버 정보';
    $et['ko']['CreateDir'] = '새 디렉토리';
    $et['ko']['CreateArq'] = '새 파일';
    $et['ko']['Symlink'] = '심링크';
    $et['ko']['HardLink'] = '하드링크';
    $et['ko']['ExecCmd'] = '명령 실행';
    $et['ko']['Upload'] = '업로드';
    $et['ko']['UploadEnd'] = '업로드 완료';
    $et['ko']['Perm'] = '권한';
    $et['ko']['Perms'] = '권한';
    $et['ko']['Owner'] = '소유자';
    $et['ko']['Group'] = '그룹';
    $et['ko']['Other'] = '기타';
    $et['ko']['Size'] = '크기';
    $et['ko']['Date'] = '날짜';
    $et['ko']['Type'] = '종류';
    $et['ko']['Free'] = '사용 가능';
    $et['ko']['Shell'] = '쉘';
    $et['ko']['Read'] = '읽기';
    $et['ko']['Write'] = '쓰기';
    $et['ko']['Exec'] = '실행';
    $et['ko']['Apply'] = '적용';
    $et['ko']['StickyBit'] = '스티키 비트';
    $et['ko']['Pass'] = '패스워드';
    $et['ko']['Lang'] = '언어';
    $et['ko']['File'] = '파일';
    $et['ko']['File_s'] = '파일';
    $et['ko']['Dir_s'] = '개의 디렉토리';
    $et['ko']['To'] = '에서';
    $et['ko']['Destination'] = '대상 디렉토리';
    $et['ko']['Configurations'] = '설정';
    $et['ko']['JSError'] = '스크립트 오류';
    $et['ko']['NoSel'] = '선택한 항목이 없습니다';
    $et['ko']['SelDir'] = '왼쪽 목록에서 대상 디렉토리를 선택해주세요';
    $et['ko']['TypeDir'] = '디렉토리 이름을 입력해주세요';
    $et['ko']['TypeArq'] = '파일 이름을 입력해주세요';
    $et['ko']['TypeCmd'] = '명령어를 입력해주세요';
    $et['ko']['TypeArqComp'] = '압축파일 이름을 입력해 주시면, 확장자에 맞는 형식으로 압축합니다.\\n\\n확장자 예시:\\nnome.zip\\nnome.tar\\nnome.bzip\\nnome.gzip';
    $et['ko']['RemSel'] = '선택한 항목을 삭제하시겠습니까';
    $et['ko']['NoDestDir'] = '선택한 대상 디렉토리가 없습니다';
    $et['ko']['DestEqOrig'] = '원본 디렉토리와 대상 디렉토리가 동일합니다';
    $et['ko']['InvalidDest'] = '대상 디렉토리가 올바르지 않습니다';
    $et['ko']['NoNewPerm'] = '권한이 설정되지 않았습니다';
    $et['ko']['CopyTo'] = '여기에 복사하시겠습니까';
    $et['ko']['MoveTo'] = '여기로 이동하시겠습니다';
    $et['ko']['AlterPermTo'] = '권한을 다음으로 변경하시겠습니까';
    $et['ko']['ConfExec'] = '다음을 실행하시겠습니까';
    $et['ko']['ConfRem'] = '다음을 삭제하시겠습니까';
    $et['ko']['EmptyDir'] = '디렉토리가 비었습니다';
    $et['ko']['IOError'] = '입출력 오류가 발생했습니다';
    $et['ko']['FileMan'] = 'PHP 파일 관리자';
    $et['ko']['InvPass'] = '패스워드가 올바르지 않습니다';
    $et['ko']['ReadDenied'] = '파일을 읽을 수 없습니다';
    $et['ko']['FileNotFound'] = '파일을 찾을 수 없습니다';
    $et['ko']['AutoClose'] = '완료 후 닫기';
    $et['ko']['OutDocRoot'] = '접근 가능한 디렉토리 범위를 벗어났습니다';
    $et['ko']['NoCmd'] = '오류: 명령어가 올바르지 않습니다';
    $et['ko']['ConfTrySave'] = '파일에 쓰기 권한이 없습니다.\\n그래도 저장을 시도하시겠습니까';
    $et['ko']['ConfSaved'] = '설정을 저장했습니다';
    $et['ko']['PassSaved'] = '패스워드를 저장했습니다';
    $et['ko']['FileDirExists'] = '이미 존재하는 파일 또는 디렉토리 이름입니다';
    $et['ko']['NoPhpinfo'] = 'phpinfo 함수를 사용할 수 없습니다';
    $et['ko']['NoReturn'] = '결과가 없습니다';
    $et['ko']['FileSent'] = '파일을 전송했습니다';
    $et['ko']['SpaceLimReached'] = '용량 제한을 초과했습니다';
    $et['ko']['InvExt'] = '확장자가 올바르지 않습니다';
    $et['ko']['FileNoOverw'] = '파일을 덮어쓸 수 없습니다';
    $et['ko']['FileOverw'] = '파일을 덮어썼습니다';
    $et['ko']['FileIgnored'] = '파일을 건너뛰었습니다';
    $et['ko']['ChkVer'] = '새로운 버전 확인';
    $et['ko']['ChkVerAvailable'] = '여기를 클릭하셔서 새로운 버전을 다운로드 하세요!';
    $et['ko']['ChkVerNotAvailable'] = '새로운 버전이 없습니다. :(';
    $et['ko']['ChkVerError'] = '연결에 실패했습니다';
    $et['ko']['Website'] = '웹사이트';
    $et['ko']['SendingForm'] = '파일을 전송하고 있습니다. 잠시만 기다려주세요';
    $et['ko']['NoFileSel'] = '선택한 파일이 없습니다';
    $et['ko']['SelAll'] = '전체선택';
    $et['ko']['SelNone'] = '선택해제';
    $et['ko']['SelInverse'] = '선택반전';
    $et['ko']['Selected_s'] = '선택됨';
    $et['ko']['Total'] = '전체';
    $et['ko']['Partition'] = '파티션';
    $et['ko']['RenderTime'] = '페이지 처리 시간';
    $et['ko']['Seconds'] = '초';
    $et['ko']['ErrorReport'] = '오류 출력';
    $et['ko']['Close'] = '닫기';
    $et['ko']['SetPass'] = '패스워드 설정';
    $et['ko']['ChangePass'] = '패스워드 변경';
    $et['ko']['Portscan'] = '포트스캔';
    $et['ko']['PHPOpenBasedir'] = '접근 가능한 디렉토리';
    $et['ko']['PHPOpenBasedirFullAccess'] = '(미설정) 전체 접근 가능';
    $et['ko']['About'] = '소개';
    $et['ko']['FileSaved'] = '파일을 저장했습니다';
    $et['ko']['FileSaveError'] = '파일 저장 중 오류가 발생했습니다';
    $et['ko']['Timezone'] = '시간대';
    $et['ko']['Stop'] = '정지';
    $et['ko']['Login'] = '로그인';

    // German - by Guido Ogrzal
    $et['de']['Version'] = 'Version';
    $et['de']['DocRoot'] = 'Dokument Wurzelverzeichnis';
    $et['de']['FMRoot'] = 'Dateimanager Wurzelverzeichnis';
    $et['de']['Name'] = 'Name';
    $et['de']['And'] = 'und';
    $et['de']['Enter'] = 'Eintreten';
    $et['de']['Send'] = 'Senden';
    $et['de']['Refresh'] = 'Aktualisieren';
    $et['de']['SaveConfig'] = 'Konfiguration speichern';
    $et['de']['SavePass'] = 'Passwort speichern';
    $et['de']['SaveFile'] = 'Datei speichern';
    $et['de']['Save'] = 'Speichern';
    $et['de']['Leave'] = 'Verlassen';
    $et['de']['Edit'] = 'Bearbeiten';
    $et['de']['View'] = 'Ansehen';
    $et['de']['Config'] = 'Konfigurieren';
    $et['de']['Ren'] = 'Umbenennen';
    $et['de']['Rem'] = 'Löschen';
    $et['de']['Compress'] = 'Komprimieren';
    $et['de']['Decompress'] = 'Dekomprimieren';
    $et['de']['ResolveIDs'] = 'Resolve IDs';
    $et['de']['Move'] = 'Verschieben';
    $et['de']['Copy'] = 'Kopieren';
    $et['de']['ServerInfo'] = 'Server-Info';
    $et['de']['CreateDir'] = 'Neues Verzeichnis';
    $et['de']['CreateArq'] = 'Neue Datei';
    $et['de']['ExecCmd'] = 'Kommando';
    $et['de']['Upload'] = 'Datei hochladen';
    $et['de']['UploadEnd'] = 'Datei hochladen beendet';
    $et['de']['Perm'] = 'Erlaubnis';
    $et['de']['Perms'] = 'Erlaubnis';
    $et['de']['Owner'] = 'Besitzer';
    $et['de']['Group'] = 'Gruppe';
    $et['de']['Other'] = 'Andere';
    $et['de']['Size'] = 'Größe';
    $et['de']['Date'] = 'Datum';
    $et['de']['Type'] = 'Typ';
    $et['de']['Free'] = 'frei';
    $et['de']['Shell'] = 'Shell';
    $et['de']['Read'] = 'Lesen';
    $et['de']['Write'] = 'Schreiben';
    $et['de']['Exec'] = 'Ausführen';
    $et['de']['Apply'] = 'Bestätigen';
    $et['de']['StickyBit'] = 'Sticky Bit';
    $et['de']['Pass'] = 'Passwort';
    $et['de']['Lang'] = 'Sprache';
    $et['de']['File'] = 'Datei';
    $et['de']['File_s'] = 'Datei(en)';
    $et['de']['Dir_s'] = 'Verzeichniss(e)';
    $et['de']['To'] = '-&gt;';
    $et['de']['Destination'] = 'Ziel';
    $et['de']['Configurations'] = 'Konfiguration';
    $et['de']['JSError'] = 'JavaScript Fehler';
    $et['de']['NoSel'] = 'Es gibt keine selektierten Objekte';
    $et['de']['SelDir'] = 'Selektiere das Zielverzeichnis im linken Verzeichnisbaum';
    $et['de']['TypeDir'] = 'Trage den Verzeichnisnamen ein';
    $et['de']['TypeArq'] = 'Trage den Dateinamen ein';
    $et['de']['TypeCmd'] = 'Gib das Kommando ein';
    $et['de']['TypeArqComp'] = 'Trage den Dateinamen ein.\\nDie Dateierweiterung wird den Kompressiontyp bestimmen.\\nBsp.:\\nnome.zip\\nnome.tar\\nnome.bzip\\nnome.gzip';
    $et['de']['RemSel'] = 'LÖSCHE die selektierten Objekte';
    $et['de']['NoDestDir'] = 'Das selektierte Zielverzeichnis existiert nicht';
    $et['de']['DestEqOrig'] = 'Quell- und Zielverzeichnis stimmen überein';
    $et['de']['InvalidDest'] = 'Zielverzeichnis ist ungültig';
    $et['de']['NoNewPerm'] = 'Neue Zugriffserlaubnis konnte nicht gesetzt werden';
    $et['de']['CopyTo'] = 'KOPIERE nach';
    $et['de']['MoveTo'] = 'VERSCHIEBE nach';
    $et['de']['AlterPermTo'] = 'ÄNDERE ZUGRIFFSERLAUBSNIS in';
    $et['de']['ConfExec'] = 'Bestätige AUSFÜHRUNG';
    $et['de']['ConfRem'] = 'Bestätige LÖSCHEN';
    $et['de']['EmptyDir'] = 'Leeres Verzeichnis';
    $et['de']['IOError'] = 'Eingabe/Ausgabe-Fehler';
    $et['de']['FileMan'] = 'PHP File Manager';
    $et['de']['TypePass'] = 'Trage das Passwort ein';
    $et['de']['InvPass'] = 'Ungültiges Passwort';
    $et['de']['ReadDenied'] = 'Lesezugriff verweigert';
    $et['de']['FileNotFound'] = 'Datei nicht gefunden';
    $et['de']['AutoClose'] = 'Schließen, wenn fertig';
    $et['de']['OutDocRoot'] = 'Datei außerhalb von DOCUMENT_ROOT';
    $et['de']['NoCmd'] = 'Fehler: Es wurde kein Kommando eingetragen';
    $et['de']['ConfTrySave'] = 'Keine Schreibberechtigung für die Datei.\\nVersuche trotzdem zu speichern';
    $et['de']['ConfSaved'] = 'Konfiguration gespeichert';
    $et['de']['PassSaved'] = 'Passwort gespeichert';
    $et['de']['FileDirExists'] = 'Datei oder Verzeichnis existiert schon';
    $et['de']['NoPhpinfo'] = 'Funktion phpinfo ist inaktiv';
    $et['de']['NoReturn'] = 'keine Rückgabe';
    $et['de']['FileSent'] = 'Datei wurde gesendet';
    $et['de']['SpaceLimReached'] = 'Verfügbares Speicherlimit wurde erreicht';
    $et['de']['InvExt'] = 'Ungültige Dateiendung';
    $et['de']['FileNoOverw'] = 'Datei kann nicht überschrieben werden';
    $et['de']['FileOverw'] = 'Datei überschrieben';
    $et['de']['FileIgnored'] = 'Datei ignoriert';
    $et['de']['ChkVer'] = 'Prüfe auf neue Version';
    $et['de']['ChkVerAvailable'] = 'Neue Version verfügbar; klicke hier, um den Download zu starten!!';
    $et['de']['ChkVerNotAvailable'] = 'Keine neue Version gefunden. :(';
    $et['de']['ChkVerError'] = 'Verbindungsfehler.';
    $et['de']['Website'] = 'Webseite';
    $et['de']['SendingForm'] = 'Sende Dateien... Bitte warten.';
    $et['de']['NoFileSel'] = 'Keine Datei selektiert';
    $et['de']['SelAll'] = 'Alle';
    $et['de']['SelNone'] = 'Keine';
    $et['de']['SelInverse'] = 'Invertieren';
    $et['de']['Selected_s'] = 'selektiert';
    $et['de']['Total'] = 'Gesamt';
    $et['de']['Partition'] = 'Partition';
    $et['de']['RenderTime'] = 'Zeit, um die Seite anzuzeigen';
    $et['de']['Seconds'] = 's';
    $et['de']['ErrorReport'] = 'Fehlerreport';

    // French - by Jean Bilwes
    $et['fr']['Version'] = 'Version';
    $et['fr']['DocRoot'] = 'Racine des documents';
    $et['fr']['FMRoot'] = 'Racine du gestionnaire de fichers';
    $et['fr']['Name'] = 'Nom';
    $et['fr']['And'] = 'et';
    $et['fr']['Enter'] = 'Enter';
    $et['fr']['Send'] = 'Envoyer';
    $et['fr']['Refresh'] = 'Rafraichir';
    $et['fr']['SaveConfig'] = 'Enregistrer la configuration';
    $et['fr']['SavePass'] = 'Enregistrer le mot de passe';
    $et['fr']['SaveFile'] = 'Enregistrer le fichier';
    $et['fr']['Save'] = 'Enregistrer';
    $et['fr']['Leave'] = 'Quitter';
    $et['fr']['Edit'] = 'Modifier';
    $et['fr']['View'] = 'Voir';
    $et['fr']['Config'] = 'Configuration';
    $et['fr']['Ren'] = 'Renommer';
    $et['fr']['Rem'] = 'Supprimer';
    $et['fr']['Compress'] = 'Compresser';
    $et['fr']['Decompress'] = 'Décompresser';
    $et['fr']['ResolveIDs'] = 'Résoudre les IDs';
    $et['fr']['Move'] = 'Déplacer';
    $et['fr']['Copy'] = 'Copier';
    $et['fr']['ServerInfo'] = 'Info serveur';
    $et['fr']['CreateDir'] = 'Créer un répertoire';
    $et['fr']['CreateArq'] = 'Créer un fichier';
    $et['fr']['ExecCmd'] = 'Executer une commande';
    $et['fr']['Upload'] = 'Upload';
    $et['fr']['UploadEnd'] = 'Upload terminé';
    $et['fr']['Perm'] = 'Perm';
    $et['fr']['Perms'] = 'Permissions';
    $et['fr']['Owner'] = 'Propriétaire';
    $et['fr']['Group'] = 'Groupe';
    $et['fr']['Other'] = 'Autre';
    $et['fr']['Size'] = 'Taille';
    $et['fr']['Date'] = 'Date';
    $et['fr']['Type'] = 'Type';
    $et['fr']['Free'] = 'libre';
    $et['fr']['Shell'] = 'Shell';
    $et['fr']['Read'] = 'Lecture';
    $et['fr']['Write'] = 'Ecriture';
    $et['fr']['Exec'] = 'Executer';
    $et['fr']['Apply'] = 'Appliquer';
    $et['fr']['StickyBit'] = 'Sticky Bit';
    $et['fr']['Pass'] = 'Mot de passe';
    $et['fr']['Lang'] = 'Langage';
    $et['fr']['File'] = 'Fichier';
    $et['fr']['File_s'] = 'fichier(s)';
    $et['fr']['Dir_s'] = 'répertoire(s)';
    $et['fr']['To'] = 'à';
    $et['fr']['Destination'] = 'Destination';
    $et['fr']['Configurations'] = 'Configurations';
    $et['fr']['JSError'] = 'Erreur JavaScript';
    $et['fr']['NoSel'] = 'Rien n\'est sélectionné';
    $et['fr']['SelDir'] = 'Selectionnez le répertoire de destination dans le panneau gauche';
    $et['fr']['TypeDir'] = 'Entrer le nom du répertoire';
    $et['fr']['TypeArq'] = 'Entrer le nom du fichier';
    $et['fr']['TypeCmd'] = 'Entrer la commande';
    $et['fr']['TypeArqComp'] = 'Entrer le nom du fichier.\\nL\'extension définira le type de compression.\\nEx:\\nnome.zip\\nnome.tar\\nnome.bzip\\nnome.gzip';
    $et['fr']['RemSel'] = 'EFFACER les objets sélectionnés';
    $et['fr']['NoDestDir'] = 'Aucun répertoire de destination n\'est sélectionné';
    $et['fr']['DestEqOrig'] = 'Les répertoires source et destination sont identiques';
    $et['fr']['InvalidDest'] = 'Le répertoire de destination est invalide';
    $et['fr']['NoNewPerm'] = 'Nouvelle permission non établie';
    $et['fr']['CopyTo'] = 'COPIER vers';
    $et['fr']['MoveTo'] = 'DEPLACER vers';
    $et['fr']['AlterPermTo'] = 'CHANGER LES PERMISSIONS';
    $et['fr']['ConfExec'] = 'Confirmer l\'EXECUTION';
    $et['fr']['ConfRem'] = 'Confirmer la DESTRUCTION';
    $et['fr']['EmptyDir'] = 'Répertoire vide';
    $et['fr']['IOError'] = 'I/O Error';
    $et['fr']['FileMan'] = 'PHP File Manager';
    $et['fr']['TypePass'] = 'Entrer le mot de passe';
    $et['fr']['InvPass'] = 'Mot de passe invalide';
    $et['fr']['ReadDenied'] = 'Droit de lecture refusé';
    $et['fr']['FileNotFound'] = 'Fichier introuvable';
    $et['fr']['AutoClose'] = 'Fermer sur fin';
    $et['fr']['OutDocRoot'] = 'Fichier au delà de DOCUMENT_ROOT';
    $et['fr']['NoCmd'] = 'Erreur: Commande non renseignée';
    $et['fr']['ConfTrySave'] = 'Fichier sans permission d\'écriture.\\nJ\'essaie de l\'enregister';
    $et['fr']['ConfSaved'] = 'Configurations enreristrée';
    $et['fr']['PassSaved'] = 'Mot de passe enreristré';
    $et['fr']['FileDirExists'] = 'Le fichier ou le répertoire existe déjà';
    $et['fr']['NoPhpinfo'] = 'Function phpinfo désactivée';
    $et['fr']['NoReturn'] = 'pas de retour';
    $et['fr']['FileSent'] = 'Fichier envoyé';
    $et['fr']['SpaceLimReached'] = 'Espace maxi atteint';
    $et['fr']['InvExt'] = 'Extension invalide';
    $et['fr']['FileNoOverw'] = 'Le fichier ne peut pas etre écrasé';
    $et['fr']['FileOverw'] = 'Fichier écrasé';
    $et['fr']['FileIgnored'] = 'Fichier ignoré';
    $et['fr']['ChkVer'] = 'Verifier nouvelle version';
    $et['fr']['ChkVerAvailable'] = 'Nouvelle version, cliquer ici pour la téléchager!!';
    $et['fr']['ChkVerNotAvailable'] = 'Aucune mise a jour de disponible. :(';
    $et['fr']['ChkVerError'] = 'Erreur de connection.';
    $et['fr']['Website'] = 'siteweb';
    $et['fr']['SendingForm'] = 'Envoi des fichiers en cours, Patienter';
    $et['fr']['NoFileSel'] = 'Aucun fichier sélectionné';
    $et['fr']['SelAll'] = 'Tous';
    $et['fr']['SelNone'] = 'Aucun';
    $et['fr']['SelInverse'] = 'Inverser';
    $et['fr']['Selected_s'] = 'selectioné';
    $et['fr']['Total'] = 'total';
    $et['fr']['Partition'] = 'Partition';
    $et['fr']['RenderTime'] = 'Temps pour afficher cette page';
    $et['fr']['Seconds'] = 'sec';
    $et['fr']['ErrorReport'] = 'Rapport d\'erreur';

    // Dutch - by Leon Buijs
    $et['nl']['Version'] = 'Versie';
    $et['nl']['DocRoot'] = 'Document Root';
    $et['nl']['FMRoot'] = 'File Manager Root';
    $et['nl']['Name'] = 'Naam';
    $et['nl']['And'] = 'en';
    $et['nl']['Enter'] = 'Enter';
    $et['nl']['Send'] = 'Verzend';
    $et['nl']['Refresh'] = 'Vernieuw';
    $et['nl']['SaveConfig'] = 'Configuratie opslaan';
    $et['nl']['SavePass'] = 'Wachtwoord opslaan';
    $et['nl']['SaveFile'] = 'Bestand opslaan';
    $et['nl']['Save'] = 'Opslaan';
    $et['nl']['Leave'] = 'Verlaten';
    $et['nl']['Edit'] = 'Wijzigen';
    $et['nl']['View'] = 'Toon';
    $et['nl']['Config'] = 'Configuratie';
    $et['nl']['Ren'] = 'Naam wijzigen';
    $et['nl']['Rem'] = 'Verwijderen';
    $et['nl']['Compress'] = 'Comprimeren';
    $et['nl']['Decompress'] = 'Decomprimeren';
    $et['nl']['ResolveIDs'] = 'Resolve IDs';
    $et['nl']['Move'] = 'Verplaats';
    $et['nl']['Copy'] = 'Kopieer';
    $et['nl']['ServerInfo'] = 'Serverinformatie';
    $et['nl']['CreateDir'] = 'Nieuwe map';
    $et['nl']['CreateArq'] = 'Nieuw bestand';
    $et['nl']['ExecCmd'] = 'Commando uitvoeren';
    $et['nl']['Upload'] = 'Upload';
    $et['nl']['UploadEnd'] = 'Upload voltooid';
    $et['nl']['Perm'] = 'Rechten';
    $et['nl']['Perms'] = 'Rechten';
    $et['nl']['Owner'] = 'Eigenaar';
    $et['nl']['Group'] = 'Groep';
    $et['nl']['Other'] = 'Anderen';
    $et['nl']['Size'] = 'Grootte';
    $et['nl']['Date'] = 'Datum';
    $et['nl']['Type'] = 'Type';
    $et['nl']['Free'] = 'free';
    $et['nl']['Shell'] = 'Shell';
    $et['nl']['Read'] = 'Lezen';
    $et['nl']['Write'] = 'Schrijven';
    $et['nl']['Exec'] = 'Uitvoeren';
    $et['nl']['Apply'] = 'Toepassen';
    $et['nl']['StickyBit'] = 'Sticky Bit';
    $et['nl']['Pass'] = 'Wachtwoord';
    $et['nl']['Lang'] = 'Taal';
    $et['nl']['File'] = 'Bestand';
    $et['nl']['File_s'] = 'bestand(en)';
    $et['nl']['Dir_s'] = 'map(pen)';
    $et['nl']['To'] = 'naar';
    $et['nl']['Destination'] = 'Bestemming';
    $et['nl']['Configurations'] = 'Instellingen';
    $et['nl']['JSError'] = 'Javascriptfout';
    $et['nl']['NoSel'] = 'Er zijn geen bestanden geselecteerd';
    $et['nl']['SelDir'] = 'Kies de bestemming in de boom aan de linker kant';
    $et['nl']['TypeDir'] = 'Voer de mapnaam in';
    $et['nl']['TypeArq'] = 'Voer de bestandsnaam in';
    $et['nl']['TypeCmd'] = 'Voer het commando in';
    $et['nl']['TypeArqComp'] = 'Voer de bestandsnaam in.\\nDe extensie zal het compressietype bepalen.\\nEx:\\nnome.zip\\nnome.tar\\nnome.bzip\\nnome.gzip';
    $et['nl']['RemSel'] = 'VERWIJDER geselecteerde itens';
    $et['nl']['NoDestDir'] = 'Er is geen doelmap geselecteerd';
    $et['nl']['DestEqOrig'] = 'Bron- en doelmap zijn hetzelfde';
    $et['nl']['InvalidDest'] = 'Doelmap is ongeldig';
    $et['nl']['NoNewPerm'] = 'Nieuwe rechten niet geset';
    $et['nl']['CopyTo'] = 'KOPIEER naar';
    $et['nl']['MoveTo'] = 'VERPLAATS naar';
    $et['nl']['AlterPermTo'] = 'VERANDER RECHTEN in';
    $et['nl']['ConfExec'] = 'Bevestig UITVOEREN';
    $et['nl']['ConfRem'] = 'Bevestig VERWIJDEREN';
    $et['nl']['EmptyDir'] = 'Lege map';
    $et['nl']['IOError'] = 'I/O Error';
    $et['nl']['FileMan'] = 'PHP File Manager';
    $et['nl']['TypePass'] = 'Voer het wachtwoord in';
    $et['nl']['InvPass'] = 'Ongeldig wachtwoord';
    $et['nl']['ReadDenied'] = 'Leestoegang ontzegd';
    $et['nl']['FileNotFound'] = 'Bestand niet gevonden';
    $et['nl']['AutoClose'] = 'Sluit na voltooien';
    $et['nl']['OutDocRoot'] = 'Bestand buiten DOCUMENT_ROOT';
    $et['nl']['NoCmd'] = 'Error: Command not informed';
    $et['nl']['ConfTrySave'] = 'Bestand zonder schrijfrechten.\\nProbeer een andere manier';
    $et['nl']['ConfSaved'] = 'Instellingen opgeslagen';
    $et['nl']['PassSaved'] = 'Wachtwoord opgeslagen';
    $et['nl']['FileDirExists'] = 'Bestand of map bestaat al';
    $et['nl']['NoPhpinfo'] = 'Functie \'phpinfo\' is uitgeschakeld';
    $et['nl']['NoReturn'] = 'no return';
    $et['nl']['FileSent'] = 'Bestand verzonden';
    $et['nl']['SpaceLimReached'] = 'Opslagruimtelimiet bereikt';
    $et['nl']['InvExt'] = 'Ongeldige extensie';
    $et['nl']['FileNoOverw'] = 'Bestand kan niet worden overgeschreven';
    $et['nl']['FileOverw'] = 'Bestand overgeschreven';
    $et['nl']['FileIgnored'] = 'Bestand genegeerd';
    $et['nl']['ChkVer'] = 'Controleer nieuwe versie';
    $et['nl']['ChkVerAvailable'] = 'Nieuwe versie, klik hier om de download te starten';
    $et['nl']['ChkVerNotAvailable'] = 'Geen nieuwe versie beschikbaar';
    $et['nl']['ChkVerError'] = 'Verbindingsfout.';
    $et['nl']['Website'] = 'Website';
    $et['nl']['SendingForm'] = 'Bestanden worden verzonden. Even geduld...';
    $et['nl']['NoFileSel'] = 'Geen bestanden geselecteerd';
    $et['nl']['SelAll'] = 'Alles';
    $et['nl']['SelNone'] = 'Geen';
    $et['nl']['SelInverse'] = 'Keer om';
    $et['nl']['Selected_s'] = 'geselecteerd';
    $et['nl']['Total'] = 'totaal';
    $et['nl']['Partition'] = 'Partitie';
    $et['nl']['RenderTime'] = 'Tijd voor maken van deze pagina';
    $et['nl']['Seconds'] = 'sec';
    $et['nl']['ErrorReport'] = 'Foutenrapport';

    // Italian - by Valerio Capello
    $et['it']['Version'] = 'Versione';
    $et['it']['DocRoot'] = 'Document Root';
    $et['it']['FMRoot'] = 'File Manager Root';
    $et['it']['Name'] = 'Nome';
    $et['it']['And'] = 'e';
    $et['it']['Enter'] = 'Immetti';
    $et['it']['Send'] = 'Invia';
    $et['it']['Refresh'] = 'Aggiorna';
    $et['it']['SaveConfig'] = 'Salva la Configurazione';
    $et['it']['SavePass'] = 'Salva la Password';
    $et['it']['SaveFile'] = 'Salva il File';
    $et['it']['Save'] = 'Salva';
    $et['it']['Leave'] = 'Abbandona';
    $et['it']['Edit'] = 'Modifica';
    $et['it']['View'] = 'Guarda';
    $et['it']['Config'] = 'Configurazione';
    $et['it']['Ren'] = 'Rinomina';
    $et['it']['Rem'] = 'Elimina';
    $et['it']['Compress'] = 'Comprimi';
    $et['it']['Decompress'] = 'Decomprimi';
    $et['it']['ResolveIDs'] = 'Risolvi IDs';
    $et['it']['Move'] = 'Sposta';
    $et['it']['Copy'] = 'Copia';
    $et['it']['ServerInfo'] = 'Informazioni sul Server';
    $et['it']['CreateDir'] = 'Crea Directory';
    $et['it']['CreateArq'] = 'Crea File';
    $et['it']['ExecCmd'] = 'Esegui Comando';
    $et['it']['Upload'] = 'Carica';
    $et['it']['UploadEnd'] = 'Caricamento terminato';
    $et['it']['Perm'] = 'Perm';
    $et['it']['Perms'] = 'Permessi';
    $et['it']['Owner'] = 'Proprietario';
    $et['it']['Group'] = 'Gruppo';
    $et['it']['Other'] = 'Altri';
    $et['it']['Size'] = 'Dimensioni';
    $et['it']['Date'] = 'Data';
    $et['it']['Type'] = 'Tipo';
    $et['it']['Free'] = 'liberi';
    $et['it']['Shell'] = 'Shell';
    $et['it']['Read'] = 'Lettura';
    $et['it']['Write'] = 'Scrittura';
    $et['it']['Exec'] = 'Esecuzione';
    $et['it']['Apply'] = 'Applica';
    $et['it']['StickyBit'] = 'Sticky Bit';
    $et['it']['Pass'] = 'Password';
    $et['it']['Lang'] = 'Lingua';
    $et['it']['File'] = 'File';
    $et['it']['File_s'] = 'file';
    $et['it']['Dir_s'] = 'directory';
    $et['it']['To'] = 'a';
    $et['it']['Destination'] = 'Destinazione';
    $et['it']['Configurations'] = 'Configurazione';
    $et['it']['JSError'] = 'Errore JavaScript';
    $et['it']['NoSel'] = 'Non ci sono elementi selezionati';
    $et['it']['SelDir'] = 'Scegli la directory di destinazione';
    $et['it']['TypeDir'] = 'Inserisci il nome della directory';
    $et['it']['TypeArq'] = 'Inserisci il nome del file';
    $et['it']['TypeCmd'] = 'Inserisci il comando';
    $et['it']['TypeArqComp'] = 'Inserisci il nome del file.\\nLa estensione definirà il tipo di compressione.\\nEsempio:\\nnome.zip\\nnome.tar\\nnome.bzip\\nnome.gzip';
    $et['it']['RemSel'] = 'ELIMINA gli elementi selezionati';
    $et['it']['NoDestDir'] = 'LA directory di destinazione non è stata selezionata';
    $et['it']['DestEqOrig'] = 'La directory di origine e di destinazione sono la stessa';
    $et['it']['InvalidDest'] = 'La directory di destinazione non è valida';
    $et['it']['NoNewPerm'] = 'Nuovi permessi non attivati';
    $et['it']['CopyTo'] = 'COPIA in';
    $et['it']['MoveTo'] = 'SPOSTA in';
    $et['it']['AlterPermTo'] = 'CAMBIA I PERMESSI: ';
    $et['it']['ConfExec'] = 'Conferma ESECUZIONE';
    $et['it']['ConfRem'] = 'Conferma ELIMINAZIONE';
    $et['it']['EmptyDir'] = 'Directory vuota';
    $et['it']['IOError'] = 'Errore di I/O';
    $et['it']['FileMan'] = 'PHP File Manager';
    $et['it']['TypePass'] = 'Immetti la password';
    $et['it']['InvPass'] = 'Password non valida';
    $et['it']['ReadDenied'] = 'Permesso di lettura negato';
    $et['it']['FileNotFound'] = 'File non trovato';
    $et['it']['AutoClose'] = 'Chiudi la finestra al termine';
    $et['it']['OutDocRoot'] = 'File oltre DOCUMENT_ROOT';
    $et['it']['NoCmd'] = 'Errore: Comando non informato';
    $et['it']['ConfTrySave'] = 'File senza permesso di scrittura.\\nProvo a salvare comunque';
    $et['it']['ConfSaved'] = 'Configurazione salvata';
    $et['it']['PassSaved'] = 'Password salvata';
    $et['it']['FileDirExists'] = 'Il file o la directory esiste già';
    $et['it']['NoPhpinfo'] = 'La funzione phpinfo è disabilitata';
    $et['it']['NoReturn'] = 'senza Return';
    $et['it']['FileSent'] = 'File inviato';
    $et['it']['SpaceLimReached'] = 'è stato raggiunto il limite di spazio disponibile';
    $et['it']['InvExt'] = 'Estensione non valida';
    $et['it']['FileNoOverw'] = 'Il file non può essere sovrascritto';
    $et['it']['FileOverw'] = 'File sovrascritto';
    $et['it']['FileIgnored'] = 'File ignorato';
    $et['it']['ChkVer'] = 'Controlla se è disponibile una nuova versione';
    $et['it']['ChkVerAvailable'] = 'è disponibile una nuova versione: premi qui per scaricarla.';
    $et['it']['ChkVerNotAvailable'] = 'Non è disponibile nessuna nuova versione. :(';
    $et['it']['ChkVerError'] = 'Errore di connessione.';
    $et['it']['Website'] = 'Sito Web';
    $et['it']['SendingForm'] = 'Invio file, attendere prego';
    $et['it']['NoFileSel'] = 'Nessun file selezionato';
    $et['it']['SelAll'] = 'Tutti';
    $et['it']['SelNone'] = 'Nessuno';
    $et['it']['SelInverse'] = 'Inverti';
    $et['it']['Selected_s'] = 'selezionato';
    $et['it']['Total'] = 'totali';
    $et['it']['Partition'] = 'Partizione';
    $et['it']['RenderTime'] = 'Tempo per elaborare questa pagina';
    $et['it']['Seconds'] = 'sec';
    $et['it']['ErrorReport'] = 'Error Reporting';

    // Turkish - by Necdet Yazilimlari
    $et['tr']['Version'] = 'Versiyon';
    $et['tr']['DocRoot'] = 'Kok dosya';
    $et['tr']['FMRoot'] = 'Kok dosya yoneticisi';
    $et['tr']['Name'] = 'Isim';
    $et['tr']['And'] = 've';
    $et['tr']['Enter'] = 'Giris';
    $et['tr']['Send'] = 'Yolla';
    $et['tr']['Refresh'] = 'Yenile';
    $et['tr']['SaveConfig'] = 'Ayarlari kaydet';
    $et['tr']['SavePass'] = 'Parolayi kaydet';
    $et['tr']['SaveFile'] = 'Dosyayi kaydet';
    $et['tr']['Save'] = 'Kaydet';
    $et['tr']['Leave'] = 'Ayril';
    $et['tr']['Edit'] = 'Duzenle';
    $et['tr']['View'] = 'Goster';
    $et['tr']['Config'] = 'Yapilandirma';
    $et['tr']['Ren'] = 'Yeniden adlandir';
    $et['tr']['Rem'] = 'Sil';
    $et['tr']['Compress'] = '.Zip';
    $et['tr']['Decompress'] = '.ZipCoz';
    $et['tr']['ResolveIDs'] = 'Kimlikleri coz';
    $et['tr']['Move'] = 'Tasi';
    $et['tr']['Copy'] = 'Kopyala';
    $et['tr']['ServerInfo'] = 'Sunucu Bilgisi';
    $et['tr']['CreateDir'] = 'Dizin olustur';
    $et['tr']['CreateArq'] = 'Dosya olusutur';
    $et['tr']['ExecCmd'] = 'Komut calistir';
    $et['tr']['Upload'] = 'Dosya yukle';
    $et['tr']['UploadEnd'] = 'Yukleme tamamlandi';
    $et['tr']['Perm'] = 'Izinler';
    $et['tr']['Perms'] = 'Izinler';
    $et['tr']['Owner'] = 'Sahip';
    $et['tr']['Group'] = 'Grup';
    $et['tr']['Other'] = 'Diger';
    $et['tr']['Size'] = 'Boyut';
    $et['tr']['Date'] = 'Tarih';
    $et['tr']['Type'] = 'Tip';
    $et['tr']['Free'] = 'Bos';
    $et['tr']['Shell'] = 'Kabuk';
    $et['tr']['Read'] = 'Oku';
    $et['tr']['Write'] = 'Yaz';
    $et['tr']['Exec'] = 'Calistir';
    $et['tr']['Apply'] = 'Uygula';
    $et['tr']['StickyBit'] = 'Sabit bit';
    $et['tr']['Pass'] = 'Parola';
    $et['tr']['Lang'] = 'Dil';
    $et['tr']['File'] = 'Dosya';
    $et['tr']['File_s'] = 'Dosya(lar)';
    $et['tr']['Dir_s'] = 'Dizin(ler)';
    $et['tr']['To'] = 'icin';
    $et['tr']['Destination'] = 'Hedef';
    $et['tr']['Configurations'] = 'Yapilandirmalar';
    $et['tr']['JSError'] = 'JavaScript hatasi';
    $et['tr']['NoSel'] = 'Secilen oge yok';
    $et['tr']['SelDir'] = 'Soldaki hedef dizin agaci secin';
    $et['tr']['TypeDir'] = 'Dizin adini girin';
    $et['tr']['TypeArq'] = 'Dosya adini girin';
    $et['tr']['TypeCmd'] = 'Komut girin';
    $et['tr']['TypeArqComp'] = 'Dosya ismini yazdiktan sonra sonuna .zip ekleyin';
    $et['tr']['RemSel'] = 'Secili ogeleri sil';
    $et['tr']['NoDestDir'] = 'Secili dizin yok';
    $et['tr']['DestEqOrig'] = 'Kokenli ve esit gidis rehberi';
    $et['tr']['InvalidDest'] = 'Hedef dizin gecersiz';
    $et['tr']['NoNewPerm'] = 'Izinler uygun degil';
    $et['tr']['CopyTo'] = 'Kopya icin';
    $et['tr']['MoveTo'] = 'Tasi icin';
    $et['tr']['AlterPermTo'] = 'Permission secin';
    $et['tr']['ConfExec'] = 'Yapilandirmayi onayla';
    $et['tr']['ConfRem'] = 'Simeyi onayla';
    $et['tr']['EmptyDir'] = 'Dizin bos';
    $et['tr']['IOError'] = 'Hata';
    $et['tr']['FileMan'] = 'Necdet_Yazilimlari';
    $et['tr']['TypePass'] = 'Parolayi girin';
    $et['tr']['InvPass'] = 'Gecersiz parola';
    $et['tr']['ReadDenied'] = 'Okumaya erisim engellendi';
    $et['tr']['FileNotFound'] = 'Dosya bulunamadi';
    $et['tr']['AutoClose'] = 'Otomatik kapat';
    $et['tr']['OutDocRoot'] = 'Kok klasor disindaki dosya';
    $et['tr']['NoCmd'] = 'Hata: Komut haberdar degil';
    $et['tr']['ConfTrySave'] = 'Dosya yazma izniniz yok. Yine de kaydetmeyi deneyebilirsiniz.';
    $et['tr']['ConfSaved'] = 'Ayarlar kaydedildi';
    $et['tr']['PassSaved'] = 'Parola kaydedildi';
    $et['tr']['FileDirExists'] = 'Dosya veya dizin zaten var';
    $et['tr']['NoPhpinfo'] = 'Php fonksiyon bilgisi devre disi';
    $et['tr']['NoReturn'] = 'Deger dondurmuyor';
    $et['tr']['FileSent'] = 'Dosya gonderildi';
    $et['tr']['SpaceLimReached'] = 'Disk limitine ulasildi';
    $et['tr']['InvExt'] = 'Gecersiz uzanti';
    $et['tr']['FileNoOverw'] = 'Dosya degistirilemiyor';
    $et['tr']['FileOverw'] = 'Dosya degistiribiliyor';
    $et['tr']['FileIgnored'] = 'Dosya kabul edildi';
    $et['tr']['ChkVer'] = 'Yeni versiyonu kontrol et';
    $et['tr']['ChkVerAvailable'] = 'Yeni surum bulundu. Indirmek icin buraya tiklayin.';
    $et['tr']['ChkVerNotAvailable'] = 'Yeni surum bulunamadi.';
    $et['tr']['ChkVerError'] = 'Baglanti hatasi';
    $et['tr']['Website'] = 'Website';
    $et['tr']['SendingForm'] = 'Dosyalar gonderiliyor, lutfen bekleyin';
    $et['tr']['NoFileSel'] = 'Secili dosya yok';
    $et['tr']['SelAll'] = 'Hepsi';
    $et['tr']['SelNone'] = 'Hicbiri';
    $et['tr']['SelInverse'] = 'Ters';
    $et['tr']['Selected_s'] = 'Secili oge(ler)';
    $et['tr']['Total'] = 'Toplam';
    $et['tr']['Partition'] = 'Bolme';
    $et['tr']['RenderTime'] = 'Olusturuluyor';
    $et['tr']['Seconds'] = 'Saniye';
    $et['tr']['ErrorReport'] = 'Hata raporu';

    // Russian - by Евгений Рашев, Алексей Гаврюшин
    $et['ru']['Version']='Версия';
    $et['ru']['DocRoot']='Корневая папка';
    $et['ru']['FMRoot']='Корневая папка файлового менеджера';
    $et['ru']['Name']='Имя';
    $et['ru']['And']='и';
    $et['ru']['Enter']='Войти';
    $et['ru']['Send']='Отправить';
    $et['ru']['Refresh']='Обновить';
    $et['ru']['SaveConfig']='Сохранить конфигурацию';
    $et['ru']['SavePass']='Сохранить пароль';
    $et['ru']['SaveFile']='Сохранить файл';
    $et['ru']['Save']='Сохранить';
    $et['ru']['Leave']='Уйти';
    $et['ru']['Edit']='Изменить';
    $et['ru']['View']='Просмотр';
    $et['ru']['Config']='Настройки';
    $et['ru']['Ren']='Переименовать';
    $et['ru']['Rem']='Удалить';
    $et['ru']['Compress']='Сжать';
    $et['ru']['Decompress']='Распаковать';
    $et['ru']['ResolveIDs']='Определить ID';
    $et['ru']['Move']='Переместить';
    $et['ru']['Copy']='Копировать';
    $et['ru']['ServerInfo']='Инфо о сервере';
    $et['ru']['CreateDir']='Создать папку';
    $et['ru']['CreateArq']='Создать файл';
    $et['ru']['ExecCmd']='Выполнить';
    $et['ru']['Upload']='Загрузить';
    $et['ru']['UploadEnd']='Загружено';
    $et['ru']['Perm']='Права';
    $et['ru']['Perms']='Разрешения';
    $et['ru']['Owner']='Владелец';
    $et['ru']['Group']='Группа';
    $et['ru']['Other']='Другие';
    $et['ru']['Size']='Размер';
    $et['ru']['Date']='Дата';
    $et['ru']['Type']='Тип';
    $et['ru']['Free']='Свободно';
    $et['ru']['Shell']='Командная строка';
    $et['ru']['Read']='Читать';
    $et['ru']['Write']='Писать';
    $et['ru']['Exec']='Выполнять';
    $et['ru']['Apply']='Применить';
    $et['ru']['StickyBit']='StickyBit';
    $et['ru']['Pass']='Пароль';
    $et['ru']['Lang']='Язык';
    $et['ru']['File']='Файл';
    $et['ru']['File_s']='Файл(ы)';
    $et['ru']['Dir_s']='Папка/и';
    $et['ru']['To']='в';
    $et['ru']['Destination']='Конечная папка';
    $et['ru']['Configurations']='Конфигурация';
    $et['ru']['JSError']='Ошибка JavaScript';
    $et['ru']['NoSel']='Нет выбранных элементов';
    $et['ru']['SelDir']='Выберите папку назначения в левом дереве';
    $et['ru']['TypeDir']='Введите имя папки';
    $et['ru']['TypeArq']='Введите имя файла';
    $et['ru']['TypeCmd']='Введите команду';
    $et['ru']['TypeArqComp']='Введите имя и расширение файла.\\nРасширение определит тип сжатия.\\n Пример: \\n nome.zip \\n nome.tar \\n nome.bzip \\n nome.gzip ';
    $et['ru']['RemSel']='Удалить выбранные элементы';
    $et['ru']['NoDestDir']='Не выбрана папка назначения';
    $et['ru']['DestEqOrig']='Исходные и конечные папки равны';
    $et['ru']['InvalidDest']='Конечная папка недействительна';
    $et['ru']['NoNewPerm']='Новые разрешения не установлены';
    $et['ru']['CopyTo']='Копировать в';
    $et['ru']['MoveTo']='Переместить в';
    $et['ru']['AlterPermTo']='Измененить разрешения на';
    $et['ru']['ConfExec']='Подтвердить ВЫПОЛНЕНИЕ';
    $et['ru']['ConfRem']='Подтвердить УДАЛЕНИЕ';
    $et['ru']['EmptyDir']='Пустая папка';
    $et['ru']['IOError']='Ошибка I/O';
    $et['ru']['FileMan']='Файловый менеджер';
    $et['ru']['TypePass']='Введите пароль';
    $et['ru']['InvPass']='Неверный пароль';
    $et['ru']['ReadDenied']='Доступ запрещен';
    $et['ru']['FileNotFound']='Файл не найден';
    $et['ru']['AutoClose']='Закрыть после окончания';
    $et['ru']['OutDocRoot']='Файлы за пределами DOCUMENT_ROOT';
    $et['ru']['NoCmd']='Ошибка: Команда не поддерживается';
    $et['ru']['ConfTrySave']='Файл без прав на запись.\\nПопытаться сохранить';
    $et['ru']['ConfSaved']='Конфигурация сохранена';
    $et['ru']['PassSaved']='Пароль сохранен';
    $et['ru']['FileDirExists']='Файл или папка уже существует';
    $et['ru']['NoPhpinfo']='Функция PHPInfo отключена';
    $et['ru']['NoReturn']='Нет возврата';
    $et['ru']['FileSent']='Файл отправлен';
    $et['ru']['SpaceLimReached']='Память полностью заполнена';
    $et['ru']['InvExt']='Недействительное расширение';
    $et['ru']['FileNoOverw']='Файл не может быть перезаписан';
    $et['ru']['FileOverw']='Файл перезаписан';
    $et['ru']['FileIgnored']='Файл игнорирован';
    $et['ru']['ChkVer']='Поиск обновлений';
    $et['ru']['ChkVerAvailable']=' Доступна новая версия; нажмите здесь, чтобы начать загрузку!';
    $et['ru']['ChkVerNotAvailable']='Не найдено новой версии.';
    $et['ru']['ChkVerError']='Ошибка подключения.';
    $et['ru']['Website']='Сайт';
    $et['ru']['SendingForm']='Отправка файлов; пожалуйста, подождите';
    $et['ru']['NoFileSel']='Нет выбранных файлов';
    $et['ru']['SelAll']='Выделить все';
    $et['ru']['SelNone']='Отмена';
    $et['ru']['SelInverse']='Обратить выбор';
    $et['ru']['Selected_s']='Выбран(ы)';
    $et['ru']['Total']='Всего';
    $et['ru']['Partition']='Раздел';
    $et['ru']['RenderTime']='Скрипт выполнен за';
    $et['ru']['Seconds']='секунд';
    $et['ru']['ErrorReport']='Отчет об ошибках';

    // Catalan - by Pere Borràs AKA @Norl
    $et['ca']['Version'] = 'Versió';
    $et['ca']['DocRoot'] = 'Arrel del programa';
    $et['ca']['FMRoot'] = 'Arrel de l`administrador d`arxius';
    $et['ca']['Name'] = 'Nom';
    $et['ca']['And'] = 'i';
    $et['ca']['Enter'] = 'Entrar';
    $et['ca']['Send'] = 'Enviar';
    $et['ca']['Refresh'] = 'Refrescar';
    $et['ca']['SaveConfig'] = 'Desar configuracions';
    $et['ca']['SavePass'] = 'Desar clau';
    $et['ca']['SaveFile'] = 'Desar Arxiu';
    $et['ca']['Save'] = 'Desar';
    $et['ca']['Leave'] = 'Sortir';
    $et['ca']['Edit'] = 'Editar';
    $et['ca']['View'] = 'Mirar';
    $et['ca']['Config'] = 'Config.';
    $et['ca']['Ren'] = 'Canviar nom';
    $et['ca']['Rem'] = 'Esborrar';
    $et['ca']['Compress'] = 'Comprimir';
    $et['ca']['Decompress'] = 'Descomprimir';
    $et['ca']['ResolveIDs'] = 'Resoldre IDs';
    $et['ca']['Move'] = 'Moure';
    $et['ca']['Copy'] = 'Copiar';
    $et['ca']['ServerInfo'] = 'Info del Server';
    $et['ca']['CreateDir'] = 'Crear Directori';
    $et['ca']['CreateArq'] = 'Crear Arxiu';
    $et['ca']['ExecCmd'] = 'Executar Comandament';
    $et['ca']['Upload'] = 'Pujar';
    $et['ca']['UploadEnd'] = 'Pujat amb èxit';
    $et['ca']['Perm'] = 'Perm';
    $et['ca']['Perms'] = 'Permisos';
    $et['ca']['Owner'] = 'Propietari';
    $et['ca']['Group'] = 'Grup';
    $et['ca']['Other'] = 'Altre';
    $et['ca']['Size'] = 'Tamany';
    $et['ca']['Date'] = 'Data';
    $et['ca']['Type'] = 'Tipus';
    $et['ca']['Free'] = 'lliure';
    $et['ca']['Shell'] = 'Executar';
    $et['ca']['Read'] = 'Llegir';
    $et['ca']['Write'] = 'Escriure';
    $et['ca']['Exec'] = 'Executar';
    $et['ca']['Apply'] = 'Aplicar';
    $et['ca']['StickyBit'] = 'Sticky Bit';
    $et['ca']['Pass'] = 'Clau';
    $et['ca']['Lang'] = 'Llenguatje';
    $et['ca']['File'] = 'Arxius';
    $et['ca']['File_s'] = 'arxiu(s)';
    $et['ca']['Dir_s'] = 'directori(s)';
    $et['ca']['To'] = 'a';
    $et['ca']['Destination'] = 'Destí';
    $et['ca']['Configurations'] = 'Configuracions';
    $et['ca']['JSError'] = 'Error de JavaScript';
    $et['ca']['NoSel'] = 'No hi ha items seleccionats';
    $et['ca']['SelDir'] = 'Seleccioneu el directori de destí a l`arbre de la dreta';
    $et['ca']['TypeDir'] = 'Escrigui el nom del directori';
    $et['ca']['TypeArq'] = 'Escrigui el nom de l`arxiu';
    $et['ca']['TypeCmd'] = 'Escrigui el comandament';
    $et['ca']['TypeArqComp'] = 'Escrigui el nombre del directorio.\\nL`extensió definirà el tipus de compressió.\\nEx:\\nnom.zip\\nnom.tar\\nnom.bzip\\nnom.gzip';
    $et['ca']['RemSel'] = 'ESBORRAR items seleccionats';
    $et['ca']['NoDestDir'] = 'No s`ha seleccionat el directori de destí';
    $et['ca']['DestEqOrig'] = 'L`origen i el destí són iguals';
    $et['ca']['InvalidDest'] = 'El destí del directori és invàlid';
    $et['ca']['NoNewPerm'] = 'Els permisos no s`han pogut establir';
    $et['ca']['CopyTo'] = 'COPIAR a';
    $et['ca']['MoveTo'] = 'MOURE a';
    $et['ca']['AlterPermTo'] = 'CAMBIAR PERMISOS a';
    $et['ca']['ConfExec'] = 'Confirmar EXECUCIÓ';
    $et['ca']['ConfRem'] = 'Confirmar ESBORRAT';
    $et['ca']['EmptyDir'] = 'Directori buit';
    $et['ca']['IOError'] = 'Error I/O';
    $et['ca']['FileMan'] = 'PHP File Manager';
    $et['ca']['TypePass'] = 'Escrigui la clau';
    $et['ca']['InvPass'] = 'Clau invàlida';
    $et['ca']['ReadDenied'] = 'Accés de lectura denegat';
    $et['ca']['FileNotFound'] = 'Arxiu no trobat';
    $et['ca']['AutoClose'] = 'Tancar al completar';
    $et['ca']['OutDocRoot'] = 'Arxiu abans de DOCUMENT_ROOT';
    $et['ca']['NoCmd'] = 'Error: No s`ha escrit cap comandament';
    $et['ca']['ConfTrySave'] = 'Arxiu sense permisos d`escriptura.\\nIntenteu desar a un altre lloc';
    $et['ca']['ConfSaved'] = 'Configuració Desada';
    $et['ca']['PassSaved'] = 'Clau desada';
    $et['ca']['FileDirExists'] = 'Arxiu o directori ja existent';
    $et['ca']['NoPhpinfo'] = 'Funció phpinfo() no habilitada';
    $et['ca']['NoReturn'] = 'sense retorn';
    $et['ca']['FileSent'] = 'Arxiu enviat';
    $et['ca']['SpaceLimReached'] = 'Límit d`espaci al disc assolit';
    $et['ca']['InvExt'] = 'Extensió no vàlida';
    $et['ca']['FileNoOverw'] = 'L`arxiu no ha pogut ser sobreescrit';
    $et['ca']['FileOverw'] = 'Arxiu sobreescrit';
    $et['ca']['FileIgnored'] = 'Arxiu ignorat';
    $et['ca']['ChkVer'] = 'Revisar les actualitzacions';
    $et['ca']['ChkVerAvailable'] = 'Nova versió, feu clic aquí per descarregar';
    $et['ca']['ChkVerNotAvailable'] = 'La vostra versió és la més recent.';
    $et['ca']['ChkVerError'] = 'Error de connexió.';
    $et['ca']['Website'] = 'Lloc Web';
    $et['ca']['SendingForm'] = 'Enviant arxius, esperi';
    $et['ca']['NoFileSel'] = 'Cap arxiu seleccionat';
    $et['ca']['SelAll'] = 'Tots';
    $et['ca']['SelNone'] = 'Cap';
    $et['ca']['SelInverse'] = 'Invers';
    $et['ca']['Selected_s'] = 'seleccionat';
    $et['ca']['Total'] = 'total';
    $et['ca']['Partition'] = 'Partició';
    $et['ca']['RenderTime'] = 'Generat en';
    $et['ca']['Seconds'] = 'seg';
    $et['ca']['ErrorReport'] = 'Informe d`error';

    // Chinese - by Wen.Xin
    $et['cn']['Version'] = '版本';
    $et['cn']['DocRoot'] = '文档根目录';
    $et['cn']['FMRoot'] = '文件管理根目录';
    $et['cn']['Name'] = '名称';
    $et['cn']['And'] = '&';
    $et['cn']['Enter'] = '确认';
    $et['cn']['Send'] = '确认';
    $et['cn']['Refresh'] = '刷新';
    $et['cn']['SaveConfig'] = '保存设置';
    $et['cn']['SavePass'] = '保存密码';
    $et['cn']['SaveFile'] = '保存文件';
    $et['cn']['Save'] = '保存';
    $et['cn']['Leave'] = '离开';
    $et['cn']['Edit'] = '编辑';
    $et['cn']['View'] = '查看';
    $et['cn']['Config'] = '设置';
    $et['cn']['Ren'] = '重命名';
    $et['cn']['Rem'] = '删除';
    $et['cn']['Compress'] = '压缩';
    $et['cn']['Decompress'] = '解压缩';
    $et['cn']['ResolveIDs'] = 'Resolve IDs';
    $et['cn']['Move'] = '移动';
    $et['cn']['Copy'] = '复制';
    $et['cn']['ServerInfo'] = '服务器信息';
    $et['cn']['CreateDir'] = '新建文件夹';
    $et['cn']['CreateArq'] = '新建文件';
    $et['cn']['ExecCmd'] = '执行命令';
    $et['cn']['Upload'] = '上传';
    $et['cn']['UploadEnd'] = '上传完成';
    $et['cn']['Perm'] = '权限';
    $et['cn']['Perms'] = '权限';
    $et['cn']['Owner'] = '所有者';
    $et['cn']['Group'] = '组';
    $et['cn']['Other'] = '公共';
    $et['cn']['Size'] = '大小';
    $et['cn']['Date'] = '日期';
    $et['cn']['Type'] = 'Type';
    $et['cn']['Free'] = '空闲';
    $et['cn']['Shell'] = '命令行';
    $et['cn']['Read'] = '读取';
    $et['cn']['Write'] = '写入';
    $et['cn']['Exec'] = '执行';
    $et['cn']['Apply'] = '应用';
    $et['cn']['StickyBit'] = '粘滞';
    $et['cn']['Pass'] = '密码';
    $et['cn']['Lang'] = '语言';
    $et['cn']['File'] = '文件';
    $et['cn']['File_s'] = '文件';
    $et['cn']['Dir_s'] = '文件夹';
    $et['cn']['To'] = '为';
    $et['cn']['Destination'] = '目标';
    $et['cn']['Configurations'] = '设置';
    $et['cn']['JSError'] = 'JavaScript 错误';
    $et['cn']['NoSel'] = '未选择项目';
    $et['cn']['SelDir'] = '从左边树目录选择目标文件夹';
    $et['cn']['TypeDir'] = '输入文件夹名称';
    $et['cn']['TypeArq'] = '输入文件名';
    $et['cn']['TypeCmd'] = '输入命令';
    $et['cn']['TypeArqComp'] = '输入文件名.\\n扩展名将定义压缩类型.\\n例如:\\nnome.zip\\nnome.tar\\nnome.bzip\\nnome.gzip';
    $et['cn']['RemSel'] = '删除选定项目';
    $et['cn']['NoDestDir'] = '未选定目标文件夹';
    $et['cn']['DestEqOrig'] = '目标文件夹与源文件夹相同';
    $et['cn']['InvalidDest'] = '目标文件夹无效';
    $et['cn']['NoNewPerm'] = '未设置新权限';
    $et['cn']['CopyTo'] = '复制到';
    $et['cn']['MoveTo'] = '移动到';
    $et['cn']['AlterPermTo'] = '修改权限为';
    $et['cn']['ConfExec'] = '确认执行';
    $et['cn']['ConfRem'] = '确认删除';
    $et['cn']['EmptyDir'] = '空文件夹';
    $et['cn']['IOError'] = 'I/O 错误';
    $et['cn']['FileMan'] = 'PHP文件管理器' ;
    $et['cn']['TypePass'] = '输入密码';
    $et['cn']['InvPass'] = '无效密码';
    $et['cn']['ReadDenied'] = '拒绝读取访问';
    $et['cn']['FileNotFound'] = '文件未找到';
    $et['cn']['AutoClose'] = '完成时关闭';
    $et['cn']['OutDocRoot'] = '文件超出 DOCUMENT_ROOT';
    $et['cn']['NoCmd'] = '错误: 指令无法识别';
    $et['cn']['ConfTrySave'] = '文件无-写入-权限.\\n尝试保存.';
    $et['cn']['ConfSaved'] = '设置密码';
    $et['cn']['PassSaved'] = '保存密码';
    $et['cn']['FileDirExists'] = '文件或目录已经存在';
    $et['cn']['NoPhpinfo'] = '函数 phpinfo 被禁用';
    $et['cn']['NoReturn'] = '无结果';
    $et['cn']['FileSent'] = '发送文件';
    $et['cn']['SpaceLimReached'] = '磁盘空间限制';
    $et['cn']['InvExt'] = '无效的扩展';
    $et['cn']['FileNoOverw'] = '文件无法被覆盖';
    $et['cn']['FileOverw'] = '覆盖文件';
    $et['cn']['FileIgnored'] = '忽略文件';
    $et['cn']['ChkVer'] = '检查新版本';
    $et['cn']['ChkVerAvailable'] = '有新版本, 点击此处开始下载!!';
    $et['cn']['ChkVerNotAvailable'] = '没有新版本可用. :(';
    $et['cn']['ChkVerError'] = '连接错误.';
    $et['cn']['Website'] = '官方网站';
    $et['cn']['SendingForm'] = '发送文件中, 请稍候...';
    $et['cn']['NoFileSel'] = '未选择文件';
    $et['cn']['SelAll'] = '全选';
    $et['cn']['SelNone'] = '取消';
    $et['cn']['SelInverse'] = '反选';
    $et['cn']['Selected_s'] = '选择';
    $et['cn']['Total'] = '总共';
    $et['cn']['Partition'] = '分区';
    $et['cn']['RenderTime'] = '此界面渲染耗时';
    $et['cn']['Seconds'] = '秒';
    $et['cn']['ErrorReport'] = '错误报告级别';
    $et['cn']['Close'] = '关闭';
    $et['cn']['SetPass'] = '设置密码';
    $et['cn']['ChangePass'] = '修改密码';
    $et['cn']['Portscan'] = '端口扫描';

    // Ukrainian - by Андрій Литвин
    $et['ua']['Version']='Версія';
    $et['ua']['DocRoot']='Коренева тека';
    $et['ua']['FMRoot']='Коренева тека файлового менеджера';
    $et['ua']['Name']='Им\'я';
    $et['ua']['And']='і';
    $et['ua']['Enter']='Увійти';
    $et['ua']['Send']='Відправити';
    $et['ua']['Refresh']='Оновити';
    $et['ua']['SaveConfig']='Зберегти налаштування';
    $et['ua']['SavePass']='Зберегти пароль';
    $et['ua']['SaveFile']='Зберегти файл';
    $et['ua']['Save']='Зберегти';
    $et['ua']['Leave']='Вихід';
    $et['ua']['Edit']='Змінити';
    $et['ua']['View']='Перегляд';
    $et['ua']['Config']='Налаштування';
    $et['ua']['Ren']='Перейменувати';
    $et['ua']['Rem']='Видалити';
    $et['ua']['Compress']='Стиснути';
    $et['ua']['Decompress']='Видобути з архіву';
    $et['ua']['ResolveIDs']='Визначити ID';
    $et['ua']['Move']='Перемістити';
    $et['ua']['Copy']='Копіювати';
    $et['ua']['ServerInfo']='Инфо о сервере';
    $et['ua']['CreateDir']='Створити теку';
    $et['ua']['CreateArq']='Створити файл';
    $et['ua']['ExecCmd']='Виконати';
    $et['ua']['Upload']='Завантажити';
    $et['ua']['UploadEnd']='Завантажено';
    $et['ua']['Perm']='Права';
    $et['ua']['Perms']='Дозволи';
    $et['ua']['Owner']='Власник';
    $et['ua']['Group']='Група';
    $et['ua']['Other']='Інші';
    $et['ua']['Size']='Розмір';
    $et['ua']['Date']='Дата';
    $et['ua']['Type']='Тип';
    $et['ua']['Free']='Вільно простору';
    $et['ua']['Shell']='Командний рядок';
    $et['ua']['Read']='Читати';
    $et['ua']['Write']='Писати';
    $et['ua']['Exec']='Виконати';
    $et['ua']['Apply']='Застосувати';
    $et['ua']['StickyBit']='StickyBit';
    $et['ua']['Pass']='Пароль';
    $et['ua']['Lang']='Мова';
    $et['ua']['File']='Файл';
    $et['ua']['File_s']='Файл(и)';
    $et['ua']['Dir_s']='Тека(и)';
    $et['ua']['To']='в';
    $et['ua']['Destination']='Кінцева тека';
    $et['ua']['Configurations']='Конфігурація';
    $et['ua']['JSError']='Помилка JavaScript';
    $et['ua']['NoSel']='Не обрано жодного елементу';
    $et['ua']['SelDir']='Выберіть теку призначення у дереві ліворуч';
    $et['ua']['TypeDir']='Введіть им\'я теки';
    $et['ua']['TypeArq']='Введіть им\'я файла';
    $et['ua']['TypeCmd']='Введіть команду';
    $et['ua']['TypeArqComp']='Введіть им\'я і розширення файлу.\\nРозширення визаче тип стиснення.\\n Наприклад: \\n name.zip \\n name.tar \\n name.bzip \\n name.gzip ';
    $et['ua']['RemSel']='Видалити обрані елементи';
    $et['ua']['NoDestDir']='Тека призначення не обана';
    $et['ua']['DestEqOrig']='Оберіть іншу теку';
    $et['ua']['InvalidDest']='Помилковий напрямок';
    $et['ua']['NoNewPerm']='Нові дозволи на файл не встановлені';
    $et['ua']['CopyTo']='Копіювати у';
    $et['ua']['MoveTo']='Перемістити у';
    $et['ua']['AlterPermTo']='Змінити дозволи на';
    $et['ua']['ConfExec']='Підтвердити ВИКОНАННЯ';
    $et['ua']['ConfRem']='Підтвердити ВИДАЛЕННЯ';
    $et['ua']['EmptyDir']='Порожня тека';
    $et['ua']['IOError']='Помилка I/O';
    $et['ua']['FileMan']='Файловий менеджер';
    $et['ua']['TypePass']='Введіть пароль';
    $et['ua']['InvPass']='Пароль хибний';
    $et['ua']['ReadDenied']='Доступ заборонено';
    $et['ua']['FileNotFound']='Файл не знайдено';
    $et['ua']['AutoClose']='Закрити після закінчення';
    $et['ua']['OutDocRoot']='Файли за межами DOCUMENT_ROOT';
    $et['ua']['NoCmd']='Помилка: Команда не підтримується';
    $et['ua']['ConfTrySave']='Файл без права на запис.\\nСпробувати зберегти';
    $et['ua']['ConfSaved']='Конфігурація збережена';
    $et['ua']['PassSaved']='Пароль збережено';
    $et['ua']['FileDirExists']='Файл або тека уже існує';
    $et['ua']['NoPhpinfo']='Функція PHPInfo вимкнена';
    $et['ua']['NoReturn']='Без відповіді';
    $et['ua']['FileSent']='Файл надіслано';
    $et['ua']['SpaceLimReached']='Пам\'ять повністью заповнена';
    $et['ua']['InvExt']='Розширення хибне';
    $et['ua']['FileNoOverw']='Файл не може бути перезаписаний';
    $et['ua']['FileOverw']='Файл перезаписаний';
    $et['ua']['FileIgnored']='Файл ігноровано';
    $et['ua']['ChkVer']='Пошук обновленнь';
    $et['ua']['ChkVerAvailable']=' Доступна нова версія; натисніть тут, щоб почати оновлення!';
    $et['ua']['ChkVerNotAvailable']='Не знайдено новох версії.';
    $et['ua']['ChkVerError']='Помилка підключення.';
    $et['ua']['Website']='Сайт';
    $et['ua']['SendingForm']='Надсилаю фалйи; будьласка, чекайте';
    $et['ua']['NoFileSel']='Оберіть файли';
    $et['ua']['SelAll']='Обрати все';
    $et['ua']['SelNone']='Відмінити';
    $et['ua']['SelInverse']='Зворотній відбір';
    $et['ua']['Selected_s']='Обрано(і)';
    $et['ua']['Total']='Всьго';
    $et['ua']['Partition']='Розділ';
    $et['ua']['RenderTime']='Виконано за';
    $et['ua']['Seconds']='секунд';
    $et['ua']['ErrorReport']='Звіт про помилки';

    // Persian/Dari - by Opensecure
    $et['fa']['Version'] = 'نسخه';
    $et['fa']['DocRoot'] = 'ریشه سند';
    $et['fa']['FMRoot'] = 'ریشه مدیریت فایل';
    $et['fa']['DateFormat'] = 'فرمت تاریخ';
    $et['fa']['GetSize'] = 'Get size';
    $et['fa']['Error'] = 'Error';
    $et['fa']['Name'] = 'نام';
    $et['fa']['And'] = 'و';
    $et['fa']['Enter'] = 'وارد شدن';
    $et['fa']['Send'] = 'ارسال';
    $et['fa']['Refresh'] = 'تازه سازی';
    $et['fa']['SaveConfig'] = 'ذخیره تنظیمات';
    //$et['fa']['SavePass'] = 'ذخیره رمز';
    //$et['fa']['TypePass'] = 'رمز خود را وارد نمایید';
    $et['fa']['SaveFile'] = 'ذخیره فایل';
    $et['fa']['Save'] = 'ذخیره';
    $et['fa']['Leave'] = 'ترک کردن';
    $et['fa']['Edit'] = 'ویرایش';
    $et['fa']['View'] = 'نمایش';
    $et['fa']['Config'] = 'تنظیم';
    $et['fa']['Ren'] = 'تغییر نام';
    $et['fa']['Rem'] = 'حذف';
    $et['fa']['Compress'] = 'فشرده سازی';
    $et['fa']['Decompress'] = 'باز کردن فایل فشرده';
    $et['fa']['ResolveIDs'] = 'رفع IDs';
    $et['fa']['Move'] = 'انتقال';
    $et['fa']['Copy'] = 'کپی';
    $et['fa']['ServerInfo'] = 'معلومات سرور';
    $et['fa']['CreateDir'] = 'ساخت دایرکتوری';
    $et['fa']['CreateArq'] = 'ساخت فایل';
    $et['fa']['Symlink'] = 'Symlink';
    $et['fa']['HardLink'] = 'Hardlink';
    $et['fa']['ExecCmd'] = 'احرای دستور';
    $et['fa']['Upload'] = 'بارگذاری';
    $et['fa']['UploadEnd'] = 'اتمام بارگذاری';
    $et['fa']['Perm'] = 'دسترسی';
    $et['fa']['Perms'] = 'دسترسی ها';
    $et['fa']['Owner'] = 'مالک';
    $et['fa']['Group'] = 'گروه';
    $et['fa']['Other'] = 'متفقره';
    $et['fa']['Size'] = 'حجم';
    $et['fa']['Date'] = 'تاریخ';
    $et['fa']['Type'] = 'نوعیت';
    $et['fa']['Free'] = 'خالی';
    $et['fa']['Shell'] = 'فرامین';
    $et['fa']['Read'] = 'خواندن';
    $et['fa']['Write'] = 'نوشتن';
    $et['fa']['Exec'] = 'اجرا';
    $et['fa']['Apply'] = 'استفاده';
    $et['fa']['StickyBit'] = 'Sticky Bit';
    $et['fa']['Pass'] = 'رمز';
    $et['fa']['Lang'] = 'زبان';
    $et['fa']['File'] = 'فایل';
    $et['fa']['File_s'] = 'فایل(ها)';
    $et['fa']['Dir_s'] = 'فولدر(ها)';
    $et['fa']['To'] = 'به';
    $et['fa']['Destination'] = 'مقصد';
    $et['fa']['Configurations'] = 'تنظیمات';
    $et['fa']['JSError'] = 'خطای JS';
    $et['fa']['NoSel'] = 'هیچ آیتمی انتخاب نشده';
    $et['fa']['SelDir'] = 'فولدر مقصد را از لیست سمت چپ انتخاب کنید';
    $et['fa']['TypeDir'] = 'نام فولدر را وارد کنید';
    $et['fa']['TypeArq'] = 'نام فایل را وارد کنید';
    $et['fa']['TypeCmd'] = 'فرمان را وارد کنید';
    $et['fa']['TypeArqComp'] = 'نام فایل را وارد کنید.\\nپسوند از نوع فشرده تعیین خواهد شد.\\nمثال:\\nnome.zip\\nnome.tar\\nnome.bzip\\nnome.gzip';
    $et['fa']['RemSel'] = 'آیتم ها انتخاب شده پاک خواهند شد';
    $et['fa']['NoDestDir'] = 'فولدر مقصد انتخاب نشده';
    $et['fa']['DestEqOrig'] = 'فولدر مبدا و مقصد یکسان است';
    $et['fa']['InvalidDest'] = 'فولدر مقصد اشتباه است';
    $et['fa']['NoNewPerm'] = 'دسترسی جدید اعمال نشده';
    $et['fa']['CopyTo'] = 'کپی به';
    $et['fa']['MoveTo'] = 'انتقال به';
    $et['fa']['AlterPermTo'] = 'نغییر دسترسی به';
    $et['fa']['ConfExec'] = 'تایید برای اجرا';
    $et['fa']['ConfRem'] = 'تایید برای پاک کردن';
    $et['fa']['EmptyDir'] = 'فولدر خالی';
    $et['fa']['IOError'] = 'خطای I/O';
    $et['fa']['FileMan'] = 'مدیریت فایل پی اچ پی';
    $et['fa']['InvPass'] = 'رمز اشتباه';
    $et['fa']['ReadDenied'] = 'عدم دسترسی خواند';
    $et['fa']['FileNotFound'] = 'فایل پیدا نشد';
    $et['fa']['AutoClose'] = 'بستن در صورت تکمیل شدن';
    $et['fa']['OutDocRoot'] = 'فایل خارج از DOCUMENT_ROOT';
    $et['fa']['NoCmd'] = 'خطا: فرمان شناخته نشد';
    $et['fa']['ConfTrySave'] = 'فایل بدون دسترسی نوشتن.\\nتلاش برای ذخیره';
    $et['fa']['ConfSaved'] = 'تنظیمات ذخیره شدند';
    $et['fa']['PassSaved'] = 'رمز ذخیره شد';
    $et['fa']['FileDirExists'] = 'فایل یا فولدر موجود است';
    $et['fa']['NoPhpinfo'] = 'تابع phpinfo غیر فعال است';
    $et['fa']['NoReturn'] = 'بدون بازگشت';
    $et['fa']['FileSent'] = 'فایل ارسال شد';
    $et['fa']['SpaceLimReached'] = 'به محدودیت فضا رسید';
    $et['fa']['InvExt'] = 'پسمند اشتباه';
    $et['fa']['FileNoOverw'] = 'فایل امکان دوباره نویسی ندارد';
    $et['fa']['FileOverw'] = 'فایل دوباره نویسی شد';
    $et['fa']['FileIgnored'] = 'فایل رد شد';
    $et['fa']['ChkVer'] = 'بررسی نسخه جدید';
    $et['fa']['ChkVerAvailable'] = 'نسخه جدید, برای دانلود اینجا کلیک کنید!!';
    $et['fa']['ChkVerNotAvailable'] = 'نسخه جدید موجود نمی باشد. :(';
    $et['fa']['ChkVerError'] = 'خطا در اتصال.';
    $et['fa']['Website'] = 'وبسایت';
    $et['fa']['SendingForm'] = 'در حال ارسال فایل ها, لطفا منتظر باشید';
    $et['fa']['NoFileSel'] = 'هیچ فایلی انتخاب نشده';
    $et['fa']['SelAll'] = 'همه';
    $et['fa']['SelNone'] = 'هیچکدام';
    $et['fa']['SelInverse'] = 'معکوس';
    $et['fa']['Selected_s'] = 'انتخاب شده اند';
    $et['fa']['Total'] = 'مجموع';
    $et['fa']['Partition'] = 'پارتیشن';
    $et['fa']['RenderTime'] = 'زمان برای تحویل این صفحه';
    $et['fa']['Seconds'] = 'ثانیه';
    $et['fa']['ErrorReport'] = 'خطرا در گزارش';
    $et['fa']['Close'] = 'بستن';
    $et['fa']['SetPass'] = 'تعیین پسورد';
    $et['fa']['ChangePass'] = 'تغییر پسورد';
    $et['fa']['Portscan'] = 'Portscan';
    $et['fa']['PHPOpenBasedir'] = 'PHP Open Basedir';
    $et['fa']['PHPOpenBasedirFullAccess'] = '(ثابت نشده) دسترسی کامل';
    $et['fa']['About'] = 'درباره';
    $et['fa']['FileSaved'] = 'فایل ذخیره شد';
    $et['fa']['FileSaveError'] = 'خطا در ذخیره فایل';

    // Serbian - by Miroljub Sunajko
    $et['sr']['Version'] = 'Verzija';
    $et['sr']['DocRoot'] = 'Koren dokumenta';
    $et['sr']['FMRoot'] = 'Koren menadžera datoteka';
    $et['sr']['DateFormat'] = 'Foramt datuma';
    $et['sr']['GetSize'] = 'dobivanje veličine';
    $et['sr']['Error'] = 'Greška';
    $et['sr']['Name'] = 'Ime';
    $et['sr']['And'] = 'i';
    $et['sr']['srter'] = 'srter';
    $et['sr']['Ssrd'] = 'Ssrd';
    $et['sr']['Refresh'] = 'Osveži';
    $et['sr']['SaveConfig'] = 'Sačuvaj konfiguraciju';
    //$et['sr']['SavePass'] = 'Save Password';
    //$et['sr']['TypePass'] = 'srter the password';
    $et['sr']['SaveFile'] = 'Sačuvaj datoteku';
    $et['sr']['Save'] = 'Sačuvaj';
    $et['sr']['Leave'] = 'Napusti';
    $et['sr']['Edit'] = 'Urediti';
    $et['sr']['View'] = 'Pogledati';
    $et['sr']['Config'] = 'Konfig';
    $et['sr']['Ren'] = 'Preimenovati';
    $et['sr']['Rsr'] = 'Rsrame';
    $et['sr']['Rem'] = 'Izbriši';
    $et['sr']['Compress'] = 'Komprimiraj';
    $et['sr']['Decompress'] = 'Dekomprimiraj';
    $et['sr']['ResolveIDs'] = 'Rešavanje IDs';
    $et['sr']['Move'] = 'Premesti';
    $et['sr']['Copy'] = 'Kopiraj';
    $et['sr']['ServerInfo'] = 'Podaci o serveru';
    $et['sr']['CreateDir'] = 'Kreiraj direktorijum';
    $et['sr']['CreateArq'] = 'Kreiraj datoteku';
    $et['sr']['Symlink'] = 'Symlink';
    $et['sr']['HardLink'] = 'Hard veza';
    $et['sr']['ExecCmd'] = 'Izvrši naredbu';
    $et['sr']['Upload'] = 'Prenos';
    $et['sr']['Uploadsrd'] = 'Prenos je završen';
    $et['sr']['Perm'] = 'Perm';
    $et['sr']['Perms'] = 'Dozvole';
    $et['sr']['Owner'] = 'Vlasnik';
    $et['sr']['Group'] = 'Grupa';
    $et['sr']['Other'] = 'Ostalo';
    $et['sr']['Size'] = 'Veličina';
    $et['sr']['Date'] = 'Datum';
    $et['sr']['Type'] = 'Vrsta';
    $et['sr']['Free'] = 'besplatno';
    $et['sr']['Shell'] = 'Školjka';
    $et['sr']['Read'] = 'Pročitaj';
    $et['sr']['Write'] = 'Piši';
    $et['sr']['Exec'] = 'Izvrši';
    $et['sr']['Apply'] = 'Primeni';
    $et['sr']['StickyBit'] = 'Lepljiv Bit';
    $et['sr']['Pass'] = 'Lozinka';
    $et['sr']['Lang'] = 'Jezik';
    $et['sr']['File'] = 'Datoteka';
    $et['sr']['File_s'] = 'datoteka(s)';
    $et['sr']['Dir_s'] = 'direktorij(s)';
    $et['sr']['To'] = 'do';
    $et['sr']['Destination'] = 'Odredište';
    $et['sr']['Configurations'] = 'Konfiguracija';
    $et['sr']['JSError'] = 'JavaScript greškar';
    $et['sr']['NoSel'] = 'Nema odabranih stavki';
    $et['sr']['SelDir'] = 'Odaberite odredišni direktorijum na levom stablu';
    $et['sr']['TypeDir'] = 'ime direktorija';
    $et['sr']['TypeArq'] = 'ime datoteke';
    $et['sr']['TypeCmd'] = 'naredba';
    $et['sr']['TypeArqComp'] = 'srter the file name.\\nThe extsrsion će definisati tip kompresije.\\nEx:\\nnome.zip\\nnome.tar\\nnome.bzip\\nnome.gzip';
    $et['sr']['RemSel'] = 'IZBRIŠI izabrane stavke';
    $et['sr']['NoDestDir'] = 'Nema izabranog odredišnog direktorijuma';
    $et['sr']['DestEqOrig'] = 'Izvorni i odredišni direktorijumi su jednaki';
    $et['sr']['InvalidDest'] = 'Direktorijum odredišta nije vašeći';
    $et['sr']['NoNewPerm'] = 'Nova dozvola nije postavljena';
    $et['sr']['CopyTo'] = 'Kopiraj u';
    $et['sr']['MoveTo'] = 'Premesti u';
    $et['sr']['AlterPermTo'] = 'PROMENI DOZVOLE u';
    $et['sr']['ConfExec'] = 'Potvrdi IZVRŠENJE';
    $et['sr']['ConfRem'] = 'Potvrdi BRISANJE';
    $et['sr']['EmptyDir'] = 'Prazan direktorijum';
    $et['sr']['IOError'] = 'I/O greška';
    $et['sr']['FileMan'] = 'Menadžer datoteka';
    $et['sr']['InvPass'] = 'Nevažeća lozinka';
    $et['sr']['ReadDsried'] = 'Pristup čitanju nije moguć';
    $et['sr']['FilsrotFound'] = 'Datoteka nije pronadjena';
    $et['sr']['AutoClose'] = 'Zatvori završeno';
    $et['sr']['OutDocRoot'] = 'Datoteka izvan DOCUMsrT_ROOT';
    $et['sr']['NoCmd'] = 'Greška: Naredba nije  informed';
    $et['sr']['ConfTrySave'] = 'Datoteka bez dozvole za pisanje.\\pokušajte ipak da je sačuvate';
    $et['sr']['ConfSaved'] = 'Konfiguracije su sačuvane';
    $et['sr']['PassSaved'] = 'Lozinka je sačuvana';
    $et['sr']['FileDirExists'] = 'Datoteka ili direktorijum već postoje';
    $et['sr']['NoPhpinfo'] = 'Funkcija phpinfo je onemogućena';
    $et['sr']['NoReturn'] = 'nema povratka';
    $et['sr']['FileSsrt'] = 'Datoteka ssrt';
    $et['sr']['SpaceLimReached'] = 'Dostignuta ograničenja prostora';
    $et['sr']['InvExt'] = 'Nevažeća extsrsion';
    $et['sr']['FilsroOverw'] = 'Datoteka se nemože prepisati';
    $et['sr']['FileOverw'] = 'Datoteka prepisana';
    $et['sr']['FileIgnored'] = 'Datoteka je ignorisana';
    $et['sr']['ChkVer'] = 'Proveri novu verziju';
    $et['sr']['ChkVerAvailable'] = 'Nova verzija, kliknite ovde da započnete preuzimanje!!';
    $et['sr']['ChkVerNotAvailable'] = 'Nova verzija nije dostupna. :(';
    $et['sr']['ChkVerError'] = 'Greška u povezivanju.';
    $et['sr']['Website'] = 'Veb lokacija';
    $et['sr']['SsrdingForm'] = 'Ssrding datoteke , molim pričekajte';
    $et['sr']['NoFileSel'] = 'Nije odabrana datoteka';
    $et['sr']['SelAll'] = 'Sve';
    $et['sr']['SelNone'] = 'Nema';
    $et['sr']['SelInverse'] = 'Inverzno';
    $et['sr']['Selected_s'] = 'izabrano';
    $et['sr']['Total'] = 'ukupno';
    $et['sr']['Partition'] = 'Particija';
    $et['sr']['RsrderTime'] = 'Vreme da se ova stranica izvrši';
    $et['sr']['Seconds'] = 'sec';
    $et['sr']['ErrorReport'] = 'Izveštaj o greškama';
    $et['sr']['Close'] = 'Zatvori';
    $et['sr']['SetPass'] = 'Postavi Lozinku';
    $et['sr']['ChangePass'] = 'Promeni Lozinku';
    $et['sr']['Portscan'] = 'Portscan';
    $et['sr']['PHPOpsrBasedir'] = 'PHP Opsr Basedir';
    $et['sr']['PHPOpsrBasedirFullAccess'] = '(ukida) Puni pristup';
    $et['sr']['About'] = 'O meni';
    $et['sr']['FileSaved'] = 'Datoteka je sačuvana';
    $et['sr']['FileSaveError'] = 'Greška prilikom čuvanja datoteke';

    if (!strlen($lang)) $lang = $sys_lang;
    if (isset($et[$lang][$tag])) return html_encode($et[$lang][$tag]);
    else if (isset($et['en'][$tag])) return html_encode($et['en'][$tag]);
    else return "$tag"; // So we can know what is missing
}
// +--------------------------------------------------
// | BASE64 FILES
// | So that PHP File Manager can remain a single file script,
// | and still work normally on offline enviroments
// +--------------------------------------------------
if(!function_exists('apache_request_headers')){
    function apache_request_headers(){
        $arh = array();
        $rx_http = '/\AHTTP_/';
        foreach($SERVER as $key => $val) {
            if( preg_match($rx_http, $key) ) {
                $arh_key = preg_replace($rx_http, '', $key);
                $rx_matches = array();
                // do some nasty string manipulations to restore the original letter case
                // this should work in most cases
                $rx_matches = explode('', $arh_key);
                if( count($rx_matches) > 0 and strlen($arh_key) > 2 ) {
                    foreach($rx_matches as $ak_key => $ak_val) {
                        $rx_matches[$ak_key] = ucfirst($ak_val);
                    }
                    $arh_key = implode('-', $rx_matches);
                }
                $arh[$arh_key] = $val;
            }
        }
        return $arh;
    }
}
function get_base64_file(){
    global $filename,$fm_path_info;
    // +--------------------------------------------------
    // | TOTAL: 25 files = 1.85 Mb = 543.8 Kb compressed
    // +--------------------------------------------------
    $base64_files = array();
    $base64_files['32px.png'] = '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';
    $base64_files['ace.js'] = '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';
    $base64_files['ext-searchbox.js'] = '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';
    $base64_files['ext-whitespace.js'] = 'eJydVm1v2zYQ/rz9CkVIDbKiaXvrh04yYwRbPxRoh2FptwGyOjASZWuTKI+knGS2/vuOerNjO/0wAZbk4/Fenrt7qESkmRTI5bGYiEczeVhnRugN/HVJ6CrxT5UpeHXF46ZURsNbUSZVbkV2S57dT3IuV25E0krGJislEsQQiXdupYWjjcpi4wZbrhzFwA+lhz04MPQ6EUbE5r1MhDTc7mfHhvCu/+fESOCdtWPYNEhLhTqbgZpLmgu5MutAeUxg4zEZqmi/nwZKmEpJx9RWV7IwIsreMjYlGn4l+8jNmhYZ+OpMkJn4Hg/mK3BVzcug8rzWN2cirKIgS9HV5MtSvw6/vPaW46WOJhRgM4hjHJfSZLISVomH04gx9xsXZ54HLsc/V8W9UPTj7R9//nb74fO7QORaNJZTxmnBTbxGky/O6wmGnX1WYCgdjXiYRleNrUY/Z+lYB/nNdDS6QvpVju0zbZ5IhXnEmjuAgL0ZJhI2M2TvraTWLK2h1rlAkJ81zjtv45mNeLl0cZOr50UNeGumqBJJFQv0vD4dxMIzNZlismE7HZdK+FPS2vOnNUmOKlaxGUA6++6A6ZbFqMJBxdhsgRK2JVuo3yxa0B98+pb0td3v0ZZNMfa3E5YQBVWARLces2+TNSbbmw1tPIN4CGLbB1HVuAYYB5Xu5WZG32AbQ8E2R2hnNwmAtoO3AoLa75N5Nnmz33eb5jP6Fhesgpa1s5N0XbaL1z5Up/dY1NZhcpOBpSMF51iBGPq19m/hkUzQlTAfwJVG06Y/oYsvTQ6SeL/f1X3XKxqvRyNBtTCftbgrU/OJ32tkxVBhxwUzXc6dFizfZf8K1ItBwYYII1x8UjzLM7m6s8xwMqFHQf5UxlUB4SAborSS2zxvI8cwdWY0as29KzbmaTGe+XYOYSBLNp4FzerfQmx+rJQu1S+lzqwTqKeNLheNS6qAOcSPZSXN4kz8IdOmfdMU+u0dh2k6paWWNWRovFkzx2o0AkQaj1SVDwwSOfzrKhdouqn0GvVLuMb+IDrEAOm2oSOMIaUpDtqG12EJzWrv1uYwCRwYKGU92AGfpwHvZyKHvuYRiVkO9rmyrLDU3vUEB5yxCiCJ5429uMyrAiCKbzIrZEdCCAE4p/W+6J37YyCDRhkgE0W5Fe+lrQ/iJCZ5X/emM4HHtkK9yMw9lllbeds7UFm5Qpa5oKqD1HYUDiTMr2QaEwMvhmUtNiUzDT0ujK+obvb/KjaCG2TtQ/CCJmVMOKtOeillu5rkcBvQjAHNNetZLIjn8OvR3DAexhHQ0GagWODuhmNtCyQ9Dwl6DW7aPO5iJYT8PUvMGhRsTkV7WqR5aV1OIJcV277S5ImlYQG8iuyDneRRkgLj4MljebiyOvZxqmNJYQUt83TFEqhi9bwyMZmSZJjIimZSN2VpFne2pjFpK26p9glD9Z5NM+B4xgGmJQBb5usNV7DSxHOrVmf0YyzIE9OdbwIvjOUPqJk/0YMQom7FYDTo+aCDepl40LYdJ8lGs02GNZ7fA1tIC+8MyJ2YQ0inwfQHzcI8bUSZOgJyaGGE9jlNAzb4vR4E+Wi+rtyoYF/4u671i4LLBKhpJ3khfPeMal0iHkXsH8d3gcsbdtAa3uxIdbbO6PTMlh2tC7R7sEaO7Z3P6UWDLe8dgQuNEVya8iM39qgYDokjl9BN/8vd8/Om8fHCuTMcXYPS5SOsrqMaB87JdSB97Oy+PV2110Mmk/KBdt+3KLz0/RsRZ7BTvGTIXlnqoK7Z2o9jhzHHLe//gm5wndHI6Tux/YY+XW33fM2BvVotOthwiuBF/friCgB1Jq8xOpH+ByID/V0=';
    $base64_files['favicon.ico'] = 'eJytWOlWVMcW7pt1H8BH8FdWHiOPklwnHFBAkEkkTDLPoAgJCCozyDzPoIQZgszdNCqYGBAQVBTR7+6v6NM5HE5Ds0yttdfpU6d2fbXnXW2x/MfyneXUKYs8T1s8/muxfG+xWE6f3n8vlvkkmftB5k5x3rI/72pARnZ2Ns6fP38iqqmpISu+fv2KrKwsxMTEYGZm5hDNzs4eosjISFRXVx/gDwoKQmpqKjY2NvBh6y2mhofxl9WKqYEBxIX9AtvcnFpLSk5ORlVVlfPdbrdjb3cXLZWVSA8Owv3ICGQGBuBOUCCybgbj98oK5IaHoTn/Psry8hAaGqrOpvF//vQJSwO/oyg3F11yriflZbD2dKOvtASznR34Tc43Ls/6X3PQW1QI+9Agvnz54uRftVmxIN+by0oRHRGBtKQkFMhepXm5KBfM+Ph4JMbGICUxAf31dWrt+vJLJ/+afVHNjbe14U5qCobbWhEfF4e0xER0yHkS5VkgNuqurUFuZqaDf9nJv/7mDUozMzAlfA9zcvBQ1o60tiBYdMr3topyFNy7h0fye6ylGUuiW/35c2Q+9NYtRAYGoqkgH5NNjajKSEf1wweoz8lG2g0/lMjZ53t7MDcygqLCQjQ1NTn5ab+ysjKsra0hU853w/c62hsbEXXzJhoEe2v1bzTI2QMCAhAncgUHBx+yP/m1948fP6rnzs6Oeg4ODqK4uFit45P7kN+IT5k+f/6M9fV17O3tOfe7du0azpw546TLly/DKr5l5B8fH0d3dzfmxNd4Bo3/6tWrOHv2rCLyzs/PH9Cfxj82Nobp6Wk1pw09vxmvxk8b2Gw2U7py5YpLXtJx8evp6emS12VicHP84MgxP7qRZzioo4sXLyq6dOnSv/LUkzZHmXclJ+jtwDEi/ktbaL6g2VVPruaPIz3fhQsXnPh6fevx6cv043+TUlJSDuAb7U187Zy1tbUqToxrvoVaW1vV/u7g8xkbG4vV1VW39v4keTpX8mp+fr7p3qSWlhZTfM0Ow5L7iM19IiRX8zfjq6+vD3uSO7bfrOG15PPemmrckZox0lCPmc52DEv+SpV64v+/n+Hz809IFt61P/80xeee586dU+fVD34fHR1Fo+RG/qbuqS8fwQ+66IH8mGgMPa5Ewe0oxF31VJR83Qd1WXeRIjmV78UJ8WjJ/Q0JXteQ5O2Fp5JfXz6bxLbUTWJ7eXkpfOYcvf9r+MyP2lk/vN3Ey4lxzHR3oVDyu4ZJuhdyU2Fp78RrFlz70yd4PjiAoeoqZAT4I1HO8Dg9DYk+3kovvj4+qK+vx/v37w/kQeM5NlaWsdDdiVmpu35+fugUPfcUPkL2rRAl33xHu6pzHVKP7kpNHxA5+d4n9cvX1xeTYq9nUqfyIsLV+cjXLrV2qr1N9Q+uBrHfvv4L810dar/nw0NKV/niD4tS1+3iH5RxoasTSyPD6p3rFp/0yfchzIzux2+z9D+LwstegL7BNRpNd7Rh11HDjP73RWxu4/6OtTapqXESA9yTuZp+GyX90URvLzIzMhAWFqbO80LOQj8tKSlRuY3+xfXMdanSD8059rSKXNTdy8k/TOODNqdsVkX7Z2Cvwj2XpXZNyz4x0dFKxxUVFfDw8FB6sPX14vbt20hISFAxGy1rno+PYbynB/7+/koGu06uGSGj/Bw7W1sKf/+s+89m6eUo/5SD/0lzk4rhQukzOD/qWEcb0b85z5pO23G+srhIrZvtf/oPvvCY+R9r4NLQwP46x74T0uuRv1381ib2rBNfI35HezvOip5rRQ8L4vP54pdnaPvmZrX+mcxZZX2u1F++TzvOr/QvMWmGr2ywuaHiZ0rkVD4o+r0sttXqNX0gMz0dy2JD2kHLJ/yWIL3ktPik9k5ib1Dy6JH4aK9T97uG3KPH7+/vh7/oMU3iivFllfhfEr+2O+iFkK2vR3rgLqSIb4WHh+PF5ISaH5M47ZQ4tTM2dOu5B+WeFZ3uvNs+ZHdtsLfi2VU/JDkv0s8XBbHRGKs7GEMz0r8OVz1GlfTU7Bepo7b7eSrfMN5LkxIxJ7GurZ+SvPBC9PVRekbKR181y39a/iexr7wlfa+n9Azh0uPWSb++IHIQhz1vvOS8FtHPovhVufTlxGXO+/WXUMTK77tytxhtbMDKzDQ2pQdnLmdvqq8/emwj/pbEAvMxe2nGNue8JRfRNuH+N3BX7gzRco5kyW3RftdRdCcTz/+YwGvrAsqlN/fgem9vPHjwQMUvcZkPjqr/xNfqL/GddwjpmdmHcp4xvrKyonpgztFezAXG/pE1U8Pj/Y+1zVX9dSW/8furV68OzS0tLR3MYR8+4I3om0RM2pF3D743NDS4Vf81/OOGkZ9Y7DGP6v80fNZ/413gpPjGs9Bf3elDo6KinL3dUfic0+5Zm5ubWFxcVPTu3TvTMwTKHfE4bPZV29vbTn85Cp+2ZP1YWFhQd526ujpF9AOzwfg6Ct+IbcTX+m+9/Lyzsa5QbrOaped3Jb+Z3EbfcaV/xn9ISIj67+O4HthMfmLzPxU9Np9m9z0z/SclJbmFbYZ/lNxmOjgq/t0ZRnx3sY3257npZ8zZJyH2HUfJrdf7cf5/0numPr+4I7eZ/MyXxrvySe/jzC3uYmv43/o/w7eO/wOEevxS';
    $base64_files['file_sprite.png'] = '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';
    $base64_files['jquery-1.11.1.min.js'] = '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';
    $base64_files['jquery.terminal.min.css'] = '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';
    $base64_files['jquery.terminal.min.js'] = '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
