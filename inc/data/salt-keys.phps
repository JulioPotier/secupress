<?php
/*
Plugin Name: SecuPress Salt Keys
Description: Good Security Keys for each of your blogs of your network (multisite only), auto-reseting each month.
Author: SecuPress
Author URI: http://SecuPress.me
Version: 1.0
*/
defined( 'ABSPATH' ) or die( 'Cheatin\' uh?' ); 

define( 'SECUPRESS_SALT_KEYS_ACTIVE', true );
global $blog_id;

$hash_1     = '{{HASH1}}';
$hash_2     = '{{HASH2}}';
$file_str   = __FILE__ . date( 'Ym' ) . $blog_id . home_url();
$hash_1    .= $hash_2;
$file_str  .= $hash_2;
$main_keys  = array( 'AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY', 'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT', );

foreach ( $main_keys as $main_key ) {
	if( ! defined( $main_key ) ) {
		define( $main_key, sha1( 'secupress' . $main_key . md5( $main_key . $file_str ) ) . md5( $main_key . $file_str ) );
	}
}

unset( $file_str, $main_key, $main_keys, $hash_1, $hash_2 );