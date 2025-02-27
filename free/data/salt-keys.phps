<?php
/**
 * Plugin Name: {{PLUGIN_NAME}} Salt Keys
 * Description: Great Security Keys for your site
 * Version: 2.2.6
 * License: GPLv2
 * License URI: http://www.gnu.org/licenses/gpl-2.0.html
 *
 * Copyright 2012-2025 SecuPress
 */

defined( 'ABSPATH' ) or die( 'Something went wrong.' );

if ( ! get_site_option( 'secupress_active_submodule_wp-config-constant-saltkeys' ) ) {
	return;
}

define( 'SECUPRESS_SALT_KEYS_MODULE_ACTIVE', true );

$hash_1     = '{{HASH1}}';
$hash_2     = '{{HASH2}}';
$file_str   = __FILE__;
$sp_setup   = get_option( 'secupress_settings' );
$hash_key   = isset( $sp_setup['hash_key'] ) ? $sp_setup['hash_key'] : md5( __FILE__ );
$hash_1    .= $hash_2;
$file_str  .= $hash_2;
$main_keys  = [ 'AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY', 'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT' ];

foreach ( $main_keys as $main_key ) {
	if( ! defined( $main_key ) ) {
		define( $main_key, sha1( 'secupress' . $hash_key . $main_key . md5( $main_key . $file_str ) ) . md5( $hash_key . $main_key . $file_str ) );
	}
}

unset( $file_str, $main_key, $main_keys, $hash_1, $hash_2, $hash_key, $sp_setup );

if ( ! function_exists( 'wp_salt' ) ) {
	function wp_salt( $scheme = 'auth' ) {
		/** This filter is documented in wp-includes/pluggable.php */
		return apply_filters( 'salt', constant( strtoupper( "{$scheme}_KEY" ) ) . constant( strtoupper( "{$scheme}_SALT" ) ), $scheme );
	}
}
