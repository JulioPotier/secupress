<?php
/**
 * Template Name: SecuPress 404 Handler
 * Description: Trigger the 404 template with "Bad Url Access" module
 * Version: 2.2.6
 * License: GPLv2
 * License URI: http://www.gnu.org/licenses/gpl-2.0.html
 *
 * Copyright 2012-2025 SecuPress
 */
while ( ! is_file( 'wp-load.php' ) ) {
	if ( is_dir( '..' ) && getcwd() != '/' ) {
		chdir( '..' );
	} else {
		header( $_SERVER['SERVER_PROTOCOL'] . ' 404 Not Found', true, 404 );
		if ( false === http_response_code( 404 ) ) {
			echo '<h1>Not Found</h1>'; // DO NOT TRANSLATE
			echo '<p>The requested URL was not found on this server.</p>'; // DO NOT TRANSLATE
		}
		die();
	}
}
require_once( 'wp-load.php' );
if ( function_exists( '_wp_admin_bar_init' ) ) {
	_wp_admin_bar_init();
}
global $wp_query;
$wp_query->set_404();	
status_header( 404 );
if ( ! defined( 'DONOTCACHEPAGE' ) ) {
	define( 'DONOTCACHEPAGE', true );
}
if ( ! defined( 'DONOTCACHEOBJECT' ) ) {
	define( 'DONOTCACHEOBJECT', true );
}
if ( ! defined( 'DONOTCACHEDB' ) ) {
	define( 'DONOTCACHEDB', true );
}
if ( false === get_template_part( '404' ) ) {
	if ( false === http_response_code( 404 ) ) {
		echo '<h1>Not Found</h1>'; // DO NOT TRANSLATE
		echo '<p>The requested URL was not found on this server.</p>'; // DO NOT TRANSLATE
	}
}
exit;