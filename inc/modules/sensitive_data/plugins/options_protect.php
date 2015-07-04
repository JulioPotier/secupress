<?php
/*
Module Name: Secupress Settings Pages Protect
Description: Ask the user's password to enter in the secupress settings pages
Main Module: sensitive_data
Author: SecuPress
Version: 1.0
*/
defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

add_action( 'admin_init', 'secupress_shortcut_settings_hooks' );
function secupress_shortcut_settings_hooks() {
	$hooks = array( 'secupress_page' => array( 'secupress', 'secupress_settings', 'secupress_modules', 'secupress_scanner' ) );
	foreach ( $hooks as $page => $subs ) {
		foreach ( $subs as $sub ) {
			add_action( "load-{$page}_{$sub}", 'secupress_shortcut_settings', 0 );
		}
	}
	add_action( 'current_screen', function( $current_screen ) use ( $hooks ) {
		global $pagenow;
		if ( 'options.php' == $pagenow && 'POST' == $_SERVER['REQUEST_METHOD'] && ! empty( $_POST ) && isset( $_POST['_wp_http_referer'], $_POST['option_page'] ) ) {
			parse_str( parse_url( $_POST['_wp_http_referer'], PHP_URL_QUERY ), $query );
			if ( isset( $query['page'] ) && in_array_deep( $query['page'], $hooks ) &&
				false === get_site_transient( 'secupress_check_password_' . get_current_user_id() ) ) {
				wp_safe_redirect( wp_get_referer() );
				die();
			}
		} 
	} );
}