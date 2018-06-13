<?php
/**
 * Module Name: Move Login
 * Description: Change your login URL.
 * Main Module: users_login
 * Author: SecuPress
 * Version: 1.3.1
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

/** --------------------------------------------------------------------------------------------- */
/** INCLUDES ==================================================================================== */
/** --------------------------------------------------------------------------------------------- */

// Priorize other "move login" like plugins.
if ( ! function_exists( 'is_plugin_active' ) ) {
	require( ABSPATH . 'wp-admin/includes/plugin.php' );
}
if ( function_exists( 'is_plugin_active' ) && (
	is_plugin_active( 'sf-move-login/sf-move-login.php' ) ||
	is_plugin_active( 'wps-hide-login/wps-hide-login.php' )
	) ) {
	return;
}

if ( is_admin() && ! function_exists( 'secupress_move_login_write_rules' ) ) {
	include( SECUPRESS_MODULES_PATH . 'users-login/plugins/inc/php/move-login/admin.php' );
}

// EMERGENCY BYPASS!
if ( ! defined( 'SECUPRESS_ALLOW_LOGIN_ACCESS' ) || ! SECUPRESS_ALLOW_LOGIN_ACCESS ) {
	include( SECUPRESS_MODULES_PATH . 'users-login/plugins/inc/php/move-login/deprecated.php' );
	include( SECUPRESS_MODULES_PATH . 'users-login/plugins/inc/php/move-login/url-filters.php' );
	include( SECUPRESS_MODULES_PATH . 'users-login/plugins/inc/php/move-login/redirections-and-dies.php' );
}


/** --------------------------------------------------------------------------------------------- */
/** TOOLS ======================================================================================= */
/** --------------------------------------------------------------------------------------------- */

/**
 * Get default slugs.
 *
 * @since 1.0
 * @author Grégory Viguier
 *
 * @return (array)
 */
function secupress_move_login_get_default_slugs() {
	$slugs = array(
		// custom.
		'login'     => 1,
		'register'  => 1,
		// hardcoded.
		'postpass'               => 1,
		'passwordless_autologin' => 1,
		'confirmaction'          => 1,
	);

	return $slugs;
}

/**
 * Get the slugs the user has set.
 *
 * @since 1.0
 * @author Grégory Viguier
 *
 * @return (array)
 */
function secupress_move_login_get_slugs() {
	$slugs = secupress_move_login_get_default_slugs();

	foreach ( $slugs as $action => $dummy ) {
		$slugs[ $action ] = secupress_get_module_option( 'move-login_slug-' . $action, $action, 'users-login' );
		$slugs[ $action ] = sanitize_title( $slugs[ $action ], $action, 'display' );
	}
	$slugs['postpass']                = 'postpass';
	$slugs['passwordless_autologin']  = 'passwordless_autologin';
	$slugs['confirmaction']           = 'confirmaction';

	return $slugs;
}
