<?php
/*
Module Name: Ban log in attempts on Non-Existing Users
Description: If someone tries to log in using a username that doesn'y exists on your website, he will be banned for x minutes.
Main Module: users_login
Author: SecuPress
Version: 1.0
*/
defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

add_action( 'authenticate', 'secupress_bannonexistsuser_auth', PHP_INT_MAX - 10, 2 );
/**
 * Ban users who try to log in with a non existing username.
 *
 * @since 1.0
 *
 * @param (null|object) $raw_user WP_User if the user is authenticated.
 *                                WP_Error or null otherwise.
 * @param (string)      $username Username or email address.
 *
 * @return (null|object)
 */
function secupress_bannonexistsuser_auth( $raw_user, $username ) {
	if ( ! empty( $_POST ) && is_wp_error( $raw_user ) && ! username_exists( $username ) && ! secupress_ip_is_whitelisted() ) { // WPCS: CSRF ok. //// @since 4.5.0 `$username` now accepts an email address.
		secupress_ban_ip( (int) secupress_get_module_option( 'login-protection_time_ban', 5, 'users-login' ) );
	}
	return $raw_user;
}
