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

function secupress_bannonexistsuser_auth( $raw_user, $username ) {
	if ( ! empty( $_POST ) && is_wp_error( $raw_user ) && ! username_exists( $username ) && ! secupress_ip_is_whitelisted() ) {
		secupress_ban_ip( (int) secupress_get_module_option( 'login-protection_time_ban', 5, 'users-login' ) );
	}
	return $raw_user;
}
