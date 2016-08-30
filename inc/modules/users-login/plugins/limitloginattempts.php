<?php
/*
Module Name: Limit Login Attempts
Description: Limit login attempts and ban if too many tries have been done.
Main Module: users_login
Author: SecuPress
Version: 1.0
*/
defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

add_action( 'authenticate', 'secupress_limitloginattempts', PHP_INT_MAX - 20, 2 );
/**
 * Check the number of attemps.
 *
 * @since 1.0
 *
 * @param (null|object) $raw_user WP_User if the user is authenticated.
 *                                WP_Error or null otherwise.
 * @param (string)      $username Username or email address.
 *
 * @return (null|object)
 */
function secupress_limitloginattempts( $raw_user, $username ) {
	if ( empty( $_POST ) || ! is_wp_error( $raw_user ) || false === ( $uid = username_exists( $username ) ) || secupress_ip_is_whitelisted() ) { // WPCS: CSRF ok.
		if ( ! empty( $raw_user->ID ) ) {
			delete_user_meta( $raw_user->ID, '_secupress_limitloginattempts' );
		}

		return $raw_user;
	}

	$max_attempts  = secupress_get_module_option( 'login-protection_number_attempts', 10, 'users-login' );
	$user_attempts = (int) get_user_meta( $uid, '_secupress_limitloginattempts', true );
	++$user_attempts;

	if ( $user_attempts >= $max_attempts ) {
		delete_user_meta( $uid, '_secupress_limitloginattempts' );
		secupress_ban_ip( (int) secupress_get_module_option( 'login-protection_time_ban', 5, 'users-login' ) );
	}

	update_user_meta( $uid, '_secupress_limitloginattempts', $user_attempts );
	$user_attempts_left = $max_attempts - $user_attempts;

	if ( $user_attempts_left <= 3 ) {
		add_filter( 'login_message', function( $message ) use ( $user_attempts_left ) {
			return secupress_limitloginattempts_error_message( $message, $user_attempts_left );
		} );
	}

	return $raw_user;
}


/**
 * Append our error message.
 *
 * @since 1.0
 *
 * @param (string) $message            Previous messages.
 * @param (int)    $user_attempts_left Number of attemps left for this user.
 *
 * @return (string)
 */
function secupress_limitloginattempts_error_message( $message, $user_attempts_left ) {
	return $message . '<p class="message">' . sprintf( _n( 'Login failed, <strong>%d</strong> attempt left.', 'Login failed, <strong>%d</strong> attempts left.', $user_attempts_left, 'secupress' ), $user_attempts_left ) . '</p><br>';
}
