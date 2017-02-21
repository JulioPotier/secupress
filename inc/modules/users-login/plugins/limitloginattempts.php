<?php
/**
 * Module Name: Limit Login Attempts
 * Description: Limit login attempts and ban if too many tries have been done.
 * Main Module: users_login
 * Author: SecuPress
 * Version: 1.1
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

add_action( 'authenticate', 'secupress_limitloginattempts', SECUPRESS_INT_MAX, 2 );
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
	static $done = false;

	if ( $done ) {
		return $raw_user;
	}
	$done = true;

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
		secupress_cache_data( 'limitloginattempts_user_attempts_left', $user_attempts_left );
		add_filter( 'login_message', 'secupress_limitloginattempts_error_message' );
	}

	return $raw_user;
}


/**
 * Append our error message.
 *
 * @since 1.0
 * @since 1.1 The 2nd argument, `$user_attempts_left`, has been removed. Its value is retrieved with `secupress_cache_data()` instead.
 *
 * @param (string) $message Previous messages.
 *
 * @return (string)
 */
function secupress_limitloginattempts_error_message( $message ) {
	$user_attempts_left = secupress_cache_data( 'limitloginattempts_user_attempts_left' );

	if ( ! isset( $user_attempts_left ) ) {
		return $message;
	}

	return $message . '<p class="message">' . sprintf( _n( 'Login failed, <strong>%d</strong> attempt left.', 'Login failed, <strong>%d</strong> attempts left.', $user_attempts_left, 'secupress' ), $user_attempts_left ) . '</p><br>';
}
