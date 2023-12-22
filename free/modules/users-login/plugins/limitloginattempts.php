<?php
/**
 * Module Name: Limit Login Attempts
 * Description: Limit login attempts and ban if too many tries have been done.
 * Main Module: users_login
 * Author: SecuPress
 * Version: 1.4.12
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );
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
	global $wpdb;
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

	// Adding initial Value
	$wpdb->query(
		$wpdb->prepare(
			"
			INSERT INTO {$wpdb->usermeta} (user_id, meta_key, meta_value)
			SELECT * FROM (SELECT %d, '_secupress_limitloginattempts', 0) as tmp
			WHERE NOT EXISTS (
				SELECT * FROM {$wpdb->usermeta}
				WHERE user_id = %d 
				AND meta_key = '_secupress_limitloginattempts'
			);
		",
		$uid,
		$uid
		)
	);

	// Start transaction
	$wpdb->query("START TRANSACTION");

	// Removed in 2.2.5, TOCTOU flaw
	// $user_attempts = (int) get_user_meta( $uid, '_secupress_limitloginattempts', true );

	// Get the number of attempts (line lock with FOR UPDATE)
	$user_attempts = $wpdb->get_var(
		$wpdb->prepare(
						"
						SELECT meta_value FROM {$wpdb->usermeta}
                        WHERE {$wpdb->usermeta}.meta_key = '_secupress_limitloginattempts'
                        AND {$wpdb->usermeta}.user_id = %d
                        LIMIT 1 FOR UPDATE
						",
						$uid
		)
	);

	++$user_attempts;

	if ( $user_attempts >= $max_attempts ) {
		delete_user_meta( $uid, '_secupress_limitloginattempts' );
		secupress_ban_ip( (int) secupress_get_module_option( 'login-protection_time_ban', 5, 'users-login' ) );
	}

	//  Removed in 2.2.5, TOCTOU flaw
	// update_user_meta( $uid, '_secupress_limitloginattempts', $user_attempts );

	// Update number of attempts
	$wpdb->query(
		$wpdb->prepare(
			"UPDATE {$wpdb->usermeta} SET meta_value = %d WHERE user_id = %d and meta_key = '_secupress_limitloginattempts'",
			$user_attempts,
			$uid
		)
	);
	
	// End transaction with a COMMIT command
	$wpdb->query("COMMIT");


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
