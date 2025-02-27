<?php
/**
 * Module Name: Limit Login Attempts
 * Description: Limit login attempts and ban if too many tries have been done.
 * Main Module: users_login
 * Author: SecuPress
 * Version: 2.2.6
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );

/**
 * Check if we have to ban the IP and redirect
 *
 * @since 2.2.6
 * @author Julio Potier
 * 
 * @param (int)  $user_id 
 * @param (bool) $redirect
 * 
 * @return (int) $user_attempts
 */
function secupress_limitloginattempts_check_max_and_die( $user_id, $redirect = true ) {
	$user_attempts = (int) get_user_meta( $user_id, '_secupress_limitloginattempts', true );
	$max_attempts  = secupress_get_module_option( 'login-protection_number_attempts', 10, 'users-login' );
	if ( $user_attempts >= $max_attempts ) {
		/**
		 * Let anyone do what they need before our die
		 * /!\ This function in not used by us, use it when you need!!
		 * 
		 * @since 2.2.6
		 * @author Julio Potier
		 * 
		 * @param (int) $user_id
		 */ 
		do_action( 'secupress.plugin.limitloginattempts.check', $user_id );

		secupress_ban_ip( (int) secupress_get_module_option( 'login-protection_time_ban', 5, 'users-login' ) );
		if ( $redirect ) {
			wp_safe_redirect( secupress_get_current_url() );
			die();
		}
	}
	return $user_attempts;
}

/**
 * Add 1 login attempt to a user
 *
 * @since 2.2.6
 * @author Julio Potier
 * 
 * @param (int)      $user_id 
 * 
 * @return (int) $user_attempts
 */
function secupress_limitloginattempts_add_one_try( $user_id ) {
	global $wpdb;

	$max_attempts = secupress_get_module_option( 'login-protection_number_attempts', 10, 'users-login' );
	$ban_time     = (int) secupress_get_module_option( 'login-protection_time_ban', 5, 'users-login' );

	// Start transaction
	$wpdb->query("START TRANSACTION");

	// Get the number of attempts (line lock with FOR UPDATE)
	$user_attempts = $wpdb->get_var(
		$wpdb->prepare(
			"SELECT meta_value FROM {$wpdb->usermeta} WHERE meta_key = '_secupress_limitloginattempts' AND user_id = %d LIMIT 1 FOR UPDATE",
			$user_id
		)
	);

	// If the user_attempts is null, it means the user has not attempted to login before, so we initialize it to 0
	if ( is_null( $user_attempts ) ) {
		$user_attempts = 0;
		$wpdb->insert(
			$wpdb->usermeta,
			array(
				'user_id'    => $user_id,
				'meta_key'   => '_secupress_limitloginattempts',
				'meta_value' => $user_attempts,
			)
		);
	}

	++$user_attempts;

	if ( $user_attempts >= $max_attempts ) {
		$wpdb->query( $wpdb->prepare( "DELETE FROM $wpdb->usermeta WHERE user_id = %d AND meta_key = '_secupress_passwordspraying'", $user_id ) );
		secupress_ban_ip( $ban_time );
	}

	// Update number of attempts
	$wpdb->update(
		$wpdb->usermeta,
		array(
			'meta_value' => $user_attempts,
		),
		array(
			'user_id'  => $user_id,
			'meta_key' => '_secupress_limitloginattempts',
		)
	);

	// End transaction with a COMMIT command
	$wpdb->query("COMMIT");

	return $user_attempts;
}

add_action( 'authenticate', 'secupress_limitloginattempts', SECUPRESS_INT_MAX, 2 );
/**
 * 
 *
 * @since 2.2.6 Refactoring
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
	$done        = true;

	if ( empty( $_POST ) || ! is_wp_error( $raw_user ) || false === ( $uid = username_exists( $username ) ) || secupress_ip_is_whitelisted() ) { // WPCS: CSRF ok.
		if ( ! empty( $raw_user->ID ) ) {
			delete_user_meta( $raw_user->ID, '_secupress_limitloginattempts' );
		}

		return $raw_user;
	}

	$max_attempts       = secupress_get_module_option( 'login-protection_number_attempts', 10, 'users-login' );
	$ban_time           = (int) secupress_get_module_option( 'login-protection_time_ban', 5, 'users-login' );
	$user_attempts      = secupress_limitloginattempts_add_one_try( $uid );
	$user_attempts_left = $max_attempts - $user_attempts;

	if ( $user_attempts >= $max_attempts ) {
		secupress_ban_ip( (int) secupress_get_module_option( 'login-protection_time_ban', 5, 'users-login' ) );
		wp_safe_redirect( secupress_get_current_url() );
		die();
	}

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
 * @return (string) html message
 */
function secupress_limitloginattempts_error_message( $message ) {
	$user_attempts_left = secupress_cache_data( 'limitloginattempts_user_attempts_left' );

	if ( ! isset( $user_attempts_left ) ) {
		return $message;
	}

	return $message . '<p class="message">' . sprintf( _n( 'Login failed, <strong>%d</strong> attempt left.', 'Login failed, <strong>%d</strong> attempts left.', $user_attempts_left, 'secupress' ), $user_attempts_left ) . '</p><br>';
}
