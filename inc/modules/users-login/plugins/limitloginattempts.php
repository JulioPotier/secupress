<?php
/*
Module Name: Limit Login Attempts
Description: Limit Login Attempts and ban if too many tries have been done
Main Module: users_login
Author: SecuPress
Version: 1.0
*/
defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

add_action( 'authenticate', 'secupress_limitloginattempts', PHP_INT_MAX - 20, 2 );

function secupress_limitloginattempts( $raw_user, $username ) {
	if ( ! empty( $_POST ) && is_wp_error( $raw_user ) && false !== ( $uid = username_exists( $username ) ) ) {
		$IP                               = secupress_get_ip();
		$login_protection_number_attempts = secupress_get_module_option( 'login_protection_number_attempts', 10, 'users_login' );
		$attempts                         = (int) get_user_meta( $uid, '_secupress_limitloginattempts', true );
		++$attempts;

		if ( $attempts < $login_protection_number_attempts ) {
			update_user_meta( $uid, '_secupress_limitloginattempts', $attempts );
			$attempts_left = $login_protection_number_attempts - $attempts;

			if ( $attempts_left <= 3 ) {
				add_filter( 'login_message', function( $message ) use( $attempts_left ) {
					return _secupress_limitloginattempts_error_message( $message, $attempts_left );
				} );
			}
		} else {
			delete_user_meta( $uid, '_secupress_limitloginattempts' );
			secupress_ban_ip();
			die();
		}
	}

	if ( isset( $raw_user->ID ) ) {
		delete_user_meta( $raw_user->ID, '_secupress_limitloginattempts' );
	}

	return $raw_user;
}


function _secupress_limitloginattempts_error_message( $message, $attempts_left = 1 ) {
	return $message . '<p class="message">' . sprintf( _n( 'Login failed, <strong>%d</strong> attempt left.', 'Login failed, <strong>%d</strong> attempts left.', $attempts_left, 'secupress' ), $attempts_left ) . '</p><br>';
}
