<?php
/*
Module Name: Email Link Double Authentication
Description: When you try to log in, you'll receive an email containing a validation link, without cliking on it, you can't log in.
Main Module: users_login
Author: SecuPress
Version: 1.0
*/
defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Send an email with the new unique login link.
 *
 * @since 1.0
 *
 * @return WP_User
 */
add_filter( 'authenticate', 'secupress_login_authenticate', PHP_INT_MAX, 2 );

function secupress_login_authenticate( $raw_user, $username ) {
	global $pagenow;

	if ( is_wp_error( $raw_user ) || ! secupress_is_affected_role( 'users-login', 'double-auth', $raw_user ) ) {
		return $raw_user;
	}

	if ( empty( $_POST ) ) {
		return null;
	}

	$rememberme = isset( $_POST['rememberme'] ) && 'forever' === $_POST['rememberme'];

	$subject = sprintf( __( '[%1$s] Secure Login Request', 'secupress' ), get_bloginfo( 'name' ) );
	/**
	 *
	 */
	$subject = apply_filters( 'secupress.plugin.emaillink_email_subject', $subject );

	$message = sprintf(
		__( 'Hello %1$s, a log-in has been requested for %2$s. <a href="%3$s">Open this page to really log in</a>.' ),
		$raw_user->display_name,
		get_bloginfo( 'name' ),
		secupress_create_activation_url( $raw_user, $rememberme )
	);
	/**
	 *
	 */
	$message = apply_filters( 'secupress.plugin.emaillink_email_message', $message );

	wp_mail( $raw_user->user_email, $subject, $message, 'content-type: text/html' );
	wp_redirect( add_query_arg( 'action', 'emaillink_autologin', site_url( 'wp-login.php' ) ) );
	die();

	return $raw_user;
}


add_action( 'login_form_emaillink_autologin', 'secupress_emaillink_autologin_validation' );

function secupress_emaillink_autologin_validation() {
	login_header( __( 'Email Link', 'secupress' ), '<p class="message">' . __( 'Check your e-mail for the confirmation link.' ) . '</p>' );
	login_footer();
	die();
}


function secupress_check_emaillink_key( $key, $uid ) {
	$token = get_user_meta( (int) $uid, 'emaillink_token', true );

	if ( $key === $token ) {
		return get_user_by( 'id', $uid );
	}

	return false;
}


/**
 * Automatically log-in a user with the correct token
 *
 * @since 1.0
 *
 */
add_action( 'admin_post_emaillink_autologin',        'secupress_emaillink_autologin' );
add_action( 'admin_post_nopriv_emaillink_autologin', 'secupress_emaillink_autologin' );

function secupress_emaillink_autologin() {
	global $wpdb;

	if ( ! isset( $_GET['token'] ) ) {
		secupress_die( sprintf( __( 'This link is not valid for this user, please try to <a href="%s">log-in again</a>.', 'secupress' ), wp_login_url( '', true ) ) );
	}

	$CLEAN = array();

	$CLEAN['uid'] = $wpdb->get_col( $wpdb->prepare( "SELECT user_id FROM $wpdb->usermeta WHERE meta_value = %s", $_GET['token'] ) );
	$CLEAN['uid'] = 1 === count( $CLEAN['uid'] ) ? (int) reset( $CLEAN['uid'] ) : 0;
	$user_by_url  = get_user_by( 'id', $CLEAN['uid'] );

	if ( ! $user_by_url || ! $CLEAN['uid'] ) {
		secupress_die( sprintf( __( 'This link is not valid for this user, please try to <a href="%s">log-in again</a>.', 'secupress' ), wp_login_url( '', true ) ) );
	}

	$user_by_check = secupress_check_emaillink_key( $_GET['token'], $user_by_url->ID );

	if ( is_wp_error( $user_by_check ) || ! is_a( $user_by_check, 'WP_User' ) || $user_by_check->ID != $user_by_url->ID ) {
		/**
		 *
		 */
		do_action( 'secupress_autologin_error', $CLEAN['uid'], $_GET['token'], 'mismatch users' );

		secupress_die( sprintf( __( 'This link is not valid for this user, please try to <a href="%s">log-in again</a>.', 'secupress' ), wp_login_url( '', true ) ) );
	}

	$user       = get_user_by( 'id', $CLEAN['uid'] );
	$time       = get_user_meta( $CLEAN['uid'], 'emaillink_timeout', true );
	$rememberme = get_user_meta( $CLEAN['uid'], 'emaillink_rememberme', true );

	delete_user_meta( $CLEAN['uid'], 'emaillink_token' );
	delete_user_meta( $CLEAN['uid'], 'emaillink_rememberme' );
	delete_user_meta( $CLEAN['uid'], 'emaillink_timeout' );

	if ( $time >= time() ) {
		$secure_cookie = is_ssl();
		$secure_args   = array(
			'user_login'    => $user->user_login,
			'user_password' => time(), // we don't have the real password, just pass something.
		);
		/**
		 *
		 */
		$secure_cookie = apply_filters( 'secure_signon_cookie', $secure_cookie, $secure_args );

		wp_set_auth_cookie( $CLEAN['uid'], (bool) $rememberme, $secure_cookie );

		$redirect_to = apply_filters( 'login_redirect', admin_url(), admin_url(), $user_by_check );
		/**
		 *
		 */
		do_action( 'secupress.plugin.emaillink_autologin_success', $CLEAN['uid'], $_GET['token'] );

		wp_redirect( $redirect_to );
		die( 'login_redirect' );
	}

	/**
	 *
	 */
	do_action( 'secupress.plugin.emaillink_autologin_error', $CLEAN['uid'], $_GET['token'], 'expired key' );

	secupress_die( sprintf( __( 'This link is now expired, please try to <a href="%s">log-in again</a>.', 'secupress' ), wp_login_url( '', true ) ) );
}


/**
 * Create a nonce like token that you only use once based on transients
 *
 *
 * @since v.1.0
 *
 * @return string
 */
function secupress_create_activation_url( $user, $rememberme ) {
	// Generate something random for a password reset key.
	remove_all_filters( 'random_password' );
	$key = wp_generate_password( 32, false );

	update_user_meta( $user->ID, 'emaillink_token', $key );
	update_user_meta( $user->ID, 'emaillink_timeout', time() + 10 * MINUTE_IN_SECONDS );
	update_user_meta( $user->ID, 'emaillink_rememberme', (int) $rememberme );

	return admin_url( 'admin-post.php?action=emaillink_autologin&token=' . $key );
}
