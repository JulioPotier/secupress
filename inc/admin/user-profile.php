<?php
defined( 'ABSPATH' ) or die( 'Cheatin\' uh?' );

add_filter( 'user_contactmethods', '__secupress_add_user_contactmethods', 0, 2 );
/**
 * Add our recovery email to the list of the users contact methods.
 *
 * @since 1.0
 *
 * @param (array)  $methods Array of contact methods and their labels.
 * @param (object) $user    WP_User object.
 *
 * @return (array)
 */
function __secupress_add_user_contactmethods( $methods, $user ) {
	if ( isset( $user->ID ) && $user->ID === $GLOBALS['current_user']->ID ) {
		$methods['secupress_recovery_email'] = __( '<span id="secupress_recovery_email">Recovery E-mail</span><p class="description">For security reasons, you may need to retrieve some private informations on an alternate email address.</p>', 'secupress' );
	}
	return $methods;
}


add_action( 'personal_options_update', '__secupress_callback_update_user_contactmethods' );
/**
 * Update the user's recovery email if correct.
 *
 * @since 1.0
 *
 * @param (int) $user_id The user ID.
 */
function __secupress_callback_update_user_contactmethods( $user_id ) {
	if ( ! isset( $_POST['secupress_recovery_email'] ) ) { // WPCS: CSRF ok.
		return;
	}

	$userdata                = get_userdata( $user_id );
	$actual_email            = isset( $_POST['email'] ) ? strtolower( $_POST['email'] ) : strtolower( $userdata->user_email ); // WPCS: CSRF ok.
	$secupress_recovery_email          = strtolower( $_POST['secupress_recovery_email'] ); // WPCS: CSRF ok.
	$secupress_recovery_email_no_alias = secupress_remove_email_alias( $secupress_recovery_email );

	// The recovery email is not correct.
	if ( $actual_email === $secupress_recovery_email || $actual_email === $secupress_recovery_email_no_alias ) {
		$_POST['secupress_recovery_email'] = '';
	} else {
		update_user_meta( $userdata->ID, 'secupress_recovery_email_no_alias', sanitize_text_field( $secupress_recovery_email_no_alias ) );
	}
}


add_action( 'user_profile_update_errors', 'secupress_user_profile_update_errors', 10, 3 );
/**
 * Additionnal email testing when a user is updated.
 *
 * @since 1.0
 *
 * @param (object) $errors WP_Error object, passed by reference.
 * @param (bool)   $update  Whether this is a user update.
 * @param (object) $user   WP_User object, passed by reference.
 */
function secupress_user_profile_update_errors( &$errors, $update, &$user ) {
	global $wpdb;

	if ( ! isset( $user->secupress_recovery_email ) ) {
		return;
	}

	$secupress_recovery_email_no_alias      = secupress_remove_email_alias( $user->secupress_recovery_email );
	$secupress_recovery_email_no_alias_like = secupress_prepare_email_for_like_search( $user->secupress_recovery_email );
	$user_email_no_alias          = secupress_remove_email_alias( $user->user_email );
	$user_email_no_alias_like     = secupress_prepare_email_for_like_search( $user->user_email );

	$user_emails                  = $wpdb->get_col( $wpdb->prepare( 'SELECT user_email FROM ' . $wpdb->users . ' WHERE ID != %d AND ( user_email LIKE %s OR user_email LIKE %s )', $user->ID, $secupress_recovery_email_no_alias_like, $user_email_no_alias_like ) );
	$user_emails                  = array_map( 'secupress_remove_email_alias', $user_emails );

	$user_exists                  = (bool) $wpdb->get_col( $wpdb->prepare( 'SELECT user_id FROM ' . $wpdb->usermeta . ' WHERE user_id != %d AND meta_key = "secupress_recovery_email_no_alias" AND meta_value = %s', $user->ID, $secupress_recovery_email_no_alias ) );
	$user_exists                  = $user_exists || in_array( $secupress_recovery_email_no_alias, $user_emails, true ) || in_array( $user_email_no_alias, $user_emails, true );

	if ( $user_exists ) {
		$errors->add( 'email_exists', __( '<strong>ERROR</strong>: This email is already registered, please choose another one.' ), array( 'form-field' => 'email' ) );
	}
}
