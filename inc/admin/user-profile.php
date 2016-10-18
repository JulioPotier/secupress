<?php
defined( 'ABSPATH' ) or die( 'Cheatin\' uh?' );

add_filter( 'user_contactmethods', 'secupress_add_user_contactmethods', 0, 2 );
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
function secupress_add_user_contactmethods( $methods, $user ) {
	if ( ! empty( $user->ID ) && $user->ID === get_current_user_id() ) {
		$methods['secupress_recovery_email'] = __( '<span id="secupress_recovery_email">Recovery E-mail</span><p class="description">For security reasons, you may need to retrieve some private informations at an alternate email address.</p>', 'secupress' );
	}
	return $methods;
}


add_action( 'personal_options_update', 'secupress_callback_update_user_contactmethods' );
/**
 * Update the user's recovery email if correct.
 *
 * @author Julio Potier
 * @since 1.0
 *
 * @param (int) $user_id The user ID.
 */
function secupress_callback_update_user_contactmethods( $user_id ) {

	if ( ! isset( $_POST['secupress_recovery_email'] ) ) { // WPCS: CSRF ok.
		return;
	}

	if ( empty( $_POST['secupress_recovery_email'] ) && defined( 'DOING_AJAX' ) && DOING_AJAX ) { // WPCS: CSRF ok.
		die( __( '<strong>ERROR</strong>: This email is not valid.' ) );
	}

	$userdata                = get_userdata( $user_id );
	$recovery_email          = strtolower( sanitize_email( $_POST['secupress_recovery_email'] ) ); // WPCS: CSRF ok.
	$recovery_email_no_alias = secupress_remove_email_alias( $recovery_email );

	update_user_meta( $userdata->ID, 'secupress_recovery_email_no_alias', $recovery_email_no_alias );
	update_user_meta( $userdata->ID, 'secupress_recovery_email', $recovery_email );
}


add_action( 'user_profile_update_errors', 'secupress_user_profile_update_errors', 10, 3 );
/**
 * Additionnal email testing when a user is updated.
 *
 * @author Julio Potier
 * @since 1.0
 *
 * @param (object) $errors WP_Error object, passed by reference.
 * @param (bool)   $update Whether this is a user update.
 * @param (object) $user   WP_User object, passed by reference.
 */
function secupress_user_profile_update_errors( &$errors, $update, &$user ) {
	global $wpdb;

	if ( ! secupress_is_user( $user ) ) {
		return;
	}

	secupress_reinit_notice( 'recovery_email', $user->ID );

	// First, simple tests focused on the user main email.
	if ( empty( $user->secupress_recovery_email ) ) {
		return secupress_send_recovery_email_result();
	}

	$userdata                = get_userdata( $user->ID );
	$user_email              = strtolower( $userdata->user_email );
	$recovery_email          = $user->secupress_recovery_email;
	$recovery_email_no_alias = secupress_remove_email_alias( $recovery_email );

	if ( ! is_email( $recovery_email ) ) {
		$error = __( '<strong>ERROR</strong>: This email is not valid.', 'secupress' );
		return secupress_send_recovery_email_result( $error, $errors, $user );
	}

	if ( $user_email === $recovery_email ) {
		$error = __( '<strong>ERROR</strong>: This email is already yours.', 'secupress' );
		return secupress_send_recovery_email_result( $error, $errors, $user );
	}

	if ( $user_email === $recovery_email_no_alias ) {
		$error = __( '<strong>ERROR</strong>: This email is already yours with an alias.', 'secupress' );
		return secupress_send_recovery_email_result( $error, $errors, $user );
	}

	// Now find duplicates in the database, focused on other users.
	$recovery_email_no_alias_like = secupress_prepare_email_for_like_search( $recovery_email );

	// Find other user unaliased emails like the unaliased recovery email of this user.
	$user_emails_like_recovery_no_alias = $wpdb->get_col( $wpdb->prepare( 'SELECT user_email FROM ' . $wpdb->users . ' WHERE ID != %d AND user_email LIKE %s', $user->ID, $recovery_email_no_alias_like ) );
	$user_emails_like_recovery_no_alias = array_map( 'secupress_remove_email_alias', $user_emails_like_recovery_no_alias );

	if ( in_array( $recovery_email_no_alias, $user_emails_like_recovery_no_alias, true ) ) {
		$error = __( '<strong>ERROR</strong>: This email is already registered.', 'secupress' );
		return secupress_send_recovery_email_result( $error, $errors, $user );
	}

	// Find other unaliased recovery emails like the unaliased recovery email of this user.
	$recovery_emails_no_alias_like_recovery_email_no_alias = $wpdb->get_col( $wpdb->prepare( 'SELECT user_id FROM ' . $wpdb->usermeta . ' WHERE user_id != %d AND meta_key = "secupress_recovery_email_no_alias" AND meta_value = %s', $user->ID, $recovery_email_no_alias ) );

	if ( $recovery_emails_no_alias_like_recovery_email_no_alias ) {
		$error = __( '<strong>ERROR</strong>: This email is already registered.', 'secupress' );
		return secupress_send_recovery_email_result( $error, $errors, $user );
	}

	// Success.
	secupress_send_recovery_email_result( '✅' );
}


/**
 * Send an error response when searching for recovery email duplicates.
 * Also delete the user metas.
 *
 * @since 1.0
 * @author Grégory Viguier
 *
 * @param (string) $message A message.
 * @param (object) $errors  WP_Error object, passed by reference.
 * @param (object) $user    WP_User object.
 */
function secupress_send_recovery_email_result( $message = '', &$errors = null, $user = null ) {
	if ( $user ) {
		delete_user_meta( $user->ID, 'secupress_recovery_email_no_alias' );
		delete_user_meta( $user->ID, 'secupress_recovery_email' );
	}

	if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
		die( $message );
	}

	if ( $message && $errors ) {
		$errors->add( 'email_error', $message, array( 'form-field' => 'email' ) );
	}
}
