<?php
/**
 * Module Name: Same Email Domain
 * Description: Prevent users to use the website domain to create an account
 * Main Module: users_login
 * Author: SecuPress
 * Version: 2.2.6
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );

add_action( 'user_profile_update_errors', 'secupress_same_email_domain_validate_user_creation', 10, 3 );
/**
 * Triggers an error on same email domain on backend creation or update
 * 
 * @since 2.2.6
 * @author Julio Potier
 *
 * @param (WP_Error) $errors Registration errors.
 * @param (bool) $update 
 * @param (WP_User) $user
 * 
 * @return (WP_Error) Registration errors
 */
function secupress_same_email_domain_validate_user_creation( $errors, $update, $user ) {
	if ( secupress_email_domain_is_same( $user->user_email ) ) {
		/**
		 * Filter the message on same domain email registration
		 * 
		 * @since 2.2.6
		 * 
		 * @param $errors
		 * @param $sanitized_user_login
		 * @param $user_email
		 */
		$message = apply_filters( 'secupress.plugins.same_email_domain.backend.message', __( '<strong>Error</strong>: The email address is not correct.', 'secupress' ), $errors, $update, $user->user_email );
		// secupress_log_attack( 'users' ); // DO NOT LOG AS AN ATTACK, we are in backoffice, this can just be an admin mistake.
		$errors->add( 'registerfail', $message );
	}

	return $errors;
}

add_filter( 'registration_errors', 'secupress_same_email_domain_validate_user_registration', 10, 3 );
/**
 * Triggers an error on same email domain on frontend registration
 * 
 * @since 2.2.6
 * @author Julio Potier
 *
 * @param (WP_Error) $errors Registration errors.
 * @param (string) $sanitized_user_login The sanitized user login.
 * @param (string) $user_email The user email address.
 * 
 * @return (WP_Error) Registration errors
 */
function secupress_same_email_domain_validate_user_registration( $errors, $sanitized_user_login, $user_email ) {
	if ( secupress_email_domain_is_same( $user_email ) ) {
		/**
		 * Filter the message on same domain email registration
		 * 
		 * @since 2.2.6
		 * 
		 * @param $errors
		 * @param $sanitized_user_login
		 * @param $user_email
		 */
		$message = apply_filters( 'secupress.plugins.same_email_domain.frontend.message', __( '<strong>Error</strong>: User registration is currently not allowed.', 'secupress' ), $errors, $sanitized_user_login, $user_email );
		secupress_log_attack( 'users' );
		$errors->add( 'registerfail', $message );
	}

	return $errors;
}
