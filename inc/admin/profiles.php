<?php
defined( 'ABSPATH' ) or die( 'Cheatin\' uh?' );

add_filter( 'user_contactmethods', '__secupress_add_user_contactmethods', 0 );
/**
 * Add our backup email hint
 *
 * @since 1.0
 * @return array $methods
 **/
function __secupress_add_user_contactmethods( $methods ) {
	$methods['backup_email'] = __( '<span id="secupress_backup_email">Backup E-mail</span><p class="description">For security reasons, you may need to retreive some private informations on an alternate email address.</p>', 'secupress' );
	return $methods;
}


add_action( 'personal_options_update', '__secupress_callback_update_user_contactmethods' );
/**
 * Update the user's backup email if correct
 *
 * @since 1.0 
 * @return void
 **/
function __secupress_callback_update_user_contactmethods( $user_id ) {
	if ( isset( $_POST['backup_email'] ) ) {
		$userdata     = get_userdata( $user_id );
		$actual_email = isset( $_POST['email'] ) ? strtolower( $_POST['email'] ) : strtolower( $userdata->user_email );
		$backup_email = strtolower( $_POST['backup_email'] );

		// Avoid gmail aliases
		if ( '@gmail.com' === strstr( $backup_email, '@' ) ) {

			$backup_email_test = explode( '+', $backup_email );
			$backup_email_test = reset( $backup_email_test );
			$backup_email_test = str_replace( '.', '', $backup_email_test );

			$actual_email_test = explode( '+', $actual_email ); 
			$actual_email_test = reset( $actual_email_test );
			$actual_email_test = str_replace( '.', '', $actual_email_test );

			if ( $actual_email_test === $backup_email_test ) {
				$_POST['backup_email'] = '';
			}
		}

		// The backup email is not correct
		if ( $actual_email === $backup_email ) {
			$_POST['backup_email'] = '';
		}
	}
}
