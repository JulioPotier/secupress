<?php 
defined( 'ABSPATH' ) or die( 'Cheatin\' uh?' );

add_filter( 'user_contactmethods', 'secupress_add_user_contactmethods', 0 );
function secupress_add_user_contactmethods( $methods ) {
	$methods['backup_email'] = __( '<span id="secupress_backup_email">Backup E-mail</span><p class="description">For security reasons, you may need to retreive some private informations on an alternate email address.</p>', 'secupress' );
	return $methods;
}

add_action( 'personal_options_update', 'secupress_callback_update_user_contactmethods' );
function secupress_callback_update_user_contactmethods( $user_id ) {
	if ( isset( $_POST['backup_email'] ) ) {
		$userdata = get_userdata( $user_id );
		$actual_email = $userdata->user_email;
		if ( $actual_email === $_POST['backup_email'] || 
			isset( $_POST['email'] ) && $_POST['backup_email'] === $_POST['email'] ) {
			$_POST['backup_email'] = '';
		}
	}	
}