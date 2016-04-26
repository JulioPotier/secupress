<?php
defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Get login error messages that we don't want to be displayed.
 *
 * @since 1.0
 *
 * @param (bool) $for_regex If false, raw messages will be returned. If true, the returned messages will be ready to be used as regex patterns (in that case, `@` must be used as delimiter).
 *
 * @return (array) An array of messages.
 */
function secupress_login_errors_disclose_get_messages( $for_regex = true ) {
	$messages = array(
		'invalid_email'      => __( '<strong>ERROR</strong>: There is no user registered with that email address.' ),
		'invalidcombo'       => __( '<strong>ERROR</strong>: Invalid username or e-mail.' ),
		'invalid_username'   => sprintf( __( '<strong>ERROR</strong>: Invalid username. <a href="%s">Lost your password?</a>' ), wp_lostpassword_url() ),
		'incorrect_password' => sprintf( __( '<strong>ERROR</strong>: The password you entered for the username <strong>%1$s</strong> is incorrect. <a href="%2$s">Lost your password?</a>' ), '%ALL%', wp_lostpassword_url() ),
	);

	if ( $for_regex ) {
		foreach ( $messages as $id => $message ) {
			$messages[ $id ] = addcslashes( $messages[ $id ], '[](){}.*+?|^$@' );
			$messages[ $id ] = str_replace( '%ALL%', '.*', $messages[ $id ] );
		}
	}

	return $messages;
}
