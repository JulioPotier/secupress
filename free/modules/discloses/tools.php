<?php
defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );

/**
 * Get login error messages that we don't want to be displayed.
 *
 * @author Julio Potier
 * @since 2.2.6 spammer_account existing_user_login existing_user_email username_exists email_exists + "_60"
 * @author Grégory Viguier
 * @since 1.0
 * 
 * @param (bool) $for_regex If false, raw messages will be returned. If true, the returned messages will be ready to be used as regex patterns (in that case, `@` must be used as delimiter).
 *
 * @return (array) An array of messages.
 */
function secupress_login_errors_disclose_get_messages( $for_regex = true ) {
	$messages = [
		'invalid_email'         => __( '<strong>Error:</strong> There is no user registered with that email address.', 'secupress' ),
		'invalid_email_60'      => __( '<strong>Error</strong>: There is no user registered with that email address.', 'secupress' ),
		'invalidcombo'          => __( '<strong>Error:</strong> Invalid username or e-mail.', 'secupress' ),
		'invalidcombo_60'       => __( '<strong>Error</strong>: Invalid username or e-mail.', 'secupress' ),
		'invalidcombo_46'       => __( '<strong>Error</strong>: Invalid username or email.', 'secupress' ),
		'invalid_username'      => sprintf( __( '<strong>Error:</strong> Invalid username. <a href="%s">Lost your password?</a>', 'secupress' ), wp_lostpassword_url() ),
		'invalid_username_60'   => sprintf( __( '<strong>Error</strong>: Invalid username. <a href="%s">Lost your password?</a>', 'secupress' ), wp_lostpassword_url() ),
		'invalid_username_46'   => __( '<strong>Error</strong>: Invalid username.', 'secupress' ) . ' <a href="' . wp_lostpassword_url() . '">' . __( 'Lost your password?' ) . '</a>',
		'incorrect_password'    => sprintf( __( '<strong>Error:</strong> The password you entered for the username <strong>%1$s</strong> is incorrect. <a href="%2$s">Lost your password?</a>', 'secupress' ), '%ALL%', wp_lostpassword_url() ),
		'incorrect_password_60' => sprintf( __( '<strong>Error</strong>: The password you entered for the username <strong>%1$s</strong> is incorrect. <a href="%2$s">Lost your password?</a>', 'secupress' ), '%ALL%', wp_lostpassword_url() ),
		'incorrect_password_46' => sprintf( __( '<strong>Error</strong>: The password you entered for the username %s is incorrect.', 'secupress' ), '<strong>%ALL%</strong>' ) . ' <a href="' . wp_lostpassword_url() . '">' . __( 'Lost your password?', 'secupress' ) . '</a>',
		'spammer_account'       => __( '<strong>Error:</strong> Your account has been marked as a spammer.' ),
		'spammer_account_60'    => __( '<strong>Error</strong>: Your account has been marked as a spammer.' ),
		'existing_user_login'   => __( 'Sorry, that username already exists!' ),
		'existing_user_email'   => __( 'Sorry, that email address is already used!' ),
		'username_exists'       => __( '<strong>Error:</strong> This username is already registered. Please choose another one.' ),
		'username_exists_60'    => __( '<strong>Error</strong>: This username is already registered. Please choose another one.' ),
		'email_exists'          => sprintf( __( '<strong>Error:</strong> This email address is already registered. <a href="%s">Log in</a> with this address or choose another one.' ), wp_login_url() ),
		'email_exists_60'       => sprintf( __( '<strong>Error</strong>: This email address is already registered. <a href="%s">Log in</a> with this address or choose another one.' ), wp_login_url() ),
	];

	if ( $for_regex ) {
		foreach ( $messages as $id => $message ) {
			$messages[ $id ] = preg_quote( $messages[ $id ] );
			$messages[ $id ] = str_replace( '%ALL%', '.*', $messages[ $id ] );
		}
	}

	return $messages;
}
