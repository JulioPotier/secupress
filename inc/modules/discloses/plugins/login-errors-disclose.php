<?php
/*
Module Name: Login Errors Disclose
Description: Replace some login error messages.
Main Module: discloses
Author: SecuPress
Version: 1.0
*/
defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );


add_filter( 'login_errors', 'secupress_replace_login_errors_disclose', PHP_INT_MAX );

function secupress_replace_login_errors_disclose( $errors ) {
	$pattern = array(
		'invalid_email'      => __( '<strong>ERROR</strong>: There is no user registered with that email address.' ),
		'invalidcombo'       => __( '<strong>ERROR</strong>: Invalid username or e-mail.' ),
		'invalid_username'   => sprintf( __( '<strong>ERROR</strong>: Invalid username. <a href="%s">Lost your password?</a>' ), wp_lostpassword_url() ),
		'incorrect_password' => sprintf( __( '<strong>ERROR</strong>: The password you entered for the username <strong>%1$s</strong> is incorrect. <a href="%2$s">Lost your password?</a>' ), '%ALL%', wp_lostpassword_url() ),
	);

	foreach ( $pattern as $id => $message ) {
		$pattern[ $id ] = addcslashes( $pattern[ $id ], '[](){}.*+?|^$@' );
		$pattern[ $id ] = str_replace( '%ALL%', '.*', $pattern[ $id ] );
	}

	$pattern = '@\s(' . implode( '|', $pattern ) . ')<br />\n@';
	$default = __( '<strong>ERROR</strong>: Invalid username or incorrect password.' );

	return preg_replace( $pattern, $default, $errors );
}