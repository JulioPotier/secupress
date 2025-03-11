<?php
/**
 * Module Name: Login Errors Disclose
 * Description: Replace some login error messages.
 * Main Module: discloses
 * Author: SecuPress
 * Version: 2.2.6
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );

add_filter( 'authenticate', 'secupress_replace_login_errors_disclose', 21 );
add_filter( 'registration_errors', 'secupress_replace_login_errors_disclose', 1 );
add_filter( 'user_profile_update_errors', 'secupress_replace_login_errors_disclose', 1 );
add_filter( 'login_errors', 'secupress_replace_login_errors_disclose', 1 );
/**
 * Replace all login errors with a more generic message.
 *
 * @author Julio Potier
 * @since 2.2.6 Back to 1.4.6 style with new keys and default message + 1 new hook filters
 * @since 2.0 Just return the default SP message
 * @since 1.4.6 Remove "\n" from pattern + new $default value
 * @author Grégory Viguier
 * @since 1.0
 *
 * @return (string)
 */
function secupress_replace_login_errors_disclose( $wp_errors ) {
	if ( ! is_wp_error( $wp_errors ) || ! isset( $wp_errors->errors ) ) {
		return $wp_errors; // Not errors here!
	}
	$ar_keys = array_flip( array_keys( secupress_login_errors_disclose_get_messages( false ) ) );
	$default = [	'authenticate'               => [ __( 'Authentication failed.', 'secupress' ) ], 
					'registration_errors'        => [ __( 'Something went wrong.', 'secupress' ) ],
					'user_profile_update_errors' => [ __( 'Incorrect data provided. Unable to proceed.', 'secupress' ) ],
				];
	foreach ( $wp_errors->errors as $key => &$wp_error ) {
		if ( isset( $ar_keys[ $key ] ) ) {
			$wp_error = $default[ current_filter() ];
			if ( isset( $_POST['log'] ) ) {
				unset( $_POST['log'] );
			}
		}
	}
	return $wp_errors;
}

add_action( 'secupress.modules.activate_submodule_' . basename( __FILE__, '.php' ), 'secupress_login_errors_de_activate_file' );
add_action( 'secupress.modules.deactivate_submodule_' . basename( __FILE__, '.php' ), 'secupress_login_errors_de_activate_file' );
/**
 * On module de/activation, rescan.
 *
 * @since 2.0
 */
function secupress_login_errors_de_activate_file() {
	secupress_scanit( 'Login_Errors_Disclose' );
}
