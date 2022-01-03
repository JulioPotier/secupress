<?php
/**
 * Module Name: Login Errors Disclose
 * Description: Replace some login error messages.
 * Main Module: discloses
 * Author: SecuPress
 * Version: 2.0
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );

add_filter( 'login_errors', 'secupress_replace_login_errors_disclose', SECUPRESS_INT_MAX );
/**
 * Replace all login errors with a more generic message.
 *
 * @since 2.0 Just return the default SP message
 * @since 1.4.6 Remove "\n" from pattern + new $default value
 * @since 1.0
 *
 * @return (string)
 */
function secupress_replace_login_errors_disclose() {
	return __( '<strong>Authentication failed</strong>.', 'secupress' );
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
