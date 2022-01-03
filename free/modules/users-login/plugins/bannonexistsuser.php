<?php
/**
 * Module Name: Ban log in attempts on Non-Existing Users
 * Description: If someone tries to log in using a username that doesn'y exists on your website, he will be banned for x minutes.
 * Main Module: users_login
 * Author: SecuPress
 * Version: 1.4.12
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );

add_action( 'authenticate', 'secupress_bannonexistsuser_auth', 100, 2 );
/**
 * Ban users who try to log in with a non existing username.
 *
 * @since 1.4.12 Don't ban, just block.
 * @since 1.0
 *
 * @param (null|object) $raw_user WP_User if the user is authenticated.
 *                                WP_Error or null otherwise.
 * @param (string)      $username Username or email address.
 *
 * @return (null|object)
 */
function secupress_bannonexistsuser_auth( $raw_user, $username ) {
	static $running = false;

	if ( $running ) {
		return $raw_user;
	}
	$running = true;

	if ( ! empty( $_POST ) && is_wp_error( $raw_user ) && ! secupress_ip_is_whitelisted() ) { // WPCS: CSRF ok.
		$errors = $raw_user->get_error_codes();
		$errors = array_flip( $errors );

		if ( isset( $errors['invalid_username'] ) || isset( $errors['invalid_email'] ) ) {
			secupress_block( 'NOUSER', [ 'code' => 403, 'b64' => [ 'data' => $username ] ] );
		}
	}

	$running = false;
	return $raw_user;
}
