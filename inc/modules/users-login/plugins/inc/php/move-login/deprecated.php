<?php
defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

/**
 * When a logged out user tries to access the admin area, deny access.
 * Does nothing if the user is logged in.
 * `admin-post.php` and `admin-ajax.php` are white listed.
 *
 * @since 1.0
 * @since 1.3 Deprecated. Was hooked on 'after_setup_theme'.
 * @author Grégory Viguier
 */
function secupress_move_login_maybe_deny_admin_redirect() {
	global $pagenow;

	_deprecated_function( __FUNCTION__, '1.3', 'secupress_move_login_maybe_deny_login_redirect' );

	// If it's not the administration area, or if it's an ajax call, no need to go further.
	if ( ! ( is_admin() && ! ( ( defined( 'DOING_AJAX' ) && DOING_AJAX ) || ( 'admin-post.php' === $pagenow && ! empty( $_REQUEST['action'] ) ) ) ) ) {
		return;
	}

	if ( is_user_admin() ) {
		$scheme = 'logged_in';
	} else {
		/** This filter is documented in wp-includes/pluggable.php */
		$scheme = apply_filters( 'auth_redirect_scheme', '' );
	}

	if ( wp_validate_auth_cookie( '', $scheme ) ) {
		return;
	}

	// Nice try. But no.
	secupress_move_login_deny_login_redirect();
}


/**
 * When a logged out user tries to access `wp-signup.php` or `wp-register.php`, deny access.
 * Does nothing if the user is logged in.
 * Does nothing in multi-site.
 *
 * @since 1.0
 * @since 1.3 Deprecated. Was hooked on 'register_url'.
 * @author Grégory Viguier
 *
 * @param (string) $url The URL.
 */
function secupress_move_login_maybe_deny_signup_redirect( $url ) {
	_deprecated_function( __FUNCTION__, '1.3', 'secupress_move_login_maybe_deny_login_redirect' );

	if ( empty( $_SERVER['REQUEST_URI'] ) ) {
		return $url;
	}
	if ( false === strpos( $_SERVER['REQUEST_URI'], '/wp-signup.php' ) && false === strpos( $_SERVER['REQUEST_URI'], '/wp-register.php' ) ) {
		return $url;
	}
	if ( is_multisite() || is_user_logged_in() ) {
		return $url;
	}

	// Nope!
	secupress_move_login_deny_login_redirect();
}


/**
 * Perform the action set for redirections to login page: die or redirect.
 *
 * @since 1.0
 * @since 1.3 Deprecated.
 * @author Grégory Viguier
 */
function secupress_move_login_deny_login_redirect() {
	_deprecated_function( __FUNCTION__, '1.3', 'secupress_move_login_maybe_deny_login_redirect' );

	secupress_move_login_maybe_deny_login_redirect();
}
