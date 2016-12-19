<?php
defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

/*------------------------------------------------------------------------------------------------*/
/* REMOVE DEFAULT WORDPRESS REDIRECTIONS TO LOGIN AND ADMIN AREAS =============================== */
/*------------------------------------------------------------------------------------------------*/

/**
 * WordPress redirects some URLs (`wp-admin`, `dashboard`, `admin`) to the administration area,
 * and some others (`wp-login.php`, `login`) to the login page.
 * We don't want that, so we remove the hook.
 *
 * @since 1.0
 */
remove_action( 'template_redirect', 'wp_redirect_admin_locations', 1000 );


add_filter( 'rewrite_rules_array', 'secupress_move_login_remove_rewrite_rules' );
/**
 * Filter the full set of generated rewrite rules.
 *
 * @since 1.0
 *
 * @param (array) $rules The compiled array of rewrite rules.
 *
 * @return (array)
 */
function secupress_move_login_remove_rewrite_rules( $rules ) {
	if ( ! is_multisite() ) {
		unset( $rules['.*wp-register.php$'] );
	}
	return $rules;
}


/*------------------------------------------------------------------------------------------------*/
/* DENY ACCESS TO THE LOGIN FORM ================================================================ */
/*------------------------------------------------------------------------------------------------*/

add_action( 'login_init', 'secupress_move_login_maybe_deny_login_page', 0 );
/**
 * When displaying the login page, if the URL does not matches those in our settings, deny access.
 * Does nothing if the user is logged in.
 *
 * @since 1.0
 */
function secupress_move_login_maybe_deny_login_page() {
	// If the user is logged in, do nothing, let WP redirect this user to the administration area.
	if ( is_user_logged_in() ) {
		return;
	}

	$uri    = secupress_get_current_url( 'uri' );
	$subdir = secupress_get_wp_directory();
	$slugs  = secupress_move_login_get_slugs();

	if ( $subdir ) {
		foreach ( $slugs as $action => $slug ) {
			$slugs[ $action ] = $subdir . $slug;
		}
	}
	/**
	 * If you want to display the login form somewhere outside wp-login.php, add your URIs here.
	 *
	 * @since 1.0
	 *
	 * @param (array)  $new_slugs An array of action => URIs (WP directory + slugs).
	 * @param (string) $uri       The current URI.
	 * @param (string) $subdir    WP directory.
	 * @param (array)  $slugs     URIs already in use.
	 */
	$new_slugs = apply_filters( 'sfml_slugs_not_to_kill', array(), $uri, $subdir, $slugs );
	$slugs     = is_array( $new_slugs ) && ! empty( $new_slugs ) ? array_merge( $new_slugs, $slugs ) : $slugs;
	$slugs     = array_flip( $slugs );

	if ( isset( $slugs[ $uri ] ) ) {
		// Display the login page.
		if ( ! defined( 'DONOTCACHEPAGE' ) ) {
			// Tell cache plugins not to cache the login page.
			define( 'DONOTCACHEPAGE', true );
		}
		return;
	}

	// You shall not pass!
	secupress_move_login_deny_login_access();
}


/**
 * Perform the action set for the login page: die or redirect.
 *
 * @since 1.0
 */
function secupress_move_login_deny_login_access() {
	/**
	 * If you want to trigger a custom action (redirect, message, die...), add it here.
	 * Don't forget to exit/die.
	 *
	 * @since 1.0
	 */
	do_action( 'secupress.plugin.move-login.deny_login_access' );

	$do = secupress_get_module_option( 'move-login_login-access', 'error', 'users-login' );

	switch ( $do ) {
		case 'redir_404':
			/**
			 * Filter the 404 page URL.
			 *
			 * @since 1.0
			 *
			 * @param (string) $redirect An URL that leads to a 404 response.
			 */
			$redirect = apply_filters( 'sfml_404_error_page', home_url( '404' ) );
			wp_redirect( esc_url_raw( user_trailingslashit( $redirect ) ) );
			exit;
		case 'redir_home':
			wp_redirect( esc_url_raw( user_trailingslashit( home_url() ) ) );
			exit;
		default:
			wp_die( __( 'The login form is not here.', 'secupress' ), __( 'Lost?', 'secupress' ), array( 'response' => 403 ) );
	}
}


/*------------------------------------------------------------------------------------------------*/
/* DO NOT REDIRECT TO THE NEW LOGIN PAGE ======================================================== */
/*------------------------------------------------------------------------------------------------*/

add_action( 'after_setup_theme', 'secupress_move_login_maybe_deny_admin_redirect', 12 );
/**
 * When a logged out user tries to access the admin area, deny access.
 * Does nothing if the user is logged in.
 * `admin-post.php` and `admin-ajax.php` are white listed.
 *
 * @since 1.0
 */
function secupress_move_login_maybe_deny_admin_redirect() {
	global $pagenow;
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


add_filter( 'register_url', 'secupress_move_login_maybe_deny_signup_redirect' );
/**
 * When a logged out user tries to access `wp-signup.php` or `wp-register.php`, deny access.
 * Does nothing if the user is logged in.
 * Does nothing in multi-site.
 *
 * @since 1.0
 *
 * @param (string) $url The URL.
 */
function secupress_move_login_maybe_deny_signup_redirect( $url ) {
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
 */
function secupress_move_login_deny_login_redirect() {
	/**
	 * If you want to trigger a custom action (redirect, message, die...), add it here.
	 * Don't forget to exit/die.
	 *
	 * @since 1.0
	 */
	do_action( 'secupress.plugin.move-login.deny_login_redirect' );

	$do = secupress_get_module_option( 'move-login_login-redirect', 'redir-login', 'users-login' );

	switch ( $do ) {
		case 'redir-login':
			// Ok, let WordPress redirect the user to the login page.
			return;
		case 'error':
			wp_die( __( 'Cheatin&#8217; uh?' ), __( 'Lost?', 'secupress' ), array( 'response' => 403 ) );
		case 'redir_404':
			/** This filter is documented in inc/modules/users-login/plugins/inc/php/move-login/redirections-and-dies.php */
			$redirect = apply_filters( 'sfml_404_error_page', home_url( '404' ) );
			wp_redirect( esc_url_raw( user_trailingslashit( $redirect ) ) );
			exit;
		case 'redir_home':
			wp_redirect( esc_url_raw( user_trailingslashit( home_url() ) ) );
			exit;
	}

	die();
}
