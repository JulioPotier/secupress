<?php
defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

/*------------------------------------------------------------------------------------------------*/
/* REMOVE DEFAULT WORDPRESS REDIRECTIONS TO LOGIN AND ADMIN AREAS =============================== */
/*------------------------------------------------------------------------------------------------*/

/*
 * WordPress redirects some URLs (`wp-admin`, `dashboard`, `admin`) to the administration area,
 * and some others (`wp-login.php`, `login`) to the login page.
 * We don't want that, so we remove the hook.
 *
 * @since 1.0
 */
remove_action( 'template_redirect', 'wp_redirect_admin_locations', 1000 );


/*------------------------------------------------------------------------------------------------*/
/* DENY ACCESS TO THE LOGIN FORM ================================================================ */
/*------------------------------------------------------------------------------------------------*/

/*
 * When displaying the login page, if the URL does not matches those in our settings, deny access.
 * Do nothing if the user is logged in.
 *
 * @since 1.0
 */
add_action( 'login_init', 'secupress_move_login_login_init', 0 );

function secupress_move_login_login_init() {
	// If the user is logged in, do nothing, let WP redirect this user to the administration area.
	if ( is_user_logged_in() ) {
		return;
	}

	$uri       = secupress_get_current_url( 'uri' );
	$subdir    = secupress_get_wp_directory();
	$slugs     = secupress_move_login_get_slugs();
	if ( $subdir ) {
		foreach ( $slugs as $action => $slug ) {
			$slugs[ $action ] = $subdir . $slug;
		}
	}
	/*
	 * If you want to display the login form somewhere outside wp-login.php, add your URIs here.
	 *
	 * @since 1.0
	 *
	 * @param (array)          An array of action => URIs (WP directory + slugs).
	 * @param (string) $uri    The current URI.
	 * @param (string) $subdir WP directory.
	 * @param (array)  $slugs  URIs already in use.
	 */
	$new_slugs = apply_filters( 'sfml_slugs_not_to_kill', array(), $uri, $subdir, $slugs );
	$slugs     = is_array( $new_slugs ) && ! empty( $new_slugs ) ? array_merge( $new_slugs, $slugs ) : $slugs;
	$slugs     = array_flip( $slugs );

	if ( isset( $slugs[ $uri ] ) ) {
		return;
	}

	/*
	 * If you want to trigger a custom action (redirect, message, die...), add it here.
	 * Don't forget to exit/die.
	 *
	 * @since 1.0
	 */
	do_action( 'sfml_wp_login_error' );

	$do = secupress_get_module_option( 'move-login_wp-login-access', 'error', 'users-login' );

	switch ( $do ) {
		case 'redir_404':
			/*
			 * Filter the 404 page URL.
			 *
			 * @since 1.0
			 *
			 * @param (string) An URL that leads to a 404 response.
			 */
			$redirect = apply_filters( 'sfml_404_error_page', home_url( '404' ) );
			wp_redirect( esc_url_raw( user_trailingslashit( $redirect ) ) );
			exit;
		case 'redir_home':
			wp_redirect( esc_url_raw( user_trailingslashit( home_url() ) ) );
			exit;
		default:
			wp_die( __( 'No no no, the login form is not here.', 'secupress' ), __( 'Nope :)', 'secupress' ), array( 'response' => 501 ) );
	}
}


/*------------------------------------------------------------------------------------------------*/
/* DO NOT REDIRECT FROM ADMIN AREA TO WP-LOGIN.PHP ============================================== */
/*------------------------------------------------------------------------------------------------*/

/*
 * When a logged out user tries to access the admin area, deny access.
 * Do nothing if the user is logged in.
 * `admin-post.php` and `admin-ajax.php` are white listed.
 *
 * @since 1.0
 */
add_action( 'after_setup_theme', 'secupress_move_login_maybe_die_before_admin_redirect', 12 );

function secupress_move_login_maybe_die_before_admin_redirect() {
	global $pagenow;
	// If it's not the administration area, or if it's an ajax call, no need to go further.
	if ( ! ( is_admin() && ! ( ( defined( 'DOING_AJAX' ) && DOING_AJAX ) || ( 'admin-post.php' === $pagenow && ! empty( $_REQUEST['action'] ) ) ) ) ) {
		return;
	}

	if ( is_user_admin() ) {
		$scheme = 'logged_in';
	} else {
		/**
		 * Filter the authentication redirect scheme.
		 *
		 * @since 1.0
		 *
		 * @param string $scheme Authentication redirect scheme. Default empty.
		 */
		$scheme = apply_filters( 'auth_redirect_scheme', '' );
	}

	if ( wp_validate_auth_cookie( '', $scheme ) ) {
		return;
	}

	if ( 'redir-login' === secupress_get_module_option( 'move-login_admin-access', 'redir-login', 'users-login' ) ) {
		return;
	}

	/*
	 * If you want to trigger a custom action (redirect, message, die...), add it here.
	 * Don't forget to exit/die.
	 *
	 * @since 1.0
	 */
	do_action( 'sfml_wp_admin_error' );

	$do = secupress_get_module_option( 'move-login_admin-access', 'redir-login', 'users-login' );

	switch ( $do ) {
		case 'error':
			wp_die( __( 'Cheatin&#8217; uh?' ), __( 'Nope :)', 'secupress' ), array( 'response' => 501 ) );
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
