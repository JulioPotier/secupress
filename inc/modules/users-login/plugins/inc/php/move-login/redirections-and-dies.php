<?php
defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

/*------------------------------------------------------------------------------------------------*/
/* REMOVE DEFAULT WORDPRESS REDIRECTIONS TO LOGIN AND ADMIN AREAS =============================== */
/*------------------------------------------------------------------------------------------------*/

remove_action( 'template_redirect', 'wp_redirect_admin_locations', 1000 );


/*------------------------------------------------------------------------------------------------*/
/* IF THE CURRENT URI IS NOT LISTED IN OUR SLUGS, DENY ACCESS TO THE FORM ======================= */
/*------------------------------------------------------------------------------------------------*/

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
	// If you want to display the login form somewhere outside wp-login.php, add your URIs here.
	$new_slugs = apply_filters( 'sfml_slugs_not_to_kill', array(), $uri, $subdir, $slugs );
	$slugs     = is_array( $new_slugs ) && ! empty( $new_slugs ) ? array_merge( $new_slugs, $slugs ) : $slugs;
	$slugs     = array_flip( $slugs );

	if ( isset( $slugs[ $uri ] ) ) {
		return;
	}

	// If you want to trigger a custom action (redirect, die...), add it here.
	do_action( 'sfml_wp_login_error' );

	$do = secupress_get_module_option( 'move-login_wp-login-access', 'error', 'users-login' );

	switch ( $do ) {
		case 'redir_404':
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
/* IF NOT CONNECTED, DO NOT REDIRECT FROM ADMIN AREA TO WP-LOGIN.PHP ============================ */
/*------------------------------------------------------------------------------------------------*/

add_action( 'after_setup_theme', 'secupress_move_login_maybe_die_before_admin_redirect', 12 );

function secupress_move_login_maybe_die_before_admin_redirect() {
	global $pagenow;
	// If it's not the administration area, or if it's an ajax call, no need to go further.
	if ( ! ( is_admin() && ! ( ( defined( 'DOING_AJAX' ) && DOING_AJAX ) || ( 'admin-post.php' === $pagenow && ! empty( $_REQUEST['action'] ) ) ) ) ) {
		return;
	}

	$scheme = is_user_admin() ? 'logged_in' : apply_filters( 'auth_redirect_scheme', '' );

	if ( wp_validate_auth_cookie( '', $scheme ) ) {
		return;
	}

	if ( 'redir-login' === secupress_get_module_option( 'move-login_admin-access', 'redir-login', 'users-login' ) ) {
		return;
	}

	// If you want to trigger a custom action (redirect, die...), add it here.
	do_action( 'sfml_wp_admin_error' );

	$do = secupress_get_module_option( 'move-login_admin-access', 'redir-login', 'users-login' );

	switch ( $do ) {
		case 'error':
			wp_die( __( 'Cheatin&#8217; uh?' ), __( 'Nope :)', 'secupress' ), array( 'response' => 501 ) );
		case 'redir_404':
			$redirect = apply_filters( 'sfml_404_error_page', home_url( '404' ) );
			wp_redirect( esc_url_raw( user_trailingslashit( $redirect ) ) );
			exit;
		case 'redir_home':
			wp_redirect( esc_url_raw( user_trailingslashit( home_url() ) ) );
			exit;
	}

	die();
}
