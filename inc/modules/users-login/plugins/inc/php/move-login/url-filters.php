<?php
defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

/*------------------------------------------------------------------------------------------------*/
/* FILTER URLS ================================================================================== */
/*------------------------------------------------------------------------------------------------*/

// !Site URL

add_filter( 'site_url', 'secupress_move_login_site_url', 10, 4 );

function secupress_move_login_site_url( $url, $path, $scheme, $blog_id = null ) {
	if ( ! empty( $path ) && is_string( $path ) && false === strpos( $path, '..' ) && 0 === strpos( ltrim( $path, '/' ), 'wp-login.php' ) ) {
		$blog_id = (int) $blog_id;

		// Base url
		if ( empty( $blog_id ) || get_current_blog_id() === $blog_id || ! is_multisite() ) {
			$url = get_option( 'siteurl' );
		}
		else {
			$url = get_blog_option( $blog_id, 'siteurl' );
		}

		$url = set_url_scheme( $url, $scheme );
		return rtrim( $url, '/' ) . '/' . ltrim( secupress_move_login_set_path( $path ), '/' );
	}

	return $url;
}


// !Network site URL: don't use network_site_url() for the login URL ffs!

add_filter( 'network_site_url', 'secupress_move_login_network_site_url', 10, 3 );

function secupress_move_login_network_site_url( $url, $path, $scheme ) {
	if ( ! empty( $path ) && is_string( $path ) && false === strpos( $path, '..' ) && 0 === strpos( ltrim( $path, '/' ), 'wp-login.php' ) ) {
		return site_url( $path, $scheme );
	}

	return $url;
}


// !Logout url: wp_logout_url() add the action param after using site_url().

add_filter( 'logout_url', 'secupress_move_login_logout_url', 1, 2 );

function secupress_move_login_logout_url( $logout_url, $redirect ) {
	return secupress_move_login_login_to_action( $logout_url, 'logout' );
}


// !Forgot password url: wp_lostpassword_url() add the action param after using network_site_url().

add_filter( 'lostpassword_url', 'secupress_move_login_lostpassword_url', 1, 2 );

function secupress_move_login_lostpassword_url( $lostpassword_url, $redirect ) {
	return secupress_move_login_login_to_action( $lostpassword_url, 'lostpassword' );
}


// !Redirections are hard-coded.

add_filter( 'wp_redirect', 'secupress_move_login_redirect', 10, 2 );

function secupress_move_login_redirect( $location, $status ) {
	if ( site_url( reset( ( explode( '?', $location ) ) ) ) === site_url( 'wp-login.php' ) ) {
		return secupress_move_login_site_url( $location, $location, 'login', get_current_blog_id() );
	}

	return $location;
}


// !Multisite: the "new site" welcome email.

add_filter( 'update_welcome_email', 'secupress_move_login_update_welcome_email', 10, 6 );

function secupress_move_login_update_welcome_email( $welcome_email, $blog_id, $user_id, $password, $title, $meta ) {
	if ( false === strpos( $welcome_email, 'wp-login.php' ) ) {
		return $welcome_email;
	}

	$url = get_blogaddress_by_id( $blog_id );

	switch_to_blog( $blog_id );
	$login_url = wp_login_url();
	restore_current_blog();

	return str_replace( $url . 'wp-login.php', $login_url, $welcome_email );
}


/*------------------------------------------------------------------------------------------------*/
/* TOOLS ======================================================================================== */
/*------------------------------------------------------------------------------------------------*/

// !Construct the url

function secupress_move_login_set_path( $path ) {
	$slugs = secupress_move_login_get_slugs();
	$other = array( 'retrievepassword' => 1, 'rp' => 1 );
	$other = array_diff_key( $other, $slugs );

	// Action
	$parsed_path = parse_url( $path );

	if ( ! empty( $parsed_path['query'] ) ) {
		wp_parse_str( $parsed_path['query'], $params );
		$action = ! empty( $params['action'] ) ? $params['action'] : 'login';

		if ( isset( $params['key'] ) ) {
			$action = 'resetpass';
		}

		if ( ! isset( $slugs[ $action ] ) && ! isset( $other[ $action ] ) && false === has_filter( 'login_form_' . $action ) ) {
			$action = 'login';
		}
	}
	else {
		$action = 'login';
	}

	// Path
	if ( isset( $slugs[ $action ] ) ) {
		$path = str_replace( 'wp-login.php', $slugs[ $action ], $path );
		$path = remove_query_arg( 'action', $path );
	}
	else {	// In case of a custom action
		$path = str_replace( 'wp-login.php', $slugs['login'], $path );
		$path = add_query_arg( 'action', $action, $path );
	}

	return '/' . ltrim( $path, '/' );
}


// !login?action=logout -> /logout

function secupress_move_login_login_to_action( $link, $action ) {
	$slugs = secupress_move_login_get_slugs();
	$need_action_param = false;

	if ( isset( $slugs[ $action ] ) ) {
		$slug = $slugs[ $action ];
	}
	else {	// Shouldn't happen, because this function is not used in this case.
		$slug = $slugs['login'];

		if ( false === has_filter( 'login_form_' . $action ) ) {
			$action = 'login';
		}
		else {		// In case of a custom action
			$need_action_param = true;
		}
	}

	if ( $link && false === strpos( $link, '/' . $slug ) ) {

		$link = str_replace( array( '/' . $slugs['login'], '&amp;', '?amp;', '&' ), array( '/' . $slug, '&', '?', '&amp;' ), remove_query_arg( 'action', $link ) );

		if ( $need_action_param ) {		// In case of a custom action, shouldn't happen.
			$link = add_query_arg( 'action', $action, $link );
		}
	}

	return $link;
}
