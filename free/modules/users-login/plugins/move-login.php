<?php
/**
 * Module Name: Move Login
 * Description: Change your login URL.
 * Main Module: users_login
 * Author: SecuPress
 * Version: 1.3.1
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );

/** --------------------------------------------------------------------------------------------- */
/** INCLUDES ==================================================================================== */
/** --------------------------------------------------------------------------------------------- */

// Priorize other "move login" like plugins.
if ( ! function_exists( 'is_plugin_active' ) ) {
	require( ABSPATH . 'wp-admin/includes/plugin.php' );
}
if ( function_exists( 'is_plugin_active' ) && (
	is_plugin_active( 'wps-hide-login/wps-hide-login.php' )
	) ) {
	return;
}

$wp_rewrite = new WP_Rewrite();
if ( ! $wp_rewrite->using_permalinks() ) {
	return;
}

// EMERGENCY BYPASS!
if ( defined( 'SECUPRESS_ALLOW_LOGIN_ACCESS' ) && SECUPRESS_ALLOW_LOGIN_ACCESS ) {
	return;
}


/** --------------------------------------------------------------------------------------------- */
/** TOOLS ======================================================================================= */
/** --------------------------------------------------------------------------------------------- */

/**
 * Get default slugs.
 *
 * @since 1.0
 * @author Grégory Viguier
 *
 * @return (array)
 */
function secupress_move_login_get_default_slugs() {
	$slugs = array(
		// custom.
		'login'     => 1,
		'register'  => 1,
		'registration_disabled'  => 1,
		// hardcoded.
		'postpass'               => 1,
		'passwordless_autologin' => 1,
		'confirmaction'          => 1,
		'confirm_admin_email'    => 1,
	);

	return $slugs;
}

/**
 * Get the slugs the user has set.
 *
 * @since 1.0
 * @author Grégory Viguier
 *
 * @return (array)
 */
function secupress_move_login_get_slugs() {
	$slugs = secupress_move_login_get_default_slugs();

	foreach ( $slugs as $action => $dummy ) {
		$slugs[ $action ] = secupress_get_module_option( 'move-login_slug-' . $action, $action, 'users-login' );
		$slugs[ $action ] = sanitize_title( $slugs[ $action ], $action, 'display' );
	}
	$slugs['postpass']                = 'postpass';
	$slugs['passwordless_autologin']  = 'passwordless_autologin';
	$slugs['confirmaction']           = 'confirmaction';
	$slugs['confirm_admin_email']     = 'confirm_admin_email';

	return $slugs;
}

/** --------------------------------------------------------------------------------------------- */
/** FILTER URLS ================================================================================= */
/** --------------------------------------------------------------------------------------------- */

add_filter( 'site_url', 'secupress_move_login_site_url', 10, 4 );
/**
 * Filter the site URL.
 *
 * @since 1.0
 * @author Grégory Viguier
 *
 * @param (string)      $url     The complete site URL including scheme and path.
 * @param (string)      $path    Path relative to the site URL. Blank string if no path is specified.
 * @param (string|null) $scheme  Scheme to give the site URL context. Accepts 'http', 'https', 'login',
 *                               'login_post', 'admin', 'relative' or null.
 * @param (int|null)    $blog_id Blog ID, or null for the current blog.
 *
 * @return (string) The site URL.
 */
function secupress_move_login_site_url( $url, $path, $scheme, $blog_id = null ) {
	if ( secupress_is_submodule_active( 'users-login', 'move-login' ) && ! empty( $path ) && is_string( $path ) && false === strpos( $path, '..' ) && 0 === strpos( ltrim( $path, '/' ), 'wp-login.php' ) ) {
		$blog_id = (int) $blog_id;
		// Base url.
		if ( empty( $blog_id ) || get_current_blog_id() === $blog_id || ! is_multisite() ) {
			$url = get_option( 'siteurl' );
		} else {
			$url = get_blog_option( $blog_id, 'siteurl' );
		}

		$url = set_url_scheme( $url, $scheme );
		$url = rtrim( $url, '/' ) . secupress_move_login_set_path( $path );
	}
	return $url;
}


add_filter( 'network_site_url', 'secupress_move_login_network_site_url', 10, 3 );
/**
 * Filter the network site URL: don't use `network_site_url()` for the login URL ffs!
 *
 * @since 1.0
 * @author Grégory Viguier
 *
 * @param (string)      $url    The complete network site URL including scheme and path.
 * @param (string)      $path   Path relative to the network site URL. Blank string if
 *                              no path is specified.
 * @param (string|null) $scheme Scheme to give the URL context. Accepts 'http', 'https',
 *                              'relative' or null.
 *
 * @return (string) The network site URL.
 */
function secupress_move_login_network_site_url( $url, $path, $scheme ) {
	if ( secupress_is_submodule_active( 'users-login', 'move-login' ) && ! empty( $path ) && is_string( $path ) && false === strpos( $path, '..' ) && 0 === strpos( ltrim( $path, '/' ), 'wp-login.php' ) ) {
		return site_url( $path, $scheme );
	}

	return $url;
}


add_filter( 'logout_url', 'secupress_move_login_logout_url', 1 );
/**
 * Filter the logout URL: `wp_logout_url()` add the action param after using `site_url()`.
 *
 * @since 1.0
 * @author Grégory Viguier
 *
 * @param (string) $logout_url The Log Out URL.
 *
 * @return (string) The Log Out URL.
 */
function secupress_move_login_logout_url( $logout_url ) {
	return secupress_move_login_login_to_action( $logout_url, 'logout' );
}


add_filter( 'lostpassword_url', 'secupress_move_login_lostpassword_url', 1 );
/**
 * Filter the Lost Password URL: `wp_lostpassword_url()` add the action param after using `network_site_url()`.
 *
 * @since 1.0
 * @author Grégory Viguier
 *
 * @param (string) $lostpassword_url The lost password page URL.
 *
 * @return (string) The lost password page URL.
 */
function secupress_move_login_lostpassword_url( $lostpassword_url ) {
	return secupress_move_login_login_to_action( $lostpassword_url, 'lostpassword' );
}


add_filter( 'wp_redirect', 'secupress_move_login_redirect', 10 );
/**
 * Filter the redirect location: some redirections are hard-coded.
 *
 * @since 1.0
 * @author Grégory Viguier
 *
 * @param (string) $location The path to redirect to.
 *
 * @return (string) The path to redirect to.
 */
function secupress_move_login_redirect( $location ) {
	if ( ! secupress_is_submodule_active( 'users-login', 'move-login' ) ) {
		return $location;
	}
	$location_base = explode( '?', $location, 2 );
	$location_base = reset( $location_base );
	if ( site_url( $location_base ) === site_url( 'wp-login.php' ) && strpos( wp_get_referer(), 'wp-login.php' ) === false ) {
		return secupress_move_login_site_url( $location, $location, 'login', get_current_blog_id() );
	}

	if ( trailingslashit( $location_base ) === trailingslashit( wp_login_url() ) ) {
		$location_query = wp_parse_url( $location );

		if ( empty( $location_query['query'] ) ) {
			return $location;
		}

		wp_parse_str( $location_query['query'], $location_query );

		if ( ! empty( $location_query['registration'] ) && 'disabled' === $location_query['registration'] ) {
			return $_REQUEST['action'] = 'registration_disabled';
		}
		if ( empty( $location_query['action'] ) ) {
			return $location;
		}

		return secupress_move_login_login_to_action( $location, $location_query['action'] );
	}

	return $location;
}


add_filter( 'update_welcome_email', 'secupress_move_login_update_welcome_email', 10, 2 );
/**
 * Multisite: filter the content of the welcome email after site activation.
 *
 * @since 1.0
 * @author Grégory Viguier
 *
 * @param (string) $welcome_email Message body of the email.
 * @param (int)    $blog_id       Blog ID.
 *
 * @return (string) Message body of the email.
 */
function secupress_move_login_update_welcome_email( $welcome_email, $blog_id ) {
	if ( false === strpos( $welcome_email, 'wp-login.php' ) ) {
		return $welcome_email;
	}

	$url = get_blogaddress_by_id( $blog_id );

	switch_to_blog( $blog_id );
	$login_url = wp_login_url();
	restore_current_blog();

	return str_replace( $url . 'wp-login.php', $login_url, $welcome_email );
}


/** --------------------------------------------------------------------------------------------- */
/** TOOLS ======================================================================================= */
/** --------------------------------------------------------------------------------------------- */

/**
 * Set the relative path: `wp-login.php?action=register -> /register`.
 *
 * @since 1.0
 * @author Grégory Viguier
 *
 * @param (string) $path Path relative to the site URL.
 *
 * @return (string) The new path relative to the site URL, with our custom slug.
 */
function secupress_move_login_set_path( $path ) {
	$slugs = secupress_move_login_get_slugs();
	$other = array( 'retrievepassword' => 1, 'rp' => 1, 'lostpassword' => 1, 'resetpass' => 1 );
	$other = array_diff_key( $other, $slugs );

	// Get the action.
	$parsed_path = wp_parse_url( $path );

	if ( ! empty( $parsed_path['query'] ) ) {
		wp_parse_str( $parsed_path['query'], $params );
		$action = ! empty( $params['action'] ) ? $params['action'] : 'login';

		if ( isset( $params['key'] ) ) {
			$action = 'resetpass';
		}

		if ( ! isset( $slugs[ $action ] ) && ! isset( $other[ $action ] ) && false === has_filter( 'login_form_' . $action ) ) {
			$action = 'login';
		}
	} else {
		$action = 'login';
	}
	// Set the path.
	if ( isset( $slugs[ $action ] ) ) {
		$path = str_replace( 'wp-login.php', $slugs[ $action ], $path );
		$path = remove_query_arg( 'action', $path );
	} else {
		// In case of a custom action.
		$path = str_replace( 'wp-login.php', $slugs['login'], $path );
		$path = add_query_arg( 'action', $action, $path );
	}

	return '/' . ltrim( $path, '/' );
}


/**
 * Set the URL: `login?action=logout -> /logout`.
 * If the action is not present when we try to build the new URL, we fallback to `/login`. Then we can use this function after the action is added.
 *
 * @since 1.0
 * @author Grégory Viguier
 *
 * @param (string) $link The URL.
 * @param (string) $action The action.
 *
 * @return (string) The new URL, with our custom slug.
 */
function secupress_move_login_login_to_action( $link, $action ) {
	$slugs = secupress_move_login_get_slugs();
	if ( isset( $slugs[ $action ] ) ) {
		$slug = $slugs[ $action ];
		$link = str_replace( array( '/' . $slugs['login'], '?amp;' ), array( '/' . $slug, '?' ), remove_query_arg( 'action', $link ) );
	} else {
		$slug = $slugs['login'];
	}

	$link = add_query_arg( 'action', $action, $link );

	return $link;
}

add_action( 'login_head', 'secupress_hack_global_error' );
/**
 * Prevent to display a '404' login error message from WP
 *
 * @since 1.3.1
 * @author Julio Potier
 **/
function secupress_hack_global_error() {
	global $error;
	if ( '404' === $error ) {
		$error = ''; // Triggers a PHPCS "Overriding WordPress globals is prohibited" message, sorry mate, can't help.
	}
}


add_filter( 'user_request_action_email_content', 'secupress_user_request_action_email_content_move_login_url', 1, 2 );
/**
 * Filter the content to replace first the confirl URL in order to hide the moved login url with a hardcoded one "conformaction".
 *
 * @return (string) $email_text
 *
 * @param (string) $email_text The email
 * @param (array)  $email_data The data
 *
 * @since 1.4.5
 * @author Julio Potier
 **/
function secupress_user_request_action_email_content_move_login_url( $email_text, $email_data ) {
	$confirmaction_query = explode( '?', $email_data['confirm_url'] );
	$confirmaction_query = end( $confirmaction_query );
	$confirmaction_url   = site_url( 'wp-login.php?' . $confirmaction_query );
	$email_text          = str_replace( '###CONFIRM_URL###', $confirmaction_url, $email_text );
	return $email_text;
}

/** --------------------------------------------------------------------------------------------- */
/** REMOVE DEFAULT WORDPRESS REDIRECTIONS TO LOGIN AND ADMIN AREAS ============================== */
/** --------------------------------------------------------------------------------------------- */

/**
 * WordPress redirects some URLs (`wp-admin`, `dashboard`, `admin`) to the administration area,
 * and some others (`wp-login.php`, `login`) to the login page.
 * We don't want that, so we remove the hook.
 *
 * @since 1.0
 * @author Grégory Viguier
 */
remove_action( 'template_redirect', 'wp_redirect_admin_locations', 1000 );


add_filter( 'rewrite_rules_array', 'secupress_move_login_remove_rewrite_rules' );
/**
 * Filter the full set of generated rewrite rules.
 *
 * @since 1.0
 * @author Grégory Viguier
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


/** --------------------------------------------------------------------------------------------- */
/** DENY ACCESS TO THE LOGIN FORM =============================================================== */
/** --------------------------------------------------------------------------------------------- */

add_action( 'login_init', 'secupress_move_login_maybe_deny_login_page', 0 );
add_action( 'secure_auth_redirect', 'secupress_move_login_maybe_deny_login_page', 0 );
/**
 * When displaying the login page, if the URL does not matches those in our settings, deny access.
 * Does nothing if the user is logged in.
 *
 * @since 1.0
 * @param (boolean) $secure The var to be filtered, but we won't.
 * @author Grégory Viguier
 */
function secupress_move_login_maybe_deny_login_page( $secure = true ) {
	// If the user is logged in, do nothing, let WP redirect this user to the administration area.
	if ( is_user_logged_in() ) {
		return $secure;
	}
	$parsed = wp_parse_url( $_SERVER['REQUEST_URI'] );
	$parsed = ! empty( $parsed['path'] ) ? $parsed['path'] : '';
	$parsed = trim( $parsed, '/' );
	$subdir = secupress_get_wp_directory();
	$slugs  = secupress_move_login_get_slugs();
	if ( $subdir ) {
		foreach ( $slugs as $action => $slug ) {
			$slugs[ $action ] = $subdir . $slug;
		}
	}

	$slugs = array_flip( $slugs );

	if ( isset( $slugs[ $parsed ] ) ) {
		// Display the login page.
		if ( ! defined( 'DONOTCACHEPAGE' ) ) {
			// Tell cache plugins not to cache the login page.
			define( 'DONOTCACHEPAGE', true );
		}

		return $secure;
	}

	// You shall not pass!
	secupress_move_login_deny_login_access();
}


/**
 * Perform the action set for the login page: die or redirect.
 *
 * @since 1.0
 * @author Grégory Viguier
 *
 * @since 1.3.1 Only redirect choice left
 * @author Julio Potier
 */
function secupress_move_login_deny_login_access() {
	/**
	 * If you want to trigger a custom action (redirect, message, die...), add it here.
	 * Don't forget to exit/die.
	 *
	 * @since 1.0
	 * @author Grégory Viguier
	 */
	do_action( 'secupress.plugin.move-login.deny_login_access' );

	secupress_die( secupress_check_ban_ips_form( [
													'content'  => '<p>' . __( 'This page does not exist, has moved or you are not allowed to access it.', 'secupress' ) . '</p>',
													'time_ban' => -1,
													'id'       => __FUNCTION__,
													'ip'       => 'admin', // use for nonce check, see action below v.
													'action'   => 'action="' . wp_nonce_url( admin_url( 'admin-post.php?action=secupress_unlock_admin' ), 'secupress-unban-ip-admin' ) . '"',
													] ), '', array( 'force_die' => true )
	);
}


add_action( 'wp', 'secupress_fallback_slug_redirect', 0 );
/**
 * Will include the wp-loing.php file/template if the URL triggers the new slug
 *
 * @since 2.0.1 Use determine_locale()
 * @since 1.4 on "wp" hook instead of "template_redirect" because of many "404 management" plugins.
 * @since 1.3.1
 * @author Julio Potier
 **/
function secupress_fallback_slug_redirect( $wp, $test = false ) {
	if ( ! $test && ( ! is_404() || ! isset( $_SERVER['REQUEST_URI'] ) ) ) {
		return;
	}
	$slugs  = secupress_move_login_get_slugs();
	$base   = secupress_get_wp_directory();
	$regex  = '^' . $base . '(' . implode( '|', $slugs ) . ')$';
	$parsed = wp_parse_url( $_SERVER['REQUEST_URI'] );
	$parsed = ! empty( $parsed['path'] ) ? $parsed['path'] : '';
	$parsed = trim( $parsed, '/' );
	if ( preg_match( "@{$regex}@", $parsed ) ) {
		$slugs  = array_flip( secupress_move_login_get_slugs() );
		$parsed = explode( '/', $parsed );
		$parsed = end( $parsed );

		if ( ! isset( $_REQUEST['action'] ) && isset( $slugs[ $parsed ] ) ) {
			$_REQUEST['action'] = $slugs[ $parsed ];
		}

		if ( ! $test && is_user_logged_in() && ! isset( $_REQUEST['action'] ) ) {
			wp_safe_redirect( admin_url(), 302 );
			die();
		}

		if ( $test ) {
			return true;
		}
		$user_login = '';
		global $error;
		$error      = '';
		if ( isset( $_REQUEST['action'] ) && 'registration_disabled' === $_REQUEST['action'] ) {
			$error = __( '<strong>Error</strong>: User registration is currently not allowed.' );
		}

		require( ABSPATH . 'wp-login.php' );
		die();
	}
}

add_action( 'setup_theme', 'secupress_set_wp_lang_early', 1 );
/**
 * Add this filter early for ligne 516 above
 *
 * @since 2.0.1
 * @author Julio Potier
 *
 * @see secupress_set_wp_lang()
 *
 **/
function secupress_set_wp_lang_early( $locale ) {
	if ( secupress_fallback_slug_redirect( null, true ) ) {
		add_filter( 'determine_locale', 'secupress_set_wp_lang' );
	}
}

/**
 * Change the locale if ?wp_lang param is set
 *
 * @since 2.0.1
 * @author Julio Potier
 *
 * @return (string) $locale
 **/
function secupress_set_wp_lang( $locale ) {
	if ( ! empty( $_GET['wp_lang'] ) ) {
		$locale = sanitize_text_field( $_GET['wp_lang'] );
	}
	return $locale;
};

add_filter( 'register_url', 'secupress_register_url_redirect' );
/**
 * Fordib the redirection on the registration URL if not logged-in, you have to know the correct new page
 *
 * @param (string) $url The register_url from WP.
 * @since 1.4
 * @return (string) $url
 * @author Julio Potier
 **/
function secupress_register_url_redirect( $url ) {
	if ( ! is_user_logged_in() ) {
		$current_url = secupress_get_current_url( 'raw' );
		if ( $url === $current_url ) {
			secupress_move_login_deny_login_access();
		}
	}
	return $url;
}
