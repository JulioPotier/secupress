<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

add_filter( 'http_request_args', 'secupress_add_own_ua', 10, 2 );
/**
 * Force our user agent header when we hit our urls
 *
 * @since 1.0
 *
 * @param (array)  $r   The request parameters.
 * @param (string) $url The request URL.
 *
 * @return (array)
 */
function secupress_add_own_ua( $r, $url ) {
	if ( false !== strpos( $url, 'secupress.me' ) ) {
		$r['headers']['X-SECUPRESS'] = secupress_user_agent( $r['user-agent'] );
	}

	return $r;
}


add_filter( 'admin_page_access_denied', 'secupress_is_jarvis', 9 );
/**
 * Easter egg when you visit a "secupress" page with a typo in it, or just don't have access (not under white label).
 *
 * @since 1.0
 * @author Tony Stark
 */
function secupress_is_jarvis() {
	if ( ! secupress_is_white_label() && isset( $_GET['page'] ) && strpos( $_GET['page'], 'secupress' ) !== false ) { // Do not use SECUPRESS_PLUGIN_SLUG, we don't want that in white label.
		wp_die( '[J.A.R.V.I.S.] You are not authorized to access this area.<br/>[Christine Everhart] Jesus ...<br/>[Pepper Potts] That\'s Jarvis, he runs the house.', 403 );
	}
}
