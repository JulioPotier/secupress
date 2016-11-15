<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/*------------------------------------------------------------------------------------------------*/
/* VARIOUS ====================================================================================== */
/*------------------------------------------------------------------------------------------------*/

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


/*------------------------------------------------------------------------------------------------*/
/* DETECT BAD PLUGINS AND THEMES ================================================================ */
/*------------------------------------------------------------------------------------------------*/

add_action( 'admin_footer', 'secupress_detect_bad_plugins_async_get_and_store_infos' ); // Cron ////.
/**
 * 4 times a day, launch an async call to refresh the vulnerable plugins.
 * Moved from Pro to Free + renamed. Originally `secupress_detect_bad_plugins_async_get_infos()`.
 *
 * @since 1.1.3
 */
function secupress_detect_bad_plugins_async_get_and_store_infos() {
	if ( false !== get_site_transient( 'secupress-detect-bad-plugins' ) ) {
		return;
	}

	$args = array(
		'timeout'   => 0.01,
		'blocking'  => false,
		'cookies'   => $_COOKIE,
		'sslverify' => apply_filters( 'https_local_ssl_verify', false ),
	);
	wp_remote_get( admin_url( 'admin-post.php' ) . '?action=secupress_refresh_bad_plugins&_wpnonce=' . wp_create_nonce( 'detect-bad-plugins' ), $args );

	set_site_transient( 'secupress-detect-bad-plugins', 1, 6 * HOUR_IN_SECONDS );
}


add_action( 'admin_footer', 'secupress_detect_bad_themes_async_get_and_store_infos' ); // Cron ////.
/**
 * 4 times a day, launch an async call to refresh the vulnerable themes.
 * Moved from Pro to Free + renamed. Originally `secupress_detect_bad_themes_async_get_infos()`.
 *
 * @since 1.1.3
 */
function secupress_detect_bad_themes_async_get_and_store_infos() {
	if ( false === get_site_transient( 'secupress-detect-bad-themes' ) ) {
		$args = array(
			'timeout'   => 0.01,
			'blocking'  => false,
			'cookies'   => $_COOKIE,
			'sslverify' => apply_filters( 'https_local_ssl_verify', false ),
		);
		wp_remote_get( admin_url( 'admin-post.php' ) . '?action=secupress_refresh_bad_themes&_wpnonce=' . wp_create_nonce( 'detect-bad-themes' ), $args );
		set_site_transient( 'secupress-detect-bad-themes', 1, 6 * HOUR_IN_SECONDS );
	}
}
