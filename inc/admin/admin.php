<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/** --------------------------------------------------------------------------------------------- */
/** VARIOUS ===================================================================================== */
/** --------------------------------------------------------------------------------------------- */

add_filter( 'admin_page_access_denied', 'secupress_is_jarvis', 9 );
/**
 * Easter egg when you visit a "secupress" page with a typo in it, or just don't have access (not under white label).
 *
 * @since 1.0
 * @author Tony Stark
 */
function secupress_is_jarvis() {
	if ( 'secupress_settings' === $_GET['page'] ) {
		wp_redirect( secupress_admin_url( 'modules' ) );
		die();
	}
	if ( ! secupress_is_white_label() && isset( $_GET['page'] ) && strpos( $_GET['page'], 'secupress' ) !== false ) { // Do not use SECUPRESS_PLUGIN_SLUG, we don't want that in white label.
		wp_die( '[J.A.R.V.I.S.] You are not authorized to access this area.<br/>[Christine Everhart] Jesus ...<br/>[Pepper Potts] That\'s Jarvis, he runs the house.', 403 );
	}
}


add_action( 'secupress.loaded', 'secupress_been_first' );
/**
 * Make SecuPress the first plugin loaded.
 *
 * @since 1.0
 */
function secupress_been_first() {
	if ( ! is_admin() ) {
		return;
	}

	$plugin_basename = plugin_basename( __FILE__ );

	if ( is_multisite() ) {
		$active_plugins = get_site_option( 'active_sitewide_plugins' );

		if ( isset( $active_plugins[ $plugin_basename ] ) && key( $active_plugins ) !== $plugin_basename ) {
			$this_plugin = array( $plugin_basename => $active_plugins[ $plugin_basename ] );
			unset( $active_plugins[ $plugin_basename ] );
			$active_plugins = array_merge( $this_plugin, $active_plugins );
			update_site_option( 'active_sitewide_plugins', $active_plugins );
		}
		return;
	}

	$active_plugins = get_option( 'active_plugins' );

	if ( isset( $active_plugins[ $plugin_basename ] ) && reset( $active_plugins ) !== $plugin_basename ) {
		unset( $active_plugins[ array_search( $plugin_basename, $active_plugins, true ) ] );
		array_unshift( $active_plugins, $plugin_basename );
		update_option( 'active_plugins', $active_plugins );
	}
}


/** --------------------------------------------------------------------------------------------- */
/** DETECT BAD PLUGINS AND THEMES =============================================================== */
/** --------------------------------------------------------------------------------------------- */

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
	if ( false !== get_site_transient( 'secupress-detect-bad-themes' ) ) {
		return;
	}

	$args = array(
		'timeout'   => 0.01,
		'blocking'  => false,
		'cookies'   => $_COOKIE,
		'sslverify' => apply_filters( 'https_local_ssl_verify', false ),
	);
	wp_remote_get( admin_url( 'admin-post.php' ) . '?action=secupress_refresh_bad_themes&_wpnonce=' . wp_create_nonce( 'detect-bad-themes' ), $args );

	set_site_transient( 'secupress-detect-bad-themes', 1, 6 * HOUR_IN_SECONDS );
}

if ( secupress_is_expert_mode() ) {
	add_filter( 'secupress.settings.help', '__return_empty_string' );
	add_filter( 'secupress.settings.description', '__return_empty_string' );
}


add_action( 'load-plugins.php', 'secupress_plugins_add_update_date_hooks' );
/**
 * Link each plugin to the update message hook
 *
 * @since 1.4.9
 * @author Julio Potier
 *
 * @hook load-plugins.php
 **/
function secupress_plugins_add_update_date_hooks() {
	foreach ( get_plugins() as $path => $content ) {
		add_action( 'in_plugin_update_message-' . $path, 'secupress_plugins_add_update_date', 10, 2 );
	}
}

/**
 * Display a spinner of the last update date
 *
 * @since 1.4.9
 * @author Julio Potier
 *
 * @see secupress_plugins_add_update_date_hooks
 *
 * @param (object) $plugin_data The installed plugin
 * @param (object) $new_plugin_data The future updated plugin
 * @return Prints our content
 **/
function secupress_plugins_add_update_date( $plugin_data, $new_plugin_data ) {
	$plugin_updated = get_site_transient( 'last_updated_plugin-' . $plugin_data['plugin'] );
	echo '</p><p>';
	if ( ! $plugin_updated ) {
		printf( '<img src="%1$s" alt="%2$s" width="16" height="16" title="%2$s" />',
			admin_url( '/images/wpspin_light.gif' ),
			__( 'Loading&hellip;' )
		);
	} elseif ( isset( $plugin_updated[ $plugin_data['new_version'] ] ) ) {
		$strtotime = strtotime( $plugin_updated[ $plugin_data['new_version'] ] );
		$count     = count( $plugin_updated );
		printf( __( 'Last Update v%s, it was %s ago. ' ),
			esc_html( $plugin_data['new_version'] ),
			human_time_diff( time(), $strtotime )
		);
		if ( $count > 1 ) {
			echo '</p><p>⚠️';
			printf( __( 'You are late of <abbr title="v%s" style="cursor:help">%d versions</abbr> since %s.' ),
				implode( ', v', array_keys( $plugin_updated ) ),
				$count,
				date_i18n( get_option( 'date_format' ), $strtotime )
			);
		}
	}
}

add_action( 'admin_footer-plugins.php', 'secupress_plugins_get_more_info' );
/**
 * If needed, do an async call to cearte our transient
 *
 * @since 1.4.9
 * @author Julio Potier
 *
 * @see secupress_plugins_add_update_date
 *
 * @hook admin_footer-plugins.php
 **/
function secupress_plugins_get_more_info() {
	$update_plugins = get_site_transient( 'update_plugins' );
	if ( ! isset( $update_plugins->response ) ) {
		return $update_plugins;
	}
	foreach ( $update_plugins->response as $path => $content ) {
		$tr_temp = get_site_transient( 'last_updated_plugin-' . $path );
		if ( isset( $tr_temp[ $update_plugins->response[ $path ]->new_version ] ) ) {
			continue;
		}
		$url = admin_url( 'admin-ajax.php?path=%s&slug=%s&action=%s' );
		$url = sprintf( $url, $path, $content->slug, __FUNCTION__ );
		$url = wp_nonce_url( $url, $path . $content->slug . __FUNCTION__ );
		$url = str_replace( '&amp;', '&', $url );
		wp_remote_get( $url, [ 'blocking' => false, 'timeout' => 0.01 ] );
	}
}

add_action( 'wp_ajax_secupress_plugins_get_more_info', 'secupress_plugins_get_more_info_ajax_cb' );
/**
 * Update or create ou transient to get more info on plugins rows
 *
 * @since 1.4.9
 * @author Julio Potier
 *
 * @see secupress_plugins_get_more_info
 *
 * @hook wp_ajax_secupress_plugins_get_more_info
 * @return (json) Error or Success, but only for debug because it's done async
 **/
function secupress_plugins_get_more_info_ajax_cb() {
	if ( ! isset( $_GET['path'], $_GET['path'], $_GET['_wpnonce'] ) ||
		! wp_verify_nonce( $_GET['_wpnonce'], $_GET['path'] . $_GET['slug'] . $_GET['action'] )
	) {
		wp_send_json_error( 'WRONG' );
	}
	$_CLEAN = $_GET;
	require_once( ABSPATH . '/wp-admin/includes/plugin-install.php' );
	$api = plugins_api(
		'plugin_information',
		[
			'slug'   => $_CLEAN['slug'],
			'fields' => [ 'last_updated' => true, 'rating' => false, 'ratings' => false, 'reviews' => false, 'banners' => false, 'icons' => false, 'active_installs' => false, 'group' => false, 'contributors' => false, 'requires' => false, 'compatibility' => false, 'screenshots' => false, 'sections' => false, 'short_description' => false, 'tested' => false, 'downloaded' => false, 'download_link' => false, 'versions' => false, 'homepage' => false, 'donate_link' => false, 'tags' => false, 'added' => false, 'template' => false, 'screenshot_url' => false ],
		]
	);
	if ( is_wp_error( $api ) ) {
		wp_send_json_error( 'API' );
	}
	$_transient                  = get_site_transient( 'last_updated_plugin-' . $_CLEAN['path'] );
	$_transient                  = $_transient ?: [];
	$_transient[ $api->version ] = $api->last_updated;
	set_site_transient( 'last_updated_plugin-' . $_CLEAN['path'], $_transient );
	wp_send_json_success( [ $api->version => $api->last_updated ] );
}

add_action( 'deleted_plugin', 'secupress_plugins_delete_transient_on_delete', 10, 2 );
/**
 * Delete the transient if the plugin is deleted
 *
 * @since 1.4.9
 * @author Julio Potier
 *
 * @hook deleted_plugin
 * @param (string) The path to the plugin, like "folder/file.php"
 * @param (bool)   Tell if the plugin has been deleted
 * @return
 **/
function secupress_plugins_delete_transient_on_delete( $plugin_file, $deleted ) {
	if ( $deleted ) {
		delete_site_transient( 'last_updated_plugin-' . $plugin_file );
	}
}

add_action( 'upgrader_process_complete', 'secupress_plugins_delete_transient_on_update', 10, 2 );
/**
 * Delete the transient if the plugin is updated
 *
 * @since 1.4.9
 * @author  Julio Potier
 *
 * @hook upgrader_process_complete
 * @param (void) $dummy .
 * @param (array) $options Infos on the update (theme, plugin, etc)
 * @return
 **/
function secupress_plugins_delete_transient_on_update( $dummy, $options ) {
	if ( 'plugin' === $options['type'] ) {
		delete_site_transient( 'last_updated_plugin-' . $options['plugin'] );
	}
}
