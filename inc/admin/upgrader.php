<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/*------------------------------------------------------------------------------------------------*/
/* MIGRATE / UPGRADE ============================================================================ */
/*------------------------------------------------------------------------------------------------*/

add_action( 'admin_init', 'secupress_upgrader' );
/**
 * Tell WP what to do when admin is loaded aka upgrader
 *
 * @since 1.0
 */
function secupress_upgrader() {
	// Grab some infos.
	$actual_version = secupress_get_option( 'version' );

	// You can hook the upgrader to trigger any action when WP SecuPress is upgraded.
	// First install.
	if ( ! $actual_version ) {
		/**
		 * Allow to prevent plugin first install hooks to fire.
		 *
		 * @since 1.0
		 *
		 * @param (bool) $prevent True to prevent triggering first install hooks. False otherwise.
		 */
		if ( ! apply_filters( 'secupress.prevent_first_install', false ) ) {
			/**
			 * Fires on the plugin first install.
			 *
			 * @since 1.0
			 *
			 * @param (string) $module The module to reset. "all" means all modules at once.
			 */
			do_action( 'secupress.first_install', 'all' );
		}
	}
	// Already installed but got updated.
	elseif ( SECUPRESS_VERSION !== $actual_version ) {
		$new_version = SECUPRESS_VERSION;
		/**
		 * Fires when SecuPress is upgraded.
		 *
		 * @since 1.0
		 *
		 * @param (string) $new_version    The version being upgraded to.
		 * @param (string) $actual_version The previous version.
		 */
		do_action( 'secupress.upgrade', $new_version, $actual_version );
	}

	// If any upgrade has been done, we flush and update version.
	if ( did_action( 'secupress.first_install' ) || did_action( 'secupress.upgrade' ) ) {

		$options = get_site_option( SECUPRESS_SETTINGS_SLUG ); // Do not use secupress_get_option() here.
		$options['version'] = SECUPRESS_VERSION;

		if ( did_action( 'secupress.first_install' ) ) {
			$options['hash_key'] = secupress_generate_key( 64 );
		}

		$keys = secupress_check_key( 'live' );

		if ( is_array( $keys ) ) {
			$options = array_merge( $keys, $options );
		}

		update_site_option( SECUPRESS_SETTINGS_SLUG, $options );
	}/* elseif ( empty( $_POST ) && secupress_valid_key() ) { // WPCS: CSRF ok.
		secupress_check_key( 'transient_30' );
	}

	if ( ! secupress_valid_key() && current_user_can( secupress_get_capability() ) && ( ! isset( $_GET['page'] ) || 'secupress' !== $_GET['page'] ) ) {
		add_action( 'admin_notices', 'secupress_need_api_key' ); // ////.
	}*/
}


add_action( 'secupress.upgrade', 'secupress_new_upgrade', 10, 2 );
/**
 * What to do when SecuPress is updated, depending on versions.
 *
 * @since 1.0
 *
 * @param (string) $secupress_version The version being upgraded to.
 * @param (string) $actual_version    The previous version.
 */
function secupress_new_upgrade( $secupress_version, $actual_version ) {
	global $wpdb;

	// < 1.0
	if ( version_compare( $actual_version, '1.0', '<' ) ) {

		secupress_deactivation();

		// From uninstall.php.

		// Transients.
		$transients = $wpdb->get_col( "SELECT option_name FROM $wpdb->options WHERE option_name LIKE '_transient_secupress_%' OR option_name LIKE '_transient_secupress-%'" );
		array_map( 'delete_transient', $transients );

		// Site transients.
		$transients = $wpdb->get_col( "SELECT option_name FROM $wpdb->options WHERE option_name LIKE '_site_transient_secupress_%' OR option_name LIKE '_site_transient_secupress-%'" );
		array_map( 'delete_site_transient', $transients );

		if ( is_multisite() ) {
			$transients = $wpdb->get_col( "SELECT meta_key FROM $wpdb->sitemeta WHERE meta_key LIKE '_site_transient_secupress_%' OR meta_key LIKE '_site_transient_secupress-%'" );
			array_map( 'delete_site_transient', $transients );
		}

		// Options.
		$options = $wpdb->get_col( "SELECT option_name FROM $wpdb->options WHERE option_name LIKE 'secupress_%'" );
		array_map( 'delete_option', $options );

		if ( is_multisite() ) {
			// Site options.
			$options = $wpdb->get_col( "SELECT meta_key FROM $wpdb->sitemeta WHERE meta_key LIKE 'secupress_%'" );
			array_map( 'delete_site_option', $options );
		}

		// User metas.
		$wpdb->query( "DELETE FROM $wpdb->usermeta WHERE meta_key LIKE 'secupress_%' OR meta_key LIKE '%_secupress_%'" );

		secupress_activation();
	}

	// < 1.0.3
	if ( version_compare( $actual_version, '1.0.3', '<' ) ) {
		// Remove some User Agents that are too generic from the settings.
		$user_agents_options = get_option( 'secupress_firewall_settings' );

		if ( is_array( $user_agents_options ) && ! empty( $user_agents_options['bbq-headers_user-agents-list'] ) ) {
			$user_agents_options['bbq-headers_user-agents-list'] = secupress_sanitize_list( $user_agents_options['bbq-headers_user-agents-list'] );
			$user_agents_options['bbq-headers_user-agents-list'] = explode( ', ', $user_agents_options['bbq-headers_user-agents-list'] );
			$user_agents_options['bbq-headers_user-agents-list'] = array_diff( $user_agents_options['bbq-headers_user-agents-list'], array( 'attache', 'email', 'Fetch', 'Link', 'Ping', 'Proxy' ) );
			$user_agents_options['bbq-headers_user-agents-list'] = implode( ', ', $user_agents_options['bbq-headers_user-agents-list'] );
			update_option( 'secupress_firewall_settings', $user_agents_options );
		}
	}

	// < 1.0.4
	if ( version_compare( $actual_version, '1.0.4', '<' ) ) {
		// Get post ids from logs.
		$post_ids = $wpdb->get_col( "SELECT ID FROM $wpdb->posts WHERE post_type LIKE 'secupress_log_%'" );

		// Delete Postmeta.
		$sql = sprintf( "DELETE FROM $wpdb->postmeta WHERE post_id IN (%s)", implode( ",", $post_ids ) );
		$wpdb->query( $sql );

		// Delete Posts.
		$sql = sprintf( "DELETE FROM $wpdb->posts WHERE ID IN (%s)", implode( ",", $post_ids ) );
		$wpdb->query( $sql );
	}
}
