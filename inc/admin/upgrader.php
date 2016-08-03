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
