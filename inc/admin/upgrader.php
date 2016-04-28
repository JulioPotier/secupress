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
		if ( ! secupress_maybe_migrate_mono_to_multi() ) {
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
	if ( did_action( 'secupress.first_install' ) || did_action( 'wp_secupress_upgrade' ) ) {

		$options = get_site_option( SECUPRESS_SETTINGS_SLUG ); // Do not use secupress_get_option() here.
		$options['version'] = SECUPRESS_VERSION;

		$keys = secupress_check_key( 'live' );
		if ( is_array( $keys ) ) {
			$options = array_merge( $keys, $options );
		}

		update_site_option( SECUPRESS_SETTINGS_SLUG, $options );
	} elseif ( empty( $_POST ) && secupress_valid_key() ) { // WPCS: CSRF ok.
		secupress_check_key( 'transient_30' );
	}

	if ( ! secupress_valid_key() && current_user_can( secupress_get_capability() ) && ( ! isset( $_GET['page'] ) || 'secupress' !== $_GET['page'] ) ) {
		add_action( 'admin_notices', 'secupress_need_api_key' );
	}
}


/**
 * When switching a monosite installation to multisite, migrate options to the sitemeta table.
 *
 * @since 1.0
 *
 * @return (bool) True if some options have been imported.
 */
function secupress_maybe_migrate_mono_to_multi() {
	if ( ! is_multisite() ) {
		return false;
	}

	$modules    = secupress_get_modules();
	$has_values = false;

	foreach ( $modules as $module => $atts ) {
		$value = get_option( "secupress_{$module}_settings" );

		if ( false !== $value ) {
			add_site_option( "secupress_{$module}_settings" );
			$has_values = true;
		}

		delete_option( "secupress_{$module}_settings" );
	}

	$options = array( SECUPRESS_SETTINGS_SLUG, SECUPRESS_SCAN_SLUG, SECUPRESS_FIX_SLUG, SECUPRESS_SCAN_TIMES, SECUPRESS_BAN_IP, 'secupress_captcha_keys' );

	foreach ( $options as $option ) {
		$value = get_option( $option );

		if ( false !== $value ) {
			add_site_option( $option );
			$has_values = true;
		}

		delete_option( $option );
	}

	return $has_values;
}
