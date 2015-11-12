<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/*
 * Tell WP what to do when admin is loaded aka upgrader
 *
 * @since 1.0
 */
add_action( 'admin_init', 'secupress_upgrader' );

function secupress_upgrader() {
	// Grab some infos
	$actual_version = secupress_get_option( 'version' );
	// You can hook the upgrader to trigger any action when WP SecuPress is upgraded.
	// first install
	if ( ! $actual_version ){
		if ( ! secupress_maybe_upgrade_mono_to_multi() ) {
			do_action( 'wp_secupress_first_install', 'all' );
		}
	}
	// already installed but got updated.
	elseif ( SECUPRESS_VERSION !== $actual_version ) {
		do_action( 'wp_secupress_upgrade', SECUPRESS_VERSION, $actual_version );
	}
	// If any upgrade has been done, we flush and update version.
	if ( did_action( 'wp_secupress_first_install' ) || did_action( 'wp_secupress_upgrade' ) ) {
		// flush_secupress_htaccess(); ////

		secupress_renew_all_boxes( 0, array( 'secupress_warning_plugin_modification' ) );

		$options = get_site_option( SECUPRESS_SETTINGS_SLUG ); // do not use secupress_get_option() here
		$options['version'] = SECUPRESS_VERSION;

		$keys = secupress_check_key( 'live' );
		if ( is_array( $keys ) ) {
			$options = array_merge( $keys, $options );
		}

		update_site_option( SECUPRESS_SETTINGS_SLUG, $options );
	} elseif ( empty( $_POST ) && secupress_valid_key() ) {
		secupress_check_key( 'transient_30' );
	}
	/** This filter is documented in inc/admin-bar.php */
	if ( ! secupress_valid_key() && current_user_can( apply_filters( 'secupress_capacity', 'manage_options' ) ) && ( ! isset( $_GET['page'] ) || 'secupress' != $_GET['page'] ) ) {
		add_action( 'admin_notices', 'secupress_need_api_key' );
	}
}


/**
 * When switching a monosite installation to multisite, migrate options to the sitemeta table.
 *
 * @since 1.0
 *
 * @return (bool) true if some options have been imported.
 */
function secupress_maybe_upgrade_mono_to_multi() {
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

	$options = array( SECUPRESS_SETTINGS_SLUG, SECUPRESS_SCAN_SLUG, SECUPRESS_FIX_SLUG, SECUPRESS_SCAN_TIMES, SECUPRESS_BAN_IP, 'secupress_captcha_keys', );

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


/* BEGIN UPGRADER'S HOOKS */

/**
 * Keeps this function up to date at each version
 *
 * @since 1.0
 */
add_action( 'wp_secupress_first_install', 'secupress_install_modules', 9 );

function secupress_install_modules( $module ) {
	if ( 'all' === $module ) {
		// Generate an random key
		// $secret_cache_key = secupress_create_uniqid();

		// secupress_dismiss_box( 'secupress_warning_plugin_modification' );
		//// secupress_reset_white_label_values( false );

		// Create Options
		add_site_option( SECUPRESS_SETTINGS_SLUG,
			array(
				//
			)
		);
	}
}


/**
 * What to do when secupress is updated, depending on versions
 *
 * @since 1.0
 */
add_action( 'wp_secupress_upgrade', 'secupress_new_upgrade', 10, 2 );

function secupress_new_upgrade( $wp_secupress_version, $actual_version ) {
	//
}
/* END UPGRADER'S HOOKS */
