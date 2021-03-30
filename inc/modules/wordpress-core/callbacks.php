<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/** --------------------------------------------------------------------------------------------- */
/** ON MODULE SETTINGS SAVE ===================================================================== */
/** --------------------------------------------------------------------------------------------- */

/**
 * Callback to filter, sanitize, validate and de/activate submodules.
 *
 * @since 1.0
 *
 * @param (array) $settings The module settings.
 *
 * @return (array) The sanitized and validated settings.
 */
function secupress_wordpress_core_settings_callback( $settings ) {
	$modulenow = 'wordpress-core';
	$activate  = secupress_get_submodule_activations( $modulenow );

	if ( isset( $settings['sanitized'] ) ) {
		return array( 'sanitized' => 1 );
	}

	if ( false === $activate ) {
		return array( 'sanitized' => 1 );
	}

	// Core update.
	secupress_manage_submodule( $modulenow, 'minor-updates', ! empty( $activate['auto-update_minor'] ) );
	secupress_manage_submodule( $modulenow, 'major-updates', ! empty( $activate['auto-update_major'] ) );

	// File editor.
	secupress_manage_submodule( $modulenow, 'wp-config-constant-file-edit', ! empty( $activate['wp-config_disallow_file_edit'] ) );

	// Unfiltered HTML.
	secupress_manage_submodule( $modulenow, 'wp-config-constant-unfiltered-html', ! empty( $activate['wp-config_disallow_unfiltered_html'] ) );

	// Unfiltered uploads.
	secupress_manage_submodule( $modulenow, 'wp-config-constant-unfiltered-uploads', ! empty( $activate['wp-config_disallow_unfiltered_uploads'] ) );

	// Database
	secupress_manage_submodule( $modulenow, 'wp-config-constant-dieondberror', ! empty( $activate['wp-config_dieondberror'] ) );

	// Repair page
	secupress_manage_submodule( $modulenow, 'wp-config-constant-repair', ! empty( $activate['wp-config_repair'] ) );

	// fs chmod
	secupress_manage_submodule( $modulenow, 'wp-config-constant-fs-chmod', ! empty( $activate['wp-config_fs_chmod'] ) );

	// Locations
	secupress_manage_submodule( $modulenow, 'wp-config-constant-locations', ! empty( $activate['wp-config_locations'] ) );

	// Debugging
	secupress_manage_submodule( $modulenow, 'wp-config-constant-debugging', ! empty( $activate['wp-config_debugging'] ) );

	// cookiehash
	secupress_manage_submodule( $modulenow, 'wp-config-constant-cookiehash', ! empty( $activate['wp-config_cookiehash'] ) );

	// saltkeys
	secupress_manage_submodule( $modulenow, 'wp-config-constant-saltkeys', ! empty( $activate['wp-config_saltkeys'] ) );

	/**
	 * Filter the settings before saving.
	 *
	 * @since 1.4.9
	 *
	 * @param (array)      $settings The module settings.
	 * @param (array\bool) $activate Contains the activation rules for the different modules
	 */
	$settings = apply_filters( "secupress_{$modulenow}_settings_callback", $settings, $activate );

	// There are no settings to save.
	return array( 'sanitized' => 1 );
}
