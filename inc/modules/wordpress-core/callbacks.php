<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

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

	// There are no settings to save.
	return array( 'sanitized' => 1 );
}
