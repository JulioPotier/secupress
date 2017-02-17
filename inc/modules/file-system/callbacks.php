<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/** --------------------------------------------------------------------------------------------- */
/** ON MODULE SETTINGS SAVE ===================================================================== */
/** --------------------------------------------------------------------------------------------- */

/**
 * Callback to filter, sanitize.
 *
 * @since 1.0
 *
 * @param (array) $settings The module settings.
 *
 * @return (array) The sanitized and validated settings.
 */
function secupress_file_system_settings_callback( $settings ) {
	$modulenow = 'file-system';
	$activate  = secupress_get_submodule_activations( $modulenow );
	$settings  = $settings && is_array( $settings ) ? $settings : array();

	if ( isset( $settings['sanitized'] ) ) {
		return $settings;
	}
	$settings['sanitized'] = 1;

	// Activate/deactivate.
	secupress_manage_submodule( $modulenow, 'bad-file-extensions', ! empty( $activate['bad-file-extensions_activated'] ) && secupress_is_pro() );
	secupress_manage_submodule( $modulenow, 'directory-index', ! empty( $activate['directory-index_activated'] ) );

	return $settings;
}
