<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/*------------------------------------------------------------------------------------------------*/
/* ON MODULE SETTINGS SAVE ====================================================================== */
/*------------------------------------------------------------------------------------------------*/

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
	$settings  = $settings ? $settings : array();
	$activate  = secupress_get_submodule_activations( $modulenow );

	if ( isset( $settings['sanitized'] ) ) {
		return $settings;
	}
	$settings['sanitized'] = 1;

	// Activate/deactivate.
	if ( secupress_is_pro() ) {
		secupress_manage_submodule( $modulenow, 'bad-file-extensions', ! empty( $activate['bad-file-extensions_activated'] ) );
	} else {
		secupress_deactivate_submodule( $modulenow, array( 'bad-file-extensions' ) );
	}

	return $settings;
}
