<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/*------------------------------------------------------------------------------------------------*/
/* ON MODULE SETTINGS SAVE ====================================================================== */
/*------------------------------------------------------------------------------------------------*/

/**
 * Callback to filter, sanitize, validate and de/activate submodules.
 *
 * @since 1.0
 *
 * @param (array) $settings The module settings.
 *
 * @return (array) The sanitized and validated settings.
 */
function __secupress_wordpress_core_settings_callback( $settings ) {
	$modulenow = 'wordpress-core';
	$activate  = secupress_get_submodule_activations( $modulenow );

	if ( false !== $activate ) {
		secupress_manage_submodule( $modulenow, 'minor-updates', ! empty( $activate['auto-update_minor'] ) );
		secupress_manage_submodule( $modulenow, 'major-updates', ! empty( $activate['auto-update_major'] ) );
	}

	// There are no settings to save.
	return array();
}
