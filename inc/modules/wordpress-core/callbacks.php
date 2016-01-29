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
	$settings  = $settings ? $settings : array();

	secupress_manage_submodule( $modulenow, 'minor-updates', ! empty( $settings['auto-update_minor'] ) );
	secupress_manage_submodule( $modulenow, 'major-updates', ! empty( $settings['auto-update_major'] ) );

	unset( $settings['auto-update_minor'], $settings['auto-update_major'] );

	return $settings;
}
