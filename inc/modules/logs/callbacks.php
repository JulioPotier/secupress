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
function __secupress_logs_settings_callback( $settings ) {
	$modulenow = 'logs';
	$activate  = secupress_get_submodule_activations( $modulenow );

	// (De)Activation.
	if ( false !== $activate ) {
		secupress_manage_submodule( $modulenow, 'action-logs', ! empty( $activate['action-logs_activated'] ) );
		secupress_manage_submodule( $modulenow, '404-logs',    ! empty( $activate['404-logs_activated'] ) );
	}

	// There are no settings to save.
	return array();
}
