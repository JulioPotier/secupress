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
	$modulenow    = 'logs';
	$settings     = $settings ? $settings : array();
	$old_settings = get_site_option( "secupress_{$modulenow}_settings" );

	/*
	 * Each submodule has its own sanitization function.
	 * The `$settings` parameter is passed by reference.
	 */

	// Action Logs
	__secupress_action_logs_settings_callback( $modulenow, $settings );

	return $settings;
}


/**
 * Sanitize and validate Action Logs plugin settings.
 *
 * @since 1.0
 *
 * @param (string) $modulenow Current module.
 * @param (array)  $settings  The module settings, passed by reference.
 */
function __secupress_action_logs_settings_callback( $modulenow, &$settings ) {
	// Activate or deactivate plugin.
	secupress_manage_submodule( $modulenow, 'action-logs', ! empty( $settings['action-logs_activated'] ) );
	unset( $settings['action-logs_activated'] );
}
