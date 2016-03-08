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
function __secupress_tools_settings_callback( $settings ) {
	$modulenow = 'tools';
	$activate  = secupress_get_submodule_activations( $modulenow );
	$settings  = $settings ? $settings : array();

	if ( isset( $settings['sanitized'] ) ) {
		return $settings;
	}
	$settings['sanitized'] = 1;

	/*
	 * Each submodule has its own sanitization function.
	 * The `$settings` parameter is passed by reference.
	 */

	// Uptime monitoring
	__secupress_uptime_monitoring_settings_callback( $modulenow, $settings, $activate );

	return $settings;
}


/**
 * Captcha plugin.
 *
 * @since 1.0
 *
 * @param (string)     $modulenow Current module.
 * @param (array)      $settings  The module settings, passed by reference.
 * @param (bool|array) $activate  Used to (de)activate plugins.
 */
function __secupress_uptime_monitoring_settings_callback( $modulenow, &$settings, $activate ) {
	// (De)Activation.
	if ( false !== $activate ) {
		secupress_manage_submodule( $modulenow, 'uptime-monitoring', ! empty( $activate['monitoring_activated'] ) );
	}

	// Settings.
	if ( empty( $settings['uptime-monitoring-token'] ) ) {
		$old_settings = get_site_option( "secupress_{$modulenow}_settings" );

		if ( ! empty( $old_settings['uptime-monitoring-token'] ) ) {
			$settings['uptime-monitoring-token'] = $old_settings['uptime-monitoring-token'];
		}
	} else {
		$settings['uptime-monitoring-token'] = sanitize_text_field( $settings['uptime-monitoring-token'] );
	}
}
