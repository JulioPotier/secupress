<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/**
 * Callback to filter, sanitize and de/activate submodules
 *
 * @since 1.0
 *
 * @param (array) $settings The module settings.
 *
 * @return (array) The sanitized and validated settings.
 */
function secupress_logs_settings_callback( $settings ) {
	$modulenow = 'logs';
	$activate  = secupress_get_submodule_activations( $modulenow );
	secupress_manage_submodule( $modulenow, 'action-logs', isset( $activate['logs_action-logs-activated'] ) );
	secupress_manage_submodule( $modulenow, '404-logs', isset( $activate['logs_404-logs-activated'] ) );
	/**
	 * Filter the settings before saving.
	 *
	 * @since 1.4.9
	 *
	 * @param (array)      $settings The module settings.
	 * @param (array\bool) $activate Contains the activation rules for the different modules
	 */
	$settings = apply_filters( "secupress_{$modulenow}_settings_callback", $settings, $activate );

	return $settings;
}