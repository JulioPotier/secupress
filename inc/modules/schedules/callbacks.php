<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/** --------------------------------------------------------------------------------------------- */
/** ON FORM SUBMIT ============================================================================== */
/** --------------------------------------------------------------------------------------------- */

/**
 * Callback to filter, sanitize, validate and de/activate submodules.
 *
 * @since 1.0
 *
 * @return (array) The sanitized and validated settings.
 */
function secupress_schedules_settings_callback( $settings ) {
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
