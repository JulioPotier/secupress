<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/** --------------------------------------------------------------------------------------------- */
/** ON MODULE SETTINGS SAVE ===================================================================== */
/** --------------------------------------------------------------------------------------------- */

/**
 * Callback to filter, sanitize.
 *
 * @since 1.0
 *
 * @return (array) The sanitized and validated settings.
 */
function secupress_backups_settings_callback( $settings ) {
	$modulenow = 'backups';
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
