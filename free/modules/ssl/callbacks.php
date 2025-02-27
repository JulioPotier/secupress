<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/** --------------------------------------------------------------------------------------------- */
/** ON MODULE SETTINGS SAVE ===================================================================== */
/** --------------------------------------------------------------------------------------------- */

/**
 * Callback to filter, sanitize, validate and de/activate submodules.
 *
 * @since 2.2.6
 *
 * @param (array) $settings The module settings.
 *
 * @return (array) The sanitized and validated settings.
 */
function secupress_ssl_settings_callback( $settings ) {
	$modulenow = 'ssl';
	$activate  = secupress_get_submodule_activations( $modulenow );
	$settings  = $settings && is_array( $settings ) ? $settings : array();

	if ( isset( $settings['sanitized'] ) ) {
		return $settings;
	}
	$settings['sanitized'] = 1;

	/*
	 * Each submodule has its own sanitization function.
	 */

	// SSL Page.
	secupress_https_settings_callback( $modulenow, $settings, $activate );

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


/**
 * SSL.
 *
 * @since 2.2.6
 *
 * @param (string)     $modulenow Current module.
 * @param (array)      $settings  The module settings, passed by reference.
 * @param (bool|array) $activate  Used to (de)activate plugins.
 */
function secupress_https_settings_callback( $modulenow, &$settings, $activate ) {
	if ( false === $activate ) {
		return;
	}

	// (De)Activation.
	secupress_manage_submodule( $modulenow, 'force-https', isset( $activate['ssl_force-https'] ) );
	secupress_manage_submodule( $modulenow, 'https-redirection', isset( $activate['ssl_https-redirection'] ) );
	secupress_manage_submodule( $modulenow, 'mixed-content', isset( $activate['ssl_mixed-content'] ) );
}
