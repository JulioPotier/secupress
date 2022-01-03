<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );


/**
 * Register the correct setting with the correct callback for the module.
 *
 * @param (string) $module      A module. Used to build the option group and maybe the option name.
 * @param (string) $option_name An option name.
 *
 * @since 1.0
 */
function secupress_register_setting( $module, $option_name = false ) {
	$option_group      = "secupress_{$module}_settings";
	$option_name       = $option_name ? $option_name : "secupress_{$module}_settings";
	$sanitize_module   = str_replace( '-', '_', $module );
	$sanitize_callback = "secupress_pro_{$sanitize_module}_settings_callback";

	if ( ! secupress_is_pro() || ! function_exists( $sanitize_callback ) ) {
		$sanitize_callback = "secupress_{$sanitize_module}_settings_callback";
	}

	if ( ! is_multisite() ) {
		if ( is_admin() ) {
			// Filter the capability required when using the Settings API.
			add_filter( "option_page_capability_$option_group", 'secupress_setting_capability_filter' );
		}
		// Register the setting.
		register_setting( $option_group, $option_name, $sanitize_callback );
		return;
	}

	$whitelist = secupress_cache_data( 'new_whitelist_network_options' );
	$whitelist = is_array( $whitelist ) ? $whitelist : array();
	$whitelist[ $option_group ]   = isset( $whitelist[ $option_group ] ) ? $whitelist[ $option_group ] : array();
	$whitelist[ $option_group ][] = $option_name;
	secupress_cache_data( 'new_whitelist_network_options', $whitelist );

	add_filter( "sanitize_option_{$option_name}", $sanitize_callback );
}


/**
 * Used to filter the capability required when using the Settings API.
 *
 * @since 1.0
 * @author Grégory Viguier
 */
function secupress_setting_capability_filter() {
	return secupress_get_capability();
}
