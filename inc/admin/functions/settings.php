<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


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
	$sanitize_callback = str_replace( '-', '_', $module );
	$sanitize_callback = "__secupress_{$sanitize_callback}_settings_callback";

	if ( ! is_multisite() ) {
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
