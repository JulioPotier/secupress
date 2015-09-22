<?php
defined( 'ABSPATH' ) or	die( 'Cheatin&#8217; uh?' );

add_action( 'admin_init', 'secupress_register_wordpress_core_settings' );
function secupress_register_wordpress_core_settings() {
	register_setting( 'secupress_wordpress_core_settings', 'secupress_wordpress_core_settings', '__secupress_wordpress_core_settings_callback' );
}

/**
 *
 *
 *
 * @since 1.0
 */
function __secupress_wordpress_core_settings_callback( $settings ) {
	$modulenow = 'wordpress_core';

	if ( isset( $settings['plugin_minor_updates'] ) ) {
		secupress_activate_submodule( $modulenow, 'minor_updates' );
	} else {
		secupress_deactivate_submodule( $modulenow, 'minor_updates' );
	}

	return $settings;
}