<?php
defined( 'ABSPATH' ) or	die( 'Cheatin&#8217; uh?' );

add_action( 'admin_init', 'secupress_register_wordpress_core_settings' );
function secupress_register_wordpress_core_settings() {
	register_setting( 'secupress_wordpress-core_settings', 'secupress_wordpress-core_settings', '__secupress_wordpress_core_settings_callback' );
}

/**
 *
 *
 *
 * @since 1.0
 */
function __secupress_wordpress_core_settings_callback( $settings ) {
	$modulenow = 'wordpress-core';

	if ( isset( $settings['auto_update_minor'] ) ) {
		secupress_activate_submodule( $modulenow, 'minor-updates' );
	} else {
		secupress_deactivate_submodule( $modulenow, 'minor-updates' );
	}

	if ( isset( $settings['auto_update_major'] ) ) {
		secupress_activate_submodule( $modulenow, 'major-updates' );
	} else {
		secupress_deactivate_submodule( $modulenow, 'major-updates' );
	}

	return $settings;
}