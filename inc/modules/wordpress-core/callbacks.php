<?php
defined( 'ABSPATH' ) or	die( 'Cheatin&#8217; uh?' );

/**
 * Callback to filter, sanitize and de/activate submodules
 *
 * @since 1.0
 * @return array $settings
 */
function __secupress_wordpress_core_settings_callback( $settings ) {
	$modulenow = 'wordpress-core';
	$settings = $settings ? $settings : array();

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