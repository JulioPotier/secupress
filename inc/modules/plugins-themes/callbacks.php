<?php
defined( 'ABSPATH' ) or	die( 'Cheatin&#8217; uh?' );

/**
 * Callback to filter, sanitize and de/activate submodules
 *
 * @since 1.0
 * @return array $settings
 */
function __secupress_plugins_themes_settings_callback( $settings ) {
	$modulenow = 'plugins-themes';
	$settings = $settings ? $settings : array();

	// plugins
	foreach( array(	
					'plugins_installation' => 'plugin-installation',
					'plugins_update'       => 'plugin-update',
					// 'plugins_deactivation' => 'plugin-deactivation',
					// 'plugins_deletion'     => 'plugin-deletion',
					// 'plugins_activation'   => 'plugin-activation',
				) as $key => $file ) {
		
		if ( array_key_exists( $key, $settings ) ) {
			secupress_activate_submodule( $modulenow, $file );
		} else {
			secupress_deactivate_submodule( $modulenow, $file );
		}

	}

	// themes
	foreach( array(	
					'themes_installation' => 'theme-installation',
					'themes_update'       => 'theme-update',
					// 'themes_deletion'     => 'theme-deletion',
					// 'themes_switch'       => 'theme-switch',
				) as $key => $file ) {

		if ( array_key_exists( $key, $settings ) ) {
			secupress_activate_submodule( $modulenow, $file );
		} else {
			secupress_deactivate_submodule( $modulenow, $file );
		}

	}

	apply_filters( 'pro.' . __FUNCTION__, $settings );

	return $settings;
}