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
	foreach( array(	'plugins_deactivation' => 'plugin-deactivation',
					'plugins_deletion'     => 'plugin-deletion',
					'plugins_installation' => 'plugin-installation',
					'plugins_activation'   => 'plugin-activation',
					'plugins_update'       => 'plugin-update' ) as $key => $file ) {
		
		if ( array_key_exists( $key, $settings ) ) {
			secupress_activate_submodule( $modulenow, $file );
		} else {
			secupress_deactivate_submodule( $modulenow, $file );
		}

	}

	// themes
	foreach( array(	'themes_deletion'     => 'theme-deletion',
					'themes_installation' => 'theme-installation',
					'themes_switch'       => 'theme-switch',
					'themes_update'       => 'theme-update' ) as $key => $file ) {

		if ( array_key_exists( $key, $settings ) ) {
			secupress_activate_submodule( $modulenow, $file );
		} else {
			secupress_deactivate_submodule( $modulenow, $file );
		}

	}

	return $settings;
}