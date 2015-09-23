<?php
defined( 'ABSPATH' ) or	die( 'Cheatin&#8217; uh?' );

add_action( 'admin_init', 'secupress_register_plugins_themes_settings' );
function secupress_register_plugins_themes_settings() {
	register_setting( "secupress_plugins-themes_settings", "secupress_plugins-themes_settings", "__secupress_plugins_themes_settings_callback" );
}

/**
 *
 *
 *
 * @since 1.0
 */
function __secupress_plugins_themes_settings_callback( $settings ) {
	$modulenow = 'plugins-themes';

	// plugins
	foreach( array(	'plugin-deactivation-plugins' 	=> 'plugin-deactivation',
					'plugin-deletion-plugins' 		=> 'plugin-deletion',
					'plugin-install-plugins' 		=> 'plugin-installation',
					'plugin-activation-plugins' 	=> 'plugin-activation',
					'plugin-update-plugins' 		=> 'plugin-update' ) as $key => $file ) {
		
		if ( array_key_exists( $key, $settings ) ) {
			secupress_activate_submodule( $modulenow, $file );
		} else {
			secupress_deactivate_submodule( $modulenow, $file );
		}

	}

	// themes
	foreach( array(	'theme-deletion-themes' 	=> 'theme-deletion',
					'theme-install-themes' 		=> 'theme-installation',
					'theme-activation-themes' 	=> 'theme-switch',
					'theme-update-themes' 		=> 'theme-update' ) as $key => $file ) {

		if ( array_key_exists( $key, $settings ) ) {
			secupress_activate_submodule( $modulenow, $file );
		} else {
			secupress_deactivate_submodule( $modulenow, $file );
		}

	}

	return $settings;
}