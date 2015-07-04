<?php
defined( 'ABSPATH' ) or	die( 'Cheatin&#8217; uh?' );

add_action( 'admin_init', 'secupress_register_plugins_themes_settings' );
function secupress_register_plugins_themes_settings() {
	register_setting( "secupress_plugins_themes_settings", "secupress_plugins_themes_settings", "__secupress_plugins_themes_settings_callback" );
}

/**
 *
 *
 *
 * @since 1.0
 */
function __secupress_plugins_themes_settings_callback( $settings ) {
	$modulenow = 'plugins_themes';

	// plugins
	foreach( array(	'plugin_deactivation_plugins' 	=> 'plugin_deactivation',
					'plugin_deletion_plugins' 		=> 'plugin_deletion',
					'plugin_install_plugins' 		=> 'plugin_installation',
					'plugin_activation_plugins' 	=> 'plugin_activation',
					'plugin_update_plugins' 		=> 'plugin_update' ) as $key => $file ) {
		
		if ( array_key_exists( $key, $settings ) ) {
			secupress_activate_submodule( $modulenow, $file );
		} else {
			secupress_deactivate_submodule( $modulenow, $file );
		}

	}

	// themes
	foreach( array(	'theme_deletion_themes' 	=> 'theme_deletion',
					'theme_install_themes' 		=> 'theme_installation',
					'theme_activation_themes' 	=> 'theme_switch',
					'theme_update_themes' 		=> 'theme_update' ) as $key => $file ) {

		if ( array_key_exists( $key, $settings ) ) {
			secupress_activate_submodule( $modulenow, $file );
		} else {
			secupress_deactivate_submodule( $modulenow, $file );
		}

	}

	return $settings;
}