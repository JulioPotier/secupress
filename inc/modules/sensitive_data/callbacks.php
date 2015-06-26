<?php
defined( 'ABSPATH' ) or	die( 'Cheatin&#8217; uh?' );

add_action( 'admin_init', 'secupress_register_sensitive_data_settings' );
function secupress_register_sensitive_data_settings() {
	register_setting( "secupress_sensitive_data_settings", "secupress_sensitive_data_settings", "__secupress_sensitive_data_settings_callback" );
}

/**
 *
 *
 *
 * @since 1.0
 */
function __secupress_sensitive_data_settings_callback( $settings ) {
	$modulenow = 'sensitive_data';
	// war_dump($settings);
	if ( isset( $settings['plugin_profile_protect'] ) ) {
		secupress_activate_submodule( $modulenow, 'profile_protect' );
	} else {
		secupress_deactivate_submodule( $modulenow, 'profile_protect' );
	}
	secupress_manage_affected_roles( $settings, 'profile_protect' );

	return $settings;
}
