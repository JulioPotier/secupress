<?php
defined( 'ABSPATH' ) or	die( 'Cheatin&#8217; uh?' );

add_action( 'admin_init', 'secupress_register_sensitive_data_settings' );
function secupress_register_sensitive_data_settings() {
	register_setting( "secupress_sensitive-data_settings", "secupress_sensitive-data_settings", "__secupress_sensitive_data_settings_callback" );
}

/**
 *
 *
 *
 * @since 1.0
 */
function __secupress_sensitive_data_settings_callback( $settings ) {
	$modulenow = 'sensitive-data';

	if ( ! isset( $settings['profile_protect_page_protect'] ) && ! isset( $settings['settings_protect_page_protect'] ) ) {
		secupress_deactivate_submodule( $modulenow, 'page_protect' );
	}

	if ( isset( $settings['profile_protect_page_protect'] ) ) {
		secupress_activate_submodule( $modulenow, 'page-protect' );
		secupress_activate_submodule( $modulenow, 'profile-protect' );
	} else {
		secupress_deactivate_submodule( $modulenow, 'profile-protect' );
	}

	if ( isset( $settings['settings_protect_page_protect'] ) ) {
		secupress_activate_submodule( $modulenow, 'page-protect' );
		secupress_activate_submodule( $modulenow, 'options-protect' );
	} else {
		secupress_deactivate_submodule( $modulenow, 'options-protect' );
	}

	return $settings;
}
