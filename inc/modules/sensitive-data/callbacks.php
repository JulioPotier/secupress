<?php
defined( 'ABSPATH' ) or	die( 'Cheatin&#8217; uh?' );

/**
 * Callback to filter, sanitize and de/activate submodules
 *
 * @since 1.0
 * @return array $settings
 */
function __secupress_sensitive_data_settings_callback( $settings ) {
	$modulenow = 'sensitive-data';
	$settings = $settings ? $settings : array();

	if ( ! isset( $settings['page_protect_profile'], $settings['page_protect_settings'] ) ) {
		secupress_deactivate_submodule( $modulenow, 'page-protect' );
	}

	if ( isset( $settings['page_protect_profile'] ) ) {
		secupress_activate_submodule( $modulenow, 'page-protect' );
		secupress_activate_submodule( $modulenow, 'profile-protect' );
	} else {
		secupress_deactivate_submodule( $modulenow, 'profile-protect' );
	}

	if ( isset( $settings['page_protect_settings'] ) ) {
		secupress_activate_submodule( $modulenow, 'page-protect' );
		secupress_activate_submodule( $modulenow, 'options-protect' );
	} else {
		secupress_deactivate_submodule( $modulenow, 'options-protect' );
	}
	
	return $settings;
}
