<?php
defined( 'ABSPATH' ) or	die( 'Cheatin&#8217; uh?' );

/**
 * Callback to filter, sanitize and de/activate submodules
 *
 * @since 1.0
 * @return array $settings
 */
function __secupress_firewall_settings_callback( $settings ) {
	$modulenow = 'firewall';
	$settings = $settings ? $settings : array();

	if ( isset( $settings['bbq-headers_user-agents-header'] ) ) {
		secupress_activate_submodule( $modulenow, 'user-agents-header' );
	} else {
		secupress_deactivate_submodule( $modulenow, 'user-agents-header' );
	}
	
	return $settings;
}
