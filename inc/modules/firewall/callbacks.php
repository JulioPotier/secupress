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
	
	if ( isset( $settings['bbq-headers_request-methods-header'] ) ) {
		secupress_activate_submodule( $modulenow, 'request-methods-header' );
	} else {
		secupress_deactivate_submodule( $modulenow, 'request-methods-header' );
	}
		
	if ( isset( $settings['bbq-url-content_bad-contents'] ) ) {
		secupress_activate_submodule( $modulenow, 'bad-url-contents' );
	} else {
		secupress_deactivate_submodule( $modulenow, 'bad-url-contents' );
	}
			
	if ( isset( $settings['bbq-url-content_bad-url-length'] ) ) {
		secupress_activate_submodule( $modulenow, 'bad-url-length' );
	} else {
		secupress_deactivate_submodule( $modulenow, 'bad-url-length' );
	}
				
	if ( isset( $settings['bbq-url-content_bad-sqli-scan'] ) ) {
		secupress_activate_submodule( $modulenow, 'bad-sqli-scan' );
	} else {
		secupress_deactivate_submodule( $modulenow, 'bad-sqli-scan' );
	}
	
	return $settings;
}
