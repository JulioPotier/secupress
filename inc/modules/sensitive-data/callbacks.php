<?php
defined( 'ABSPATH' ) or	die( 'Cheatin&#8217; uh?' );

/*------------------------------------------------------------------------------------------------*/
/* ON MODULE SETTINGS SAVE ====================================================================== */
/*------------------------------------------------------------------------------------------------*/

/**
 * Callback to filter, sanitize, validate and de/activate submodules.
 *
 * @since 1.0
 *
 * @param (array) $settings The module settings.
 *
 * @return (array) The sanitized and validated settings.
 */
function __secupress_sensitive_data_settings_callback( $settings ) {
	$modulenow = 'sensitive-data';
	$settings  = $settings ? $settings : array();

	/*
	 * Each submodule has its own sanitization function.
	 * The `$settings` parameter is passed by reference.
	 */

	// Pages Protection
	__secupress_pages_protection_settings_callback( $modulenow, $settings );

	// Content Protection
	__secupress_content_protection_settings_callback( $modulenow, $settings );

	// WordPress Endpoints
	__secupress_wp_endpoints_settings_callback( $modulenow, $settings );

	return $settings;
}


/**
 * (De)Activate Pages Protection plugins.
 *
 * @since 1.0
 *
 * @param (string) $modulenow Current module.
 * @param (array)  $settings  The module settings, passed by reference.
 */
function __secupress_pages_protection_settings_callback( $modulenow, &$settings ) {
	if ( secupress_is_pro() ) {
		secupress_manage_submodule( $modulenow, 'page-protect',    ! empty( $settings['page-protect_profile'] ) && ! empty( $settings['page-protect_settings'] ) );
		secupress_manage_submodule( $modulenow, 'profile-protect', ! empty( $settings['page-protect_profile'] ) );
		secupress_manage_submodule( $modulenow, 'options-protect', ! empty( $settings['page-protect_settings'] ) );
	} else {
		secupress_deactivate_submodule( $modulenow, array( 'page-protect', 'profile-protect', 'options-protect' ) );
	}

	unset( $settings['page-protect_profile'], $settings['page-protect_settings'] );
}


/**
 * (De)Activate Content Protection plugins.
 *
 * @since 1.0
 *
 * @param (string) $modulenow Current module.
 * @param (array)  $settings  The module settings, passed by reference.
 */
function __secupress_content_protection_settings_callback( $modulenow, &$settings ) {
	secupress_manage_submodule( $modulenow, 'hotlink',   ! empty( $settings['content-protect_hotlink'] ) && secupress_is_pro() );
	secupress_manage_submodule( $modulenow, 'blackhole', ! empty( $settings['content-protect_blackhole'] ) );

	unset( $settings['content-protect_hotlink'], $settings['content-protect_blackhole'] );
}


/**
 * (De)Activate WordPress Endpoints plugins and sanitize settings.
 *
 * @since 1.0
 *
 * @param (string) $modulenow Current module.
 * @param (array)  $settings  The module settings, passed by reference.
 */
function __secupress_wp_endpoints_settings_callback( $modulenow, &$settings ) {
	if ( ! empty( $settings['wp-endpoints_xmlrpc'] ) && is_array( $settings['wp-endpoints_xmlrpc'] ) ) {
		$settings['wp-endpoints_xmlrpc'] = array_intersect( array(
			'block-all',
			'block-multi',
		), $settings['wp-endpoints_xmlrpc'] );

		secupress_manage_submodule( $modulenow, 'xmlrpc', (bool) $settings['wp-endpoints_xmlrpc'] );
	} else {
		unset( $settings['wp-endpoints_xmlrpc'] );

		secupress_deactivate_submodule( $modulenow, array( 'xmlrpc' ) );
	}

	secupress_manage_submodule( $modulenow, 'restapi', ! empty( $settings['wp-endpoints_restapi'] ) && secupress_is_pro() );

	unset( $settings['wp-endpoints_restapi'] );
}
