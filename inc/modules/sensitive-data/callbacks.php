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
	$activate  = secupress_get_submodule_activations( $modulenow );
	$settings  = $settings ? $settings : array();

	if ( isset( $settings['sanitized'] ) ) {
		return $settings;
	}
	$settings['sanitized'] = 1;

	/*
	 * Each submodule has its own sanitization function.
	 * The `$settings` parameter is passed by reference.
	 */

	// Pages Protection.
	__secupress_pages_protection_settings_callback( $modulenow, $activate );

	// Content Protection.
	__secupress_content_protection_settings_callback( $modulenow, $activate );

	// WordPress Endpoints.
	__secupress_wp_endpoints_settings_callback( $modulenow, $settings, $activate );

	return $settings;
}


/**
 * Pages Protection plugins.
 *
 * @since 1.0
 *
 * @param (string)     $modulenow Current module.
 * @param (bool|array) $activate  Used to (de)activate plugins.
 */
function __secupress_pages_protection_settings_callback( $modulenow, $activate ) {
	if ( false === $activate ) {
		return;
	}

	// (De)Activation.
	if ( secupress_is_pro() ) {
		secupress_manage_submodule( $modulenow, 'page-protect', ! empty( $activate['page-protect_profile'] ) || ! empty( $activate['page-protect_settings'] ) );
		secupress_manage_submodule( $modulenow, 'profile-protect', ! empty( $activate['page-protect_profile'] ) );
		secupress_manage_submodule( $modulenow, 'options-protect', ! empty( $activate['page-protect_settings'] ) );
	} else {
		secupress_deactivate_submodule( $modulenow, array( 'page-protect', 'profile-protect', 'options-protect' ) );
	}
}


/**
 * Content Protection plugins.
 *
 * @since 1.0
 *
 * @param (string)     $modulenow Current module.
 * @param (bool|array) $activate  Used to (de)activate plugins.
 */
function __secupress_content_protection_settings_callback( $modulenow, $activate ) {
	if ( false === $activate ) {
		return;
	}

	// (De)Activation.
	secupress_manage_submodule( $modulenow, 'hotlink', ! empty( $activate['content-protect_hotlink'] ) && secupress_is_pro() );
	secupress_manage_submodule( $modulenow, 'blackhole', ! empty( $activate['content-protect_blackhole'] ) && secupress_blackhole_is_robots_txt_enabled() );
}


/**
 * WordPress Endpoints plugins.
 *
 * @since 1.0
 *
 * @param (string)     $modulenow Current module.
 * @param (array)      $settings  The module settings, passed by reference.
 * @param (bool|array) $activate  Used to (de)activate plugins.
 */
function __secupress_wp_endpoints_settings_callback( $modulenow, &$settings, $activate ) {
	// Settings.
	if ( ! empty( $settings['wp-endpoints_xmlrpc'] ) && is_array( $settings['wp-endpoints_xmlrpc'] ) ) {
		$xmlrpc = array(
			'block-all',
			'block-multi',
		);
		$settings['wp-endpoints_xmlrpc'] = array_intersect( $xmlrpc, $settings['wp-endpoints_xmlrpc'] );
		$settings['wp-endpoints_xmlrpc'] = array_slice( $settings['wp-endpoints_xmlrpc'], 0, 1 ); // Only one choice.
	} else {
		unset( $settings['wp-endpoints_xmlrpc'] );
	}

	// (De)Activation.
	secupress_manage_submodule( $modulenow, 'xmlrpc', ! empty( $settings['wp-endpoints_xmlrpc'] ) ); // `$settings`, not `$activate`.
	secupress_manage_submodule( $modulenow, 'restapi', ! empty( $activate['wp-endpoints_restapi'] ) );
}


/*------------------------------------------------------------------------------------------------*/
/* TOOLS ======================================================================================== */
/*------------------------------------------------------------------------------------------------*/

/**
 * Tell if a `robots.txt` file is in use.
 * WordPress does not create a rewrite rule for the `robots.txt` file if it is installed in a folder.
 * If a constant `SECUPRESS_FORCE_ROBOTS_TXT` is defined to `true`, the field will be available.
 *
 * @since 1.0
 *
 * @see `WP_Rewrite::rewrite_rules()`.
 *
 * @return (bool)
 */
function secupress_blackhole_is_robots_txt_enabled() {
	$home_path = parse_url( home_url() );
	return empty( $home_path['path'] ) || '/' === $home_path['path'] || defined( 'SECUPRESS_FORCE_ROBOTS_TXT' ) && SECUPRESS_FORCE_ROBOTS_TXT;
}
