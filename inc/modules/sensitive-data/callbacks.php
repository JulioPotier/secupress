<?php
defined( 'ABSPATH' ) or	die( 'Something went wrong.' );

/** --------------------------------------------------------------------------------------------- */
/** ON MODULE SETTINGS SAVE ===================================================================== */
/** --------------------------------------------------------------------------------------------- */

/**
 * Callback to filter, sanitize, validate and de/activate submodules.
 *
 * @since 1.0
 *
 * @param (array) $settings The module settings.
 *
 * @return (array) The sanitized and validated settings.
 */
function secupress_sensitive_data_settings_callback( $settings ) {
	$modulenow = 'sensitive-data';
	$activate  = secupress_get_submodule_activations( $modulenow );
	$settings  = $settings && is_array( $settings ) ? $settings : array();

	if ( isset( $settings['sanitized'] ) ) {
		return $settings;
	}
	$settings['sanitized'] = 1;

	/*
	 * Each submodule has its own sanitization function.
	 * The `$settings` parameter is passed by reference.
	 */

	// Content Protection.
	secupress_content_protection_settings_callback( $modulenow, $activate );

	// WordPress Endpoints.
	secupress_wp_endpoints_settings_callback( $modulenow, $settings, $activate );

	/**
	 * Filter the settings before saving.
	 *
	 * @since 1.4.9
	 *
	 * @param (array)      $settings The module settings.
	 * @param (array\bool) $activate Contains the activation rules for the different modules
	 */
	$settings = apply_filters( "secupress_{$modulenow}_settings_callback", $settings, $activate );

	return $settings;
}


/**
 * Content Protection plugins.
 *
 * @since 1.0
 *
 * @param (string)     $modulenow Current module.
 * @param (bool|array) $activate  Used to (de)activate plugins.
 */
function secupress_content_protection_settings_callback( $modulenow, $activate ) {
	if ( false === $activate ) {
		return;
	}

	// (De)Activation.
	secupress_manage_submodule( $modulenow,  '404guess', ! empty( $activate['content-protect_404guess'] ) && secupress_is_pro() );
	secupress_manage_submodule( $modulenow,  'hotlink', ! empty( $activate['content-protect_hotlink'] ) && secupress_is_pro() );
	secupress_manage_submodule( $modulenow,  'blackhole', ! empty( $activate['content-protect_blackhole'] ) && secupress_blackhole_is_robots_txt_enabled() );
	secupress_manage_submodule( $modulenow,  'directory-listing', ! empty( $activate['content-protect_directory-listing'] ) );
	secupress_manage_submodule( $modulenow,  'php-easter-egg', ! empty( $activate['content-protect_php-disclosure'] ) );
	secupress_manage_submodule( 'discloses', 'no-x-powered-by', ! empty( $activate['content-protect_php-version'] ) );
	secupress_manage_submodule( 'discloses', 'wp-version', ! empty( $activate['content-protect_wp-version'] ) );
	secupress_manage_submodule( $modulenow,  'bad-url-access', ! empty( $activate['content-protect_bad-url-access'] ) );
	secupress_manage_submodule( 'discloses', 'readmes', ! empty( $activate['content-protect_readmes'] ) );

	$plugin_disclose = ! empty( $activate['content-protect_plugin-version-discloses'] ) && is_array( $activate['content-protect_plugin-version-discloses'] ) ? array_flip( $activate['content-protect_plugin-version-discloses'] ) : array();
	$wp_plugins      = array( 'woocommerce', 'wpml' );

	foreach ( $wp_plugins as $wp_plugin ) {
		secupress_manage_submodule( 'discloses', $wp_plugin . '-version', isset( $plugin_disclose[ $wp_plugin ] ) );
	}
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
function secupress_wp_endpoints_settings_callback( $modulenow, &$settings, $activate ) {
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
}


/** --------------------------------------------------------------------------------------------- */
/** TOOLS ======================================================================================= */
/** --------------------------------------------------------------------------------------------- */

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
	$home_path = wp_parse_url( home_url() );
	return empty( $home_path['path'] ) || '/' === $home_path['path'] || defined( 'SECUPRESS_FORCE_ROBOTS_TXT' ) && SECUPRESS_FORCE_ROBOTS_TXT;
}
