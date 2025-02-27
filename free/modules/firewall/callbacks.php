<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/** --------------------------------------------------------------------------------------------- */
/** ON MODULE SETTINGS SAVE ===================================================================== */
/** --------------------------------------------------------------------------------------------- */

/**
 * Callback to filter, sanitize and de/activate submodules
 *
 * @since 1.0
 *
 * @param (array) $settings The module settings.
 *
 * @return (array) The sanitized and validated settings.
 */
function secupress_firewall_settings_callback( $settings ) {
	$modulenow = 'firewall';
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
	// Bad headers.
	secupress_bad_headers_settings_callback( $modulenow, $settings, $activate );

	// Bad contents.
	secupress_bad_contents_settings_callback( $modulenow, $settings, $activate );

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
 * Bad Headers plugins.
 *
 * @since 1.0
 *
 * @param (string)     $modulenow Current module.
 * @param (array)      $settings  The module settings, passed by reference.
 * @param (bool|array) $activate  Used to (de)activate plugins.
 */
function secupress_bad_headers_settings_callback( $modulenow, &$settings, $activate ) {
	// (De)Activation.
	if ( false !== $activate ) {
		secupress_manage_submodule( $modulenow, 'user-agents-header', ! empty( $activate['bbq-headers_user-agents-header'] ) );
		if ( secupress_is_pro() ) {
			secupress_manage_submodule( $modulenow, 'bad-referer', ! empty( $activate['bbq-headers_bad-referer'] ) );
		}
		secupress_manage_submodule( $modulenow, 'fake-google-bots', ! empty( $activate['bbq-headers_fake-google-bots'] ) );
	}

	// Settings.
	if ( ! empty( $settings['bbq-headers_user-agents-list'] ) ) {
		$settings['bbq-headers_user-agents-list'] = sanitize_text_field( $settings['bbq-headers_user-agents-list'] );
		$settings['bbq-headers_user-agents-list'] = secupress_sanitize_list( $settings['bbq-headers_user-agents-list'] );
		$settings['bbq-headers_user-agents-list'] = secupress_unique_sorted_list( $settings['bbq-headers_user-agents-list'], ', ' );
	}

	if ( empty( $settings['bbq-headers_user-agents-list'] ) ) {
		$settings['bbq-headers_user-agents-list'] = secupress_firewall_bbq_headers_user_agents_list_default();
	}

	if ( secupress_is_pro() && ! empty( $settings['bbq-headers_bad-referer-list'] ) ) {
		$settings['bbq-headers_bad-referer-list'] = trim( implode( ',', secupress_unique_sorted_list( $settings['bbq-headers_bad-referer-list'], "\n", 'array' ) ), ',' );
	}
}

/**
 * Bad Contents plugins.
 *
 * @since 1.0
 *
 * @param (string)     $modulenow Current module.
 * @param (array)      $settings  The module settings, passed by reference.
 * @param (bool|array) $activate  Used to (de)activate plugins.
 */
function secupress_bad_contents_settings_callback( $modulenow, &$settings, $activate ) {
	// (De)Activation.
	if ( false !== $activate ) {
		if ( ! empty( $settings['bbq-url-content_block-functions-sources'] ) ) {
			secupress_manage_submodule( $modulenow, 'block-functions', ! empty( $activate['bbq-url-content_block-functions'] ) );
		}
		secupress_manage_submodule( $modulenow, 'bad-url-contents', ! empty( $activate['bbq-url-content_bad-contents'] ) );
		secupress_manage_submodule( $modulenow, 'ban-404-php', ! empty( $activate['bbq-url-content_ban-404-php'] ) );
	}

	// Settings.
	if ( ! empty( $settings['bbq-url-content_bad-contents-list'] ) ) {
		// Do not sanitize the value or the sky will fall.
		$settings['bbq-url-content_bad-contents-list'] = secupress_sanitize_list( $settings['bbq-url-content_bad-contents-list'] );
		$settings['bbq-url-content_bad-contents-list'] = secupress_unique_sorted_list( $settings['bbq-url-content_bad-contents-list'], ', ' );
	}

	if ( empty( $settings['bbq-url-content_bad-contents-list'] ) ) {
		$settings['bbq-url-content_bad-contents-list'] = secupress_firewall_bbq_url_content_bad_contents_list_default();
	}
}



/** --------------------------------------------------------------------------------------------- */
/** INSTALL/RESET =============================================================================== */
/** --------------------------------------------------------------------------------------------- */

add_action( 'secupress.first_install', 'secupress_install_firewall_module' );
/**
 * Create default option on install and reset.
 *
 * @since 1.0
 *
 * @param (string) $module The module(s) that will be reset to default. `all` means "all modules".
 */
function secupress_install_firewall_module( $module ) {
	if ( 'all' === $module || 'firewall' === $module ) {
		update_site_option( 'secupress_firewall_settings', array(
			// Bad headers.
			'bbq-headers_user-agents-list'      => secupress_firewall_bbq_headers_user_agents_list_default(),
			// Bad contents.
			'bbq-url-content_bad-contents-list' => secupress_firewall_bbq_url_content_bad_contents_list_default(),
		) );
	}
}
