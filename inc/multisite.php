<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/*
 * Autoload network options.
 *
 * @since 1.0
 *
 * @param (array)  $option_names A list of option names to cache.
 * @param (string) $prefix       A prefix for the option names. Handy for transients for example (`_site_transient_`).
 */
function secupress_load_site_options( $option_names, $prefix = '' ) {
	global $wpdb;

	if ( ! $option_names ) {
		return;
	}

	$network_id = (int) $wpdb->siteid;

	// Get values.
	$options   = "'$prefix" . implode( "', '$prefix", $option_names ) . "'";
	$results   = $wpdb->get_results( $wpdb->prepare( "SELECT meta_key, meta_value FROM $wpdb->sitemeta WHERE meta_key IN ( $options ) AND site_id = %d", $network_id ), OBJECT_K );
	$not_exist = array();

	foreach ( $option_names as $option_name ) {
		$option_name = $prefix . $option_name;
		// Cache the value.
		if ( isset( $results[ $option_name ] ) ) {
			$value = $results[ $option_name ]->meta_value;
			$value = maybe_unserialize( $value );
			wp_cache_set( "$network_id:$option_name", $value, 'site-options' );
		}
		// No value.
		else {
			$not_exist[ $option_name ] = true;
		}
	}

	// Cache the options that don't exist in the DB.
	if ( $not_exist ) {
		$notoptions_key = "$network_id:notoptions";
		$notoptions     = wp_cache_get( $notoptions_key, 'site-options' );
		$notoptions     = is_array( $notoptions ) ? $notoptions : array();
		$notoptions     = array_merge( $notoptions, $not_exist );
		wp_cache_set( $notoptions_key, $notoptions, 'site-options' );
	}
}


/*
 * Get some of our network options for autoload.
 * Transients are not listed if an external object cache is used.
 *
 * @since 1.0
 *
 * @return (array) A list of option/transient names.
 */
function secupress_get_global_site_option_names_for_autoload() {
	if ( secupress_wp_installing() ) {
		return array();
	}

	// Basic options.
	$option_names = array(
		SECUPRESS_SETTINGS_SLUG,
		SECUPRESS_ACTIVE_SUBMODULES,
		SECUPRESS_SCAN_SLUG,
		SECUPRESS_BAN_IP,
		'secupress_firewall_settings',
		'secupress_users_login_settings',
	);

	if ( is_admin() ) {
		$option_names[] = SECUPRESS_SCAN_FIX_SITES_SLUG;
	}

	// Transients.
	if ( ! wp_using_ext_object_cache() ) {
		$option_names = array_merge( $option_names, array(
			'_site_transient_secupress-rename-admin-username',
			'_site_transient_secupress-add-cookiehash-muplugin',
			'_site_transient_secupress-add-salt-muplugin',
		) );

		if ( is_admin() ) {
			$option_names = array_merge( $option_names, array(
				'_site_transient_secupress-admin-as-author-administrator',
			) );
		}
	}

	return $option_names;
}


// Launch this autoload directly.

secupress_load_site_options( secupress_get_global_site_option_names_for_autoload() );


/*
 * Autoload some options with dynamic name.
 *
 * @since 1.0
 */
add_action( ( is_network_admin() ? 'network_' : '' ) . 'admin_menu', 'secupress_load_delayed_site_options', 0 );

function secupress_load_delayed_site_options() {
	if ( secupress_wp_installing() ) {
		return;
	}

	// Transients.
	if ( ! wp_using_ext_object_cache() && current_user_can( secupress_get_capability() ) ) {
		$current_user_id = get_current_user_id();

		$option_names = array(
			'_site_transient_' . $current_user_id . '_donotdeactivatesecupress',
			'_site_transient_secupress_module_activation_' . $current_user_id,
			'_site_transient_secupress_module_deactivation_' . $current_user_id,
		);

		secupress_load_site_options( $option_names );
	}
}
