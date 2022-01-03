<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/**
 * Autoload network options and put them in cache.
 *
 * @since 1.0
 *
 * @param (array)  $option_names A list of option names to cache.
 * @param (string) $prefix       A prefix for the option names. Handy for transients for example (`_site_transient_`).
 */
function secupress_load_network_options( $option_names, $prefix = '' ) {
	global $wpdb;

	if ( ! $option_names || count( $option_names ) === 1 ) {
		return;
	}

	// Get values.
	$not_exist    = array();
	$option_names = array_flip( array_flip( $option_names ) );
	$options      = "'$prefix" . implode( "', '$prefix", esc_sql( $option_names ) ) . "'";

	if ( is_multisite() ) {
		$network_id     = function_exists( 'get_current_network_id' ) ? get_current_network_id() : (int) $wpdb->siteid;
		$cache_prefix   = "$network_id:";
		$notoptions_key = "$network_id:notoptions";
		$cache_group    = 'site-options';
		$results        = $wpdb->get_results( $wpdb->prepare( "SELECT meta_key as name, meta_value as value FROM $wpdb->sitemeta WHERE meta_key IN ( $options ) AND site_id = %d", $network_id ), OBJECT_K ); // WPCS: unprepared SQL ok.
	} else {
		$cache_prefix   = '';
		$notoptions_key = 'notoptions';
		$cache_group    = 'options';
		$results        = $wpdb->get_results( "SELECT option_name as name, option_value as value FROM $wpdb->options WHERE option_name IN ( $options )", OBJECT_K ); // WPCS: unprepared SQL ok.
	}

	foreach ( $option_names as $option_name ) {
		$option_name = $prefix . $option_name;

		if ( isset( $results[ $option_name ] ) ) {
			// Cache the value.
			$value = $results[ $option_name ]->value;
			$value = maybe_unserialize( $value );
			wp_cache_set( "$cache_prefix$option_name", $value, $cache_group );
		} else {
			// No value.
			$not_exist[ $option_name ] = true;
		}
	}

	if ( ! $not_exist ) {
		return;
	}

	// Cache the options that don't exist in the DB.
	$notoptions = wp_cache_get( $notoptions_key, $cache_group );
	$notoptions = is_array( $notoptions ) ? $notoptions : array();
	$notoptions = array_merge( $notoptions, $not_exist );

	wp_cache_set( $notoptions_key, $notoptions, $cache_group );
}


/**
 * Get some of our network options for autoload.
 * Transients are not listed if an external object cache is used.
 *
 * @since 1.0
 *
 * @return (array) A list of option/transient names.
 */
function secupress_get_global_network_option_names_for_autoload() {
	if ( secupress_wp_installing() ) {
		return array();
	}

	// Main options.
	$option_names = array(
		SECUPRESS_SETTINGS_SLUG,
		SECUPRESS_ACTIVE_SUBMODULES,
		SECUPRESS_BAN_IP,
	);

	if ( is_admin() ) {
		$option_names = array_merge( $option_names, array(
			SECUPRESS_SCAN_TIMES,
		) );
	}

	// Transients.
	if ( ! wp_using_ext_object_cache() ) {
		$option_names = array_merge( $option_names, array(
			'_site_transient_secupress-rename-admin-username',
			'_site_transient_secupress-add-cookiehash-muplugin',
			'_site_transient_secupress-add-salt-muplugin',
			'_site_transient_' . SECUPRESS_ACTIVE_SUBMODULES,
			'_site_transient_secupress_autoscans',
		) );

		if ( is_admin() ) {
			$option_names = array_merge( $option_names, array(
				'_site_transient_secupress_toggle_file_scan', // Pro.
				'_site_transient_secupress_pro_activation', // Pro.
				'_site_transient_secupress_activation',
				'_site_transient_timeout_secupress-detect-bad-plugins',
				'_site_transient_secupress-detect-bad-plugins',
				'_site_transient_timeout_secupress-detect-bad-themes',
				'_site_transient_secupress-detect-bad-themes',
				'_site_transient_secupress_offer_migration_information',
			) );
		}
	}

	return $option_names;
}


/**
 * Autoload main options and transients directly.
 */
secupress_load_network_options( secupress_get_global_network_option_names_for_autoload() );


add_action( 'secupress.plugins.loaded', 'secupress_load_plugins_network_options', 5 );
/**
 * Autoload some options/transients after submodules are included.
 *
 * @since 1.0
 */
function secupress_load_plugins_network_options() {
	if ( secupress_wp_installing() ) {
		return;
	}

	$option_names = array();

	// Active modules settings.
	$modules = get_site_option( SECUPRESS_ACTIVE_SUBMODULES );

	if ( $modules ) {
		foreach ( $modules as $module => $plugins ) {
			$option_names[ "secupress_{$module}_settings" ] = 1;
		}
	}

	$option_names['secupress_users-login_settings'] = 1; // It is used for the "Ban IP" duration, even if the submodule is not activated. See `secupress_check_ban_ips()`.
	$option_names = array_keys( $option_names );

	/**
	 * Filter the network options to autoload.
	 * This is where our plugins should autoload their custom options.
	 *
	 * @since 1.0
	 *
	 * @param (array) $option_names An array of network option names.
	 */
	$option_names = apply_filters( 'secupress.options.load_plugins_network_options', $option_names );

	secupress_load_network_options( $option_names );
}


add_action( 'auth_cookie_valid', 'secupress_load_user_network_options', 0, 2 );
/**
 * Autoload some options/transients used for logged in users.
 *
 * @since 1.0
 *
 * @param (array)  $cookie_elements An array of data for the authentication cookie.
 * @param (object) $user            WP_User object.
 */
function secupress_load_user_network_options( $cookie_elements, $user ) {
	static $done     = array();
	$current_user_id = (int) $user->ID;

	if ( isset( $done[ $current_user_id ] ) ) {
		return;
	}

	$done[ $current_user_id ] = 1;

	if ( secupress_wp_installing() ) {
		return;
	}

	$option_names = array();
	$user_can     = user_can( $user, secupress_get_capability() );

	// Transients.
	if ( ! wp_using_ext_object_cache() && $user_can ) {
		$option_names = array(
			'_site_transient_secupress_module_activation_' . $current_user_id,
			'_site_transient_secupress_module_deactivation_' . $current_user_id,
			'_transient_secupress-notices-' . $current_user_id,
		);
	}

	/**
	 * Filter the network options to autoload.
	 * This is where options/transients related to the current user should be autoloaded.
	 *
	 * @since 1.0
	 *
	 * @param (array)  $option_names An array of network option names.
	 * @param (object) $user         WP_User object.
	 * @param (bool)   $user_can     Tells if the current user has the SecuPress capability.
	 */
	$option_names = apply_filters( 'secupress.options.load_user_network_options', $option_names, $user, $user_can );

	secupress_load_network_options( $option_names );
}
