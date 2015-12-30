<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Create a URL to easily access to our pages.
 *
 * @since 1.0
 *
 * @param (string) $page  : the last word of the secupress page slug.
 * @param (string) $module: the required module.
 *
 * @return (string) The URL.
 */
function secupress_admin_url( $page, $module = '' ) {
	$module = $module ? '&module=' . sanitize_key( $module ) : '';
	$page   = str_replace( '&', '_', $page );
	$url    = 'admin.php?page=secupress_' . sanitize_key( $page ) . $module;

	return is_multisite() ? network_admin_url( $url ) : admin_url( $url );
}


/**
 * Get the user capability required to work with the plugin.
 *
 * @since 1.0
 *
 * @param (bool) $force_mono: set to true to get the capability for monosite, whatever we're on multisite or not.
 *
 * @return (string) The capability.
 */
function secupress_get_capability( $force_mono = false ) {
	if ( $force_mono ) {
		return 'administrator';
	}
	return is_multisite() ? 'manage_network_options' : 'administrator';
}


/**
 * Like in_array but for nested arrays.
 *
 * @since 1.0
 *
 * @return (bool)
 */
if ( ! function_exists( 'in_array_deep' ) ) :
	function in_array_deep( $needle, $haystack ) {
		if ( $haystack ) {
			foreach ( $haystack as $item ) {
				if ( $item == $needle || ( is_array( $item ) && in_array_deep( $needle, $item ) ) ) {
					return true;
				}
			}
		}
		return false;
	}
endif;


/**
 * Return the path to a class.
 *
 * @since 1.0
 *
 * @param (string) $prefix         : only one possible value so far: "scan".
 * @param (string) $class_name_part: the classes name is built as follow: "SecuPress_{$prefix}_{$class_name_part}".
 *
 * @return (string) Path of the class.
 */
function secupress_class_path( $prefix, $class_name_part = '' ) {
	$folders = array(
		'scan'      => 'scanners',
		'singleton' => 'common',
		'logs'      => 'common',
		'log'       => 'common',
	);

	$prefix = strtolower( str_replace( '_', '-', $prefix ) );
	$folder = isset( $folders[ $prefix ] ) ? $folders[ $prefix ] : $prefix;

	$class_name_part = strtolower( str_replace( '_', '-', $class_name_part ) );
	$class_name_part = $class_name_part ? '-' . $class_name_part : '';

	return SECUPRESS_CLASSES_PATH . $folder . '/class-secupress-' . $prefix . $class_name_part . '.php';
}


/**
 * Require a class.
 *
 * @since 1.0
 *
 * @param (string) $prefix         : only one possible value so far: "scan".
 * @param (string) $class_name_part: the classes name is built as follow: "SecuPress_{$prefix}_{$class_name_part}".
*/
function secupress_require_class( $prefix, $class_name_part = '' ) {
	$path = secupress_class_path( $prefix, $class_name_part );

	if ( $path ) {
		require_once( $path );
	}
}


/**
 * Is current WordPress version older than X.X.X?
 *
 * @since 1.0
 *
 * @param (string) $version: the version to test.
 *
 * @return (bool) Result of the `version_compare()`.
 */
function secupress_wp_version_is( $version ) {
	global $wp_version;
	static $is = array();

	if ( isset( $is[ $version ] ) ) {
		return $is[ $version ];
	}

	return ( $is[ $version ] = version_compare( $wp_version, $version ) >= 0 );
}


/**
 * Return the "unaliased" version of an email address.
 *
 * @param (string) $email
 * @since 1.0
 * @return (string)
 **/
function secupress_remove_email_alias( $email ) {
	$provider = strstr( $email, '@' );
	$email    = strstr( $email, '@', true );
	$email    = explode( '+', $email );
	$email    = reset( $email );
	$email    = str_replace( '.', '', $email );
	return $email . $provider;
}


/**
 * Return the email "example@example.com" like "e%x%a%m%p%l%e%@example.com"
 *
 * @param (string) $email
 * @since 1.0
 * @return (string)
 **/
function secupress_prepare_email_for_like_search( $email ) {
	global $wpdb;
	$email    = secupress_remove_email_alias( $email );
	$provider = strstr( $email, '@' );
	$email    = $wpdb->esc_like( strstr( $email, '@', true ) );
	$email    = str_split( $email );
	$email    = implode( '%', $email );
	return $email . '%' . $provider;
}


/**
 * Store, get or delete static data.
 *
 * Getter:   no need to provide a second parameter.
 * Setter:   provide a second parameter for the value.
 * Deletter: provide null as second parameter to remove the previous value.
 *
 * @since 1.0
 *
 * @param (string) $key:  An identifier key.
 *
 * @return (mixed) The stored data or null.
 */
function secupress_cache_data( $key ) {
	static $datas = array();

	$func_get_args = func_get_args();

	if ( array_key_exists( 1, $func_get_args ) ) {
		if ( null === $func_get_args[1] ) {
			unset( $datas[ $key ] );
		} else {
			$datas[ $key ] = $func_get_args[1];
		}
	}

	return isset( $datas[ $key ] ) ? $datas[ $key ] : null;
}


/**
 * Check whether WordPress is in "installation" mode.
 *
 * @since 1.0
 *
 * @return (bool) true if WP is installing, otherwise false.
 */
function secupress_wp_installing() {
	function_exists( 'wp_installing' ) ? wp_installing() : defined( 'WP_INSTALLING' ) && WP_INSTALLING;
}


/**
 * Returns a i18n message used with a packed plugin activation checkbox to tell the user that the standalone plugin will be deactivated.
 *
 * @param (string) $plugin_basename The standalone plugin basename.
 * @since 1.0
 * @return (string|null) Return null if the plugin is not activated.
 **/
function secupress_get_deactivate_plugin_string( $plugin_basename ) {
	if ( ! is_plugin_active( $plugin_basename ) ) {
		return null;
	}

	$plugin_basename = path_join( WP_PLUGIN_DIR, $plugin_basename );
	$plugin = get_plugin_data( $plugin_basename, false, false );

	return sprintf( __( 'This will also deactivate the plugin %s.', 'secupress' ), '<b>' . $plugin['Name'] . '</b>' );
}


/**
 * Returns a i18n message to act like a CTA on pro version
 *
 * @param (string) $format You can use it to embed the message in a HTML tag, usage of "%s" is mandatory.
 * @since 1.0
 * @return (string)
 **/
function secupress_get_pro_version_string( $format = '' ) {
	if ( secupress_is_pro() ) {
		return '';
	}

	$message = sprintf( __( 'Available in <a href="%s">Pro Version</a>.', 'secupress' ), '#' ); //// #

	if ( $format ) {
		$message = sprintf( $format, $message );
	}

	return $message;
}


/**
 * Returns a i18n message to act like a CTA to get an API key
 *
 * @param (string) $format You can use it to embed the message in a HTML tag, usage of "%s" is mandatory.
 * @since 1.0
 * @return (string)
 **/
function secupress_get_valid_key_string( $format = '' ) {
	$message = sprintf( __( 'Requires a <a href="%s">Free API Key</a>.', 'secupress' ), '#' ); //// # + wording
	if ( $format ) {
		$message = sprintf( $format, $message );
	}
	return $message;
}
