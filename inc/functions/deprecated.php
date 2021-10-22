<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/**
 * Deprecated constants.
 * Be aware that they are not defined as soon as the plugin loads anymore.
 */
define( 'SECUPRESS_SCAN_SLUG',           'secupress_scanners' );  // Since 1.3.
define( 'SECUPRESS_FIX_SLUG',            'secupress_fixes' );     // Since 1.3.
define( 'SECUPRESS_SCAN_FIX_SITES_SLUG', 'secupress_fix_sites' ); // Since 1.3.


/**
 * Send an email message to our awesome support team (yes it is).
 *
 * @since 1.1.1
 * @since 1.1.4 Deprecated.
 * @author Grégory Viguier
 *
 * @param (string) $summary     A title. The value is not escaped.
 * @param (string) $description A message. The value has been sanitized with `wp_kses()`.
 * @param (array)  $data        An array of infos related to the site.
 */
function secupress_send_support_request( $summary, $description, $data ) {
	_deprecated_function( __FUNCTION__, '1.1.4', 'secupress_pro_send_support_request()' );
	// To.
	$to = 'sserpuces' . chr( 64 );
	$to = strrev( 'em.' . $to . 'troppus' );

	// From.
	$from_user = wp_get_current_user();
	$from      = secupress_get_user_full_name( $from_user ) . ' <' . $from_user->data->user_email . '>';

	// Headers.
	$headers = array(
		'from: ' . $from,
		'content-type: text/html',
	);

	// Subject.
	$summary = esc_html( $summary );
	if ( function_exists( 'mb_convert_encoding' ) ) {
		$summary = preg_replace_callback( '/(&#[0-9]+;)/', function( $m ) {
			return mb_convert_encoding( $m[1], 'UTF-8', 'HTML-ENTITIES' );
		}, $summary );
	}
	$summary = wp_specialchars_decode( $summary );

	// Message.
	$data = array_merge( array(
		'license_email'  => sprintf( __( 'License email: %s', 'secupress' ), secupress_get_consumer_email() ),
		'license_key'    => sprintf( __( 'License key: %s', 'secupress' ), secupress_get_consumer_key() ),
		'sp_pro_version' => secupress_has_pro() ? sprintf( __( 'Version of SecuPress Pro: %s', 'secupress' ), SECUPRESS_PRO_VERSION ) : __( 'Version of SecuPress Pro: inactive', 'secupress' ),
	), $data );

	$data = '<br/>' . str_repeat( '-', 40 ) . '<br/>' . implode( '<br/>', $data );

	// Go!
	$success = wp_mail( $to, $summary, $description . $data, $headers );

	if ( $success ) {
		secupress_add_settings_error( 'general', 'message_sent', __( 'Your message has been sent, we will come back to you shortly. Thank you.', 'secupress' ), 'updated' );
	} else {
		$summary     = str_replace( '+', '%20', urlencode( $summary ) );
		$description = str_replace( array( '+', '%3E%0A' ), array( '%20', '%3E' ), urlencode( $description . $data ) );
		$url         = 'mailto:' . $to . '?subject=' . $summary . '&body=' . $description;

		secupress_add_settings_error( 'general', 'message_failed', sprintf(
			/** Translators: %s is an email address. */
			__( 'Something prevented your message to be sent. Please send it manually to %s. Thank you.', 'secupress' ),
			'<a href="' . esc_url( $url ) . '">' . $to . '</a>'
		) );
	}
}


/**
 * Will lately add admin notices added by `secupress_add_transient_notice()`.
 *
 * @since 1.0
 * @since 1.3 Deprecated.
 * @author Julio Potier
 */
function secupress_display_transient_notices() {
	_deprecated_function( __FUNCTION__, '1.3', 'SecuPress_Admin_Notices::get_instance()->add_transient_notices()' );

	$notices = secupress_get_transient( 'secupress-notices-' . get_current_user_id() );

	if ( ! $notices ) {
		return;
	}

	foreach ( $notices as $notice ) {
		secupress_add_notice( $notice['message'], $notice['error_code'], false );
	}

	delete_transient( 'secupress-notices-' . get_current_user_id() );
}


/**
 * This warning is displayed when the license is not valid.
 *
 * @since 1.0.6
 * @since 1.3 Deprecated.
 * @author Grégory Viguier
 */
function secupress_warning_no_license() {
	global $current_screen;

	_deprecated_function( __FUNCTION__, '1.3', 'SecuPress_Pro_Admin_Free_Downgrade::get_instance()->maybe_warn_no_license()' );

	if ( SECUPRESS_PLUGIN_SLUG . '_page_' . SECUPRESS_PLUGIN_SLUG . '_settings' === $current_screen->base ) {
		return;
	}

	if ( ! secupress_has_pro() || secupress_is_pro() ) {
		return;
	}

	if ( ! current_user_can( secupress_get_capability() ) ) {
		return;
	}

	$message  = sprintf( __( '%s:', 'secupress' ), '<strong>' . SECUPRESS_PLUGIN_NAME . '</strong>' ) . ' ';
	/** Translators: %s is a link to the "plugin settings page". */
	$message .= sprintf(
		__( 'Your Pro license is not valid or is not set yet. If you want to activate all the Pro features, premium support and updates, take a look at %s.', 'secupress' ),
		'<a href="' . esc_url( secupress_admin_url( 'settings' ) ) . '">' . __( 'the plugin settings page', 'secupress' ) . '</a>'
	);

	secupress_add_notice( $message, 'updated', false );
}


/**
 * Get a user name.
 * Try first to have first name + last name, then only first name or last name, then only last name or first name, then display name.
 *
 * @since 1.1.1
 * @since 1.1.4 Deprecated.
 * @author Grégory Viguier
 *
 * @param (object) $user A WP_User object.
 *
 * @return (string)
 */
function secupress_get_user_full_name( $user ) {
	_deprecated_function( __FUNCTION__, '1.1.4' );

	if ( ! empty( $user->first_name ) && ! empty( $user->last_name ) ) {
		return sprintf( _x( '%1$s %2$s', 'User full name. 1: first name, 2: last name', 'secupress' ), $user->first_name, $user->last_name );
	}

	$field1 = sprintf( _x( '%1$s %2$s', 'User full name. 1: first name, 2: last name', 'secupress' ), 'first_name', 'last_name' );

	if ( strpos( $field1, 'first_name' ) < strpos( $field1, 'last_name' ) ) {
		$field1 = 'first_name';
		$field2 = 'last_name';
	} else {
		$field1 = 'last_name';
		$field2 = 'first_name';
	}

	if ( ! empty( $user->$field1 ) ) {
		return $user->$field1;
	}

	if ( ! empty( $user->$field2 ) ) {
		return $user->$field2;
	}

	return $user->display_name;
}


/**
 * Get name & version of all active plugins.
 *
 * @since 1.0.6
 * @since 1.1.4 Deprecated.
 * @author Grégory Viguier
 *
 * @return (array) An array of active plugins: name and version.
 */
function secupress_get_active_plugins() {
	_deprecated_function( __FUNCTION__, '1.1.4' );

	$all_plugins    = get_plugins();
	$active_plugins = array();

	if ( is_multisite() ) {
		// Get network activated plugins.
		$network_plugins = array_filter( (array) get_site_option( 'active_sitewide_plugins', array() ) );
		$network_plugins = array_intersect_key( $all_plugins, $network_plugins );

		if ( $network_plugins ) {
			foreach ( $network_plugins as $plugin ) {
				$active_plugins[] = $plugin['Name'] . ' ' . $plugin['Version'] . ' (' . __( 'network', 'secupress' ) . ')';
			}
		}

		// Get blog activated plugins.
		$plugins = get_site_option( 'secupress_active_plugins' );

		if ( is_array( $plugins ) ) {
			// We can use our option that stores all blog activated plugins.
			$plugins = call_user_func_array( 'array_merge', $plugins ); // The plugin paths are the array keys.
			$plugins = array_diff_key( $plugins, $network_plugins );    // Make sure we don't have network activated plugins in the list.
			$plugins = array_intersect_key( $all_plugins, $plugins );

			if ( $plugins ) {
				foreach ( $plugins as $plugin ) {
					$active_plugins[] = $plugin['Name'] . ' ' . $plugin['Version'];
				}
			}
		} else {
			// At least, get the plugins active on the main blog.
			$plugins = array_diff_key( $all_plugins, $network_plugins ); // Remove network activated plugins.
			$plugins = array_intersect_key( $all_plugins, array_flip( array_filter( array_keys( $plugins ), 'is_plugin_active' ) ) );

			if ( $plugins ) {
				foreach ( $plugins as $plugin ) {
					$active_plugins[] = $plugin['Name'] . ' ' . $plugin['Version'] . ' (' . __( 'main site', 'secupress' ) . ')';
				}
			}
		}
	} else {
		// Not a multisite.
		$plugins = array_intersect_key( $all_plugins, array_flip( array_filter( array_keys( $all_plugins ), 'is_plugin_active' ) ) );

		if ( $plugins ) {
			foreach ( $plugins as $plugin ) {
				$active_plugins[] = $plugin['Name'] . ' ' . $plugin['Version'];
			}
		}
	}

	// Must-Use plugins.
	$plugins = get_mu_plugins();

	if ( $plugins ) {
		foreach ( $plugins as $plugin ) {
			$active_plugins[] = $plugin['Name'] . ' ' . $plugin['Version'] . ' (' . __( 'Must-Use plugin', 'secupress' ) . ')';
		}
	}

	// Drop-ins.
	$plugins = get_dropins();

	if ( $plugins ) {
		foreach ( $plugins as $plugin ) {
			/** Translators: a drop-in is specific kind of WordPress plugin. */
			$active_plugins[] = $plugin['Name'] . ' ' . $plugin['Version'] . ' (' . __( 'drop-in', 'secupress' ) . ')';
		}
	}

	return $active_plugins;
}

/**
 * Get contents to put in the `.htaccess` file to ban IPs.
 *
 * @since 1.4.9 Deprecated
 * @since 1.0
 *
 * @return (string)
 */
function secupress_get_htaccess_ban_ip() {
	_deprecated_function( __FUNCTION__, '1.4.9' );
}


/**
 * Update the 2 files for GeoIP database on demand
 *
 * @since 2.1 Deprecated function
 * @since 1.4.9
 * @author Julio Potier
 **/
function secupress_geoips_update_datafiles() {
	_deprecated_function( __FUNCTION__, '2.1', 'secupress_geoips_update_datafile' );
	secupress_geoips_update_datafile();
}