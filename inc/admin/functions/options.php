<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/*------------------------------------------------------------------------------------------------*/
/* MAIN OPTION ================================================================================== */
/*------------------------------------------------------------------------------------------------*/

/**
 * Is this version White Labeled?
 *
 * @since 1.0
 *
 * @return (string)
 */
function secupress_is_white_label() {
	$names = array( 'wl_plugin_name', 'wl_plugin_URI', 'wl_description', 'wl_author', 'wl_author_URI' );

	foreach ( $names as $value ) {
		if ( false !== secupress_get_option( $value ) ) {
			return true;
		}
	}

	return false;
}


/**
 * Determine if the key is valid.
 * The function do the live check and update the option.
 *
 * @since 1.0
 *
 * @param (string) $type ////.
 *
 * @return (bool)
 */
function secupress_check_key( $type = 'transient_1' ) {
	// Recheck the license.
	$return = secupress_valid_key();

	if ( ! $return
		|| ( 'transient_1' === $type && ! get_transient( 'secupress_check_licence_1' ) )
		|| ( 'transient_30' === $type && ! get_transient( 'secupress_check_licence_30' ) )
		|| 'live' === $type ) {

		$response          = wp_remote_get( SECUPRESS_WEB_VALID, array( 'timeout' => 30 ) );
		$json              = ! is_wp_error( $response ) ? json_decode( $response['body'] ) : false;
		$secupress_options = array();

		if ( $json ) {
			$secupress_options['consumer_key']   = $json->data->consumer_key;
			$secupress_options['consumer_email'] = $json->data->consumer_email;

			if ( $json->success ) {
				$secupress_options['secret_key'] = $json->data->secret_key;
				if ( ! secupress_get_option( 'license' ) ) {
					$secupress_options['license'] = '1';
				}

				if ( 'live' !== $type ) {
					if ( 'transient_1' === $type ) {
						set_transient( 'secupress_check_licence_1', true, DAY_IN_SECONDS );
					} elseif ( 'transient_30' === $type ) {
						set_transient( 'secupress_check_licence_30', true, DAY_IN_SECONDS * 30 );
					}
				}
			} else {
				$messages = array(
					'BAD_LICENSE' => __( 'Your license is not valid.', 'secupress' ),
					'BAD_NUMBER'  => __( 'You cannot add more websites. Upgrade your account.', 'secupress' ),
					'BAD_SITE'    => __( 'This website is not allowed.', 'secupress' ),
					'BAD_KEY'     => __( 'This license key is not accepted.', 'secupress' ),
				);
				$secupress_options['secret_key'] = '';

				add_settings_error( 'general', 'settings_updated', $messages[ $json->data->reason ], 'error' );
			}

			set_transient( SECUPRESS_SETTINGS_SLUG, $secupress_options );
			$return = (array) $secupress_options;
		}
	}

	return $return;
}


/**
 * Determine if the key is valid.
 *
 * @since 1.0
 *
 * @return (bool)
 */
function secupress_valid_key() {
	return 8 === strlen( secupress_get_option( 'consumer_key' ) ) && secupress_get_option( 'secret_key' ) === hash( 'crc32', secupress_get_consumer_email() ); // secret_key? ////.
}


/**
 * ////
 *
 * @since 1.0
 */
function secupress_need_api_key() {}


/*------------------------------------------------------------------------------------------------*/
/* MODULE OPTIONS =============================================================================== */
/*------------------------------------------------------------------------------------------------*/

/**
 * Update a SecuPress module option.
 *
 * @since 1.0
 *
 * @param (string) $option  The option name.
 * @param (mixed)  $value   The new value.
 * @param (string) $module  The module slug (see array keys from `modules.php`). Default is the current module.
 */
function secupress_update_module_option( $option, $value, $module = false ) {
	if ( ! $module ) {
		$module = secupress_get_current_module();
	}

	$options = get_site_option( "secupress_{$module}_settings" );
	$options = is_array( $options ) ? $options : array();
	$options[ $option ] = $value;

	update_site_option( "secupress_{$module}_settings", $options );
}


/**
 * Update a SecuPress module options.
 *
 * @since 1.0
 *
 * @param (array)  $values The new values. Keys not provided are not removed, previous values are kept.
 * @param (string) $module The module slug (see array keys from `modules.php`). Default is the current module.
 */
function secupress_update_module_options( $values, $module = false ) {
	if ( ! $values || ! is_array( $values ) ) {
		return null;
	}

	if ( ! $module ) {
		$module = secupress_get_current_module();
	}

	$options = get_site_option( "secupress_{$module}_settings" );
	$options = is_array( $options ) ? $options : array();
	$options = array_merge( $options, $values );

	update_site_option( "secupress_{$module}_settings", $options );
}


/**
 * Get the current module.
 *
 * @since 1.0
 *
 * @return (string).
 */
function secupress_get_current_module() {
	if ( ! class_exists( 'SecuPress_Settings' ) ) {
		secupress_require_class( 'settings' );
	}
	if ( ! class_exists( 'SecuPress_Settings_Modules' ) ) {
		secupress_require_class( 'settings', 'modules' );
	}

	return SecuPress_Settings_Modules::get_instance()->get_current_module();
}
