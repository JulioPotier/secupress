<?php
defined( 'ABSPATH' ) or	die( 'Cheatin&#8217; uh?' );

/**
 * A wrapper to easily get SecuPress option
 *
 * @since 1.0
 *
 * @param string $option  The option name
 * @param bool   $default (default: false) The default value of option
 * @return mixed The option value
 */
function get_secupress_option( $option, $default = false )
{
	/**
	 * Pre-filter any SecuPress option before read
	 *
	 * @since 1.0
	 *
	 * @param variant $default The default value
	*/
	$value = apply_filters( 'pre_get_secupress_option_' . $option, NULL, $default );
	if ( NULL !== $value ) {
		return $value;
	}
	$options = get_option( SECUPRESS_SETTINGS_SLUG );
	$value = isset( $options[ $option ] ) && $options[ $option ] !== false ? $options[ $option ] : $default;
	/**
	 * Filter any SecuPress option after read
	 *
	 * @since 1.0
	 *
	 * @param variant $default The default value
	*/
	return apply_filters( 'get_secupress_option_' . $option, $value, $default );
}


/**
 * A wrapper to easily get SecuPress module option
 *
 * @since 1.0
 *
 * @param string $option  The option name
 * @param bool   $default (default: false) The default value of option
 * @param string $module  The module slug (see array keys from modules.php) default is $modulenow global var
 * @return mixed The option value
 */
function get_secupress_module_option( $option, $default = false, $module = false )
{
	global $modulenow;
	$module = $module ? $module : $modulenow;
	/**
	 * Pre-filter any SecuPress option before read
	 *
	 * @since 1.0
	 *
	 * @param variant $default The default value
	*/
	$value = apply_filters( 'pre_get_secupress_module_option_' . $option, NULL, $default, $module );
	if ( NULL !== $value ) {
		return $value;
	}
	$options = get_option( "secupress_{$module}_settings" );
	$value = isset( $options[ $option ] ) && $options[ $option ] !== false ? $options[ $option ] : $default;
	/**
	 * Filter any SecuPress option after read
	 *
	 * @since 1.0
	 *
	 * @param variant $default The default value
	*/
	return apply_filters( 'get_secupress_module_option_' . $option, $value, $default, $module );
}

function update_secupress_module_option( $option, $value, $module = false )
{
	global $modulenow;
	$module = $module ? $module : $modulenow;
	$options = get_option( "secupress_{$module}_settings" );
	$options[ $option ] = $value;
	update_option( "secupress_{$module}_settings", $options );
}

function secupress_submit_button( $type = 'primary large', $name = 'main_submit', $wrap = false, $other_attributes = null, $echo = true ) {
	if ( true === $wrap ) {
		$wrap = '';
	} elseif ( $wrap ) {
		$wrap = '<p class="' . sanitize_html_class( $wrap ) . '">';
	}
	$button = get_submit_button( __( 'Save All Changes', 'secupress' ), $type, $name, false, $other_attributes );
	if ( $wrap ) {
		$button = $wrap . $button . '</p>';
	}
	if ( $echo ) {
		echo $button;
	} else {
		return $button;
	}
}


/**
 * Determine if the key is valid
 *
 * @since 1.0 The function do the live check and update the option
 */
function secupress_check_key( $type = 'transient_1', $data = null )
{
	// Recheck the license
	$return = secupress_valid_key();

	if ( ! secupress_valid_key()
		|| ( 'transient_1' == $type && ! get_transient( 'secupress_check_licence_1' ) )
		|| ( 'transient_30' == $type && ! get_transient( 'secupress_check_licence_30' ) )
		|| 'live' == $type ) {

		$response = wp_remote_get( SECUPRESS_WEB_VALID, array( 'timeout'=>30 ) );

		$json = ! is_wp_error( $response ) ? json_decode( $response['body'] ) : false;
		$secupress_options = array();

		if ( $json ) {

			$secupress_options['consumer_key'] 	= $json->data->consumer_key;
			$secupress_options['consumer_email']	= $json->data->consumer_email;

			if( $json->success ) {

				$secupress_options['secret_key'] = $json->data->secret_key;
				if ( ! get_secupress_option( 'license' ) ) {
					$secupress_options['license'] = '1';
				}
				
				if ( 'live' != $type ) {
					if ( 'transient_1' == $type ) {
						set_transient( 'secupress_check_licence_1', true, DAY_IN_SECONDS );
					} elseif ( 'transient_30' == $type ) {
						set_transient( 'secupress_check_licence_30', true, DAY_IN_SECONDS*30 );
					}
				}

			} else {

				$messages = array( 	'BAD_LICENSE'	=> __( 'Your license is not valid.', 'secupress' ),
									'BAD_NUMBER'	=> __( 'You cannot add more websites. Upgrade your account.', 'secupress' ),
									'BAD_SITE'		=> __( 'This website is not allowed.', 'secupress' ),
									'BAD_KEY'		=> __( 'This license key is not accepted.', 'secupress' ),
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
 * Determine if the key is valid
 *
 * @since 1.0
 */
function secupress_valid_key()
{
	return 8 == strlen( get_secupress_option( 'consumer_key' ) ) && get_secupress_option( 'secret_key' ) == hash( 'crc32', get_secupress_option( 'consumer_email' ) );
}

function secupress_need_api_key(){}