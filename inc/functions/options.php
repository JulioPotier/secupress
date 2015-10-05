<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * A wrapper to easily get SecuPress option
 *
 * @since 1.0
 *
 * @param string $option  The option name
 * @param bool   $default (default: false) The default value of option
 * @return mixed The option value
 */
function secupress_get_option( $option, $default = false ) {
	/**
	 * Pre-filter any SecuPress option before read
	 *
	 * @since 1.0
	 *
	 * @param variant $default The default value
	*/
	$value = apply_filters( 'pre_secupress_get_option_' . $option, null, $default );

	if ( null !== $value ) {
		return $value;
	}

	$options = get_option( SECUPRESS_SETTINGS_SLUG );
	$value   = isset( $options[ $option ] ) && $options[ $option ] !== false ? $options[ $option ] : $default;
	/**
	 * Filter any SecuPress option after read
	 *
	 * @since 1.0
	 *
	 * @param variant $default The default value
	*/
	return apply_filters( 'secupress_get_option_' . $option, $value, $default );
}


/**
 * A wrapper to easily get SecuPress module option
 *
 * @since 1.0
 *
 * @param string $option  The option name
 * @param bool   $default (default: false) The default value of option.
 * @param string $module  The module slug (see array keys from modules.php) default is the current module.
 * @return mixed The option value
 */
function secupress_get_module_option( $option, $default = false, $module = false ) {

	if ( ! $module ) {
		if ( ! class_exists( 'SecuPress_Settings' ) ) {
			secupress_require_class( 'settings' );
		}
		if ( ! class_exists( 'SecuPress_Settings_Modules' ) ) {
			secupress_require_class( 'settings', 'modules' );
		}

		$module = SecuPress_Settings_Modules::get_instance()->get_current_module();
	}

	/**
	 * Pre-filter any SecuPress option before read
	 *
	 * @since 1.0
	 *
	 * @param variant $default The default value
	*/
	$value = apply_filters( 'pre_secupress_get_module_option_' . $option, null, $default, $module );

	if ( null !== $value ) {
		return $value;
	}

	$options = get_option( "secupress_{$module}_settings" );
	$value   = isset( $options[ $option ] ) && $options[ $option ] !== false ? $options[ $option ] : $default;
	/**
	 * Filter any SecuPress option after read
	 *
	 * @since 1.0
	 *
	 * @param variant $default The default value
	*/
	return apply_filters( 'secupress_get_module_option_' . $option, $value, $default, $module );
}


function update_secupress_module_option( $option, $value, $module = false ) {

	if ( ! $module ) {
		if ( ! class_exists( 'SecuPress_Settings' ) ) {
			secupress_require_class( 'settings' );
		}
		if ( ! class_exists( 'SecuPress_Settings_Modules' ) ) {
			secupress_require_class( 'settings', 'modules' );
		}

		$module = SecuPress_Settings_Modules::get_instance()->get_current_module();
	}

	$options = get_option( "secupress_{$module}_settings" );
	$options[ $option ] = $value;

	update_option( "secupress_{$module}_settings", $options );
}


function secupress_get_scanners() {
	static $tests;

	if ( ! isset( $tests ) ) {
		$tests = array();
		$tmps  = secupress_get_tests();

		foreach ( $tmps as $tmp ) {
			$tests = array_merge( $tests, array_map( 'strtolower', $tmp ) );
		}
	}

	$transients = array();
	$fixes      = secupress_get_scanner_fixes();

	foreach ( $tests as $test_name ) {
		$transient = get_transient( 'secupress_scan_' . $test_name );

		if ( $transient && is_array( $transient ) ) {
			delete_transient( 'secupress_scan_' . $test_name );
			$transients[ $test_name ] = $transient;
			// In the same time, when a scan is good, remove the related fix.
			if ( 'good' === $transient['status'] ) {
				unset( $fixes[ $test_name ] );
			}
		}
	}

	$options = get_option( SECUPRESS_SCAN_SLUG, array() );
	$options = is_array( $options ) ? $options : array();

	if ( $transients ) {
		$options = array_merge( $options, $transients );
		update_option( SECUPRESS_SCAN_SLUG, $options );

		// Also update the fixes.
		update_option( SECUPRESS_FIX_SLUG, $fixes );
	}

	return $options;
}


function secupress_get_scanner_fixes() {
	static $tests;

	if ( ! isset( $tests ) ) {
		$tests = array();
		$tmps  = secupress_get_tests();

		foreach ( $tmps as $tmp ) {
			$tests = array_merge( $tests, array_map( 'strtolower', $tmp ) );
		}
	}

	$transients = array();

	foreach ( $tests as $test_name ) {
		$transient = get_transient( 'secupress_fix_' . $test_name );

		if ( $transient && is_array( $transient ) ) {
			delete_transient( 'secupress_fix_' . $test_name );
			$transients[ $test_name ] = $transient;
		}
	}

	$options = get_option( SECUPRESS_FIX_SLUG, array() );
	$options = is_array( $options ) ? $options : array();

	if ( $transients ) {
		$options = array_merge( $options, $transients );
		update_option( SECUPRESS_FIX_SLUG, $options );
	}

	return $options;
}


function secupress_get_tests() {
	return array(
		'high' => array(
			'Core_Update',      'Plugins_Update',    'Themes_Update',
			'Auto_Update',      'Bad_Old_Plugins',   'Bad_Old_Files',
			'Bad_Config_Files', 'Directory_Listing', 'PHP_INI',
			'Admin_User',       'Easy_Login',        'Subscription',
			'WP_Config',        'Salt_Keys',         'Passwords_Strength',
			'Chmods',           'Common_Flaws',      'Bad_User_Agent',
			'SQLi',
		),
		'medium' => array(
			'Inactive_Plugins_Themes', 'Bad_Url_Access', 'Bad_Usernames',
			'Bad_Request_Methods',     'PhpVersion',     'Too_Many_Admins', 
			'Block_HTTP_1_0',          'Discloses',      'Block_Long_URL',
		),
		'low' => array(
			'Login_Errors_Disclose', 'PHP_Disclosure', 'Admin_As_Author'
		),
	);
}


/**
 * Determine if the key is valid
 *
 * @since 1.0 The function do the live check and update the option
 */
function secupress_check_key( $type = 'transient_1', $data = null ) {
	// Recheck the license
	$return = secupress_valid_key();

	if ( ! secupress_valid_key()
		|| ( 'transient_1' == $type && ! get_transient( 'secupress_check_licence_1' ) )
		|| ( 'transient_30' == $type && ! get_transient( 'secupress_check_licence_30' ) )
		|| 'live' == $type ) {

		$response = wp_remote_get( SECUPRESS_WEB_VALID, array( 'timeout' => 30 ) );

		$json = ! is_wp_error( $response ) ? json_decode( $response['body'] ) : false;
		$secupress_options = array();

		if ( $json ) {

			$secupress_options['consumer_key'] 	= $json->data->consumer_key;
			$secupress_options['consumer_email']	= $json->data->consumer_email;

			if ( $json->success ) {

				$secupress_options['secret_key'] = $json->data->secret_key;
				if ( ! secupress_get_option( 'license' ) ) {
					$secupress_options['license'] = '1';
				}

				if ( 'live' != $type ) {
					if ( 'transient_1' == $type ) {
						set_transient( 'secupress_check_licence_1', true, DAY_IN_SECONDS );
					} elseif ( 'transient_30' == $type ) {
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
 * Determine if the key is valid
 *
 * @since 1.0
 */
function secupress_valid_key() {
	return 8 == strlen( secupress_get_option( 'consumer_key' ) ) && secupress_get_option( 'secret_key' ) === hash( 'crc32', secupress_get_option( 'consumer_email' ) );
}


function secupress_need_api_key() {}
