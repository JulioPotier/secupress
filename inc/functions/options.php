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

	$options = get_site_option( SECUPRESS_SETTINGS_SLUG );
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
 * @param bool   $default (default: null) The default value of option.
 * @param string $module  The module slug (see array keys from modules.php) default is the current module.
 * @return mixed The option value
 */
function secupress_get_module_option( $option, $default = null, $module = false ) {

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

	$options = get_site_option( "secupress_{$module}_settings" );
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


function secupress_update_module_option( $option, $value, $module = false ) {

	if ( ! $module ) {
		if ( ! class_exists( 'SecuPress_Settings' ) ) {
			secupress_require_class( 'settings' );
		}
		if ( ! class_exists( 'SecuPress_Settings_Modules' ) ) {
			secupress_require_class( 'settings', 'modules' );
		}

		$module = SecuPress_Settings_Modules::get_instance()->get_current_module();
	}

	$options = get_site_option( "secupress_{$module}_settings" );
	$options = is_array( $options ) ? $options : array();
	$options[ $option ] = $value;

	update_site_option( "secupress_{$module}_settings", $options );
}


function secupress_update_module_options( $values, $module = false ) {
	if ( ! $values || ! is_array( $values ) ) {
		return null;
	}

	if ( ! $module ) {
		if ( ! class_exists( 'SecuPress_Settings' ) ) {
			secupress_require_class( 'settings' );
		}
		if ( ! class_exists( 'SecuPress_Settings_Modules' ) ) {
			secupress_require_class( 'settings', 'modules' );
		}

		$module = SecuPress_Settings_Modules::get_instance()->get_current_module();
	}

	$options = get_site_option( "secupress_{$module}_settings" );
	$options = is_array( $options ) ? $options : array();
	$options = array_merge( $options, $values );

	update_site_option( "secupress_{$module}_settings", $options );
}


function secupress_get_scanners() {
	static $tests;

	if ( ! isset( $tests ) ) {
		$tests = array();
		$tmps  = secupress_get_tests();

		foreach ( $tmps as $tmp ) {
			$tests = array_merge( $tests, array_map( 'strtolower', $tmp ) );
		}

		// Cache transients.
		if ( ! wp_using_ext_object_cache() ) {
			secupress_load_network_options( $tests, '_site_transient_secupress_scan_' );
		}
	}

	$transients = array();
	$to_remove  = array();

	foreach ( $tests as $test_name ) {
		$transient = secupress_get_site_transient( 'secupress_scan_' . $test_name );

		if ( $transient && is_array( $transient ) ) {
			secupress_delete_site_transient( 'secupress_scan_' . $test_name );
			$transients[ $test_name ] = $transient;
			// In the same time, when a scan is good, remove the related fix.
			if ( 'good' === $transient['status'] ) {
				$to_remove[ $test_name ] = 1;
			}
		}
	}

	$options = get_site_option( SECUPRESS_SCAN_SLUG, array() );
	$options = is_array( $options ) ? $options : array();

	if ( $transients ) {
		$options = array_merge( $options, $transients );
		update_site_option( SECUPRESS_SCAN_SLUG, $options );

		// Also update the fixes.
		$fixes = secupress_get_scanner_fixes();
		if ( $to_remove ) {
			$fixes = array_diff_key( $fixes, $to_remove );
		}
		update_site_option( SECUPRESS_FIX_SLUG, $fixes );
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

		// Cache transients.
		if ( ! wp_using_ext_object_cache() ) {
			secupress_load_network_options( $tests, '_site_transient_secupress_fix_' );
		}
	}

	$transients = array();

	foreach ( $tests as $test_name ) {
		$transient = secupress_get_site_transient( 'secupress_fix_' . $test_name );

		if ( $transient && is_array( $transient ) ) {
			secupress_delete_site_transient( 'secupress_fix_' . $test_name );
			$transients[ $test_name ] = $transient;
		}
	}

	$options = get_site_option( SECUPRESS_FIX_SLUG, array() );
	$options = is_array( $options ) ? $options : array();

	if ( $transients ) {
		$options = array_merge( $options, $transients );
		update_site_option( SECUPRESS_FIX_SLUG, $options );
	}

	return $options;
}


/**
 * Delete a site transient.
 *
 * This is almost the same function than `delete_site_transient()`, but without the timeout check: it saves database calls.
 *
 * @since 1.0
 * @since WP 2.9.0
 *
 * @param (string) $transient Transient name. Expected to not be SQL-escaped.
 *
 * @return (bool) true if successful, false otherwise.
 */
function secupress_delete_site_transient( $transient ) {

	/**
	 * Fires immediately before a specific site transient is deleted.
	 *
	 * The dynamic portion of the hook name, `$transient`, refers to the transient name.
	 *
	 * @since 1.0
	 * @since WP 3.0.0
	 *
	 * @param (string) $transient Transient name.
	 */
	do_action( 'delete_site_transient_' . $transient, $transient );

	if ( wp_using_ext_object_cache() ) {
		$result = wp_cache_delete( $transient, 'site-transient' );
	} else {
		$option = '_site_transient_' . $transient;
		$result = delete_site_option( $option );
	}

	if ( $result ) {

		/**
		 * Fires after a site transient is deleted.
		 *
		 * @since 1.0
		 * @since WP 3.0.0
		 *
		 * @param (string) $transient Deleted transient name.
		 */
		do_action( 'deleted_site_transient', $transient );
	}

	return $result;
}


/**
 * Get the value of a site transient.
 *
 * This is almost the same function than `get_site_transient()`, but without the timeout check: it saves database calls.
 * If the transient does not exist or does not have a value, then the return value will be false.
 *
 * @since 1.0
 * @since WP 2.9.0
 *
 * @param (string) $transient Transient name. Expected to not be SQL-escaped.
 *
 * @return (mixed) Value of transient.
 */
function secupress_get_site_transient( $transient ) {

 	/**
	 * Filter the value of an existing site transient.
	 *
	 * The dynamic portion of the hook name, `$transient`, refers to the transient name.
	 *
	 * Passing a truthy value to the filter will effectively short-circuit retrieval
	 * of the transient, returning the passed value instead.
	 *
	 * @since 1.0
	 * @since WP 2.9.0
	 * @since WP 4.4.0 The `$transient` parameter was added.
	 *
	 * @param (mixed)  $pre_transient The default value to return if the site transient does not exist.
	 *                                Any value other than false will short-circuit the retrieval
	 *                                of the transient, and return the returned value.
	 * @param (string) $transient     Transient name.
	 */
	$pre = apply_filters( 'pre_site_transient_' . $transient, false, $transient );
	if ( false !== $pre ) {
		return $pre;
	}

	if ( wp_using_ext_object_cache() ) {
		$value = wp_cache_get( $transient, 'site-transient' );
	} else {
		$option = '_site_transient_' . $transient;
		$value  = get_site_option( $option );
	}

	/**
	 * Filter the value of an existing site transient.
	 *
	 * The dynamic portion of the hook name, `$transient`, refers to the transient name.
	 *
	 * @since 1.0
	 * @since WP 2.9.0
	 * @since WP 4.4.0 The `$transient` parameter was added.
	 *
	 * @param (mixed)  $value     Value of transient.
	 * @param (string) $transient Transient name.
	 */
	return apply_filters( 'site_transient_' . $transient, $value, $transient );
}


/**
 * Set/update the value of a site transient.
 *
 * This is almost the same function than `set_site_transient()`, but without the timeout check.
 * You do not need to serialize values. If the value needs to be serialized, then it will be serialized before it is set.
 *
 * @since 1.0
 * @since WP 2.9.0
 *
 * @param (string) $transient  Transient name. Expected to not be SQL-escaped. Must be
 *                             40 characters or fewer in length.
 * @param (mixed)  $value      Transient value. Must be serializable if non-scalar.
 *                             Expected to not be SQL-escaped.
 *
 * @return (bool) False if value was not set and true if value was set.
 */
function secupress_set_site_transient( $transient, $value ) {

	/**
	 * Filter a specific site transient before its value is set.
	 *
	 * The dynamic portion of the hook name, `$transient`, refers to the transient name.
	 *
	 * @since 1.0
	 * @since WP 3.0.0
	 * @since WP 4.4.0 The `$transient` parameter was added.
	 *
	 * @param (mixed)  $value      New value of site transient.
	 * @param (string) $transient  Transient name.
	 */
	$value = apply_filters( 'pre_set_site_transient_' . $transient, $value, $transient );

	if ( wp_using_ext_object_cache() ) {
		$result = wp_cache_set( $transient, $value, 'site-transient' );
	} else {
		$option = '_site_transient_' . $transient;
		if ( false === get_site_option( $option ) ) {
			$result = add_site_option( $option, $value );
		} else {
			$result = update_site_option( $option, $value );
		}
	}

	if ( $result ) {

		/**
		 * Fires after the value for a specific site transient has been set.
		 *
		 * The dynamic portion of the hook name, `$transient`, refers to the transient name.
		 *
		 * @since 1.0
		 * @since WP 3.0.0
		 * @since WP 4.4.0 The `$transient` parameter was added.
		 *
		 * @param (mixed)  $value      Transient value.
		 * @param (int)    $expiration Time until expiration in seconds, forced to 0.
		 * @param (string) $transient  The name of the transient.
		 */
		do_action( 'set_site_transient_' . $transient, $value, 0, $transient );

		/**
		 * Fires after the value for a site transient has been set.
		 *
		 * @since 1.0
		 * @since WP 3.0.0
		 *
		 * @param (string) $transient  The name of the transient.
		 * @param (mixed)  $value      Transient value.
		 * @param (int)    $expiration Time until expiration in seconds, forced to 0.
		 */
		do_action( 'setted_site_transient', $transient, $value, 0 );
	}
	return $result;
}


/**
 * Delete a transient.
 *
 * This is almost the same function than `delete_transient()`, but without the timeout check: it saves database calls.
 *
 * @since 1.0
 * @since WP 2.8.0
 *
 * @param (string) $transient Transient name. Expected to not be SQL-escaped.
 *
 * @return (bool) true if successful, false otherwise.
 */
function secupress_delete_transient( $transient ) {

	/**
	 * Fires immediately before a specific transient is deleted.
	 *
	 * The dynamic portion of the hook name, `$transient`, refers to the transient name.
	 *
	 * @since 1.0
	 * @since WP 3.0.0
	 *
	 * @param (string) $transient Transient name.
	 */
	do_action( 'delete_transient_' . $transient, $transient );

	if ( wp_using_ext_object_cache() ) {
		$result = wp_cache_delete( $transient, 'transient' );
	} else {
		$option = '_transient_' . $transient;
		$result = delete_option( $option );
	}

	if ( $result ) {

		/**
		 * Fires after a transient is deleted.
		 *
		 * @since 1.0
		 * @since WP 3.0.0
		 *
		 * @param (string) $transient Deleted transient name.
		 */
		do_action( 'deleted_transient', $transient );
	}

	return $result;
}


/**
 * Get the value of a transient.
 *
 * This is almost the same function than `get_transient()`, but without the timeout check: it saves database calls.
 * If the transient does not exist or does not have a value, then the return value will be false.
 *
 * @since 1.0
 * @since WP 2.8.0
 *
 * @param (string) $transient Transient name. Expected to not be SQL-escaped.
 *
 * @return (mixed) Value of transient.
 */
function secupress_get_transient( $transient ) {

	/**
	 * Filter the value of an existing transient.
	 *
	 * The dynamic portion of the hook name, `$transient`, refers to the transient name.
	 *
	 * Passing a truthy value to the filter will effectively short-circuit retrieval
	 * of the transient, returning the passed value instead.
	 *
	 * @since 1.0
	 * @since WP 2.8.0
	 * @since WP 4.4.0 The `$transient` parameter was added
	 *
	 * @param (mixed)  $pre_transient The default value to return if the transient does not exist.
	 *                                Any value other than false will short-circuit the retrieval
	 *                                of the transient, and return the returned value.
	 * @param (string) $transient     Transient name.
	 */
	$pre = apply_filters( 'pre_transient_' . $transient, false, $transient );
	if ( false !== $pre ) {
		return $pre;
	}

	if ( wp_using_ext_object_cache() ) {
		$value = wp_cache_get( $transient, 'transient' );
	} else {
		$option = '_transient_' . $transient;
		$value  = get_option( $option );
	}

	/**
	 * Filter an existing transient's value.
	 *
	 * The dynamic portion of the hook name, `$transient`, refers to the transient name.
	 *
	 * @since 1.0
	 * @since WP 2.8.0
	 * @since WP 4.4.0 The `$transient` parameter was added
	 *
	 * @param (mixed)  $value     Value of transient.
	 * @param (string) $transient Transient name.
	 */
	return apply_filters( 'transient_' . $transient, $value, $transient );
}


/**
 * Set/update the value of a transient.
 *
 * This is almost the same function than `set_site_transient()`, but without the timeout check.
 * You do not need to serialize values. If the value needs to be serialized, then it will be serialized before it is set.
 *
 * @since 1.0
 * @since WP 2.8.0
 *
 * @param (string) $transient  Transient name. Expected to not be SQL-escaped. Must be
 *                             172 characters or fewer in length.
 * @param (mixed)  $value      Transient value. Must be serializable if non-scalar.
 *                             Expected to not be SQL-escaped.
 *
 * @return bool False if value was not set and true if value was set.
 */
function secupress_set_transient( $transient, $value ) {

	/**
	 * Filter a specific transient before its value is set.
	 *
	 * The dynamic portion of the hook name, `$transient`, refers to the transient name.
	 *
	 * @since 1.0
	 * @since WP 3.0.0
	 * @since WP 4.2.0 The `$expiration` parameter was added.
	 * @since WP 4.4.0 The `$transient` parameter was added.
	 *
	 * @param (mixed)  $value      New value of transient.
	 * @param (int)    $expiration Time until expiration in seconds, forced to 0.
	 * @param (string) $transient  Transient name.
	 */
	$value = apply_filters( 'pre_set_transient_' . $transient, $value, 0, $transient );

	if ( wp_using_ext_object_cache() ) {
		$result = wp_cache_set( $transient, $value, 'transient', 0 );
	} else {
		$option = '_transient_' . $transient;
		if ( false === get_option( $option ) ) {
			$result = add_option( $option, $value );
		} else {
			$result = update_option( $option, $value );
		}
	}

	if ( $result ) {

		/**
		 * Fires after the value for a specific transient has been set.
		 *
		 * The dynamic portion of the hook name, `$transient`, refers to the transient name.
		 *
		 * @since 1.0
		 * @since WP 3.0.0
		 * @since WP 3.6.0 The `$value` and `$expiration` parameters were added.
		 * @since WP 4.4.0 The `$transient` parameter was added.
		 *
		 * @param (mixed)  $value      Transient value.
		 * @param (int)    $expiration Time until expiration in seconds, forced to 0.
		 * @param (string) $transient  The name of the transient.
		 */
		do_action( 'set_transient_' . $transient, $value, 0, $transient );

		/**
		 * Fires after the value for a transient has been set.
		 *
		 * @since 1.0
		 * @since WP 3.0.0
		 * @since WP 3.6.0 The `$value` and `$expiration` parameters were added.
		 *
		 * @param (string) $transient  The name of the transient.
		 * @param (mixed)  $value      Transient value.
		 * @param (int)    $expiration Time until expiration in seconds, forced to 0.
		 */
		do_action( 'setted_transient', $transient, $value, 0 );
	}
	return $result;
}


/**
 * Return all tests to scan
 *
 * @since 1.0
 * @return array Tests to scan
 **/
function secupress_get_tests() {
	$tests = array(
		'high' => array(
			'Core_Update',      'Plugins_Update',    'Themes_Update',
			'Auto_Update',      'Bad_Old_Plugins',   'Bad_Old_Files',
			'Bad_Config_Files', 'Directory_Listing', /*'PHP_INI',*/
			'Admin_User',       'Easy_Login',        'Subscription',
			'WP_Config',        'Salt_Keys',         'Passwords_Strength',
			'Chmods',           'Common_Flaws',      'Bad_User_Agent',
			'SQLi',             'Anti_Scanner',
		),
		'medium' => array(
			'Inactive_Plugins_Themes', 'Bad_Url_Access', 'Bad_Usernames',
			'Bad_Request_Methods',     'PhpVersion',     /*'Too_Many_Admins',*/
			'Block_HTTP_1_0',          'Discloses',      'Block_Long_URL',
			'Readme_Discloses',
		),
		'low' => array(
			'Login_Errors_Disclose', 'PHP_Disclosure', /*'Admin_As_Author',*/
			'DirectoryIndex'
		)
	);

	if ( class_exists( 'SitePress' ) ) {
		$tests['medium'][] = 'Wpml_Discloses';
	}

	if ( class_exists( 'WooCommerce' ) ) {
		$tests['medium'][] = 'Woocommerce_Discloses';
	}

	return $tests;
}


/*
 * Get tests that can't be fixes from the network admin.
 *
 * @since 1.0
 *
 * @return (array) Array of "class name parts".
 */
function secupress_get_tests_for_ms_scanner_fixes() {
	return array(
		'Bad_Old_Plugins',
		'Subscription',
//		'Too_Many_Admins',
//		'Admin_As_Author',
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

			$secupress_options['consumer_key']   = $json->data->consumer_key;
			$secupress_options['consumer_email'] = $json->data->consumer_email;

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
