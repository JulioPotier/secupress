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


/*
 * Get scans et fixes results of subsites, organized by test and site ID.
 * It's a kind of `secupress_get_scanners()` + `secupress_get_scanner_fixes()` in one function, and for subsites.
 * The "scans et fixes of subsites" are related to the fixes that can't be done from the network admin if we are in a multisite installation.
 *
 * @since 1.0
 *
 * @return (array) The results, like:
 *  array(
 *  	test_name_lower => array(
 *  		site_id => array(
 *  			'scan' => array(
 *  				'status' => 'bad',
 *  				'msgs'   => array( 202 => array( params ) )
 *  			),
 *  			'fix'  => array(
 *  				'status' => 'cantfix',
 *  				'msgs'   => array( 303 => array( params ) )
 *  			)
 *  		)
 *  	)
 *  )
 */
function secupress_get_results_for_ms_scanner_fixes() {
	// Tests that must be fixed outside the network admin.
	$tests     = secupress_get_tests_for_ms_scanner_fixes();
	// Current results.
	$options   = get_site_option( 'secupress_fix_sites', array() );
	$options   = is_array( $options ) ? $options : array();
	$modified  = false;
	$schedules = array();
	$current_site_id       = get_current_blog_id();
	$current_site_modified = false;

	foreach ( $tests as $test_name ) {
		$test_name_lower = strtolower( $test_name );

		// Each test has its own transient.
		$transient = secupress_get_site_transient( 'secupress_fix_sites_' . $test_name_lower );

		if ( false === $transient ) {
			continue;
		}

		// The transient has a value: delete the transient.
		secupress_delete_site_transient( 'secupress_fix_sites_' . $test_name_lower );

		if ( ! $transient || ! is_array( $transient ) ) {
			continue;
		}

		// The option must be edited.
		$modified = true;

		foreach ( $transient as $site_id => $data ) {
			// If the site data is empty or if the scan result is good: remove previous values from the option.
			if ( empty( $data ) || isset( $data['scan']['status'] ) && 'good' === $data['scan']['status'] ) {
				if ( $site_id === $current_site_id && ! empty( $options[ $test_name_lower ][ $site_id ] ) ) {
					$schedules[] = $test_name;
				}

				unset( $options[ $test_name_lower ][ $site_id ] );

				if ( empty( $options[ $test_name_lower ] ) ) {
					unset( $options[ $test_name_lower ] );
				}

				if ( $site_id === $current_site_id ) {
					$current_site_modified = true;
				}
			}
			// The data is not empty: add it to the option.
			else {
				$options[ $test_name_lower ] = isset( $options[ $test_name_lower ] ) ? $options[ $test_name_lower ] : array();
				$options[ $test_name_lower ][ $site_id ] = $data;
			}
		}
	}

	if ( $modified ) {
		// We had transient(s), update the option.
		update_site_option( 'secupress_fix_sites', $options );

		if ( $schedules ) {
			// Schedule scan updates.
			secupress_require_class( 'scan' );

			foreach ( $schedules as $test_name ) {
				if ( ! file_exists( secupress_class_path( 'scan', $test_name ) ) ) {
					continue;
				}

				secupress_require_class( 'scan', $test_name );

				$classname = 'SecuPress_Scan_' . $test_name;

				if ( class_exists( $classname ) ) {
					$classname::get_instance()->schedule_autoscan();
				}
			}
		}

		if ( $current_site_modified ) {
			$current_site_is_empty = true;

			foreach ( $tests as $test_name ) {
				$test_name_lower = strtolower( $test_name );

				if ( ! empty( $options[ $test_name_lower ][ $current_site_id ] ) ) {
					$current_site_is_empty = false;
					break;
				}
			}

			if ( $current_site_is_empty ) {
				do_action( 'secupress_empty_results_for_ms_scanner_fixes' );
			}
		}
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
 * @param string $transient Transient name. Expected to not be SQL-escaped.
 * @return bool true if successful, false otherwise
 */
function secupress_delete_site_transient( $transient ) {

	/**
	 * Fires immediately before a specific site transient is deleted.
	 *
	 * The dynamic portion of the hook name, `$transient`, refers to the transient name.
	 *
	 * @since WP 3.0.0
	 *
	 * @param string $transient Transient name.
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
		 * @since WP 3.0.0
		 *
		 * @param string $transient Deleted transient name.
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
 * @param string $transient Transient name. Expected to not be SQL-escaped.
 * @return mixed Value of transient.
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
	 * @param mixed  $pre_transient The default value to return if the site transient does not exist.
	 *                              Any value other than false will short-circuit the retrieval
	 *                              of the transient, and return the returned value.
	 * @param string $transient     Transient name.
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
	 * @param mixed  $value     Value of transient.
	 * @param string $transient Transient name.
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
 * @param string $transient  Transient name. Expected to not be SQL-escaped. Must be
 *                           40 characters or fewer in length.
 * @param mixed  $value      Transient value. Must be serializable if non-scalar.
 *                           Expected to not be SQL-escaped.
 * @return bool False if value was not set and true if value was set.
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
	 * @param mixed  $value      New value of site transient.
	 * @param string $transient  Transient name.
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
		 * @param mixed  $value      Transient value.
		 * @param int    $expiration Time until expiration in seconds, forced to 0.
		 * @param string $transient  The name of the transient.
		 */
		do_action( 'set_site_transient_' . $transient, $value, 0, $transient );

		/**
		 * Fires after the value for a site transient has been set.
		 *
		 * @since 1.0
		 * @since WP 3.0.0
		 *
		 * @param string $transient  The name of the transient.
		 * @param mixed  $value      Transient value.
		 * @param int    $expiration Time until expiration in seconds, forced to 0.
		 */
		do_action( 'setted_site_transient', $transient, $value, 0 );
	}
	return $result;
}


function secupress_get_tests() {
	return array(
		'high' => array(
			'Core_Update',      'Plugins_Update',    'Themes_Update',
			'Auto_Update',      'Bad_Old_Plugins',   'Bad_Old_Files',
			'Bad_Config_Files', 'Directory_Listing',// 'PHP_INI',
			'Admin_User',       'Easy_Login',        'Subscription',
			'WP_Config',        'Salt_Keys',         'Passwords_Strength',
			'Chmods',           'Common_Flaws',      'Bad_User_Agent',
			'SQLi',             'Anti_Scanner',
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
		'Too_Many_Admins',
		'Admin_As_Author',
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
