<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/** --------------------------------------------------------------------------------------------- */
/** MAIN OPTION ================================================================================= */
/** --------------------------------------------------------------------------------------------- */

/**
 * A wrapper to easily get a SecuPress option.
 *
 * @since 1.0
 *
 * @param (string) $option  The option name.
 * @param (mixed)  $default The default value of option. Default: false.
 *
 * @return (mixed) The option value.
 */
function secupress_get_option( $option, $default = false ) {
	$pre = null;
	/**
	 * Pre-filter any SecuPress option before read.
	 *
	 * @since 1.0
	 *
	 * @param (mixed) $pre     Null.
	 * @param (mixed) $default The default value.
	 */
	$value = apply_filters( 'pre_secupress_get_option_' . $option, $pre, $default );

	if ( null !== $value ) {
		return $value;
	}

	$options = get_site_option( SECUPRESS_SETTINGS_SLUG );
	$value   = is_array( $options ) && isset( $options[ $option ] ) && false !== $options[ $option ] ? $options[ $option ] : $default;
	/**
	 * Filter any SecuPress option after read
	 *
	 * @since 1.0
	 *
	 * @param (mixed) $value   The option value.
	 * @param (mixed) $default The default value.
	 */
	return apply_filters( 'secupress_get_option_' . $option, $value, $default );
}

/**
 * A wrapper to easily set a SecuPress option.
 *
 * @since 1.4.2
 *
 * @param (string) $option  The option name.
 * @param (string) $value  The value.
 */
function secupress_set_option( $option, $value ) {
	/**
	 * Pre-filter any SecuPress option before set.
	 *
	 * @since 1.0
	 *
	 * @param (mixed) $value     Null.
	 */
	$value = apply_filters( 'pre_secupress_set_option_' . $option, $value );

	$options = get_site_option( SECUPRESS_SETTINGS_SLUG );
	$options = is_array( $options ) ? $options : array();

	$options[ $option ] = $value;

	secupress_update_options( $options );
}


/**
 * A wrapper to update SecuPress options.
 * If you want the options to be sanitized, make sure to `unset( $options['sanitized'] )` before.
 *
 * @since 1.1.4
 * @author Grégory Viguier
 *
 * @param (array) $options The new option values.
 */
function secupress_update_options( $options ) {
	// Make sure we don't mess everything.
	if ( ! is_array( $options ) ) {
		return;
	}

	update_site_option( SECUPRESS_SETTINGS_SLUG, $options );
}


/** --------------------------------------------------------------------------------------------- */
/** MODULE OPTIONS ============================================================================== */
/** --------------------------------------------------------------------------------------------- */

/**
 * A wrapper to easily get a SecuPress module option.
 *
 * @since 1.0
 *
 * @param (string) $option  The option name.
 * @param (mixed)  $default The default value of option. Default: null.
 * @param (string) $module  The module slug (see array keys from `modules.php`). Default is the current module.
 *
 * @return (mixed) The option value.
 */
function secupress_get_module_option( $option, $default = null, $module = false ) {
	if ( ! $module ) {
		$module = secupress_get_current_module();
	}

	$pre = null;
	/**
	 * Pre-filter any SecuPress option before read.
	 *
	 * @since 1.0
	 *
	 * @param (mixed)  $pre     Null.
	 * @param (mixed)  $default The default value.
	 * @param (string) $module  The module.
	 */
	$value = apply_filters( 'pre_secupress_get_module_option_' . $option, $pre, $default, $module );

	if ( null !== $value ) {
		return $value;
	}

	$options = get_site_option( "secupress_{$module}_settings" );
	$value   = is_array( $options ) && isset( $options[ $option ] ) && false !== $options[ $option ] ? $options[ $option ] : $default;
	/**
	 * Filter any SecuPress option after read.
	 *
	 * @since 1.0
	 *
	 * @param (mixed)  $value   The option value.
	 * @param (mixed)  $default The default value.
	 * @param (string) $module  The module.
	*/
	return apply_filters( 'secupress_get_module_option_' . $option, $value, $default, $module );
}


/** --------------------------------------------------------------------------------------------- */
/** SCAN / FIX ================================================================================== */
/** --------------------------------------------------------------------------------------------- */

/**
 * Get all scan results.
 *
 * @since 1.0
 * @since 1.3 Use multiple options instead of 1 option and multiple transients.
 * @author Grégory Viguier
 *
 * @return (array)
 */
function secupress_get_scan_results() {
	return SecuPress_Scanner_Results::get_scan_results();
}


/**
 * Get all fix results.
 *
 * @since 1.0
 * @since 1.3 Use multiple options instead of 1 option and multiple transients.
 * @author Grégory Viguier
 *
 * @return (array)
 */
function secupress_get_fix_results() {
	return SecuPress_Scanner_Results::get_fix_results();
}


/** --------------------------------------------------------------------------------------------- */
/** TRANSIENTS ================================================================================== */
/** --------------------------------------------------------------------------------------------- */

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
