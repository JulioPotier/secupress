<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

if ( ! function_exists( 'doing_filter' ) ) :
	/**
	 * Retrieve the name of a filter currently being processed.
	 *
	 * The function current_filter() only returns the most recent filter or action
	 * being executed. did_action() returns true once the action is initially
	 * processed.
	 *
	 * This function allows detection for any filter currently being
	 * executed (despite not being the most recent filter to fire, in the case of
	 * hooks called from hook callbacks) to be verified.
	 *
	 * @since 1.0
	 * @since WP 3.9.0
	 *
	 * @see current_filter()
	 * @see did_action()
	 * @global array $wp_current_filter Current filter.
	 *
	 * @param (null|string) $filter Optional. Filter to check. Defaults to null, which
	 *                              checks if any filter is currently being run.
	 *
	 * @return (bool) Whether the filter is currently in the stack.
	 */
	function doing_filter( $filter = null ) {
		global $wp_current_filter;

		if ( null === $filter ) {
			return ! empty( $wp_current_filter );
		}

		return in_array( $filter, $wp_current_filter, true );
	}
endif;


if ( ! function_exists( 'doing_action' ) ) :
	/**
	 * Retrieve the name of an action currently being processed.
	 *
	 * @since 1.0
	 * @since WP 3.9.0
	 *
	 * @param (string|null) $action Optional. Action to check. Defaults to null, which checks
	 *                            if any action is currently being run.
	 *
	 * @return (bool) Whether the action is currently in the stack.
	 */
	function doing_action( $action = null ) {
		return doing_filter( $action );
	}
endif;


if ( ! function_exists( 'wp_normalize_path' ) ) :
	/**
	 * Normalize a filesystem path.
	 *
	 * On windows systems, replaces backslashes with forward slashes and forces upper-case drive letters.
	 * Allows for two leading slashes for Windows network shares, but ensures that all other duplicate slashes are reduced to a single.
	 *
	 * @since 1.0
	 * @since WP 3.9.0
	 * @since WP 4.4.0 Ensures upper-case drive letters on Windows systems.
	 * @since WP 4.5.0 Allows for Windows network shares.
	 *
	 * @param (string) $path Path to normalize.
	 *
	 * @return (string) Normalized path.
	 */
	function wp_normalize_path( $path ) {
		$path = str_replace( '\\', '/', $path );
		$path = preg_replace( '|(?<=.)/+|', '/', $path );
		if ( ':' === substr( $path, 1, 1 ) ) {
			$path = ucfirst( $path );
		}
		return $path;
	}
endif;


if ( ! function_exists( 'wp_is_ini_value_changeable' ) ) :
	/**
	 * Determines whether a PHP ini value is changeable at runtime.
	 *
	 * @since 1.0.4
	 * @since WP 4.6.0
	 *
	 * @link http://php.net/manual/en/function.ini-get-all.php
	 *
	 * @param (string) $setting The name of the ini setting to check.
	 *
	 * @return (bool) True if the value is changeable at runtime. False otherwise.
	 */
	function wp_is_ini_value_changeable( $setting ) {
		static $ini_all;

		if ( ! isset( $ini_all ) ) {
			$ini_all = false;
			// Sometimes `ini_get_all()` is disabled via the `disable_functions` option for "security purposes".
			if ( function_exists( 'ini_get_all' ) ) {
				$ini_all = ini_get_all();
			}
	 	}

		// Bit operator to workaround https://bugs.php.net/bug.php?id=44936 which changes access level to 63 in PHP 5.2.6 - 5.2.17.
		if ( isset( $ini_all[ $setting ]['access'] ) && ( INI_ALL === ( $ini_all[ $setting ]['access'] & 7 ) || INI_USER === ( $ini_all[ $setting ]['access'] & 7 ) ) ) {
			return true;
		}

		// If we were unable to retrieve the details, fail gracefully to assume it's changeable.
		if ( ! is_array( $ini_all ) ) {
			return true;
		}

		return false;
	}
endif;
