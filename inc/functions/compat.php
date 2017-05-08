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


if ( ! function_exists( 'wp_parse_url' ) ) :
	/**
	 * A wrapper for PHP's parse_url() function that handles consistency in the return
	 * values across PHP versions.
	 *
	 * PHP 5.4.7 expanded parse_url()'s ability to handle non-absolute url's, including
	 * schemeless and relative url's with :// in the path. This function works around
	 * those limitations providing a standard output on PHP 5.2~5.4+.
	 *
	 * Secondly, across various PHP versions, schemeless URLs starting containing a ":"
	 * in the query are being handled inconsistently. This function works around those
	 * differences as well.
	 *
	 * Error suppression is used as prior to PHP 5.3.3, an E_WARNING would be generated
	 * when URL parsing failed.
	 *
	 * @since 1.2.4
	 * @since WP 4.4.0
	 * @since WP 4.7.0 The $component parameter was added for parity with PHP's parse_url().
	 *
	 * @param (string) $url       The URL to parse.
	 * @param (int)    $component The specific component to retrieve. Use one of the PHP
	 *                            predefined constants to specify which one.
	 *                            Defaults to -1 (= return all parts as an array).
	 *                            @see http://php.net/manual/en/function.parse-url.php
	 *
	 * @return (mixed) False on parse failure; Array of URL components on success;
	 *                 When a specific component has been requested: null if the component
	 *                 doesn't exist in the given URL; a sting or - in the case of
	 *                 PHP_URL_PORT - integer when it does. See parse_url()'s return values.
	 */
	function wp_parse_url( $url, $component = -1 ) {
		$to_unset = array();
		$url = strval( $url );

		if ( '//' === substr( $url, 0, 2 ) ) {
			$to_unset[] = 'scheme';
			$url = 'placeholder:' . $url;
		} elseif ( '/' === substr( $url, 0, 1 ) ) {
			$to_unset[] = 'scheme';
			$to_unset[] = 'host';
			$url = 'placeholder://placeholder' . $url;
		}

		$parts = @parse_url( $url );

		if ( false === $parts ) {
			// Parsing failure.
			return $parts;
		}

		// Remove the placeholder values.
		if ( $to_unset ) {
			foreach ( $to_unset as $key ) {
				unset( $parts[ $key ] );
			}
		}

		return _get_component_from_parsed_url_array( $parts, $component );
	}
endif;


if ( ! function_exists( '_get_component_from_parsed_url_array' ) ) :
	/**
	 * Retrieve a specific component from a parsed URL array.
	 *
	 * @since 1.2.4
	 * @since WP 4.7.0
	 *
	 * @param (array|false) $url_parts The parsed URL. Can be false if the URL failed to parse.
	 * @param (int)         $component The specific component to retrieve. Use one of the PHP
	 *                                 predefined constants to specify which one.
	 *                                 Defaults to -1 (= return all parts as an array).
	 * @see http://php.net/manual/en/function.parse-url.php
	 *
	 * @return (mixed) False on parse failure; Array of URL components on success;
	 *                 When a specific component has been requested: null if the component
	 *                 doesn't exist in the given URL; a sting or - in the case of
	 *                 PHP_URL_PORT - integer when it does. See parse_url()'s return values.
	 */
	function _get_component_from_parsed_url_array( $url_parts, $component = -1 ) {
		if ( -1 === $component ) {
			return $url_parts;
		}

		$key = _wp_translate_php_url_constant_to_key( $component );

		if ( false !== $key && is_array( $url_parts ) && isset( $url_parts[ $key ] ) ) {
			return $url_parts[ $key ];
		} else {
			return null;
		}
	}
endif;


if ( ! function_exists( '_wp_translate_php_url_constant_to_key' ) ) :
	/**
	 * Translate a PHP_URL_* constant to the named array keys PHP uses.
	 *
	 * @since 1.2.4
	 * @since WP 4.7.0
	 * @see   http://php.net/manual/en/url.constants.php
	 *
	 * @param (int) $constant PHP_URL_* constant.
	 *
	 * @return (string|bool) The named key or false.
	 */
	function _wp_translate_php_url_constant_to_key( $constant ) {
		$translation = array(
			PHP_URL_SCHEME   => 'scheme',
			PHP_URL_HOST     => 'host',
			PHP_URL_PORT     => 'port',
			PHP_URL_USER     => 'user',
			PHP_URL_PASS     => 'pass',
			PHP_URL_PATH     => 'path',
			PHP_URL_QUERY    => 'query',
			PHP_URL_FRAGMENT => 'fragment',
		);

		if ( isset( $translation[ $constant ] ) ) {
			return $translation[ $constant ];
		} else {
			return false;
		}
	}
endif;


if ( ! function_exists( 'hash_equals' ) ) :
	/**
	 * Timing attack safe string comparison
	 * Compares two strings using the same time whether they're equal or not.
	 * This function was added in PHP 5.6.
	 * Note: It can leak the length of a string when arguments of differing length are supplied.
	 *
	 * @since 1.3
	 * @since WP 3.9.2
	 *
	 * @param (string) $a Expected string.
	 * @param (string) $b Actual, user supplied, string.
	 *
	 * @return (bool) Whether strings are equal.
	 */
	function hash_equals( $a, $b ) {
		$a_length = strlen( $a );
		if ( strlen( $b ) !== $a_length ) {
			return false;
		}
		$result = 0;

		// Do not attempt to "optimize" this.
		for ( $i = 0; $i < $a_length; $i++ ) {
			$result |= ord( $a[ $i ] ) ^ ord( $b[ $i ] );
		}

		return 0 === $result;
	}
endif;


if ( ! function_exists( 'wp_get_raw_referer' ) ) :
	/**
	 * Retrieves unvalidated referer from '_wp_http_referer' or HTTP referer.
	 *
	 * Do not use for redirects, use wp_get_referer() instead.
	 *
	 * @since 1.3
	 * @since WP 4.5.0
	 *
	 * @return (string|false) Referer URL on success, false on failure.
	 */
	function wp_get_raw_referer() {
		if ( ! empty( $_REQUEST['_wp_http_referer'] ) ) {
			return wp_unslash( $_REQUEST['_wp_http_referer'] );
		} elseif ( ! empty( $_SERVER['HTTP_REFERER'] ) ) {
			return wp_unslash( $_SERVER['HTTP_REFERER'] );
		}

		return false;
	}
endif;


if ( ! function_exists( 'do_action_deprecated' ) ) :
	/**
	 * Fires functions attached to a deprecated action hook.
	 *
	 * When an action hook is deprecated, the do_action() call is replaced with do_action_deprecated(), which triggers a deprecation notice and then fires the original hook.
	 *
	 * @since 1.3
	 * @since WP 4.6.0
	 *
	 * @see _deprecated_hook()
	 *
	 * @param (string) $tag         The name of the action hook.
	 * @param (array)  $args        Array of additional function arguments to be passed to do_action().
	 * @param (string) $version     The version of WordPress that deprecated the hook.
	 * @param (string) $replacement Optional. The hook that should have been used.
	 * @param (string) $message     Optional. A message regarding the change.
	 */
	function do_action_deprecated( $tag, $args, $version, $replacement = false, $message = null ) {
		if ( ! has_action( $tag ) ) {
			return;
		}

		_deprecated_hook( $tag, $version, $replacement, $message );

		do_action_ref_array( $tag, $args );
	}
endif;


if ( ! function_exists( '_deprecated_hook' ) ) :
	/**
	 * Marks a deprecated action or filter hook as deprecated and throws a notice.
	 *
	 * Use the {@see 'deprecated_hook_run'} action to get the backtrace describing where the deprecated hook was called.
	 *
	 * Default behavior is to trigger a user error if `WP_DEBUG` is true.
	 *
	 * This function is called by the do_action_deprecated() and apply_filters_deprecated() functions, and so generally does not need to be called directly.
	 *
	 * @since 1.3
	 * @since WP 4.6.0
	 *
	 * @param (string) $hook        The hook that was used.
	 * @param (string) $version     The version of WordPress that deprecated the hook.
	 * @param (string) $replacement Optional. The hook that should have been used.
	 * @param (string) $message     Optional. A message regarding the change.
	 */
	function _deprecated_hook( $hook, $version, $replacement = null, $message = null ) {
		/**
		 * Fires when a deprecated hook is called.
		 *
		 * @since 1.3
		 * @since WP 4.6.0
		 *
		 * @param (string) $hook        The hook that was called.
		 * @param (string) $replacement The hook that should be used as a replacement.
		 * @param (string) $version     The version of WordPress that deprecated the argument used.
		 * @param (string) $message     A message regarding the change.
		 */
		do_action( 'deprecated_hook_run', $hook, $replacement, $version, $message );

		/**
		 * Filters whether to trigger deprecated hook errors.
		 *
		 * @since 1.3
		 * @since WP 4.6.0
		 *
		 * @param (bool) $trigger Whether to trigger deprecated hook errors. Requires `WP_DEBUG` to be defined true.
		 */
		if ( WP_DEBUG && apply_filters( 'deprecated_hook_trigger_error', true ) ) {
			$message = empty( $message ) ? '' : ' ' . $message;
			if ( ! is_null( $replacement ) ) {
				/* Translators: 1: WordPress hook name, 2: version number, 3: alternative hook name. */
				trigger_error( sprintf( __( '%1$s is <strong>deprecated</strong> since version %2$s! Use %3$s instead.', 'secupress' ), $hook, $version, $replacement ) . $message );
			} else {
				/* Translators: 1: WordPress hook name, 2: version number. */
				trigger_error( sprintf( __( '%1$s is <strong>deprecated</strong> since version %2$s with no alternative available.', 'secupress' ), $hook, $version ) . $message );
			}
		}
	}
endif;
