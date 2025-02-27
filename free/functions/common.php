<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/** --------------------------------------------------------------------------------------------- */
/** REQUIRE FILES =============================================================================== */
/** --------------------------------------------------------------------------------------------- */

/**
 * Return the path to a class.
 *
 * @since 1.0
 * @author Grégory Viguier
 *
 * @param (string) $prefix          Only one possible value so far: "scan".
 * @param (string) $class_name_part The classes name is built as follow: "SecuPress_{$prefix}_{$class_name_part}".
 *
 * @return (string) Path of the class.
 */
function secupress_class_path( $prefix, $class_name_part = '' ) {
	$folders = array(
		'scan'              => 'scanners',
		'singleton'         => 'common',
		'logs'              => 'common',
		'log'               => 'common',
		'cleanup-leftovers' => 'common',
		'scanner-results'   => 'common',
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
 * @author Grégory Viguier
 *
 * @param (string) $prefix          Only one possible value so far: "scan".
 * @param (string) $class_name_part The classes name is built as follow: "SecuPress_{$prefix}_{$class_name_part}".
 */
function secupress_require_class( $prefix, $class_name_part = '' ) {
	$path = secupress_class_path( $prefix, $class_name_part );

	if ( $path ) {
		require_once( $path );
	}
}


/**
 * Will load the async classes.
 *
 * @since 1.0
 * @author Grégory Viguier
 */
function secupress_require_class_async() {
	/* https://github.com/A5hleyRich/wp-background-processing v1.0 */
	secupress_require_class( 'Admin', 'wp-async-request' );
	secupress_require_class( 'Admin', 'wp-background-process' );
}


/** --------------------------------------------------------------------------------------------- */
/** SCAN / FIX ================================================================================== */
/** --------------------------------------------------------------------------------------------- */

/**
 * Return all tests to scan
 *
 * @since 1.0
 * @author Grégory Viguier
 *
 * @return (array) Tests to scan.
 */
function secupress_get_scanners() {
	$tests = array(
		'users-login' => array(
			0 => 'Admin_User',
			1 => 'Easy_Login',
			2 => 'Subscription',
			3 => 'Passwords_Strength',
			4 => 'Bad_Usernames',
			5 => 'Login_Errors_Disclose',
		),
		'plugins-themes' => array(
			0 => 'Plugins_Update',
			1 => 'Themes_Update',
			2 => 'Bad_Old_Plugins',
			3 => 'Bad_Vuln_Plugins',
			4 => 'Inactive_Plugins_Themes',
			5 => 'Bad_Old_Themes', // 2.2.6
		),
		'wordpress-core' => array(
			0 => 'Core_Update',
			1 => 'Auto_Update',
			2 => 'Bad_Old_Files',
			3 => 'Bad_Config_Files',
			4 => 'WP_Config',
			5 => 'DB_Prefix',
			6 => 'Salt_Keys',
			7 => 'WPOrg',
		),
		'sensitive-data' => array(
			0 => 'Discloses',
			1 => 'Readme_Discloses',
			2 => 'PHP_Disclosure',
			3 => 'HTTPS',
		),
		'file-system' => array(
			0 => 'Chmods',
			1 => 'Directory_Listing',
			2 => 'Bad_File_Extensions',
		),
		'firewall' => array(
			0 => 'Shellshock',
			1 => 'Bad_User_Agent',
			// DO NOT DELETE COMMENTED, DO NOT REUSE THE INDEXES.
			// 2 => 'SQLi',
			// 3 => 'Anti_Scanner',
			// 4 => 'Anti_Front_Brute_Force',
			// 5 => 'Bad_Request_Methods',
			6 => 'Bad_Url_Access',
			7 => 'PhpVersion',
			8 => 'Php_404',
		),
	);

	// 3rd party.
	if ( class_exists( 'SitePress' ) ) {
		$tests['sensitive-data'][3] = 'Wpml_Discloses';
	}

	if ( class_exists( 'WooCommerce' ) ) {
		$tests['sensitive-data'][4] = 'Woocommerce_Discloses';
	}
	if ( secupress_is_ecommerce() ) {
		/**
		* @since 2.0 Do not remove login errors when e-commerce is active.
		**/
		unset( $tests['users-login'][5] );
	}

	return apply_filters( 'secupress.scanner.tests', $tests );
}


/**
 * Get tests that can't be fixes from the network admin.
 *
 * @since 2.2.6 Bad_Old_Themes
 * @author Julio Potier
 * @since 1.0
 * @author Grégory Viguier
 *
 * @return (array) Array of "class name parts".
 */
function secupress_get_tests_for_ms_scanner_fixes() {
	return array(
		'Bad_Old_Plugins',
		'Bad_Old_Themes',
		'Subscription',
	);
}


/**
 * Get SecuPress scanner counter(s).
 *
 * @since 1.0
 * @author Grégory Viguier
 *
 * @param (string) $type Info to retrieve: good, warning, bad, notscannedyet, grade, total.
 * @return (string|array) The desired counter info if `$type` is provided and the info exists. An array of all counters otherwise.
 */
function secupress_get_scanner_counts( $type = '' ) {
	static $counts;
	if ( ! isset( $counts ) ) {
		$tests_by_status = secupress_get_scanners();
		$scanners        = secupress_get_scan_results();
		$fixes           = secupress_get_fix_results();
		unset( $tests_by_status['users-login'][1] ); // 2FA
		unset( $tests_by_status['firewall'][7] ); // PHP Version

		$empty_statuses  = array( 'good' => 0, 'warning' => 0, 'bad' => 0 );
		$scanners_count  = $scanners ? array_count_values( wp_list_pluck( $scanners, 'status' ) ) : array();
		$counts          = array_merge( $empty_statuses, $scanners_count );
		$total           = array_sum( array_map( 'count', $tests_by_status ) );

		$counts['notscannedyet'] = $total - array_sum( $counts );
		$counts['total']         = $total;
		$counts['percent']       = (int) floor( $counts['good'] * 100 / $counts['total'] );
		$counts['hasaction']     = 0;

		if ( $fixes ) {
			foreach ( $fixes as $test_name => $fix ) {
				if ( ! empty( $fix['has_action'] ) ) {
					++$counts['hasaction'];
				}
			}
		}

		if ( 100 <= $counts['percent'] ) {
			$counts['grade'] = 'A';
		} elseif ( $counts['percent'] >= 80 ) { // 20 less
			$counts['grade'] = 'B';
		} elseif ( $counts['percent'] >= 65 ) { // 15 less
			$counts['grade'] = 'C';
		} elseif ( $counts['percent'] >= 52 ) { // 13 less
			$counts['grade'] = 'D';
		} elseif ( $counts['percent'] >= 42 ) { // 10 less
			$counts['grade'] = 'E';
		} elseif ( $counts['percent'] >= 34 ) { // 8 less
			$counts['grade'] = 'F';
		} elseif ( $counts['percent'] >= 28 ) { // 6 less
			$counts['grade'] = 'G';
		} elseif ( $counts['percent'] >= 22 ) { // 6 less
			$counts['grade'] = 'H';
		} elseif ( $counts['percent'] >= 16 ) { // 6 less
			$counts['grade'] = 'I';
		} elseif ( $counts['percent'] >= 10 ) { // 6 less
			$counts['grade'] = 'J';
		} elseif ( 0 === $counts['percent'] ) { // 0...
			$counts['grade'] = '∅';
		} else {
			$counts['grade'] = 'K'; // < 10 %
		}
		$label = $counts['grade'];
		$counts['temp_grade'] = $counts['grade'];
		if ( isset( $scanners['bad_vuln_plugins']['status'] ) && 'bad' === $scanners['bad_vuln_plugins']['status'] ) {
			$counts['temp_grade'] .= '-';
			$label .= '-';
		} elseif ( ( isset( $scanners['easy_login']['status'] ) && 'good' === $scanners['easy_login']['status'] ) ||
			( isset( $scanners['phpversion']['status'] ) && 'good' === $scanners['phpversion']['status'] ) ) {
			$counts['temp_grade'] .= '+';
			$label .= '+';
		}
		switch ( strlen( $label ) ) {
			case 3:
				$css_class = ' secupress-grade-plus-plus';
			break;
			case 2:
				$css_class = ' secupress-grade-plus';
			break;
			default:
				$css_class = '';
			break;
		}

		$counts['letter']  = '<span class="letter l' . $counts['grade'][0] . $css_class . '">' . $label . '</span>';
		$counts['color']   = '195,34,34';

		switch ( $counts['grade'] ) {
			case 'A':
				$counts['text']  = __( 'Congratulations! 🎉', 'secupress' );
				$counts['color'] = '43,205,193';
				break;
			case 'B':
				$counts['text']  = __( 'Almost perfect!', 'secupress' );
				$counts['color'] = '241,196,15';
				break;
			case 'C':
				$counts['text']  = __( 'Not bad, but try to fix more items.', 'secupress' );
				$counts['color'] = '247,171,19';
				break;
			case 'D':
				$counts['text']  = __( 'Well, it’s not good yet.', 'secupress' );
				$counts['color'] = '242,41,94';
				break;
			case 'E':
				$counts['text']  = __( 'Better than nothing, but still not good.', 'secupress' );
				$counts['color'] = '203,35,79';
				break;
			case 'F':
				$counts['text'] = __( 'Not good at all, fix more issues.', 'secupress' );
				break;
			case 'G':
				$counts['text'] = __( 'Bad, fix issues right away!', 'secupress' );
				break;
			case 'H':
				$counts['text'] = __( 'Still very bad, start fixing things!', 'secupress' );
				break;
			case 'I':
				$counts['text'] = __( 'Very bad. You should take some actions.', 'secupress' );
				break;
			case 'J':
				$counts['text'] = __( 'Very very bad, please fix something!', 'secupress' );
				break;
			case 'K':
				$counts['text'] = __( 'Very very, really very bad.', 'secupress' );
				break;
			case '∅':
				$counts['text'] = __( 'Error when saving the scanner results.', 'secupress' ); // Old (ᕗ‶⇀︹↼)ᕗ彡┻━┻
				break;
		}
		$counts['subtext'] = sprintf( _n( 'Your grade is %1$s with %2$d good scanned item.', 'Your grade is %1$s with %2$d good scanned items.', $counts['good'], 'secupress' ), $counts['letter'], $counts['good'] );
	}
	$counts['grade'] = $counts['temp_grade'];
	if ( $type ) {
		// Make sure to not return the whole array if a type is given, even if it isn't set.
		return isset( $counts[ $type ] ) ? $counts[ $type ] : '';
	}

	return $counts;
}


/**
 * Tell if we can perform "extra fix actions" (something we do on page reload after a fix is done).
 *
 * @author Grégory Viguier
 * @since 1.2.3
 *
 * @return (bool)
 */
function secupress_can_perform_extra_fix_action() {
	global $pagenow;
	return empty( $_POST ) && ! wp_doing_ajax() && ! defined( 'DOING_AUTOSAVE' ) && is_admin() && 'admin-post.php' !== $pagenow && is_user_logged_in(); // WPCS: CSRF ok.
}


/** --------------------------------------------------------------------------------------------- */
/** PLUGINS ===================================================================================== */
/** --------------------------------------------------------------------------------------------- */

/**
 * Check whether a plugin is active.
 *
 * @author Grégory Viguier
 * @since 1.0
 *
 * @param (string) $plugin A plugin path, relative to the plugins folder.
 * @return (bool)
 */
function secupress_is_plugin_active( $plugin ) {
	$plugins = (array) get_option( 'active_plugins', [] );
	$plugins = array_flip( $plugins );
	return isset( $plugins[ $plugin ] ) || secupress_is_plugin_active_for_network( $plugin );
}


/**
 * Check whether a plugin is active for the entire network.
 *
 * @since 1.0
 * @author Grégory Viguier
 * 
 * @param (string) $plugin A plugin path, relative to the plugins folder.
 * @return (bool)
 */
function secupress_is_plugin_active_for_network( $plugin ) {
	if ( ! is_multisite() ) {
		return false;
	}

	$plugins = get_site_option( 'active_sitewide_plugins' );

	return isset( $plugins[ $plugin ] );
}


/** --------------------------------------------------------------------------------------------- */
/** DIE ========================================================================================= */
/** --------------------------------------------------------------------------------------------- */

/**
 * Die with SecuPress format.
 *
 * @author Julio Potier
 * @since 2.0 Add the response code
 * @author Grégory Viguier
 * @since 1.0
 *
 * @param (string) $message Guess what.
 * @param (string) $title   Window title.
 * @param (array)  $args    An array of arguments.
 */
function secupress_die( $message = '', $title = '', $args = array() ) {
	$has_p           = strpos( $message, '<p>' ) !== false;
	$message         = ( $has_p ? '' : '<p>' ) . $message . ( $has_p ? '' : '</p>' );
	$message         = '<h1>' . SECUPRESS_PLUGIN_NAME . '</h1>' . $message;
	$url             = secupress_get_current_url( 'raw' );
	$force_die       = ! empty( $args['force_die'] );
	$context         = ! empty( $args['context'] ) ? $args['context'] : '';
	$is_scan_request = secupress_is_scan_request(); // Used to bypass the whitelist for scans.
	$attack_type     = isset( $args['attack_type'] ) ? $args['attack_type'] : false;
	if ( $attack_type ) { // We can die when it's not an attack.
		secupress_log_attack( $attack_type );
	}

	/**
	 * Filter the message.
	 *
	 * @since 1.0
	 *
	 * @param (string) $message         The message displayed.
	 * @param (string) $url             The current URL.
	 * @param (array)  $args            Facultative arguments.
	 * @param (bool)   $is_scan_request Tell if the request comes from one of our scans.
	 */
	$message = apply_filters( 'secupress.die.message', $message, $url, $args, $is_scan_request, $context );

	/**
	 * Fires right before `wp_die()`.
	 *
	 * @since 1.0
	 *
	 * @param (string) $message         The message displayed.
	 * @param (string) $url             The current URL.
	 * @param (array)  $args            Facultative arguments.
	 * @param (bool)   $is_scan_request Tell if the request comes from one of our scans.
	 */
	do_action( 'secupress.before.die', $message, $url, $args, $is_scan_request, $context );

	if ( $force_die || $is_scan_request ) {
		// Die.
		// Tell cache plugins not to cache our error message.
		if ( ! defined( 'DONOTCACHEPAGE' ) ) {
			define( 'DONOTCACHEPAGE', true );
		}
		if ( ! defined( 'DONOTCACHEOBJECT' ) ) {
			define( 'DONOTCACHEOBJECT', true );
		}
		if ( ! defined( 'DONOTCACHEDB' ) ) {
			define( 'DONOTCACHEDB', true );
		}
		if ( ! empty( $args['response'] ) ) {
			http_response_code( absint( $args['response'] ) );
		}
		// https://core.trac.wordpress.org/ticket/53262
		remove_filter( 'wp_robots', 'wp_robots_noindex_embeds' );
		remove_filter( 'wp_robots', 'wp_robots_noindex_search' );

		wp_die( $message, $title, $args );
	}
}


/**
 * Block a request and die with more informations.
 *
 * @since 1.0
 * @author Grégory Viguier
 *
 * @param (string)           $module The related module.
 * @param (array|int|string) $args   Contains the "code" (def. 403) and a "content" (def. empty), this content will replace the default message.
 *                                   $args can be used only for the "code" or "content" or both using an array.
 */
function secupress_block( $module, $args = array( 'code' => 403 ) ) {
	$ip = secupress_get_ip();

	/**
	 * Allow to give a proper name to the block ID.
	 *
	 * @since 1.1.4
	 *
	 * @param (string) $module The related module.
	 */
	$block_id = apply_filters( 'secupress_block_id', $module );

	if ( $block_id === $module ) {
		$block_id = ucwords( str_replace( '-', ' ', $block_id ) );
		$block_id = preg_replace( '/[^0-9A-Z]/', '', $block_id );
	}

	if ( is_int( $args ) ) {
		$args = array( 'code' => (int) $args ); // Cast to prevent recursion.
	} elseif ( is_string( $args ) ) {
		$args = array( 'content' => (string) $args ); // Cast to prevent recursion.
	}
	$args     = wp_parse_args( $args, array( 'code' => 403, 'content' => '', 'b64' => [], 'attack_type' => 'ban_ip' ) );

	// Preventing the display of possible sent passwords
	$hidden = '***… // ' . sprintf( __( 'Hidden by %s.', 'secupress' ), SECUPRESS_PLUGIN_NAME );
	foreach ( [ 'password', 'psswrd', 'pass', 'pwd', 'pw', 'user_pass', 'edd_user_pass' ] as $key ) {
		if ( isset( $_REQUEST[ $key ] ) ) {
			$_REQUEST[ $key ] = $hidden;
		}
		if ( isset( $_GET[ $key ] ) ) {
			$_GET[ $key ] = $hidden;
		}
		if ( isset( $_POST[ $key ] ) ) {
			$_POST[ $key ] = $hidden;
		}
	}

	// Use these filters to remove or modify contents
	$_REQUEST = apply_filters( 'secupress.block.remove_content_from._REQUEST', $_REQUEST );
	$_GET     = apply_filters( 'secupress.block.remove_content_from._GET',     $_GET     );
	$_POST    = apply_filters( 'secupress.block.remove_content_from._POST',    $_POST    );
	$_COOKIE  = apply_filters( 'secupress.block.remove_content_from._COOKIE',  $_COOKIE  );
	$_FILES   = apply_filters( 'secupress.block.remove_content_from._FILES',   $_FILES   );

	$data     = var_export(
			[   '$_REQUEST' => $_REQUEST,
				'$_GET'     => $_GET,
				'$_POST'    => $_POST,
				'$_COOKIE'  => $_COOKIE,
				'$_FILES'   => $_FILES,
			], true );

	// Add some hardcoded b64 args to be printed for support help.
	$args['b64']['URL']  = secupress_get_current_url( 'raw' );
	$args['b64']['SP']   = secupress_has_pro() ? 'Pro v' . SECUPRESS_PRO_VERSION : 'Free v' . SECUPRESS_VERSION;
	$args['b64']['ID']   = $module;
	$args['b64']['data'] = $data;
	$args['b64']['user'] = is_user_logged_in() ? var_export( wp_get_current_user()->user_login, true ) : false;

	/**
	 * Fires before a user is blocked by a certain module.
	 *
	 * @since 1.0
	 * @since 1.1.4 Added `$block_id` argument.
	 *
	 * @param (string) $ip       The IP address.
	 * @param (array)  $args     Contains the "code" (def. 403) and a "content" (def. empty), this content will replace the default message.
	 * @param (string) $block_id The block ID.
	 */
	do_action( 'secupress.block.' . $module, $ip, $args, $block_id );

	/**
	 * Fires before a user is blocked.
	 *
	 * @since 1.0
	 * @since 1.1.4 Added `$block_id` argument.
	 *
	 * @param (string) $module   The module.
	 * @param (string) $ip       The IP address.
	 * @param (array)  $args     Contains the "code" (def. 403) and a "content" (def. empty), this content will replace the default message.
	 * @param (string) $block_id The block ID.
	 */
	do_action( 'secupress.block', $module, $ip, $args, $block_id );
	$title   = $args['code'] . ' ' . get_status_header_desc( $args['code'] );
	$content = '<h2>' . $title . '</h2>';
	if ( ! $args['content'] ) {
		$content .= '<p>' . __( 'You are not allowed to access the requested page.', 'secupress' ) . '</p>';
	} else {
		$content .= '<p>' . $args['content'] . '</p>';
	}

	$content .= '<h3>' . __( 'Logged Details:', 'secupress' ) . '</h3>';
	$content .= '<p>';
	$content .= sprintf( __( 'Your IP: %s', 'secupress' ), $ip ) . '<br>';
	$content .= sprintf( __( 'Time: %s', 'secupress' ), date_i18n( _x( 'F j, Y g:i a', 'date', 'secupress' ) ) ) . '<br>';
	$content .= sprintf( __( 'Reason: %s', 'secupress' ), $block_id ) . '<br>';
	$content .= sprintf( __( 'Support ID: %s', 'secupress' ), '<textarea style="width:100%;height:27px;vertical-align:text-top">' . base64_encode( json_encode( $args['b64'] ) ) . '</textarea>' ) . '<br>';
	$content .= '</p>';

	secupress_die( $content, $title, [ 'response' => $args['code'], 'force_die' => true, 'attack_type' => $args['attack_type'] ] );
}


/**
 * Tell if the request comes from one of our scans by detecting a specific header.
 * Careful, this header can be forged, the result is not trustful.
 *
 * @since 1.0
 * @author Grégory Viguier
 *
 * @return (bool) True if the request comes from a scan. False otherwize.
 */
function secupress_is_scan_request() {
	return ! empty( $_SERVER['HTTP_X_SECUPRESS_ORIGIN'] );
}


/** --------------------------------------------------------------------------------------------- */
/** OTHER TOOLS ================================================================================= */
/** --------------------------------------------------------------------------------------------- */

/**
 * Create a URL to easily access to our pages.
 *
 * @author Julio Potier
 * @since 1.4.4 'get-pro' $page is now returning the external URL
 * @author Grégory Viguier
 * @since 1.0
 *
 * @param (string) $page   The last word of the secupress page slug.
 * @param (string) $module The required module.
 *
 * @return (string) The URL.
 */
function secupress_admin_url( $page, $module = '' ) {
	if ( 'get-pro' === $page ) {
		return trailingslashit( set_url_scheme( SECUPRESS_WEB_MAIN, 'https' ) ) . _x( 'pricing', 'link to website (Only FR or EN!)', 'secupress' );
	}

	$module = $module ? '&module=' . $module : '';
	$page   = str_replace( '&', '_', $page );
	$url    = 'admin.php?page=' . SECUPRESS_PLUGIN_SLUG . '_' . $page . $module;

	return is_multisite() ? network_admin_url( $url ) : admin_url( $url );
}


/**
 * Get the user capability/role required to work with the plugin.
 *
 * @author Grégory Viguier
 * @since 1.0
 *
 * @param (bool) $force_mono Set to true to get the capability/role for monosite, whatever we're on multisite or not.
 *
 * @return (string) The capability.
 */
function secupress_get_capability( $force_mono = false, $context = '' ) {
	if ( ! $force_mono && is_multisite() ) {
		return 'manage_network_options';
	}

	$role = 'administrator';
	/**
	 * Filter the user capability/role that gives access to SecuPress features.
	 *
	 * @since 1.0
	 * @param (string) $role
	 *
	 * @since 2.2
	 * @param (string) $context
	 */
	return apply_filters( 'secupress.user_capability', $role, $context );
}

/**
 * Add SecuPress informations into USER_AGENT.
 *
 * @since 2.2.6 Remove "white_label"
 * @since 2.0 Remove "do_beta"
 * @author Julio Potier
 * 
 * @since 1.1.4 Available in global scope.
 * @since 1.0
 * @author Grégory Viguier
 *
 * @param (string) $user_agent A User Agent.
 *
 * @return (string)
 */
function secupress_user_agent( $user_agent ) {
	return sprintf( '%s;SecuPress|%s|%s|%s|%s;', $user_agent, esc_url( secupress_get_main_url() ), SECUPRESS_VERSION, $GLOBALS['wp_version'], phpversion() );
}

/**
 * Get the site main URL. Will be the same for any site of a network, and for any lang of a multilang site.
 *
 * @since 1.2.2
 * @author Grégory Viguier
 *
 * @return (string) The URL.
 */
function secupress_get_main_url() {
	$current_network = false;

	if ( function_exists( 'get_network' ) ) {
		$current_network = get_network();
	} elseif ( function_exists( 'get_current_site' ) ) {
		$current_network = get_current_site();
	}

	if ( ! $current_network ) {
		if ( function_exists( '__get_option' ) ) {
			if ( __get_option( 'siteurl' ) ) {
				return __get_option( 'siteurl' );
			}
		} else {
			return get_option( 'siteurl' );
		}
	}

	$scheme   = secupress_server_is_ssl() ? 'https' : 'http';
	$main_url = set_url_scheme( 'http://' . $current_network->domain . $current_network->path, $scheme );

	return untrailingslashit( $main_url );
}

/**
 * Is this version White Labeled?
 *
 * @author Grégory Viguier
 * @since 1.0
 * @since 1.1.4 Available in global scope.
 *
 * @return (bool)
 */
function secupress_is_white_label() {
	if ( ! secupress_is_pro() ) {
		return false;
	}

	$names = array( 'wl_plugin_name', 'wl_plugin_URI', 'wl_description', 'wl_author', 'wl_author_URI' );

	foreach ( $names as $value ) {
		if ( false !== secupress_get_option( $value ) ) {
			return true;
		}
	}

	return false;
}


/**
 * Get SecuPress logo.
 *
 * @since 2.2.6 $return parameter
 * @since 1.0.6 Remove the yellow Pro logo
 * @author Julio Potier
 *
 * @since 1.0
 * @author Geoffrey Crofte
 * 
 * @param (array) $atts An array of HTML attributes.
 * @param (string) $return 'html': as <IMG> ; 'url': https:// ...png ; 'path': /home/www/ ...png
 * @return (string) The HTML tag.
 */
function secupress_get_logo( $atts = [], $return = 'html' ) {
	$base_url  = SECUPRESS_ADMIN_IMAGES_URL . 'logo';
	$base_path = SECUPRESS_ADMIN_PATH . 'images/logo';
	if ( secupress_is_white_label() ) {
		/**
		 * If white label is activated, no SecuPress logo is retrieved.
		 *
		 * @since 1.4.2
		 *
		 * @param (string) Should return a <img> or dashicon span tag.
		 * @param (array) $atts Attributes, contains logo size.
		 */
		switch ( $return ) {
			case 'url':
				$base_url = $base_url . '-white-label.png';
			break;
			case 'path':
				$base_url = $base_path . '-white-label.png';
			break;
			default:
			case 'html':
				$base_url = $base_url . '-white-label';
			break;
		}
		$base_url = apply_filters( 'secupress.white_label.logo', $base_url, $atts, $return );
	}
	switch ( $return ) {
		case 'url':
			return $base_url . '.png';
			break;
		case 'path':
			return $base_path . '.png';
			break;
	} // case 'html': // below

	$atts = array_merge( [
		'src'    => "{$base_url}.png",
		'srcset' => secupress_is_white_label() ? '' : "{$base_url}2x.svg 1x, {$base_url}2x.svg 2x",
		'alt'    => '',
	], $atts );

	$attributes = '';

	foreach ( $atts as $att => $value ) {
		$attributes .= " {$att}=\"{$value}\"";
	}

	return "<img{$attributes}/>";
}

/**
 * Get SecuPress logo word.
 *
 * @author Julio Potier
 * @since 2.0 Set as test to print the version
 * @author Grégory Viguier
 * @since 1.0
 *
 * @param (array) $atts An array of HTML attributes.
 *
 * @return (string) The HTML tag.
 */
function secupress_get_logo_word( $atts = array() ) {
	return sprintf( '%s v%s', SECUPRESS_PLUGIN_NAME, SECUPRESS_VERSION );
}


/**
 * Tell if users can register, whatever we're in a Multisite or not.
 *
 * @since 1.0
 * @author Grégory Viguier
 *
 * @return (bool)
 */
function secupress_users_can_register() {
	if ( ! is_multisite() ) {
		return (bool) get_option( 'users_can_register' );
	}

	$registration = get_site_option( 'registration' );

	return 'user' === $registration || 'all' === $registration;
}


/**
 * Get the email address used when the plugin send a message.
 *
 * @since 1.0
 * @author Grégory Viguier
 *
 * @param (bool) $from_header True to return the "from" header.
 *
 * @return (string)
 */
function secupress_get_email( $from_header = false ) {
	$sitename = strtolower( $_SERVER['SERVER_NAME'] );

	if ( substr( $sitename, 0, 4 ) === 'www.' ) {
		$sitename = substr( $sitename, 4 );
	}

	/**
	 * Give the possibility to replace the "from" email address
	 *
	 * @since 2.0.1 Change the order to let SP have priority, but can also use the default WP one with new context param
	 * @since 1.0
	 *
	 * @param (string)
	 */
	$email = apply_filters( 'secupress.get_email', 'noreply@' . $sitename );
	$email = apply_filters( 'wp_mail_from', $email );


	return $from_header ? 'from: ' . SECUPRESS_PLUGIN_NAME . ' <' . $email . '>' : $email;
}


/**
 * Send mail.
 *
 * @author Julio Potier
 * @since 2.2.6  Can replace LOGINURL
 * @since 2.0    Can replace SITEURL, ADMIN_EMAIL, default plain/text instead of html.
 * 
 * @author Grégory Viguier
 * @since 1.2.4  Can replace SITENAME
 *
 * @param (string|array) $to          Array or comma-separated list of email addresses to send message.
 * @param (string)       $subject     Email subject.
 * @param (string)       $message     Message contents.
 * @param (array)        $headers     Optional. Additional headers.
 * @param (string|array) $attachments Optional. Files to attach.
 *
 * @return (bool) Whether the email contents were sent successfully.
 */
function secupress_send_mail( $to, $subject, $message, $headers = [], $attachments = array() ) {
	$replacement = [ '###SITENAME###', '###ADMIN_EMAIL###', '###SITEURL###', '###LOGINURL###' ];
	/**
	 * Filter the replacements strings
	 * 
	 * @since 2.2.6
	 * @author Julio Potier
	 */
	$replacement = apply_filters( 'secupress.mail.replacement', $replacement );
	$replaced    = [ secupress_get_blogname(), get_option( 'admin_email' ), home_url(), wp_login_url() ];
	/**
	 * Filter the replaced strings
	 * 
	 * @since 2.2.6
	 * @author Julio Potier
	 */
	$replaced    = apply_filters( 'secupress.mail.replaced', $replaced );

	$subject     = str_replace( $replacement, $replaced, $subject );
	$subject     = wp_specialchars_decode( $subject );

	$message     = str_replace( $replacement, $replaced, $message );

	$headers     = array_merge( [
		'from'         => secupress_get_email( true ),
	], $headers );

	/**
	 * Filter the email headers
	 * 
	 * @since 1.2.4
	 * @author Grégory Viguier
	 */
	$headers = apply_filters( 'secupress.mail.headers', $headers );

	/**
	 * Action before the wp_mail
	 * 
	 * @since 2.2.6
	 * @author Julio Potier
	 */
	do_action( 'secupress.mail.before.wp_mail', [ $to, $subject, $message, $headers, $attachments ] );

	return wp_mail( $to, $subject, $message, $headers, $attachments );
}


/**
 * Get the blog name or host if empty.
 *
 * @since 1.4.9
 * @author Julio Potier
 *
 * @return (string)
 */
function secupress_get_blogname() {
	static $blogname;

	if ( ! isset( $blogname ) ) {
		/**
		 * The blogname option is escaped with esc_html on the way into the database in sanitize_option
		 * we want to reverse this for the plain text arena of emails.
		 */
		$blogname = wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES );
		$blogname = $blogname ?: parse_url( home_url(), PHP_URL_HOST );
	}

	return $blogname;
}

/**
 * Return the current URL.
 *
 * @since 2.2.6 'domain' param
 * @since 2.0 Remove usage of HTTP_HOST and $port
 * @author Julio Potier
 * 
 * @since 1.0
 * @author Grégory Viguier
 * 
 * 
 * @param (string) $mode What to return: raw (all), base (before '?'), uri (before '?', without the domain), 'domain' (only the domain 'example.com').
 * @return (string)
 */
function secupress_get_current_url( $mode = 'base' ) {
	$host = str_replace( [ 'http://', 'https://', '/' ], '', home_url() );
	$url  = ! empty( $GLOBALS['HTTP_SERVER_VARS']['REQUEST_URI'] ) ? $GLOBALS['HTTP_SERVER_VARS']['REQUEST_URI'] : ( ! empty( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : '' );
	$url  = 'http' . ( secupress_server_is_ssl() ? 's' : '' ) . '://' . $host . str_replace( '//', '/', $url );

	switch ( $mode ) {
		case 'uri' :
			$home = set_url_scheme( home_url() );
			$url  = explode( '?', $url, 2 );
			$url  = reset( $url );
			$url  = str_replace( $home, '', $url );
			return trim( $url, '/' );
		case 'base' :
			$url  = explode( '?', $url, 2 );
			return reset( $url );
		case 'domain' :
			$url = parse_url( get_site_url(), PHP_URL_HOST );
			$url = preg_replace( '/^www\./', '', $url ); // Remove "www." if present
			return $url;
		default :
		case 'raw' :
			return $url;
	}
}


/**
 * Store, get or delete static data.
 * Getter:   no need to provide a second parameter.
 * Setter:   provide a second parameter for the value.
 * Deletter: provide null as second parameter to remove the previous value.
 *
 * @since 1.0
 * @author Grégory Viguier
 *
 * @param (string) $key An identifier key.
 *
 * @return (mixed) The stored data or null.
 */
function secupress_cache_data( $key ) {
	static $data = array();

	$func_get_args = func_get_args();

	if ( array_key_exists( 1, $func_get_args ) ) {
		if ( null === $func_get_args[1] ) {
			unset( $data[ $key ] );
		} else {
			$data[ $key ] = $func_get_args[1];
		}
	}

	return isset( $data[ $key ] ) ? $data[ $key ] : null;
}


/**
 * Get the main blog ID.
 *
 * @since 1.0
 * @author Grégory Viguier
 *
 * @return (int)
 */
function secupress_get_main_blog_id() {
	static $blog_id;

	if ( ! isset( $blog_id ) ) {
		if ( ! is_multisite() ) {
			$blog_id = 1;
		}
		elseif ( ! empty( $GLOBALS['current_site']->blog_id ) ) {
			$blog_id = absint( $GLOBALS['current_site']->blog_id );
		}
		elseif ( defined( 'BLOG_ID_CURRENT_SITE' ) ) {
			$blog_id = absint( BLOG_ID_CURRENT_SITE );
		}
		$blog_id = ! empty( $blog_id ) ? $blog_id : 1;
	}

	return $blog_id;
}


/**
 * Is current WordPress version older than X.X.X?
 *
 * @since 1.0
 * @author Grégory Viguier
 *
 * @param (string) $version The version to test.
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
 * Check whether WordPress is in "installation" mode.
 *
 * @since 1.0
 * @author Grégory Viguier
 *
 * @return (bool) true if WP is installing, otherwise false.
 */
function secupress_wp_installing() {
	return function_exists( 'wp_installing' ) ? wp_installing() : defined( 'WP_INSTALLING' ) && WP_INSTALLING;
}


/**
 * Tell if the site frontend is served over SSL.
 *
 * @since 1.0
 * @author Grégory Viguier
 *
 * @return (bool)
 **/
function secupress_is_site_ssl() {
	static $is_site_ssl;

	if ( isset( $is_site_ssl ) ) {
		return $is_site_ssl;
	}

	if ( is_multisite() ) {
		switch_to_blog( secupress_get_main_blog_id() );
		$site_url = get_option( 'siteurl' );
		$home_url = get_option( 'home' );
		restore_current_blog();
	} else {
		$site_url = get_option( 'siteurl' );
		$home_url = get_option( 'home' );
	}

	$is_site_ssl = strpos( $site_url, 'https://' ) === 0 && strpos( $home_url, 'https://' ) === 0;
	/**
	 * Filter the value of `$is_site_ssl`, that tells if the site frontend is served over SSL.
	 *
	 * @since 1.0
	 *
	 * @param (bool) $is_site_ssl True if the site frontend is served over SSL.
	 */
	$is_site_ssl = apply_filters( 'secupress.front.is_site_ssl', $is_site_ssl );

	return $is_site_ssl;
}


/**
 * Like in_array but for nested arrays.
 *
 * @since 1.0
 * @author Grégory Viguier
 *
 * @param (mixed) $needle   The value to find.
 * @param (array) $haystack The array to search.
 *
 * @return (bool)
 */
function secupress_in_array_deep( $needle, $haystack ) {
	if ( $haystack ) {
		foreach ( $haystack as $item ) {
			if ( $item === $needle || ( is_array( $item ) && secupress_in_array_deep( $needle, $item ) ) ) {
				return true;
			}
		}
	}
	return false;
}


/**
 * `array_intersect_key()` + `array_merge()`.
 *
 * @since 1.0
 * @author Grégory Viguier
 *
 * @param (array) $values  The array we're interested in.
 * @param (array) $default The array we use as boudaries.
 *
 * @return (array)
 */
function secupress_array_merge_intersect( $values, $default ) {
	$values = array_merge( $default, $values );
	return array_intersect_key( $values, $default );
}


/**
 * Get the consumer email.
 *
 * @since 1.0
 * @author Grégory Viguier
 *
 * @return (string|bool) The email if it is valid. False otherwise.
 */
function secupress_get_consumer_email() {
	return is_email( secupress_get_option( 'consumer_email' ) );
}


/**
 * Get the consumer key.
 *
 * @since 2.2.6
 * @author Julio Potier
 *
 * @since 1.0
 * @author Grégory Viguier
 *
 * @return (string)
 */
function secupress_get_consumer_key() {
	return secupress_get_option( 'consumer_key' );
}


/**
 * Return true if secupress pro is installed
 *
 * @since 1.3
 * @author Julio Potier
 *
 * @return (bool)
 */
function secupress_has_pro() {
	return defined( 'SECUPRESS_PRO_VERSION' );
}


/**
 * Return true if the license is ok.
 *
 * @since 1.3
 * @author Grégory Viguier
 *
 * @return (bool)
 */
function secupress_has_pro_license() {
	static $has_pro;

	if ( ! isset( $has_pro ) ) {
		$has_pro = secupress_get_consumer_key() && 1 === secupress_get_option( 'site_is_pro' );
	}

	return $has_pro;
}


/**
 * Return true if secupress pro is installed and the license is ok.
 *
 * @since 1.0
 * @author Grégory Viguier
 *
 * @return (bool)
 */
function secupress_is_pro() {
	return secupress_has_pro() && secupress_has_pro_license();
}


/**
 * Tell if a feature is for pro version.
 *
 * @since 1.0
 * @author Grégory Viguier
 *
 * @param (string) $feature The feature to test. Basically it can be:
 *                          - A field "name" when the whole field is pro: the result of `$this->get_field_name( $field_name )`.
 *                          - A field "name + value" when only one (or some) of the values is pro: the result of `$this->get_field_name( $field_name ) . "|" . $value`.
 *
 * @return (bool) True if the feature is in the white-list.
 */
function secupress_feature_is_pro( $feature ) {
	$features = [
		// Field names.
		'login-protection_sessions_control'         => 1,
		'blacklist-logins_prevent-user-creation'    => 1,
		'double-auth_type'                          => 1,
		'password-policy_force-logout'              => 1,
		'password-policy_send-emails'               => 1,
		'password-policy_password_expiration'       => 1,
		'password-policy_strong_passwords'          => 1,
		'plugins_detect_bad_plugins'                => 1,
		'themes_activation'                         => 1,
		'themes_deletion'                           => 1,
		'themes_detect_bad_themes'                  => 1,
		'uploads_uploads'                           => 1,
		'content-protect_hotlink'                   => 1,
		'content-protect_404guess'                  => 1,
		'file-scanner_file-scanner'                 => 1,
		'content-protect_bad-url-access'            => 1,
		'backup-files_backup-file'                  => 1,
		'backup-db_backup-db'                       => 1,
		'backup-history_backup-history'             => 1,
		'import-export_export_settings'             => 1,
		'import-export_import_settings'             => 1,
		'geoip-system_type'                         => 1,
		'schedules-backups_type'                    => 1,
		'schedules-backups_periodicity'             => 1,
		'schedules-backups_email'                   => 1,
		'schedules-backups_scheduled'               => 1,
		'schedules-scan_type'                       => 1,
		'schedules-scan_periodicity'                => 1,
		'schedules-scan_email'                      => 1,
		'schedules-scan_scheduled'                  => 1,
		'schedules-file-monitoring_type'            => 1,
		'schedules-file-monitoring_periodicity'     => 1,
		'schedules-file-monitoring_email'           => 1,
		'schedules-file-monitoring_scheduled'       => 1,
		'notification-types_types'                  => 1,
		'alerts_activated'                          => 1,
		'backups-storage_location'                  => 1,
		'event-alerts_activated'                    => 1,
		'notification-types_emails'                 => 1,
		'notification-types_slack'                  => 1,
		'daily-reporting_activated'                 => 1,
		'move-login_whattodo|custom_error'          => 1,
		'move-login_whattodo|custom_page'           => 1,
		'move-login_singlesignon'                   => 1,
		'login-protection_type|passwordspraying'    => 1,
		'database_db_prefix'                        => 1,
		'database_tables_selection'                 => 1,
		'bbq-headers_bad-referer'                   => 1,
		'bbq-headers_bad-referer-list'              => 1,
		'bbq-headers_block-ai'                      => 1,
		'blacklist-logins_user-creation-protection' => 1,
		'bbq-url-content_block-functions'           => 1,
	];

	return isset( $features[ $feature ] );
}

/**
 * Tell if a user is affected by its role for the asked module.
 *
 * @since 1.0
 * @author Julio Potier
 *
 * @param (string) $module    A module.
 * @param (string) $submodule A sub-module.
 * @param (object) $user      A WP_User object.
 *
 * @return (-1|bool) -1 = every role is affected, true = the user's role is affected, false = the user's role isn't affected.
 */
function secupress_is_affected_role( $module, $submodule, $user ) {
	$roles = secupress_get_module_option( $submodule . '_affected_role', array(), $module );

	if ( ! $roles ) {
		return -1;
	}

	return secupress_is_user( $user ) && ! array_intersect( $roles, $user->roles );
}

/**
 * Used with the filter hook 'nonce_user_logged_out' to create nonces for disconnected users.
 *
 * @since 2.2.6 crc32()
 * @since 2.2.5.2 hash( 'crc32b' )
 * @author Julio Potier
 * 
 * @since 1.0
 * @author Grégory Viguier
 *
 * @param (int) $uid A userID.
 * @param (string) $action The action.
 *
 * @return (int)
 */
function secupress_modify_userid_for_nonces( $uid = 0, $action = '' ) {
	return crc32( $uid . $action . secupress_get_ip() );
}


/**
 * Tell if the param $user is a real user from your installation.
 *
 * @since 1.0
 * @author Julio Potier
 *
 * @param (mixed) $user The object to be tested to be a valid user.
 *
 * @return (bool)
 */
function secupress_is_user( $user ) {
	return is_a( $user, 'WP_User' ) && user_can( $user, 'exist' );
}

/**
 * Get all meta values from a meta key for all users
 *
 * @since 2.2.6
 * @author Julio Potier
 *
 * @param (string) The meta key
 * @return (array)
 */
function secupress_get_user_metas( $meta_key ) {
	global $wpdb;
	$res = secupress_cache_data( __FUNCTION__ . $meta_key );
	if ( ! $res ) {
		$res = $wpdb->get_results( $wpdb->prepare( "SELECT user_id, meta_value FROM {$wpdb->usermeta} WHERE meta_key = %s", sanitize_key( $meta_key ) ), ARRAY_A );
		secupress_cache_data( __FUNCTION__ . $meta_key, $res );
	}
	return $res;
}

/**
 * Get a user by id, login or email
 *
 * @since 2.2.6
 * @author Julio Potier
 *
 * @see get_user_by()
 * 
 * @param (int|string) $value ID, email, or login
 * @return (bool|WP_User) False or WP_User
 */
function secupress_get_user_by( $value ) {
	if ( secupress_is_user( $value ) ) {
		return $value;
	}
	if ( is_int( $value ) ) {
		return get_user_by( 'ID', $value );
	}
	$by   = is_email( $value ) ? 'email' : 'login';
	$user = get_user_by( $by, $value );

	if ( ! secupress_is_user( $user ) && is_email( $value ) ) {
		$user = get_user_by( 'login', $value );
	}
	return $user;
}

/**
 * Compress some data to be stored in the database.
 *
 * @since 1.0.6
 * @author Grégory Viguier
 *
 * @param (mixed) $data The data to compress.
 *
 * @return (string) The compressed data.
 */
function secupress_compress_data( $data ) {
	/** Little and gentle obfuscation to avoid being tagged as "malicious script", I hope you understand :) — Julio. */
	$gz  = 'eta';
	$gz  = 'gz' . strrev( $gz . 'lfed' );
	$bsf = 'cne';
	$bsf = strrev( 'edo' . $bsf );
	$bsf = '64_' . $bsf;
	$bsf = 'base' . $bsf;

	return $bsf// Hey.
		( $gz// Hoy.
			( serialize( $data ) ) );
}


/**
 * Decompress some data coming from the database.
 *
 * @since 1.0.6
 * @author Grégory Viguier
 *
 * @param (string) $data The data to decompress.
 *
 * @return (mixed) The decompressed data.
 */
function secupress_decompress_data( $data ) {
	if ( ! $data || ! is_string( $data ) ) {
		return $data;
	}

	/** Little and gentle obfuscation to avoid being tagged as "malicious script", I hope you understand :) — Julio. */
	$gz  = 'eta';
	$gz  = 'gz' . strrev( $gz . 'lfni' );
	$bsf = 'ced';
	$bsf = strrev( 'edo' . $bsf );
	$bsf = '64_' . $bsf;
	$bsf = 'base' . $bsf;

	$data_tmp = $bsf// Hey.
		( $data );

	if ( ! $data_tmp ) {
		return $data;
	}

	$data     = $data_tmp;
	$data_tmp = $gz// Hoy.
		( $data );

	if ( ! $data_tmp ) {
		return $data;
	}

	return maybe_unserialize( $data_tmp );
}


/**
 * Try to increase the memory limit if possible.
 *
 * @since 1.0
 * @author Grégory Viguier
 */
function secupress_maybe_increase_memory_limit() {
	if ( ! wp_is_ini_value_changeable( 'memory_limit' ) ) {
		return;
	}

	$limits = array(
		'64M'  => 67108864,
		'128M' => 134217728,
		'256M' => 268435456,
	);
	$current_limit     = @ini_get( 'memory_limit' );
	$current_limit_int = wp_convert_hr_to_bytes( $current_limit );

	if ( -1 === $current_limit_int || $current_limit_int > $limits['256M'] ) {
		return;
	}

	foreach ( $limits as $limit => $bytes ) {
		if ( $current_limit_int < $bytes ) {
			@ini_set( 'memory_limit', $limit );
			return;
		}
	}
}


/**
 * Register a settings error to be displayed to the user.
 * This a clone of `add_settings_error()`, but available in the global scope.
 *
 * @since 1.3
 * @author Grégory Viguier
 *
 * @param (string) $setting Slug title of the setting to which this error applies.
 * @param (string) $code    Slug-name to identify the error. Used as part of 'id' attribute in HTML output.
 * @param (string) $message The formatted message text to display to the user (will be shown inside styled
 *                          `<div>` and `<p>` tags).
 * @param (string) $type    Optional. Message type, controls HTML class. Accepts 'error' or 'updated'.
 *                          Default 'error'.
 */
function secupress_add_settings_error( $setting, $code, $message, $type = 'error' ) {
	global $wp_settings_errors;

	$wp_settings_errors[] = array(
		'setting' => $setting,
		'code'    => $code,
		'message' => $message,
		'type'    => $type,
	);
}


/**
 * Fetch settings errors registered by `add_settings_error()` and `secupress_add_settings_error()`.
 * This a clone of `get_settings_errors()`, but available in the global scope.
 *
 * @since 1.3
 * @author Grégory Viguier
 *
 * @param (string)  $setting  Optional slug title of a specific setting who's errors you want.
 * @param (boolean) $sanitize Whether to re-sanitize the setting value before returning errors.
 *
 * @return (array) Array of settings errors
 */
function secupress_get_settings_errors( $setting = '', $sanitize = false ) {
	global $wp_settings_errors;

	/**
	 * If `$sanitize` is true, manually re-run the sanitization for this option.
	 * This allows the $sanitize_callback from register_setting() to run, adding any settings errors you want to show by default.
	 */
	if ( $sanitize ) {
		sanitize_option( $setting, get_option( $setting ) );
	}

	// If settings were passed back from options.php then use them.
	if ( isset( $_GET['settings-updated'] ) && $_GET['settings-updated'] && get_transient( 'settings_errors' ) ) {
		$wp_settings_errors = array_merge( (array) $wp_settings_errors, get_transient( 'settings_errors' ) ); // WPCS: override ok.
		delete_transient( 'settings_errors' );
	}

	// Check global in case errors have been added on this pageload.
	if ( is_array( $wp_settings_errors ) && ! count( $wp_settings_errors ) ) {
		return array();
	}

	// Filter the results to those of a specific setting if one was set.
	if ( $setting ) {
		$setting_errors = array();

		foreach ( (array) $wp_settings_errors as $key => $details ) {
			if ( $setting === $details['setting'] ) {
				$setting_errors[] = $wp_settings_errors[ $key ];
			}
		}

		return $setting_errors;
	}

	return is_array( $wp_settings_errors ) ? $wp_settings_errors : [];
}

/**
 * Checks whether function is disabled.
 *
 * @since 1.4.5
 * @author Julio Potier
 *
 * @param (string) $function Name of the function.
 * @return (bool) Whether or not the function is disabled.
 */
function secupress_is_function_disabled( $function ) {
	if ( ! function_exists( $function ) ) {
		return true;
	}

	$disabled = explode( ',', @ini_get( 'disable_functions' ) );
	$disabled = array_map( 'trim', $disabled );
	$disabled = array_flip( $disabled );

	return isset( $disabled[ $function ] );
}

/**
 * Returns true if SECUPRESS_MODE is defined on "expert"
 *
 * @since 2.0.1 Read the new setting too
 * @since 1.4.6
 * @return (bool)
 * @author Julio Potier
 **/
function secupress_is_expert_mode() {
	return secupress_get_module_option( 'advanced-settings_expert-mode', false , 'welcome') || defined( 'SECUPRESS_MODE' ) && ( 'expert' === strtolower( SECUPRESS_MODE ) );
}


/**
 * Set recursive chmod rights on a path
 *
 * @since 2.0
 * @author Julio Potier
 *
 * @param (string) $path Default value ABSPATH
 * @return (void)
 **/
function secupress_set_recursive_chmod_rights( $path = ABSPATH ) {
	$dir  = new DirectoryIterator( $path );
	$exts = [ 'php' => 1, 'js' => 1, 'css' => 1 ];
	/**
	* Filter the file extensions that will be chmoded
	*
	* @since 2.0
	* @param (array) $exts
	*/
	$exts = apply_filters( 'secupress.chmod.file_types', $exts );
	foreach ( $dir as $item ) {
		if ( $item->isDot() ) {
			continue;
		}
		if ( $item->isDir() ) {
			@chmod( $item->getPathname(), 0755 );
			secupress_set_recursive_chmod_rights( $item->getPathname() );
		} elseif( isset( $exts[ pathinfo( $item->getPathname(), PATHINFO_EXTENSION ) ] ) ) {
			@chmod( $item->getPathname(), 0644 );
		}
	}
}

/**
 * Checks whether the website is using HTTPS.
 * This is based on whether both the home and site URL are using HTTPS.
 *
 * @since 2.0
 * @author Julio Potier
 *
 * @see wp_is_using_https()
 *
 * @param (string) 'both', 'site', 'home' accepted, anything else will return false;
 * @return (bool) True if site is actually using HTTPS
 **/
function secupress_site_is_using_https( $type = 'both' ) {
	$home = 'https' === wp_parse_url( get_option( 'home' ), PHP_URL_SCHEME );
	$site = 'https' === wp_parse_url( apply_filters( 'site_url', get_option( 'siteurl' ), '', null, null ), PHP_URL_SCHEME );
	$both = $home && $site;

	return isset( $$type ) && $$type;
}

/**
 * Check if https with ssl verify returns an error
 *
 * @since 2.2.6 secupress_server_is_ssl() = 
 * @since 2.0
 * @author Julio Potier
 *
 * @see wp_is_https_supported()
 *
 * @return (bool) True if https/ssl is OK
 **/
function secupress_is_https_supported() {
	if ( ! secupress_server_is_ssl() ) {
		$error = new WP_Error();
		$error->add( 'invalid_ssl', sprintf( __( 'SSL is not supported on HTTP PORT %s', 'secupress' ), esc_html( $_SERVER['SERVER_PORT'] ) ) );
		set_transient( 'secupress_is_https_supported', $error, 6 * HOUR_IN_SECONDS );
		return false;
	}
	if ( ! wp_http_supports( [ 'ssl' ] ) ) {
		$error = new WP_Error();
		$error->add( 'invalid_ssl', __( 'SSL is not supported on this website.', 'secupress' ) );
		set_transient( 'secupress_is_https_supported', $error, 6 * HOUR_IN_SECONDS );
		return false;
	}
	$response = get_transient( 'secupress_is_https_supported' );
	if ( $response && ! is_wp_error( $response ) ) {
		return true;
	}
	$response = wp_remote_get(
		home_url( '/', 'https' ),
		[
			'headers'   => [
				'Cache-Control' => 'no-cache',
			],
			'sslverify' => true,
		]
	);

	set_transient( 'secupress_is_https_supported', $response, 6 * HOUR_IN_SECONDS );
	return ! is_wp_error( $response );
}

/**
 * Determines if SSL is used, Cloudflare Compatible.
 *
 * @since 2.2.6
 * @author Julio Potier
 * 
 * @param (bool) $with_cloudflare Whenever to also check the CF-Visitor value
 * 
 * @return (bool)
 **/
function secupress_server_is_ssl( $with_cloudflare = true ) {
	$is_ssl = false;
	if ( isset( $_SERVER['HTTPS'] ) ) {
		if ( 'on' === strtolower( $_SERVER['HTTPS'] ) ) {
			$is_ssl = true;
		}

		if ( '1' === (string) $_SERVER['HTTPS'] ) {
			$is_ssl = true;
		}
	} elseif ( isset( $_SERVER['SERVER_PORT'] ) && ( '443' === (string) $_SERVER['SERVER_PORT'] ) ) {
		$is_ssl = true;
	}
	// Cloudflare
	if ( $with_cloudflare && isset( $_SERVER['HTTP_CF_VISITOR'] ) ) {
		$cf_visitor = json_decode( $_SERVER['HTTP_CF_VISITOR'], true );
		if ( isset( $cf_visitor['scheme'] ) && 'https' === $cf_visitor['scheme'] ) {
			$is_ssl = true;
		}
	}

	/**
	 * Filter the SSL return
	 * 
	 * @since 2.2.§
	 * @param (bool) $is_sll
	 * @param (bool) $with_cloudflare
	 */
	return apply_filters( 'secupress.is_sll', $is_ssl, $with_cloudflare );
}


/**
 * Update home and siteurl with HTTPS
 *
 * @since 2.2.6 Do not relay on the WP function
 * @since 2.0
 * @author Julio Potier
 *
 * @see wp_update_urls_to_https()
 * @return (bool) True if URL are updated
 **/
function secupress_update_urls_to_https() {
	if ( ! current_user_can( 'update_https' ) ) {
		return false;
	}
	// Get current URL options.
	$orig_home    = get_option( 'home' );
	$orig_siteurl = get_option( 'siteurl' );

	// Get current URL options, replacing HTTP with HTTPS.
	$home    = str_replace( 'http://', 'https://', $orig_home );
	$siteurl = str_replace( 'http://', 'https://', $orig_siteurl );

	// Update the options.
	update_option( 'home', $home );
	update_option( 'siteurl', $siteurl );

	return true;
}

/**
 * Before each usage of secupress_send_slack_notification(), maybe check if this is still correct
 *
 * @since 2.0
 * @author Julio Potier
 *
 * @see secupress_send_slack_notification()
 *
 * @return (bool) True if still OK, false if not.
 **/
function secupress_maybe_reset_slack_notifs() {
	$url      = secupress_get_module_option( 'notification-types_slack', false, 'alerts' );
	$accepted = secupress_get_option( 'notification-types_slack', false );
	if ( apply_filters( 'secupress.notifications.slack.bypass', false ) || ( ! empty( $accepted ) && $url === $accepted ) ) {
		return true;
	}
	secupress_set_option( 'notification-types_slack', 0 );
	return false;
}


/**
 * Try to delete a file, if not, will empty the file, if not, will rename it.
 *
 * @since 2.2.6 time()
 * @since 1.4.3
 * @author Julio Potier
 * 
 * @param (string) $file The file to be deleted.
 * @return (bool)
 **/
function secupress_remove_old_plugin_file( $file ) {
	// Is it a sym link ?
	if ( is_link( $file ) ) {
		$file = @readlink( $file );
	}
	// Try to delete.
	if ( file_exists( $file ) && ! @unlink( $file ) ) {
		// Or try to empty it.
		$fh = @fopen( $file, 'w' );
		$fw = @fwrite( $fh, '<?php // File removed by SecuPress' );
		@fclose( $fh );
		if ( ! $fw ) {
			// Or try to rename it.
			return @rename( $file, $file . '.' . time() . '.old' );
		}
	}
	return true;
}

/**
 * Translate the WP role as we want to
 *
 * @since 2.0
 * @author Julio Potier
 * 
 * @param (string) $role
 *
 * @return (string)
 **/
function secupress_translate_user_role( $role ) {
	global $wp_roles;
	_x( 'Administrator', 'User role', 'secupress' );
	_x( 'Editor',        'User role', 'secupress' );
	_x( 'Author',        'User role', 'secupress' );
	_x( 'Contributor',   'User role', 'secupress' );
	_x( 'Subscriber',    'User role', 'secupress' );
	$role        = isset( $wp_roles->role_names[ $role ] ) ? $wp_roles->role_names[ $role ] : $role;
	$translation = translate_user_role( $role, 'secupress' );
	// If a new role is added (even by a plugin etc), and we do not know it, backcompat with WP domain.
	if ( 0 === strcmp( $translation, $role ) ) {
		$translation = translate_user_role( $role );
	}
	return $translation;
}

/**
 * Our own set_time_limit function because some hosts are banning it
 *
 * @param (int) seconds
 * @author Julio Potier
 * @since 2.2
 * @return (bool) True if one of the function was usable, False if not
 **/
function secupress_time_limit( $seconds ) {
	if ( function_exists( 'set_time_limit' ) ) {
		set_time_limit( (int) $seconds );
		return true;
	} elseif( function_exists( 'ini_set' ) ) {
		ini_set( 'max_execution_time', (int) $seconds );
		return true;
	}
	return false;
}


/**
 * Get a scan or fix status, formatted with icon and human readable text.
 *
 * @since 1.0
 * @author Grégory Viguier
 *
 * @param (string) $status The status code.
 * @return (string) Formatted status.
 */
function secupress_status( $status ) {
	$statuses            = [];
	$statuses['bad']     = _x( 'Bad', 'scan result', 'secupress' );
	$statuses['good']    = _x( 'Good', 'scan result', 'secupress' );
	$statuses['warning'] = _x( 'Pending', 'scan result', 'secupress' );
	$statuses['cantfix'] = _x( 'Error', 'scan result', 'secupress' );

	return isset( $statuses[ $status ] ) ? $statuses[ $status ] : _x( 'New', 'scanner item', 'secupress' );
}


/**
 * Retrieve messages by their ID and format them by wrapping them in `<ul>` and `<li>` tags.
 *
 * @since 1.0
 * @author Grégory Viguier
 *
 * @param (array)  $msgs      An array of messages.
 * @param (string) $test_name The scanner name.
 *
 * @return (string) An HTML list of formatted messages.
 */
function secupress_format_message( $msgs, $test_name ) {
	$classname = 'SecuPress_Scan_' . $test_name;
	$messages  = $classname::get_instance()->get_messages();

	$output = array();

	if ( empty( $msgs ) ) {
		return implode( '<br/>', $output );
	}

	foreach ( $msgs as $id => $atts ) {

		if ( ! isset( $messages[ $id ] ) ) {

			$string = __( 'Fix done.', 'secupress' );

		} elseif ( is_array( $messages[ $id ] ) ) {

			$count  = array_shift( $atts );
			$string = translate_nooped_plural( $messages[ $id ], $count );

		} else {

			$string = $messages[ $id ];

		}

		if ( $atts ) {
			foreach ( $atts as $i => $att ) {
				if ( is_array( $att ) ) {
					$atts[ $i ] = wp_sprintf_l( '%l', $att );
				}
			}
		}

		$output[] = ! empty( $atts ) ? vsprintf( $string, $atts ) : $string;
	}

	return implode( '<br/>', $output );
}

/**
 * Log blocked attacks
 *
 * @author Julio Potier
 * @since 2.2.6
 * 
 **/
function secupress_log_attack( $type ) {
	$attack_types = get_option( SECUPRESS_ATTACKS, [] );
	if ( ! isset( $attack_types[ $type ] ) ) {
		$attack_types[ $type ] = 0;
	}
	++$attack_types[ $type ];
	update_option( SECUPRESS_ATTACKS, $attack_types );
}

/**
 * Get blocked attacks by type or all
 *
 * @author Julio Potier
 * @since 2.2.6
 * 
 * @param (string) $type 'All' or a type of attacks, see secupress_attacks_get_type_title()
 **/
function secupress_get_attacks( $type = 'all' ) {
	$attack_types = get_option( SECUPRESS_ATTACKS, [] );
	if ( 'all' === $type ) {
		return $attack_types;
	}
	if ( isset( $attack_types[ $type ] ) ) {
		return (int) $attack_types[ $type ];
	}
	return false;
}

/**
 * Get the translated attack titles
 *
 * @author Julio Potier
 * @since 2.2.6
 * 
 **/
function secupress_attacks_get_type_title( $type ) {
	switch ( $type ) {
		case 'ban_ip':
			return __( 'Banned IPs', 'secupress' );
		break;
		
		case 'plugins':
			return __( 'Plugin Interactions', 'secupress' );
		break;
		
		case 'theme':
			return __( 'Theme Interactions', 'secupress' );
		break;
		
		case 'zipfile':
			return __( 'ZIP Upload Attempts', 'secupress' );
		break;
		
		case 'xmlrpc':
			return __( 'XMLRPC Intrusions', 'secupress' );
		break;
		
		case 'move_login':
			return __( 'Login Page', 'secupress' );
		break;
		
		case 'loginattempts':
			return __( 'Login Attempts', 'secupress' );
		break;
		
		case 'passwordspraying':
			return __( 'Password Spraying Attempts', 'secupress' );
		break;
		
		case 'users':
			return __( 'User Actions', 'secupress' );
		break;
		
		case 'bad_robots':
			return __( 'Bad Robots', 'secupress' );
		break;
		
		case 'bad_request_content':
			return __( 'Bad Request Content', 'secupress' );
		break;
		
		default:
			return _x( 'All', 'types of attacks', 'secupress' );
		break;
	}
}

/**
 * Get all files from a given folder
 *
 * @author Julio Potier
 * @since 2.2.6
 * 
 * @param (string) $path
 * @return (array) $list List of files only
 **/
function secupress_list_files_from_folder( $path ) {
	$list    = [];
	$content = scandir( $path );

	foreach( $content as $element ) {
		if ( $element !== '.' && $element !== '..' ) {
			$path_element = $path . '/' . $element;
			if ( is_dir( $path_element ) ) {
				$_list = secupress_list_files_from_folder( $path_element );
				foreach ( $_list as $file ) {
					$list[] = $element . '/' . $file;
				}
			} else {
				$list[] = $element;
			}
		}
	}

	return $list;
}


add_action( 'login_form_md5', 'secupress_login_form_md5' );
/**
 * Dirty function to create a md5 in JS
 *
 * @since 2.2.6 from wp_ajax_nopriv_md5 to login_form_md5
 * @since 2.0
 * @author Julio Potier
 *
 * @return (string) A md5 string
 **/
function secupress_login_form_md5( $t ) {
	if ( isset( $_GET['e'] ) ) {
		die( md5( trim( $_GET['e'] ) ) );
	} else {
		die( '-1' );
	}
}

/**
 * Test if the current browser runs on a mobile device (smart phone, tablet, etc.).
 * 
 * @see wp_is_mobile()
 *
 * @since 2.2.6
 * @author Julio Potier
 *
 * @return (bool) $is_mobile
 **/
function secupress_is_mobile( $ua = null ) {
	if ( is_null( $ua ) ) {
		return wp_is_mobile();
	}
	$is_mobile = false;
	if (   str_contains( $ua, 'Mobile' )
		|| str_contains( $ua, 'Android' )
		|| str_contains( $ua, 'Silk/' )
		|| str_contains( $ua, 'Kindle' )
		|| str_contains( $ua, 'BlackBerry' )
		|| str_contains( $ua, 'Opera Mini' )
		|| str_contains( $ua, 'Opera Mobi' )
		|| str_contains( $ua, 'iPhone' )
		|| str_contains( $ua, 'iPod' )
		|| str_contains( $ua, 'webOS' )
		|| str_contains( $ua, 'Symbian' )
		|| str_contains( $ua, 'Windows Phone' )
	) {
		$is_mobile = true;
	}

	/**
	 * @see WP /wp-includes/vars.php 
	 */
	return apply_filters( 'wp_is_mobile', $is_mobile );	
}

/**
 * Get info for a given plugin
 * 
 * @since 2.2.6
 * @author Julio Potier
 *
 * @param (string) $plugin_slug
 * 
 * @return (string) $plugin
 **/
function secupress_plugins_api( $plugin_slug ) {

	$api = get_site_transient( 'secupress_plugins_api_' . $plugin_slug );
	if ( false === $api ) {
		if ( ! function_exists( 'plugins_api' ) ) {
			require_once( ABSPATH . 'wp-admin/includes/plugin-install.php' );
		}
		$api = plugins_api(
			'plugin_information',
			[
				'slug'   => $plugin_slug,
				'fields' => 
				[
					// https://core.trac.wordpress.org/ticket/60783#ticket
					// 'downloadlink' => false,
					'short_description' => false,
					'description' => false,
					'tested' => false,
					'requires' => false,
					'requires_php' => false,
					'rating' => false,
					'ratings' => false,
					'num_ratings' => false,
					'requires_plugins' => false,
					'support' => false,
					'support_url' => false,
					'support_threads' => false,
					'support_threads_resolved' => false,
					'downloaded' => false,
					'screenshots' => false,
					'business_model' => false,
					'repository_url' => false,
					'commercial_support_url' => false,
					'preview_link' => false,
					'last_updated' => false,
					'added' => false,
					'tags' => false,
					'compatibility' => false,
					'homepage' => false,
					'donate_link' => false,
					'contributors' => false,
					'sections' => false,
					'active_installs' => false,
					'group' => false,
					'icons' => false,
					'reviews' => false,
					'banners' => false,
					'versions' => false,
				],
			]
		);
		if ( ! is_object( $api ) || is_wp_error( $api ) ) {
			return new WP_Error( 'plugin_not_found', __( 'Plugin not found', 'secupress' ) );
		}
		$api->source = 'wp_org';
		set_site_transient( 'secupress_plugins_api_' . $plugin_slug, $api, WEEK_IN_SECONDS );
	} else {
		$api->source = 'db';
	}

	return $api;
}

/**
 * Return a string containing the server type name between "apache" "nginx" "iis7" "unknown"
 *
 * @since 2.2.6
 * @author Julio Potier
 * 
 * @return (string)
 */
function secupress_get_server_type() {
	global $is_apache, $is_nginx, $is_iis7;
	static $server_type;

	if ( isset( $server_type ) ) {
		return $server_type;
	}

	switch( true ) {
		case $is_apache: $server_type = 'apache';  break;
		case $is_nginx:  $server_type = 'nginx';   break;
		case $is_iis7:   $server_type = 'iis7';    break;
		default:         $server_type = 'unknown'; break;
	}

	return $server_type;
}

/**
 * Return the function name depending on the server type
 *
 * @since 2.2.6
 * @author Julio Potier
 * 
 * @param (string) $prefix
 * @param (string) $default
 * @return (string)
 */
function secupress_get_function_name_by_server_type( $prefix, $default = '__return_empty_string' ) {
	global $is_apache, $is_nginx, $is_iis7;
	
	$server_type = secupress_get_server_type();
	$function    = $prefix . $server_type;

	return function_exists( $function ) ? $function : $default;
}
