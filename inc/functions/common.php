<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/*------------------------------------------------------------------------------------------------*/
/* REQUIRE FILES ================================================================================ */
/*------------------------------------------------------------------------------------------------*/

/**
 * Return the path to a class.
 *
 * @since 1.0
 *
 * @param (string) $prefix          Only one possible value so far: "scan".
 * @param (string) $class_name_part The classes name is built as follow: "SecuPress_{$prefix}_{$class_name_part}".
 *
 * @return (string) Path of the class.
 */
function secupress_class_path( $prefix, $class_name_part = '' ) {
	$folders = array(
		'scan'      => 'scanners',
		'singleton' => 'common',
		'logs'      => 'common',
		'log'       => 'common',
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
 */
function secupress_require_class_async() {
	/* https://github.com/A5hleyRich/wp-background-processing v1.0 */
	secupress_require_class( 'Admin', 'wp-async-request' );
	secupress_require_class( 'Admin', 'wp-background-process' );
}


/*------------------------------------------------------------------------------------------------*/
/* SCAN / FIX =================================================================================== */
/*------------------------------------------------------------------------------------------------*/

/**
 * Return all tests to scan
 *
 * @since 1.0
 *
 * @return (array) Tests to scan.
 */
function secupress_get_scanners() {
	$tests = array(
		'high' => array(
			'Core_Update',
			'Plugins_Update',
			'Themes_Update',
			'Auto_Update',
			'Bad_Old_Plugins',
			'Bad_Old_Files',
			'Bad_Config_Files',
			'Bad_Vuln_Plugins',
			'Admin_User',
			'Easy_Login',
			'Subscription',
			'WP_Config',
			'Salt_Keys',
			'Passwords_Strength',
			'Chmods',
			'Common_Flaws',
			'Bad_User_Agent',
			'SQLi',
			'Anti_Scanner',
			'Anti_Front_Bruteforce',
			'Directory_Listing',
		),
		'medium' => array(
			'Inactive_Plugins_Themes',
			'Bad_Usernames',
			'Bad_Request_Methods',
			'PhpVersion',
			'Block_HTTP_1_0',
			'Discloses',
			'Block_Long_URL',
			'Readme_Discloses',
			'Bad_Url_Access',
			'Uptime_Monitor',
		),
		'low' => array(
			'Login_Errors_Disclose',
			'PHP_Disclosure',
			'DirectoryIndex',
		),
	);

	if ( ! secupress_users_can_register() ) {
		$tests['medium'][] = 'Non_Login_Time_Slot';
	}

	if ( class_exists( 'SitePress' ) ) {
		$tests['medium'][] = 'Wpml_Discloses';
	}

	if ( class_exists( 'WooCommerce' ) ) {
		$tests['medium'][] = 'Woocommerce_Discloses';
	}

	return $tests;
}


/**
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
	);
}


/**
 * Get SecuPress scanner counter(s).
 *
 * @since 1.0
 *
 * @param (string) $type Info to retrieve: good, warning, bad, notscannedyet, grade, total.
 *
 * @return (string|array) The desired counter info if `$type` is provided and the info exists. An array of all counters otherwise.
 */
function secupress_get_scanner_counts( $type = '' ) {
	$tests_by_status = secupress_get_scanners();
	$scanners        = secupress_get_scan_results();
	$empty_statuses  = array( 'good' => 0, 'warning' => 0, 'bad' => 0 );
	$scanners_count  = ! empty( $scanners ) ? array_count_values( wp_list_pluck( $scanners, 'status' ) ) : array();
	$counts          = array_merge( $empty_statuses, $scanners_count );

	$counts['notscannedyet'] = count( $tests_by_status['high'] ) + count( $tests_by_status['medium'] ) + count( $tests_by_status['low'] ) - array_sum( $counts );
	$counts['total']         = count( $tests_by_status['high'] ) + count( $tests_by_status['medium'] ) + count( $tests_by_status['low'] );
	$percent                 = floor( $counts['good'] * 100 / $counts['total'] );

	if ( $percent >= 90 ) {
		$counts['grade'] = 'A';
	} elseif ( $percent >= 80 ) {
		$counts['grade'] = 'B';
	} elseif ( $percent >= 70 ) {
		$counts['grade'] = 'C';
	} elseif ( $percent >= 60 ) {
		$counts['grade'] = 'D';
	} elseif ( $percent >= 50 ) {
		$counts['grade'] = 'E';
	} else {
		$counts['grade'] = 'F';
	}

	if ( isset( $counts[ $type ] ) ) {
		return $counts[ $type ];
	}

	return $counts;
}


/*------------------------------------------------------------------------------------------------*/
/* PLUGINS ====================================================================================== */
/*------------------------------------------------------------------------------------------------*/

/**
 * Check whether a plugin is active.
 *
 * @since 1.0
 *
 * @param (string) $plugin A plugin path, relative to the plugins folder.
 *
 * @return (bool)
 */
function secupress_is_plugin_active( $plugin ) {
	$plugins = (array) get_option( 'active_plugins', array() );
	$plugins = array_flip( $plugins );
	return isset( $plugins[ $plugin ] ) || secupress_is_plugin_active_for_network( $plugin );
}


/**
 * Check whether a plugin is active for the entire network.
 *
 * @since 1.0
 *
 * @param (string) $plugin A plugin path, relative to the plugins folder.
 *
 * @return (bool)
 */
function secupress_is_plugin_active_for_network( $plugin ) {
	if ( ! is_multisite() ) {
		return false;
	}

	$plugins = get_site_option( 'active_sitewide_plugins' );

	return isset( $plugins[ $plugin ] );
}


/*------------------------------------------------------------------------------------------------*/
/* DIE ========================================================================================== */
/*------------------------------------------------------------------------------------------------*/

/**
 * Die with SecuPress format.
 *
 * @since 1.0
 *
 * @param (string) $message Guess what.
 * @param (string) $title   Window title.
 * @param (array)  $args    An array of arguments.
 */
function secupress_die( $message = '', $title = '', $args = array() ) {
	$has_p   = strpos( $message, '<p>' ) !== false;
	$message = ( $has_p ? '' : '<p>' ) . $message . ( $has_p ? '' : '</p>' );
	$message = '<h1>' . SECUPRESS_PLUGIN_NAME . '</h1>' . $message;
	$url     = secupress_get_current_url( 'raw' );

	/**
	 * Filter the message.
	 *
	 * @since 1.0
	 *
	 * @param (string) $message The message displayed.
	 * @param (string) $url     The current URL.
	 * @param (array)  $args    Facultative arguments.
	 */
	$message = apply_filters( 'secupress.die.message', $message, $url, $args );

	/**
	 * Fires right before `wp_die()`.
	 *
	 * @since 1.0
	 *
	 * @param (string) $message The message displayed.
	 * @param (string) $url     The current URL.
	 * @param (array)  $args    Facultative arguments.
	 */
	do_action( 'secupress.before.die', $message, $url, $args );

	wp_die( $message, $title, $args );
}


/**
 * Block a request and die with more informations.
 *
 * @since 1.0
 *
 * @param (string)           $module The related module.
 * @param (array|int|string) $args   Contains the "code" (def. 403) and a "content" (def. empty), this content will replace the default message.
 *                                   $args can be used only for the "code" or "content" or both using an array.
 */
function secupress_block( $module, $args = array( 'code' => 403 ) ) {

	if ( is_int( $args ) ) {
		$args = array( 'code' => $args );
	} elseif ( is_string( $args ) ) {
		$args = array( 'content' => $args );
	}

	$ip   = secupress_get_ip();
	$args = wp_parse_args( $args, array( 'code' => 403, 'content' => '' ) );

	do_action( 'secupress.block.' . $module, $ip, $args );
	do_action( 'secupress.block', $module, $ip, $args );

	$module = ucwords( str_replace( '-', ' ', $module ) );
	$module = preg_replace( '/[^0-9A-Z]/', '', $module );

	$title   = $args['code'] . ' ' . get_status_header_desc( $args['code'] );
	$content = '<h4>' . $title . '</h4>';

	if ( ! $args['content'] ) {
		$content .= '<p>' . __( 'You are not allowed to access the requested page.', 'secupress' ) . '</p>';
	} else {
		$content .= '<p>' . $args['content'] . '</p>';
	}

	$content  = '<h4>' . __( 'Logged Details:', 'secupress' ) . '</h4><p>';
	$content .= sprintf( __( 'Your IP: %s', 'secupress' ), $ip ) . '<br>';
	$content .= sprintf( __( 'Time: %s', 'secupress' ), date_i18n( __( 'F j, Y g:i a' ) ) ) . '<br>';
	$content .= sprintf( __( 'Block ID: %s', 'secupress' ), $module ) . '</p>';

	secupress_die( $content, $title, array( 'response' => $args['code'] ) );
}


/*------------------------------------------------------------------------------------------------*/
/* OTHER TOOLS ================================================================================== */
/*------------------------------------------------------------------------------------------------*/

/**
 * Create a URL to easily access to our pages.
 *
 * @since 1.0
 *
 * @param (string) $page   The last word of the secupress page slug.
 * @param (string) $module The required module.
 *
 * @return (string) The URL.
 */
function secupress_admin_url( $page, $module = '' ) {
	$module = $module ? '&module=' . $module : '';
	$page   = str_replace( '&', '_', $page );
	$url    = 'admin.php?page=secupress_' . $page . $module;

	return is_multisite() ? network_admin_url( $url ) : admin_url( $url );
}


/**
 * Get the user capability required to work with the plugin.
 *
 * @since 1.0
 *
 * @param (bool) $force_mono Set to true to get the capability for monosite, whatever we're on multisite or not.
 *
 * @return (string) The capability.
 */
function secupress_get_capability( $force_mono = false ) {
	if ( $force_mono ) {
		return 'administrator';
	}
	return is_multisite() ? 'manage_network_options' : 'administrator';
}


/**
 * Tell if users can register, whatever we're in a Multisite or not.
 *
 * @since 1.0
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

	$email = 'noreply@' . $sitename;

	return $from_header ? 'from: ' . SECUPRESS_PLUGIN_NAME . ' <' . $email . '>' : $email;
}


/**
 * Return the current URL.
 *
 * @since 1.0
 *
 * @param (string) $mode What to return: raw (all), base (before '?'), uri (before '?', without the domain).
 *
 * @return (string)
 */
function secupress_get_current_url( $mode = 'base' ) {
	$mode = (string) $mode;
	$port = (int) $_SERVER['SERVER_PORT'];
	$port = 80 !== $port && 443 !== $port ? ( ':' . $port ) : '';
	$url  = ! empty( $GLOBALS['HTTP_SERVER_VARS']['REQUEST_URI'] ) ? $GLOBALS['HTTP_SERVER_VARS']['REQUEST_URI'] : ( ! empty( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : '' );
	$url  = 'http' . ( is_ssl() ? 's' : '' ) . '://' . $_SERVER['HTTP_HOST'] . $port . $url;

	switch ( $mode ) :
		case 'raw' :
			return $url;
		case 'uri' :
			$home = set_url_scheme( home_url() );
			$url  = explode( '?', $url, 2 );
			$url  = reset( $url );
			$url  = str_replace( $home, '', $url );
			return trim( $url, '/' );
		default :
			$url  = explode( '?', $url, 2 );
			return reset( $url );
	endswitch;
}


/**
 * Store, get or delete static data.
 * Getter:   no need to provide a second parameter.
 * Setter:   provide a second parameter for the value.
 * Deletter: provide null as second parameter to remove the previous value.
 *
 * @since 1.0
 *
 * @param (string) $key An identifier key.
 *
 * @return (mixed) The stored data or null.
 */
function secupress_cache_data( $key ) {
	static $datas = array();

	$func_get_args = func_get_args();

	if ( array_key_exists( 1, $func_get_args ) ) {
		if ( null === $func_get_args[1] ) {
			unset( $datas[ $key ] );
		} else {
			$datas[ $key ] = $func_get_args[1];
		}
	}

	return isset( $datas[ $key ] ) ? $datas[ $key ] : null;
}


/**
 * Get the main blog ID.
 *
 * @since 1.0
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
 * Return true if secupress pro is installed
 *
 * @since 1.0
 *
 * @return (bool)
 */
function secupress_is_pro() {
	return defined( 'SECUPRESS_PRO_VERSION' );
}


/**
 * Tell if a feature is for pro version.
 *
 * @since 1.0
 *
 * @param (string) $feature The feature to test. Basically it can be:
 *                          - A field "name" when the whole field is pro: the result of `$this->get_field_name( $field_name )`.
 *                          - A field "name + value" when only one (or some) of the values is pro: the result of `$this->get_field_name( $field_name ) . "|" . $value`.
 *
 * @return (bool) True if the feature is in the white-list.
 */
function secupress_feature_is_pro( $feature ) {
	$features = array(
		// Field names.
		'login-protection_only-one-connexion'    => 1,
		'login-protection_sessions_control'      => 1,
		'double-auth_type'                       => 1,
		'password-policy_password_expiration'    => 1,
		'password-policy_strong_passwords'       => 1,
		'plugins_activation'                     => 1,
		'plugins_deactivation'                   => 1,
		'plugins_deletion'                       => 1,
		'plugins_detect_bad_plugins'             => 1,
		'themes_activation'                      => 1,
		'themes_deletion'                        => 1,
		'plugins_detect_bad_themes'              => 1,
		'uploads_uploads'                        => 1,
		'page-protect_profile'                   => 1,
		'page-protect_settings'                  => 1,
		'content-protect_hotlink'                => 1,
		'file-scanner_file-scanner'              => 1,
		'backup-files_backup-file'               => 1,
		'import-export_export_settings'          => 1,
		'import-export_import_settings'          => 1,
		'geoip-system_type'                      => 1,
		'bruteforce_activated'                   => 1,
		'schedules_backups'                      => 1,
		'schedules_scans'                        => 1,
		'schedules_filemon'                      => 1,
		// Field values.
		'notification-types_types|sms'           => 1,
		'notification-types_types|push'          => 1,
		'notification-types_types|slack'         => 1,
		'notification-types_types|twitter'       => 1,
		'login-protection_type|nonlogintimeslot' => 1,
		'backups-storage_location|ftp'           => 1,
		'backups-storage_location|amazons3'      => 1,
		'backups-storage_location|dropbox'       => 1,
		'backups-storage_location|rackspace'     => 1,
	);

	return isset( $features[ $feature ] );
}
