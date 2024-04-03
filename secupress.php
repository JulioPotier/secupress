<?php
/**
 * Plugin Name: SecuPress Free — WordPress Security
 * Plugin URI: https://secupress.me
 * Description: More than a plugin, the guarantee of a protected website by experts.
 * Author: SecuPress
 * Author URI: https://secupress.me
 * Version: 2.2.5.3
 * Code Name: Python (Mark XX)
 * Network: true
 * Contributors: SecuPress, juliobox, GregLone
 * License: GPLv2
 * Domain Path: /languages/
 * Requires at least: 4.9
 * Requires PHP: 5.6
 * Copyright 2012-2024 SecuPress
 */
defined( 'ABSPATH' ) or die( 'Something went wrong.' );


/** --------------------------------------------------------------------------------------------- */
/** DEFINES ===================================================================================== */
/** --------------------------------------------------------------------------------------------- */

// Common constants
if ( ! defined( 'SECUPRESS_FILE' ) ) {
	define( 'SECUPRESS_FILE', __FILE__ );
}
if ( file_exists( plugin_dir_path( __FILE__ ) . 'defines.php' ) ) {
	require_once( plugin_dir_path( __FILE__ ) . 'defines.php' );
}

define( 'SECUPRESS_ACTIVE_SUBMODULES'     , 'secupress_active_submodules' );
define( 'SECUPRESS_SETTINGS_SLUG'         , 'secupress_settings' );
define( 'SECUPRESS_SCAN_TIMES'            , 'secupress_scanners_times' );
define( 'SECUPRESS_WP_CORE_FILES_HASHES'  , 'secupress_wp_core_files_hashes' );
define( 'SECUPRESS_FULL_FILETREE'         , 'secupress_full_filetree' );
define( 'SECUPRESS_DATABASE_MALWARES'     , 'secupress_database_malwares' );
define( 'SECUPRESS_FIX_DISTS'             , 'secupress_fix_dists' );
define( 'SECUPRESS_BAN_IP'                , 'secupress_ban_ip' );
define( 'SECUPRESS_WHITE_IP'              , 'secupress_whitelist_ip' );
define( 'SECUPRESS_RATE_URL'              , 'https://wordpress.org/support/view/plugin-reviews/secupress?filter=5#topic' );
define( 'SECUPRESS_WEB_MAIN'              , 'https://secupress.me/' );
define( 'SECUPRESS_MODULES_PATH'          , SECUPRESS_INC_PATH . 'modules' . DIRECTORY_SEPARATOR );
define( 'SECUPRESS_ADMIN_PATH'            , SECUPRESS_INC_PATH . 'admin' . DIRECTORY_SEPARATOR );
define( 'SECUPRESS_CLASSES_PATH'          , SECUPRESS_INC_PATH . 'classes' . DIRECTORY_SEPARATOR );
define( 'SECUPRESS_ADMIN_SETTINGS_MODULES', SECUPRESS_ADMIN_PATH . 'modules' . DIRECTORY_SEPARATOR );
define( 'SECUPRESS_PLUGIN_URL'            , plugin_dir_url( SECUPRESS_FILE ) );
define( 'SECUPRESS_FREE_URL'              , SECUPRESS_PLUGIN_URL . 'free/' );
define( 'SECUPRESS_FRONT_URL'             , SECUPRESS_FREE_URL . 'front/' );
define( 'SECUPRESS_ADMIN_URL'             , SECUPRESS_FREE_URL . 'admin/' );
define( 'SECUPRESS_ASSETS_URL'            , SECUPRESS_PLUGIN_URL . 'assets/' );
define( 'SECUPRESS_ADMIN_CSS_URL'         , SECUPRESS_ASSETS_URL . 'admin/css/' );
define( 'SECUPRESS_ADMIN_JS_URL'          , SECUPRESS_ASSETS_URL . 'admin/js/' );
define( 'SECUPRESS_ADMIN_IMAGES_URL'      , SECUPRESS_ASSETS_URL . 'admin/images/' );
define( 'SECUPRESS_PHP_MIN'               , '5.6' );
define( 'SECUPRESS_WP_MIN'                , '4.9' );
define( 'SECUPRESS_INT_MAX'               , PHP_INT_MAX - 20 );

if ( defined( 'SECUPRESS_API_EMAIL' ) && defined( 'SECUPRESS_API_KEY' ) && ! defined( 'SECUPRESS_HIDE_API_KEY' ) ) {
	define( 'SECUPRESS_HIDE_API_KEY', true );
}

/** --------------------------------------------------------------------------------------------- */
/** INIT ======================================================================================== */
/** --------------------------------------------------------------------------------------------- */

/**
 * Requires hotfixes first because it's hot.
 */ 
require_once( SECUPRESS_INC_PATH . 'functions/hotfixes.php' );

/**
 * All the stuff for the plugin activation and deactivation.
 */
require_once( SECUPRESS_INC_PATH . 'activation.php' );


add_action( 'plugins_loaded', 'secupress_init', 0 );
/**
 * Tell WP what to do when the plugin is loaded.
 *
 * @since 1.0
 */
function secupress_init() {
	// Nothing to do if autosave.
	if ( defined( 'DOING_AUTOSAVE' ) ) {
		return;
	}

	// Load translations.
	secupress_load_plugin_textdomain_translations();

	// Functions.
	secupress_load_functions();

	// Hooks.
	require_once( SECUPRESS_INC_PATH . 'network-options-autoload.php' );
	require_once( SECUPRESS_INC_PATH . 'common.php' );
	require_once( SECUPRESS_INC_PATH . 'admin-bar.php' );

	// Last constants.
	if ( secupress_is_pro() ) {
		define( 'SECUPRESS_PLUGIN_NAME', esc_html( secupress_get_option( 'wl_plugin_name', 'SecuPress' ) ) );
	} else {
		define( 'SECUPRESS_PLUGIN_NAME', 'SecuPress' );
	}

	define( 'SECUPRESS_PLUGIN_SLUG', sanitize_title( SECUPRESS_PLUGIN_NAME ) );

	// Cleanup leftovers periodically.
	SecuPress_Cleanup_Leftovers::get_instance();

	if ( is_admin() ) {
		if ( is_multisite() ) {
			// Hooks for multisite.
			require_once( SECUPRESS_ADMIN_PATH . 'multisite/centralize-blog-options.php' );
			require_once( SECUPRESS_ADMIN_PATH . 'multisite/settings.php' );
		}

		// Notices.
		SecuPress_Admin_Notices::get_instance();

		// Pro upgrade.
		SecuPress_Admin_Pro_Upgrade::get_instance();

		// Hooks.
		require_once( SECUPRESS_ADMIN_PATH . 'options.php' );
		require_once( SECUPRESS_ADMIN_PATH . 'settings.php' );
		require_once( SECUPRESS_ADMIN_PATH . 'admin.php' );
		require_once( SECUPRESS_ADMIN_PATH . 'ajax-post-callbacks.php' );
		require_once( SECUPRESS_ADMIN_PATH . 'notices.php' );
	}

	/**
	 * Fires when SecuPress is correctly loaded.
	 *
	 * @since 1.0
	 */
	do_action( 'secupress.loaded' );
	// Load the upgrader after the load of our plugins, SecuPress is still considered "loaded" even without this file since it's not usefull for security
	if ( is_admin() ) {
		require_once( SECUPRESS_ADMIN_PATH . 'upgrader.php' );
		secupress_upgrader();
	}
}


add_action( 'secupress.loaded', 'secupress_load_plugins' );
/**
 * Load modules.
 *
 * @since 1.0
 */
function secupress_load_plugins() {
	// All modules.
	$modules = secupress_get_modules();

	if ( $modules ) {
		foreach ( $modules as $key => $module ) {
			if ( secupress_has_pro() ) {
				$file = SECUPRESS_PRO_MODULES_PATH . sanitize_key( $key ) . '/tools.php';

				if ( file_exists( $file ) ) {
					require_once( $file );
				}
			}

			$file = SECUPRESS_MODULES_PATH . sanitize_key( $key ) . '/tools.php';

			if ( file_exists( $file ) ) {
				require_once( $file );
			}

			if ( ! is_admin() ) {
				continue;
			}

			if ( secupress_has_pro() ) {
				$file = SECUPRESS_PRO_MODULES_PATH . sanitize_key( $key ) . '/callbacks.php';

				if ( file_exists( $file ) ) {
					require_once( $file );
				}
			}

			$file = SECUPRESS_MODULES_PATH . sanitize_key( $key ) . '/callbacks.php';

			if ( file_exists( $file ) ) {
				require_once( $file );
			}
		}
	}

	// OK, this one is a bit lonely.
	require_once( SECUPRESS_MODULES_PATH . 'discloses/tools.php' );

	// Active sub-modules.
	$modules = secupress_get_active_submodules();

	if ( $modules ) {
		foreach ( $modules as $module => $plugins ) {
			foreach ( $plugins as $plugin ) {
				if ( secupress_is_pro() || ! secupress_submodule_is_pro( $module, $plugin ) ) {
					$file_path = secupress_get_submodule_file_path( $module, $plugin );
					if ( is_array( $file_path ) ) {
						foreach ( $file_path as $path ) {
							if ( file_exists( $path ) ) {
								require_once( $path );
							}
						}
					} else {
						if ( file_exists( $file_path ) ) {
							require_once( $file_path );
						}
					}
				}
			}
		}
	}

	$has_activation = false;

	if ( is_admin() && secupress_get_site_transient( 'secupress_activation' ) ) {
		$has_activation = true;

		secupress_delete_site_transient( 'secupress_activation' );

		/**
		 * Fires once SecuPress is activated, after the SecuPress's plugins are loaded.
		 *
		 * @since 1.0
		 * @see `secupress_activation()`
		 */
		do_action( 'secupress.plugins.activation' );
	}

	if ( secupress_is_pro() && is_admin() && secupress_get_site_transient( 'secupress_pro_activation' ) ) {
		$has_activation = true;

		secupress_delete_site_transient( 'secupress_pro_activation' );

		/**
		 * Fires once SecuPress Pro is activated, after the SecuPress's plugins are loaded.
		 *
		 * @since 1.1.4
		 * @see `secupress_pro_activation()`
		 */
		do_action( 'secupress.pro.plugins.activation' );
	}

	if ( $has_activation ) {
		/**
		 * Fires once SecuPress or SecuPress Pro is activated, after the SecuPress's plugins are loaded.
		 *
		 * @since 1.1.4
		 */
		do_action( 'secupress.all.plugins.activation' );
	}
	// Autovalidate license if constants are set.
	if ( ! secupress_has_pro_license() && defined( 'SECUPRESS_API_EMAIL' ) && defined( 'SECUPRESS_API_KEY' ) ) {
		if ( ! function_exists( 'secupress_global_settings_activate_pro_license' ) ) {
			include( SECUPRESS_MODULES_PATH . 'welcome/callbacks.php' );
		}
		$args                   = array();
		$options                = get_site_option( SECUPRESS_SETTINGS_SLUG );
		$args['install_time']   = isset( $options['install_time'] ) && -1 !== (int) $options['install_time'] ? $options['install_time'] : time();
		$args['consumer_email'] = SECUPRESS_API_EMAIL;
		$args['consumer_key']   = SECUPRESS_API_KEY;
		secupress_global_settings_activate_pro_license( $args );
	}

	/**
	 * Fires once all our plugins/submodules has been loaded.
	 *
	 * @since 1.0
	 */
	do_action( 'secupress.plugins.loaded' );
}

/**
 * Check is the $locale if a FR one
 *
 * @return (bool) True if $locale is fr_FR (france) or fr_BE (belgium) or fr_CA (canada)
 * @author Julio Potier
 * @since 2.2
 * @param (string) $locale The locale to be tested
 **/
function secupress_locale_is_FR( $locale ) {
	return 'fr_FR' === $locale || 'fr_CA' === $locale || 'fr_BE' === $locale;
}

/**
 * Include files that contain our functions.
 *
 * @since 1.2.3
 * @since 1.2.5 Includes requirement checks.
 * @author Grégory Viguier
 */
function secupress_load_functions() {
	global $is_iis7, $wp_version;
	static $done = false;

	if ( $done ) {
		return;
	}
	$done = true;

	/**
	 * Check requirements.
	 */
	// Check php version.
	if ( version_compare( phpversion(), SECUPRESS_PHP_MIN ) < 0 ) {
		$plugin = plugin_basename( SECUPRESS_FILE );

		if ( current_filter() !== 'activate_' . $plugin ) {
			require_once( ABSPATH . 'wp-admin/includes/plugin.php' );
			deactivate_plugins( SECUPRESS_FILE, true );
		}

		secupress_load_plugin_textdomain_translations();

		wp_die( sprintf( __( '<strong>%1$s</strong> requires PHP %2$s minimum, your website is actually running version %3$s.', 'secupress' ), 'SecuPress', '<code>' . SECUPRESS_PHP_MIN . '</code>', '<code>' . phpversion() . '</code>' ) );
	}

	// Check WordPress version.
	if ( version_compare( $wp_version, SECUPRESS_WP_MIN ) < 0 ) {
		$plugin = plugin_basename( SECUPRESS_FILE );

		if ( current_filter() !== 'activate_' . $plugin ) {
			require_once( ABSPATH . 'wp-admin/includes/plugin.php' );
			deactivate_plugins( SECUPRESS_FILE, true );
		}

		secupress_load_plugin_textdomain_translations();

		wp_die( sprintf( __( '<strong>%1$s</strong> requires WordPress %2$s minimum, your website is actually running version %3$s.', 'secupress' ), 'SecuPress', '<code>' . SECUPRESS_WP_MIN . '</code>', '<code>' . $wp_version . '</code>' ) );
	}

	/**
	 * Require our functions.
	 */
	require_once( SECUPRESS_INC_PATH . 'functions/compat.php' );
	require_once( SECUPRESS_INC_PATH . 'functions/deprecated.php' );
	require_once( SECUPRESS_INC_PATH . 'functions/common.php' );
	require_once( SECUPRESS_INC_PATH . 'functions/3rdparty.php' );
	require_once( SECUPRESS_INC_PATH . 'functions/formatting.php' );
	require_once( SECUPRESS_INC_PATH . 'functions/options.php' );
	require_once( SECUPRESS_INC_PATH . 'functions/modules.php' );
	require_once( SECUPRESS_INC_PATH . 'functions/db.php' );
	require_once( SECUPRESS_INC_PATH . 'functions/ip.php' );
	require_once( SECUPRESS_INC_PATH . 'functions/files.php' );
	require_once( SECUPRESS_INC_PATH . 'functions/htaccess.php' );

	if ( $is_iis7 ) {
		require_once( SECUPRESS_INC_PATH . 'functions/iis7.php' );
	}

	// The Singleton class.
	secupress_require_class( 'Singleton' );

	// Cleanup leftovers periodically.
	secupress_require_class( 'Cleanup_Leftovers' );
	// The Scanner results class.
	secupress_require_class( 'Scanner_Results' );

	// Admin side but need when running cron.
	require_once( SECUPRESS_ADMIN_PATH . 'functions/settings.php' );
	require_once( SECUPRESS_ADMIN_PATH . 'functions/scan-fix.php' );

	if ( ! is_admin() ) {
		return;
	}

	if ( is_multisite() ) {
		// Functions for multisite.
		require_once( SECUPRESS_ADMIN_PATH . 'multisite/options.php' );
	}

	// The notices class.
	secupress_require_class( 'Admin', 'Notices' );

	// The Pro upgrade class.
	secupress_require_class( 'Admin', 'Offer_Migration' );
	secupress_require_class( 'Admin', 'Pro_Upgrade' );
	secupress_require_class( 'Admin', 'Pointers' );

	// Functions for the admin side.
	require_once( SECUPRESS_ADMIN_PATH . 'functions/admin.php' );
	require_once( SECUPRESS_ADMIN_PATH . 'functions/options.php' );
	require_once( SECUPRESS_ADMIN_PATH . 'functions/ajax-post.php' );
	require_once( SECUPRESS_ADMIN_PATH . 'functions/modules.php' );
	require_once( SECUPRESS_ADMIN_PATH . 'functions/notices.php' );
}


/** --------------------------------------------------------------------------------------------- */
/** I18N ======================================================================================== */
/** --------------------------------------------------------------------------------------------- */

add_filter( 'load_textdomain_mofile', 'secupress_load_own_i18n', 10, 2 );
/**
 * Load our own i18n to prevent too long strings or spelling errors from voluteers at translate.wp.org, sorry guys.
 *
 * @since 2.2 Usage of secupress_locale_is_FR()
 * @since 2.0.3 fr_BE & fr_CA = fr_FR
 * @since 2.0
 * @author Julio Potier
 *
 * @hook load_textdomain_mofile
 * @param (string)  $mofile The file to be loaded
 * @param (string)  $domain The desired textdomain
 * @return (string) $mofile
 **/
function secupress_load_own_i18n( $mofile, $domain ) {
	if ( 'secupress' === $domain && false !== strpos( $mofile, WP_LANG_DIR . '/plugins/' ) ) {
		$locale = apply_filters( 'plugin_locale', determine_locale(), $domain );
		if ( ! function_exists( 'determine_locale' ) ) { // WP 5.0.
			$determined_locale     = get_locale();
			if ( is_admin() ) {
				$determined_locale = get_user_locale();
			}
		} else {
			$determined_locale = determine_locale();
		}
		$locale = apply_filters( 'plugin_locale', $determined_locale, $domain );
		if ( secupress_locale_is_FR( $locale ) ) {
			$locale = 'fr_FR';
		}
		$mofile = WP_PLUGIN_DIR . '/' . dirname( plugin_basename( SECUPRESS_FILE ) ) . '/languages/' . $domain . '-' . $locale . '.mo';
	}
	return $mofile;
}
/**
 * Translations for the plugin textdomain.
 *
 * @since 1.0
 */
function secupress_load_plugin_textdomain_translations() {
	static $done = false;

	if ( $done ) {
		return;
	}
	$done = true;

	load_plugin_textdomain( 'secupress', false, dirname( plugin_basename( SECUPRESS_FILE ) ) . '/languages' );
	/**
	 * Fires right after the plugin text domain is loaded.
	 *
	 * @since 1.0
	 */
	do_action( 'secupress.plugin_textdomain_loaded' );

	// Make sure Poedit keeps our plugin headers.
	/** Translators: Plugin Name of the plugin/theme */
	__( 'SecuPress Free — WordPress Security', 'secupress' );
	/** Translators: Description of the plugin/theme */
	__( 'Protect your WordPress with SecuPress, analyze and ensure the safety of your website daily.', 'secupress' );
}
