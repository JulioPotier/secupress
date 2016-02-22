<?php
/**
 * Plugin Name: WordPress Security by SecuPress
 * Plugin URI: http://secupress.me
 * Description: WordPress Security by SecuPress, the best and simpler way to protect your websites.
 * Author: SecuPress, WP Media
 * Version: 1.0-alpha
 * Author URI: http://secupress.me
 * Network: true
 * License: GPLv2
 * License URI: http://secupress.me/gpl.txt

 * Text Domain: secupress
 * Domain Path: /languages/

 * Copyright 2012-2015 SecuPress
 */

defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


/*------------------------------------------------------------------------------------------------*/
/* DEFINES ====================================================================================== */
/*------------------------------------------------------------------------------------------------*/

define( 'SECUPRESS_VERSION'               , '1.0-alpha' );
define( 'SECUPRESS_PRIVATE_KEY'           , false );
define( 'SECUPRESS_ACTIVE_SUBMODULES'     , 'secupress_active_submodules' );
define( 'SECUPRESS_SETTINGS_SLUG'         , 'secupress_settings' );
define( 'SECUPRESS_SCAN_SLUG'             , 'secupress_scanners' );
define( 'SECUPRESS_SCAN_TIMES'            , 'secupress_scanners_times' );
define( 'SECUPRESS_FIX_SLUG'              , 'secupress_fixes' );
define( 'SECUPRESS_SCAN_FIX_SITES_SLUG'   , 'secupress_fix_sites' );
define( 'SECUPRESS_WP_CORE_FILES_HASHES'  , 'secupress_wp_core_files_hashes' );
define( 'SECUPRESS_FULL_FILETREE'         , 'secupress_full_filetree' );
define( 'SECUPRESS_FIX_DISTS'             , 'secupress_fix_dists' );
define( 'SECUPRESS_BAN_IP'                , 'secupress_ban_ip' );
define( 'SECUPRESS_WEB_MAIN'              , 'http://secupress.me/' );
define( 'SECUPRESS_WEB_DEMO'              , home_url( '/' ) ); ////
define( 'SECUPRESS_BOT_URL'               , 'http://bot.secupress.me' );
define( 'SECUPRESS_WEB_VALID'             , 'http://support.secupress.me/' );
define( 'SECUPRESS_FILE'                  , __FILE__ );
define( 'SECUPRESS_PLUGIN_FILE'           , 'secupress/secupress.php' );
define( 'SECUPRESS_PATH'                  , realpath( plugin_dir_path( SECUPRESS_FILE ) ) . '/' );
define( 'SECUPRESS_INC_PATH'              , realpath( SECUPRESS_PATH . 'inc/' ) . '/' );
define( 'SECUPRESS_MODULES_PATH'          , realpath( SECUPRESS_INC_PATH . 'modules/' ) . '/' );
define( 'SECUPRESS_FRONT_PATH'            , realpath( SECUPRESS_INC_PATH . 'front/' ) . '/' );
define( 'SECUPRESS_ADMIN_PATH'            , realpath( SECUPRESS_INC_PATH . 'admin/' ) . '/' );
define( 'SECUPRESS_FUNCTIONS_PATH'        , realpath( SECUPRESS_INC_PATH . 'functions/' ) . '/' );
define( 'SECUPRESS_CLASSES_PATH'          , realpath( SECUPRESS_INC_PATH . 'classes/' ) . '/' );
define( 'SECUPRESS_ADMIN_SETTINGS_MODULES', SECUPRESS_ADMIN_PATH . 'modules/' );
define( 'SECUPRESS_PLUGIN_URL'            , plugin_dir_url( SECUPRESS_FILE ) );
define( 'SECUPRESS_INC_URL'               , SECUPRESS_PLUGIN_URL . 'inc/' );
define( 'SECUPRESS_FRONT_URL'             , SECUPRESS_INC_URL . 'front/' );
define( 'SECUPRESS_ADMIN_URL'             , SECUPRESS_INC_URL . 'admin/' );
define( 'SECUPRESS_ASSETS_URL'            , SECUPRESS_PLUGIN_URL . 'assets/' );
define( 'SECUPRESS_ADMIN_CSS_URL'         , SECUPRESS_ASSETS_URL . 'admin/css/' );
define( 'SECUPRESS_ADMIN_JS_URL'          , SECUPRESS_ASSETS_URL . 'admin/js/' );
define( 'SECUPRESS_ADMIN_IMAGES_URL'      , SECUPRESS_ASSETS_URL . 'admin/images/' );
define( 'SECUPRESS_FRONT_IMAGES_URL'      , SECUPRESS_ASSETS_URL . 'front/images/' );

if ( ! defined( 'SECUPRESS_LASTVERSION' ) ) {
	define( 'SECUPRESS_LASTVERSION', '0' ); ////
}


/*------------------------------------------------------------------------------------------------*/
/* INIT ========================================================================================= */
/*------------------------------------------------------------------------------------------------*/

/**
 * Tell WP what to do when plugin is loaded
 *
 * @since 1.0
 */
add_action( 'plugins_loaded', 'secupress_init', 0 );

function secupress_init() {
	// Nothing to do if autosave
	if ( defined( 'DOING_AUTOSAVE' ) ) {
		return;
	}

	// Load translations
	load_plugin_textdomain( 'secupress', false, dirname( plugin_basename( __FILE__ ) ) . '/languages/' );

	// Call defines, classes and functions
	require( SECUPRESS_FUNCTIONS_PATH . 'formatting.php' );
	require( SECUPRESS_FUNCTIONS_PATH . 'options.php' );
	require( SECUPRESS_INC_PATH . 'network-options-autoload.php' );

	// Last constants
	define( 'SECUPRESS_PLUGIN_NAME', secupress_get_option( 'wl_plugin_name', 'SecuPress' ) );
	define( 'SECUPRESS_PLUGIN_SLUG', sanitize_title( SECUPRESS_PLUGIN_NAME ) );

	// Call defines, classes and functions
	require( SECUPRESS_FUNCTIONS_PATH . 'files.php' );
	require( SECUPRESS_FUNCTIONS_PATH . 'admin.php' );
	require( SECUPRESS_FUNCTIONS_PATH . 'plugins.php' );
	require( SECUPRESS_FUNCTIONS_PATH . 'geoip.inc.php' );
	require( SECUPRESS_FUNCTIONS_PATH . 'db.php' );
	require( SECUPRESS_FRONT_PATH     . 'htaccess.php' );
	require( SECUPRESS_FRONT_PATH     . 'common.php' );
	require( SECUPRESS_INC_PATH       . 'admin-bar.php' );
	require( SECUPRESS_INC_PATH       . 'cron.php' );
	require( SECUPRESS_MODULES_PATH   . 'modules.php' );

	secupress_require_class( 'Singleton' );

	if ( is_admin() ) {

		if ( is_multisite() ) {
			require( SECUPRESS_ADMIN_PATH . 'multisite/active-plugins-themes-option.php' );
			require( SECUPRESS_ADMIN_PATH . 'multisite/options.php' );
			require( SECUPRESS_ADMIN_PATH . 'multisite/settings.php' );
		}

		secupress_require_class( 'Admin', 'Notices' );
		SecuPress_Admin_Notices::get_instance();

		require( SECUPRESS_FUNCTIONS_PATH . 'modules.php' );
		require( SECUPRESS_FUNCTIONS_PATH . 'backup.php' );
		require( SECUPRESS_ADMIN_PATH . 'options.php' );
		require( SECUPRESS_ADMIN_PATH . 'notices.php' );
		require( SECUPRESS_ADMIN_PATH . 'admin.php' );
		require( SECUPRESS_ADMIN_PATH . 'profiles.php' );
		require( SECUPRESS_ADMIN_PATH . 'upgrader.php' );

	}

	/**
	 * Fires when SecuPress is correctly loaded.
	 *
	 * @since 1.0
	 */
	do_action( 'secupress_loaded' );
}


/**
 * Load modules.
 *
 * @since 1.0
 */
add_action( 'secupress_loaded', 'secupress_load_plugins' );

function secupress_load_plugins() {
	$modules = secupress_get_modules();

	if ( $modules && is_admin() ) {
		foreach ( $modules as $key => $module ) {
			$file = SECUPRESS_MODULES_PATH . sanitize_key( $key ) . '/callbacks.php';
			if ( file_exists( $file ) ) {
				require_once( $file );
			}
		}
	}

	$modules = get_site_option( SECUPRESS_ACTIVE_SUBMODULES );

	if ( $modules ) {
		foreach ( $modules as $module => $plugins ) {
			foreach ( $plugins as $plugin ) {
				$file = SECUPRESS_MODULES_PATH . sanitize_key( $module ) . '/plugins/' . sanitize_key( $plugin ) . '.php';
				if ( file_exists( $file ) ) {
					require_once( $file );
				}
			}
		}
	}

	if ( is_admin() && secupress_get_site_transient( 'secupress_activation' ) ) {

		secupress_delete_site_transient( 'secupress_activation' );

		/**
		 * Fires once SecuPress is activated, after the SecuPress's plugins are loaded.
		 *
		 * @since 1.0
		 */
		do_action( 'secupress.plugins.activation' );
	}

	/**
	 * Fires once all our plugins/submodules has been loaded.
	 *
	 * @since 1.0
	 */
	do_action( 'secupress_plugins_loaded' );
}


/**
 * Make SecuPress is the first plugin loaded.
 *
 * @since 1.0
 */
add_action( 'secupress_loaded', 'secupress_been_first' );

function secupress_been_first() {
	if ( ! is_admin() ) {
		return;
	}

	$plugin_basename = plugin_basename( __FILE__ );

	if ( is_multisite() ) {
		$active_plugins = get_site_option( 'active_sitewide_plugins' );

		if ( isset( $active_plugins[ $plugin_basename ] ) && key( $active_plugins ) !== $plugin_basename ) {
			$this_plugin = array( $plugin_basename => $active_plugins[ $plugin_basename ] );
			unset( $active_plugins[ $plugin_basename ] );
			$active_plugins = array_merge( $this_plugin, $active_plugins );
			update_site_option( 'active_sitewide_plugins', $active_plugins );
		}
		return;
	}

	$active_plugins = get_option( 'active_plugins' );

	if ( isset( $active_plugins[ $plugin_basename ] ) && reset( $active_plugins ) !== $plugin_basename ) {
		unset( $active_plugins[ array_search( $plugin_basename, $active_plugins ) ] );
		array_unshift( $active_plugins, $plugin_basename );
		update_option( 'active_plugins', $active_plugins );
	}
}


/**
 * Translations for the default textdomain must be loaded on init, not before.
 *
 * @since 1.0
 */
add_action( 'init', 'secupress_load_default_textdomain_translations' );

function secupress_load_default_textdomain_translations() {
	if ( ! defined( 'DOING_AUTOSAVE' ) ) {
		load_plugin_textdomain( 'default', false, dirname( plugin_basename( __FILE__ ) ) . '/languages/' );
	}
}


/*------------------------------------------------------------------------------------------------*/
/* ACTIVATE/DEACTIVATE ========================================================================== */
/*------------------------------------------------------------------------------------------------*/

/**
 * Tell WP what to do when plugin is activated
 *
 * @since 1.1.0
 */
register_activation_hook( __FILE__, 'secupress_activation' );

function secupress_activation() {
	// Last constants
	define( 'SECUPRESS_PLUGIN_NAME', 'SecuPress' );
	define( 'SECUPRESS_PLUGIN_SLUG', sanitize_key( SECUPRESS_PLUGIN_NAME ) );

	/**
	 * Fires on SecuPress activation.
	 *
	 * @since 1.0
	 */
	do_action( 'secupress_activation' );

	/**
	 * As this activation hook appends before our plugins are loaded (and the page is reloaded right after that),
	 * this transient will trigger a custom activation hook in `secupress_load_plugins()`.
	 */
	set_site_transient( 'secupress_activation', 1 );
}


/**
 * Tell WP what to do when plugin is deactivated.
 *
 * @since 1.0
 */
register_deactivation_hook( __FILE__, 'secupress_deactivation' );

function secupress_deactivation() {
	// Pause the licence.
	wp_remote_get( SECUPRESS_WEB_MAIN . 'pause-licence.php' );

	// While the plugin is deactivated, some sites may activate or deactivate other plugins.
	if ( is_multisite() ) {
		delete_site_option( 'secupress_active_plugins' );
		delete_site_option( 'secupress_active_themes' );
	}

	/**
	 * Fires on SecuPress deactivation.
	 *
	 * @since 1.0
	 *
	 * @param (array) An empty array to mimic the `$args` parameter from `secupress_deactivate_submodule()`.
	 */
	do_action( 'secupress_deactivation', array() );
}
