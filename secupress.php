<?php
/**
 * Plugin Name: WordPress Security by SecuPress (Free)
 * Plugin URI: http://secupress.me
 * Description: WordPress Security by SecuPress, the best and simpler way to protect your websites.
 * Author: SecuPress, WP Media
 * Version: 1.0-beta2
 * Author URI: http://wp-media.me
 * Network: true
 * License: GPLv2
 * License URI: http://secupress.me/gpl.txt
 *
 * Text Domain: secupress
 * Domain Path: /languages/
 *
 * Copyright 2012-2015 SecuPress
 */

defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


/*------------------------------------------------------------------------------------------------*/
/* DEFINES ====================================================================================== */
/*------------------------------------------------------------------------------------------------*/

define( 'SECUPRESS_VERSION'               , '1.0-beta2' );
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
define( 'SECUPRESS_RATE_URL'              , 'https://wordpress.org/support/view/plugin-reviews/secupress?filter=5#topic' );
define( 'SECUPRESS_REPO_URL'              , 'https://wordpress.org/plugins/secupress/' );
define( 'SECUPRESS_WEB_MAIN'              , 'http://secupress.me/' );
define( 'SECUPRESS_WEB_DEMO'              , 'http://secupress.me/' );
define( 'SECUPRESS_BOT_URL'               , 'http://bot.secupress.me' );
define( 'SECUPRESS_WEB_VALID'             , 'http://support.secupress.me/' );
define( 'SECUPRESS_FILE'                  , __FILE__ );
define( 'SECUPRESS_PLUGIN_FILE'           , 'secupress-free/secupress.php' );
define( 'SECUPRESS_PATH'                  , realpath( plugin_dir_path( SECUPRESS_FILE ) ) . '/' );
define( 'SECUPRESS_INC_PATH'              , realpath( SECUPRESS_PATH . 'inc/' ) . '/' );
define( 'SECUPRESS_MODULES_PATH'          , realpath( SECUPRESS_INC_PATH . 'modules/' ) . '/' );
define( 'SECUPRESS_ADMIN_PATH'            , realpath( SECUPRESS_INC_PATH . 'admin/' ) . '/' );
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
define( 'SECUPRESS_PHP_MIN'               , '5.3' );
define( 'SECUPRESS_WP_MIN'                , '3.7' );

if ( ! defined( 'SECUPRESS_LASTVERSION' ) ) {
	define( 'SECUPRESS_LASTVERSION', '0' );
}


/*------------------------------------------------------------------------------------------------*/
/* INIT ========================================================================================= */
/*------------------------------------------------------------------------------------------------*/

/**
 * All the stuff for the plugin activation and deactivation.
 */
if ( is_admin() ) {
	require( SECUPRESS_ADMIN_PATH . 'activation.php' );
}


add_action( 'plugins_loaded', 'secupress_init', 0 );
/**
 * Tell WP what to do when the plugin is loaded.
 *
 * @since 1.0
 */
function secupress_init() {
	global $wp_version, $is_iis7;

	// Nothing to do if autosave.
	if ( defined( 'DOING_AUTOSAVE' ) ) {
		return;
	}

	// Load translations.
	secupress_load_plugin_textdomain_translations();

	// Check php version.
	if ( version_compare( phpversion(), SECUPRESS_PHP_MIN ) < 0 ) {
		require_once( ABSPATH . 'wp-admin/includes/plugin.php' );
		deactivate_plugins( plugin_basename( SECUPRESS_FILE ) );
		wp_die( sprintf( __( '<strong>SecuPress</strong> requires PHP %s minimum, your website is actually running version %s.', 'secupress' ), '<code>' . SECUPRESS_PHP_MIN . '</code>', '<code>' . phpversion() . '</code>' ) );
	}

	// Check WordPress version.
	if ( version_compare( $wp_version, SECUPRESS_WP_MIN ) < 0 ) {
		require_once( ABSPATH . 'wp-admin/includes/plugin.php' );
		deactivate_plugins( plugin_basename( SECUPRESS_FILE ) );
		wp_die( sprintf( __( '<strong>SecuPress</strong> requires WordPress %s minimum, your website is actually running version %s.', 'secupress' ), '<code>' . SECUPRESS_WP_MIN . '</code>', '<code>' . $wp_version . '</code>' ) );
	}

	// Functions.
	require( SECUPRESS_INC_PATH . 'functions/compat.php' );
	require( SECUPRESS_INC_PATH . 'functions/common.php' );
	require( SECUPRESS_INC_PATH . 'functions/formatting.php' );
	require( SECUPRESS_INC_PATH . 'functions/options.php' );
	require( SECUPRESS_INC_PATH . 'functions/modules.php' );
	require( SECUPRESS_INC_PATH . 'functions/ip.php' );
	require( SECUPRESS_INC_PATH . 'functions/files.php' );
	require( SECUPRESS_INC_PATH . 'functions/htaccess.php' );
	if ( $is_iis7 ) {
		require( SECUPRESS_INC_PATH . 'functions/iis7.php' );
	}

	// Hooks.
	require( SECUPRESS_INC_PATH . 'network-options-autoload.php' );
	require( SECUPRESS_INC_PATH . 'common.php' );
	require( SECUPRESS_INC_PATH . 'admin-bar.php' );
	require( SECUPRESS_INC_PATH . 'cron.php' );

	// Last constants.
	define( 'SECUPRESS_PLUGIN_NAME', esc_html( secupress_get_option( 'wl_plugin_name', 'SecuPress' ) ) );
	define( 'SECUPRESS_PLUGIN_SLUG', sanitize_title( SECUPRESS_PLUGIN_NAME ) );

	// The Singleton class.
	secupress_require_class( 'Singleton' );

	if ( is_admin() ) {
		if ( is_multisite() ) {
			// Hooks and functions for multisite.
			require( SECUPRESS_ADMIN_PATH . 'multisite/centralize-blog-options.php' );
			require( SECUPRESS_ADMIN_PATH . 'multisite/options.php' );
			require( SECUPRESS_ADMIN_PATH . 'multisite/settings.php' );
		}

		// The notices class.
		secupress_require_class( 'Admin', 'Notices' );
		SecuPress_Admin_Notices::get_instance();

		// Functions.
		require( SECUPRESS_ADMIN_PATH . 'functions/admin.php' );
		require( SECUPRESS_ADMIN_PATH . 'functions/options.php' );
		require( SECUPRESS_ADMIN_PATH . 'functions/settings.php' );
		require( SECUPRESS_ADMIN_PATH . 'functions/ajax-post.php' );
		require( SECUPRESS_ADMIN_PATH . 'functions/scan-fix.php' );
		require( SECUPRESS_ADMIN_PATH . 'functions/modules.php' );
		require( SECUPRESS_ADMIN_PATH . 'functions/notices.php' );
		require( SECUPRESS_ADMIN_PATH . 'functions/db.php' );
		require( SECUPRESS_ADMIN_PATH . 'functions/backup.php' );

		// Temporary Updates when not on repo yet.
		require( SECUPRESS_ADMIN_PATH . 'functions/wp-updates-plugin.php' );
		new WPUpdatesPluginUpdater_spfree( 'http://wp-updates.com/api/2/plugin', plugin_basename( __FILE__ ) );

		// Hooks.
		require( SECUPRESS_ADMIN_PATH . 'options.php' );
		require( SECUPRESS_ADMIN_PATH . 'settings.php' );
		require( SECUPRESS_ADMIN_PATH . 'admin.php' );
		require( SECUPRESS_ADMIN_PATH . 'ajax-post-callbacks.php' );
		require( SECUPRESS_ADMIN_PATH . 'notices.php' );
		require( SECUPRESS_ADMIN_PATH . 'user-profile.php' );
		require( SECUPRESS_ADMIN_PATH . 'upgrader.php' );
	}

	/**
	 * Fires when SecuPress is correctly loaded.
	 *
	 * @since 1.0
	 */
	do_action( 'secupress.loaded' );
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
			$file = SECUPRESS_MODULES_PATH . sanitize_key( $key ) . '/tools.php';

			if ( file_exists( $file ) ) {
				require_once( $file );
			}

			if ( ! is_admin() ) {
				continue;
			}

			if ( defined( 'SECUPRESS_PRO_MODULES_PATH' ) ) {
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
	$modules = get_site_option( SECUPRESS_ACTIVE_SUBMODULES );

	if ( $modules ) {
		foreach ( $modules as $module => $plugins ) {
			foreach ( $plugins as $plugin ) {
				$file_path = secupress_get_submodule_file_path( $module, $plugin );
				if ( $file_path ) {
					require_once( $file_path );
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
		 * @see `secupress_activation()`
		 */
		do_action( 'secupress.plugins.activation' );
	}

	/**
	 * Fires once all our plugins/submodules has been loaded.
	 *
	 * @since 1.0
	 */
	do_action( 'secupress.plugins.loaded' );
}


add_action( 'secupress.loaded', 'secupress_been_first' );
/**
 * Make SecuPress the first plugin loaded.
 *
 * @since 1.0
 */
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
 * Translations for the plugin textdomain.
 *
 * @since 1.0
 */
function secupress_load_plugin_textdomain_translations() {
	static $done = false;

	if ( ! $done ) {
		$done = true;
		load_plugin_textdomain( 'secupress', false, dirname( plugin_basename( __FILE__ ) ) . '/languages' );
		/**
		 * Fires right after the plugin text domain is loaded.
		 *
		 * @since 1.0
		 */
		do_action( 'secupress.plugin_textdomain_loaded' );
	}
}


add_action( 'init', 'secupress_load_default_textdomain_translations' );
/**
 * Translations for the default textdomain must be loaded on init, not before.
 *
 * @since 1.0
 */
function secupress_load_default_textdomain_translations() {
	if ( ! defined( 'DOING_AUTOSAVE' ) ) {
		load_plugin_textdomain( 'default', false, dirname( plugin_basename( __FILE__ ) ) . '/languages' );
	}
}
