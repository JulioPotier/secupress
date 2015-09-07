<?php
/*
Plugin Name: WordPress Security by SecuPress
Plugin URI: http://secupress.me
Description: WordPress Security by SecuPress, the best and simpler way to protect your websites.
Author: SecuPress, WP Media
Version: 1.0-alpha
Author URI: http://www.secupress.me

Text Domain: secupress
Domain Path: languages

Copyright 2012-2015 SecuPress
*/
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );
// SecuPress defines
define( 'SECUPRESS_VERSION'               , '1.0-alpha' );
define( 'SECUPRESS_PRIVATE_KEY'           , false );
define( 'SECUPRESS_ACTIVE_SUBMODULES'     , 'secupress_active_submodules' );
define( 'SECUPRESS_SETTINGS_SLUG'         , 'secupress_settings' );
define( 'SECUPRESS_SCAN_SLUG'             , 'secupress_scanners' );
define( 'SECUPRESS_SCAN_TIMES'            , 'secupress_scanners_times' );
define( 'SECUPRESS_BAN_IP'            	  , 'secupress_ban_ip' );
define( 'SECUPRESS_WEB_MAIN'              , 'http://secupress.me/' );
define( 'SECUPRESS_WEB_DEMO'              , home_url( '/' ) );
define( 'SECUPRESS_BOT_URL'               , 'http://bot.secupress.me' );
define( 'SECUPRESS_WEB_VALID'             , 'http://support.secupress.me/' );
define( 'SECUPRESS_FILE'                  , __FILE__ );
define( 'SECUPRESS_PLUGIN_FILE'           , 'secupress/secupress.php' );
define( 'SECUPRESS_PATH'                  , realpath( plugin_dir_path( SECUPRESS_FILE ) ) . '/' );
define( 'SECUPRESS_INC_PATH'              , realpath( SECUPRESS_PATH . 'inc/' ) . '/' );
define( 'SECUPRESS_MODULES_PATH'          , realpath( SECUPRESS_INC_PATH . 'modules/' ) . '/' );
define( 'SECUPRESS_FRONT_PATH'            , realpath( SECUPRESS_INC_PATH . 'front/' ) . '/' );
define( 'SECUPRESS_ADMIN_PATH'            , realpath( SECUPRESS_INC_PATH . 'admin/' ) . '/' );
define( 'SECUPRESS_FUNCTIONS_PATH'        , realpath( SECUPRESS_INC_PATH . 'functions' ) . '/' );
define( 'SECUPRESS_ADMIN_SETTINGS_MODULES', SECUPRESS_ADMIN_PATH . 'modules/' );
define( 'SECUPRESS_PLUGIN_URL'            , plugin_dir_url( SECUPRESS_FILE ) );
define( 'SECUPRESS_INC_URL'               , SECUPRESS_PLUGIN_URL . 'inc/' );
define( 'SECUPRESS_FRONT_URL'             , SECUPRESS_INC_URL . 'front/' );
define( 'SECUPRESS_ADMIN_URL'             , SECUPRESS_INC_URL . 'admin/' );
define( 'SECUPRESS_ADMIN_JS_URL'          , SECUPRESS_ADMIN_URL . 'js/' );
define( 'SECUPRESS_ADMIN_CSS_URL'         , SECUPRESS_ADMIN_URL . 'css/' );

if ( ! defined( 'SECUPRESS_LASTVERSION' ) ) {
    define( 'SECUPRESS_LASTVERSION', '0' );
}

/*
 * Tell WP what to do when plugin is loaded
 *
 * @since 1.0
 */
add_action( 'plugins_loaded', 'secupress_init', 0 );
function secupress_init()
{
    // Nothing to do if autosave
    if ( defined( 'DOING_AUTOSAVE' ) ) {
        return;
    }

    // Load translations
    load_plugin_textdomain( 'secupress', false, dirname( plugin_basename( __FILE__ ) ) . '/languages/' );

    // Call defines,  classes and functions
    require( SECUPRESS_FUNCTIONS_PATH 	. '/options.php' );
    // Last constants
    define( 'SECUPRESS_PLUGIN_NAME', get_secupress_option( 'wl_plugin_name', 'SecuPress' ) );
    define( 'SECUPRESS_PLUGIN_SLUG', sanitize_key( str_replace( ' ', '-', SECUPRESS_PLUGIN_NAME ) ) );
    // Call defines,  classes and functions
	require( SECUPRESS_FUNCTIONS_PATH	. '/files.php' );
    require( SECUPRESS_FUNCTIONS_PATH	. '/admin.php' );
    require( SECUPRESS_FUNCTIONS_PATH	. '/formatting.php' );
    require( SECUPRESS_FUNCTIONS_PATH	. '/plugins.php' );
    require( SECUPRESS_FUNCTIONS_PATH	. '/bots.php' );
    require( SECUPRESS_FRONT_PATH		. '/htaccess.php' );
    require( SECUPRESS_FRONT_PATH		. '/main-protections.php' );
    require( SECUPRESS_INC_PATH			. '/admin-bar.php' );
    require( SECUPRESS_INC_PATH 		. '/cron.php' );
	require( SECUPRESS_MODULES_PATH 	. '/modules.php' );

    if ( is_admin() ) {

        require( SECUPRESS_ADMIN_PATH . '/options.php' );
        require( SECUPRESS_ADMIN_PATH . '/notices.php' );
        require( SECUPRESS_ADMIN_PATH . '/admin.php' );
        require( SECUPRESS_ADMIN_PATH . '/profiles.php' );
        require( SECUPRESS_ADMIN_PATH . '/upgrader.php' );

    } 

	/**
	 * Fires when WP Rocket is correctly loaded
	 *
	 * @since 1.0
	*/
	do_action( 'secupress_loaded' );
}

register_uninstall_hook( SECUPRESS_FILE, 'secupress_uninstaller' );
function secupress_uninstaller()
{
	delete_option( 'secupress' );
}


/*
 * Tell WP what to do when plugin is deactivated
 *
 * @since 1.0
 */
register_deactivation_hook( __FILE__, 'secupress_deactivation' );
function secupress_deactivation()
{

	// Pause the licence.
	wp_remote_get( SECUPRESS_WEB_MAIN . '/pause-licence.php' );

}


/*
 * Tell WP what to do when plugin is activated
 *
 * @since 1.1.0
 */
register_activation_hook( __FILE__, 'secupress_activation' );
function secupress_activation()
{
	// Last constants
    define( 'SECUPRESS_PLUGIN_NAME', 'SecuPress' );
    define( 'SECUPRESS_PLUGIN_SLUG', sanitize_key( SECUPRESS_PLUGIN_NAME ) );

}

add_action( 'secupress_loaded', 'secupress_load_plugins' );
function secupress_load_plugins() {
	global $secupress_modules;
	foreach ( $secupress_modules as $key => $module ) {
		$file = SECUPRESS_MODULES_PATH . sanitize_key( $key ) . '/callbacks.php';
		if ( is_admin() && file_exists( $file ) ) {
			require( $file );
		}
	}
	$modules = get_site_option( SECUPRESS_ACTIVE_SUBMODULES );
	if ( $modules ) {
		foreach ( $modules as $module => $plugins ) {
			if ( secupress_is_module_active( $module ) ) {
				foreach ( $plugins as $plugin ) {
					$file = SECUPRESS_MODULES_PATH . sanitize_key( $module ) . '/plugins/' . sanitize_key( $plugin ) . '.php';
					if ( file_exists( $file ) ) {
						require( $file );
					}
				}
			}
		}
	}
}

add_action( 'secupress_loaded', 'secupress_been_first' );
function secupress_been_first() {
	$active_plugins = get_option( 'active_plugins' );
	$plugin_basename = plugin_basename( __FILE__ );
	if ( reset( $active_plugins ) != plugin_basename( __FILE__ ) ) {
		unset( $active_plugins[ array_search( $plugin_basename, $active_plugins ) ] );
		array_unshift( $active_plugins, $plugin_basename );
		update_option( 'active_plugins', $active_plugins );
	}
}