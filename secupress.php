<?php
/*
Plugin Name: SecuPress
Plugin URI: http://secupress.fr
Description: SecuPress Security, the best and simpler way to protect your websites.
Author: SecuPress, WP Media
Version: 1.0-alpha
Author URI: http://www.secupress.fr

Text Domain: secupress
Domain Path: languages

Copyright 2012-2015 SecuPress
*/
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );
// SecuPress defines
define( 'SECUPRESS_VERSION'             , '1.0-alpha' );
define( 'SECUPRESS_PRIVATE_KEY'         , false );
define( 'SECUPRESS_SLUG'                , 'secupress_settings' );
define( 'SECUPRESS_SCAN_SLUG'           , 'secupress_scanners' );
define( 'SECUPRESS_WEB_MAIN'            , 'http://support.secupress.fr/' );
define( 'SECUPRESS_BOT_URL'             , 'http://bot.secupress.fr' );
define( 'SECUPRESS_FILE'                , __FILE__ );
define( 'SECUPRESS_PLUGIN_FILE'         , 'secupress/secupress.php' );
define( 'SECUPRESS_PATH'                , realpath( plugin_dir_path( SECUPRESS_FILE ) ) . '/' );
define( 'SECUPRESS_INC_PATH'            , realpath( SECUPRESS_PATH . 'inc/' ) . '/' );
define( 'SECUPRESS_FRONT_PATH'          , realpath( SECUPRESS_INC_PATH . 'front/' ) . '/' );
define( 'SECUPRESS_ADMIN_PATH'          , realpath( SECUPRESS_INC_PATH . 'admin' ) . '/' );
define( 'SECUPRESS_FUNCTIONS_PATH'      , realpath( SECUPRESS_INC_PATH . 'functions' ) . '/' );
define( 'SECUPRESS_PLUGIN_URL'          , plugin_dir_url( SECUPRESS_FILE ) );
define( 'SECUPRESS_INC_URL'             , SECUPRESS_PLUGIN_URL . 'inc/' );
define( 'SECUPRESS_FRONT_URL'           , SECUPRESS_INC_URL . 'front/' );
define( 'SECUPRESS_ADMIN_URL'           , SECUPRESS_INC_URL . 'admin/' );
define( 'SECUPRESS_ADMIN_JS_URL'        , SECUPRESS_ADMIN_URL . 'js/' );
define( 'SECUPRESS_ADMIN_CSS_URL'       , SECUPRESS_ADMIN_URL . 'css/' );
if ( ! defined( 'SECUPRESS_LASTVERSION' ) ) {
    define( 'SECUPRESS_LASTVERSION', '0' );
}

require( SECUPRESS_INC_PATH	. '/compat.php' );


/*
 * Tell WP what to do when plugin is loaded
 *
 * @since 1.0
 */
add_action( 'plugins_loaded', 'secupress_init' );
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
    define( 'SECUPRESS_PLUGIN_SLUG', sanitize_key( SECUPRESS_PLUGIN_NAME ) );
    // Call defines,  classes and functions
// die(var_dump(time()));
	require( SECUPRESS_FUNCTIONS_PATH	. '/files.php' );
    require( SECUPRESS_FUNCTIONS_PATH	. '/admin.php' );
    require( SECUPRESS_FUNCTIONS_PATH	. '/formatting.php' );
    require( SECUPRESS_FUNCTIONS_PATH	. '/plugins.php' );
    require( SECUPRESS_FUNCTIONS_PATH	. '/bots.php' );
    require( SECUPRESS_INC_PATH			. '/deprecated.php' );
    require( SECUPRESS_FRONT_PATH		. '/htaccess.php' );
    require( SECUPRESS_FRONT_PATH		. '/plugin-compatibility.php' );
    require( SECUPRESS_INC_PATH			. '/admin-bar.php' );
    require( SECUPRESS_INC_PATH 		. '/cron.php' );

    
    if ( is_admin() ) {

        require( SECUPRESS_ADMIN_PATH . '/options.php' );
        require( SECUPRESS_ADMIN_PATH . '/notices.php' );
        require( SECUPRESS_ADMIN_PATH . '/admin.php' );
        require( SECUPRESS_ADMIN_PATH . '/plugin-compatibility.php' );

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
// add_action( 'plugins_loaded', create_function( '', '
// 	$filename  = "inc/";
// 	$filename .= is_admin() ? "backend-" : "frontend-";
// 	$filename .= defined( "DOING_AJAX" ) && DOING_AJAX ? "" : "no";
// 	$filename .= "ajax.inc.php";
// 	if( file_exists( plugin_dir_path( __FILE__ ) . $filename ) )
// 		include( plugin_dir_path( __FILE__ ) . $filename );
// 	$filename  = "inc/";
// 	$filename .= "bothend-";
// 	$filename .= defined( "DOING_AJAX" ) && DOING_AJAX ? "" : "no";
// 	$filename .= "ajax.inc.php";
// 	if( file_exists( plugin_dir_path( __FILE__ ) . $filename ) )
// 		include( plugin_dir_path( __FILE__ ) . $filename );
// ' )
// );