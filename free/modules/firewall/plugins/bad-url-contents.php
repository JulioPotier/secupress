<?php
/**
 * Module Name: Block Bad URL Contents
 * Description: Block requests containing bad keywords in URL.
 * Main Module: firewall
 * Author: SecuPress
 * Version: 1.1
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );

add_action( 'secupress.plugins.loaded', 'secupress_block_bad_url_contents', 5 );
/**
 * Filter the query string to block the request or not
 *
 * @since 1.0
 */
function secupress_block_bad_url_contents() {
	secupress_block_bad_content_but_what( 'url',     'QUERY_STRING', 'BUC' );
	secupress_block_bad_content_but_what( 'host',    'REMOTE_HOST',  'BHC' );
	secupress_block_bad_content_but_what( 'referer', 'HTTP_REFERER', 'BRC' );
}

add_filter( 'secupress.options.load_plugins_network_options', 'secupress_block_bad_url_contents_autoload_options' );
/**
 * Add the option(s) we use in this plugin to be autoloaded.
 *
 * @since 1.3
 * @author Grégory Viguier
 *
 * @param (array) $option_names An array of network option names.
 *
 * @return (array)
 */
function secupress_block_bad_url_contents_autoload_options( $option_names ) {
	$option_names[] = 'secupress_firewall_settings';
	return $option_names;
}

add_action( 'secupress.modules.activate_submodule_' . basename( __FILE__, '.php' ), 'secupress_bad_url_contents_de_activate_file' );
add_action( 'secupress.modules.deactivate_submodule_' . basename( __FILE__, '.php' ), 'secupress_bad_url_contents_de_activate_file' );
/**
 * On module de/activation, rescan.
 *
 * @since 2.0
 */
function secupress_bad_url_contents_de_activate_file() {
	secupress_scanit( 'SQLi' );
}
