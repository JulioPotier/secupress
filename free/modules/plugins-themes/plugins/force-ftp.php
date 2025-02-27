<?php
/**
 * Module Name: Force FTP for Plugins and Themes Upload
 * Description: Restrict plugins and themes upload by FTP.
 * Main Module: plugins_themes
 * Author: Julio Potier
 * Version: 2.2
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );

if ( ! is_admin() ) {
	return;
}

add_filter( 'filesystem_method', 
    function( $method ) {
        return secupress_get_ftp_fs_method() ?: $method;
    }
);