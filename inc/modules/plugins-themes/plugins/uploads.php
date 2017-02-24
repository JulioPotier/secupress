<?php
/**
 * Module Name: No Plugins and Themes Upload
 * Description: Disabled plugins and themes upload.
 * Main Module: uploads
 * Author: SecuPress
 * Version: 1.1
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

if ( isset( $_FILES['pluginzip'] ) ) {
	secupress_die( __( 'You do not have sufficient permissions to install plugins on this site.', 'secupress' ), '', array( 'force_die' => true ) );
}

if ( isset( $_FILES['themezip'] ) ) {
	secupress_die( __( 'You do not have sufficient permissions to install themes on this site.', 'secupress' ), '', array( 'force_die' => true ) );
}
