<?php
/**
 * Module Name: No Plugins and Themes Upload
 * Description: Disabled plugins and themes upload.
 * Main Module: plugins&themes
 * Author: Julio Potier
 * Version: 1.2
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );

if ( ! is_admin() ) {
	return;
}

if ( isset( $_FILES['pluginzip'] ) ) {
	secupress_die( __( 'You do not have sufficient permissions to install plugins on this site.', 'secupress' ), '', array( 'force_die' => true ) );
}

if ( isset( $_FILES['themezip'] ) ) {
	secupress_die( __( 'You do not have sufficient permissions to install themes on this site.', 'secupress' ), '', array( 'force_die' => true ) );
}

add_action( 'admin_print_styles-plugin-install.php', function () {
	?><style>a.upload-view-toggle{display:none}</style><?php
});
