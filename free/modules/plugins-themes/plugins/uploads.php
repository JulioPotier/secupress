<?php
/**
 * Module Name: No Plugins and Themes Upload
 * Description: Disabled plugins and themes upload.
 * Main Module: plugins&themes
 * Author: Julio Potier
 * Version: 2.3.19
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );

if ( ! is_admin() ) {
	return;
}

if ( isset( $_FILES['pluginzip'] ) ) {
	secupress_die( __( 'You do not have sufficient permissions to install plugins on this site.', 'secupress' ), '', [ 'force_die' => true, 'attack_type' => 'zipfile' ] );
}

if ( isset( $_FILES['themezip'] ) ) {
	secupress_die( __( 'You do not have sufficient permissions to install themes on this site.', 'secupress' ), '', [ 'force_die' => true, 'attack_type' => 'zipfile' ] );
}

add_action( 'admin_print_styles-plugin-install.php', 'secupress_no_plugins_themes_upload_button_css' );
add_action( 'admin_print_styles-theme-install.php', 'secupress_no_plugins_themes_upload_button_css' );
/**
 * Hide the "uplaod" button
 *
 * @since 2.3.19 .page-title-action class
 * @since 1.0
 * @author Julio Potier
 **/
function secupress_no_plugins_themes_upload_button_css() {
	?><style>
	a.upload-view-toggle,
	a.upload-view-toggle.page-title-action,
	button.upload-view-toggle,
	button.upload-view-toggle.page-title-action {
		display:none;
	}
</style><?php
}
