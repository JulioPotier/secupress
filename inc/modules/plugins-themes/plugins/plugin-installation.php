<?php
/**
 * Module Name: No Plugin Installation
 * Description: Disabled the plugin installation from repository
 * Main Module: plugins_themes
 * Author: SecuPress
 * Version: 1.1
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );

if ( is_admin() ) {

	add_action( 'admin_print_styles-plugins.php', 'secupress_no_plugin_install_tab_css' );
	/**
	 * Hide the "Add new plugin" link next to the page title.
	 *
	 * @since 1.0
	 */
	function secupress_no_plugin_install_tab_css() {
		?><style>h1 a.page-title-action,h2 a.add-new-h2{display:none}</style><?php
	}


	add_action( 'load-plugin-install.php', 'secupress_no_plugin_install_page_redirect' );
	/**
	 * Forbid access to the plugin installation page.
	 *
	 * @since 1.0
	 */
	function secupress_no_plugin_install_page_redirect() {
		if ( ! isset( $_GET['tab'] ) || 'plugin-information' !== $_GET['tab'] ) {
			secupress_die( __( 'You do not have sufficient permissions to install plugins on this site.', 'secupress' ), '', array( 'force_die' => true ) );
		}
	}


	add_action( 'check_admin_referer', 'secupress_avoid_install_plugin' );
	/**
	 * Forbid plugin installation.
	 *
	 * @since 1.0
	 *
	 * @param (string) $action The nonce action.
	 */
	function secupress_avoid_install_plugin( $action ) {
		if ( 'plugin-upload' === $action || strpos( $action, 'install-plugin_' ) === 0 ) {
			secupress_die( __( 'You do not have sufficient permissions to install plugins on this site.', 'secupress' ), '', array( 'force_die' => true ) );
		}
	}


	add_action( 'admin_menu', 'secupress_remove_new_plugins_link', 100 );
	/**
	 * Remove the "Add new plugin" item from the admin menu.
	 *
	 * @since 1.0
	 */
	function secupress_remove_new_plugins_link() {
		global $submenu;
		unset( $submenu['plugins.php'][10] );
	}
}

if ( isset( $_FILES['pluginzip'] ) ) {
	secupress_die( __( 'You do not have sufficient permissions to install plugins on this site.', 'secupress' ), '', array( 'force_die' => true ) );
}
