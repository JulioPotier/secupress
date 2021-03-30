<?php
/**
 * Module Name: No Theme Installation
 * Description: Disabled the theme installation from repository
 * Main Module: plugins_themes
 * Author: SecuPress
 * Version: 1.1
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );

if ( is_admin() ) {

	add_action( 'admin_print_styles-themes.php', 'secupress_no_theme_add_css' );
	/**
	 * Hide the "Add new plugin" link next to the page title.
	 *
	 * @since 1.0
	 */
	function secupress_no_theme_add_css() {
		?><style>div.theme.add-new-theme,h1 a.page-title-action,h2 a.add-new-h2{display:none}</style><?php
	}


	add_action( 'load-theme-install.php', 'secupress_no_theme_install_page' );
	/**
	 * Forbid access to the theme installation page.
	 *
	 * @since 1.0
	 */
	function secupress_no_theme_install_page() {
		secupress_die( __( 'You do not have sufficient permissions to install themes on this site.', 'secupress' ), '', array( 'force_die' => true ) );
	}


	add_action( 'check_admin_referer', 'secupress_avoid_switch_theme' );
	/**
	 * Forbid theme installation.
	 *
	 * @since 1.0
	 *
	 * @param (string) $action The nonce action.
	 */
	function secupress_avoid_switch_theme( $action ) {
		if ( 'theme-upload' === $action || strpos( $action, 'install-theme_' ) === 0 ) {
			secupress_die( __( 'You do not have sufficient permissions to install themes on this site.', 'secupress' ), '', array( 'force_die' => true ) );
		}
	}
}

if ( isset( $_FILES['themezip'] ) ) {
	secupress_die( __( 'You do not have sufficient permissions to install themes on this site.', 'secupress' ), '', array( 'force_die' => true ) );
}
