<?php
/**
 * Module Name: No Theme Actions
 * Description: Disabled the theme installation, switch and deletion actions
 * Main Module: plugins_themes
 * Author: SecuPress
 * Version: 2.2.6
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );

if ( is_admin() ) {

	add_action( 'admin_print_styles-themes.php', 'secupress_no_theme_add_css' );
	/**
	 * Hide the "Add new plugin" link next to the page title.
	 *
	 * @since 1.0
	 * @author Julio Potier
	 */
	function secupress_no_theme_add_css() {
		?><style>div.theme.add-new-theme,h1 a.page-title-action,h2 a.add-new-h2{display:none}</style><?php
	}


	add_action( 'load-theme-install.php', 'secupress_no_theme_install_page' );
	/**
	 * Forbid access to the theme installation page.
	 *
	 * @since 1.0
	 * @author Julio Potier
	 */
	function secupress_no_theme_install_page() {
		secupress_die( __( 'You do not have sufficient permissions to install themes on this site.', 'secupress' ), '', [ 'force_die' => true, 'attack_type' => 'themes' ] );
	}


	add_action( 'check_admin_referer', 'secupress_avoid_switch_theme' );
	/**
	 * Forbid theme installation.
	 *
	 * @since 1.0
	 * @author Julio Potier
	 *
	 * @param (string) $action The nonce action.
	 */
	function secupress_avoid_switch_theme( $action ) {
		if ( 'theme-upload' === $action || 0 === strpos( $action, 'install-theme_' ) ) {
			secupress_die( __( 'You do not have sufficient permissions to install themes on this site.', 'secupress' ), '', [ 'force_die' => true, 'attack_type' => 'themes' ] );
		}
	}

	add_action( 'check_admin_referer', 'secupress_avoid_delete_theme' );
	/**
	 * Prevent theme deletion.
	 *
	 * @since 1.0
	 * @author Julio Potier
	 *
	 * @param (string) $action The action.
	 */
	function secupress_avoid_delete_theme( $action ) {
		if ( 0 === strpos( $action, 'delete-theme_' ) ) {
			secupress_die( __( 'You do not have sufficient permissions to delete themes on this site.', 'secupress' ), '', [ 'force_die' => true, 'attack_type' => 'themes' ] );
		}
	}


	add_action( 'admin_footer-themes.php', 'secupress_add_css_to_delete_button', 100 );
	/**
	 * Print some CSS that will hide Deletion buttons.
	 *
	 * @since 1.0
	 * @author Julio Potier
	 */
	function secupress_add_css_to_delete_button() {
		?>
		<style>a.delete-theme{display:none!important;}</style>
		<?php
	}

	add_action( 'check_admin_referer', 'secupress_avoid_install_theme' );
	/**
	 * Prevent theme activation.
	 *
	 * @since 1.0
	 * @author Julio Potier
	 *
	 * @param (string) $action The action.
	 */
	function secupress_avoid_install_theme( $action ) {
		if ( 0 === strpos( $action, 'switch-theme_' ) ) {
			secupress_die( __( 'You do not have sufficient permissions to switch themes on this site.', 'secupress' ), '', [ 'force_die' => true, 'attack_type' => 'themes' ] );
		}
	}


	add_action( 'admin_footer-themes.php', 'secupress_add_css_to_active_button', 100 );
	/**
	 * Print some CSS that will hide Activation buttons.
	 *
	 * @since 1.0
	 * @author Julio Potier
	 */
	function secupress_add_css_to_active_button() {
		?>
		<style>.inactive-theme .activate, .theme-actions .activate{display:none!important;}</style>
		<?php
	}
}

/**
 * Prevent the upload of theme files
 *
 * @since 1.0
 * @author Julio Potier
 */
if ( isset( $_FILES['themezip'] ) ) {
	secupress_die( __( 'You do not have sufficient permissions to install themes on this site.', 'secupress' ), '', [ 'force_die' => true, 'attack_type' => 'themes' ] );
}
