<?php
/*
Module Name: No Theme Switch
Description: Disabled the theme switch
Main Module: plugins_themes
Author: SecuPress
Version: 1.0
*/
defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

if ( is_admin() ) {

	add_action( 'check_admin_referer', 'secupress_avoid_install_theme' );
	function secupress_avoid_install_theme( $action ) {
		if ( strpos( $action, 'switch-theme_' ) === 0 ) {
			secupress_die( __( 'You do not have sufficient permissions to switch themes on this site.' ) );
		}
	}

	add_action( 'admin_footer-themes.php', 'secupress_add_css_to_active_button', 100 );
	function secupress_add_css_to_active_button() {
		?>
		<style>
			.inactive-theme .activate, .theme-actions .activate{display:none !important;}
		</style>
		<?php
	}

}