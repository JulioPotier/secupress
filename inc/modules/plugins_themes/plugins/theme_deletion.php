<?php
/*
Module Name: No Theme Deletion
Description: Disabled the theme deletion
Main Module: plugins_themes
Author: SecuPress
Version: 1.0
*/
defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

if ( is_admin() ) {

	add_action( 'check_admin_referer', 'secupress_avoid_delete_theme' );
	function secupress_avoid_delete_theme( $action ) {
		if ( strpos( $action, 'delete-theme_' ) === 0 ) {
			secupress_die( __( 'You do not have sufficient permissions to delete plugins on this site.' ) );
		}
	}

	add_action( 'admin_footer-themes.php', 'secupress_add_css_to_delete_button', 100 );
	function secupress_add_css_to_delete_button() {
		?>
		<style>
			a.delete-theme{display:none !important;}
		</style>
		<?php
	}

}