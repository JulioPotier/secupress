<?php
/*
Module Name: No Theme Updates
Description: Disabled the theme updates
Main Module: plugins_themes
Author: SecuPress
Version: 1.0
*/
defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

if ( is_admin() ) {

	add_action( 'check_admin_referer', 'secupress_avoid_update_theme' );
	function secupress_avoid_update_theme( $action ) {
		global $pagenow;
		if ( ( 'update.php' == $pagenow && isset( $_GET['action'] ) && 'upgrade-theme' == $_GET['action'] ) || // page access
			( 'update-core.php' == $pagenow && isset( $_GET['action'] ) && 'do-theme-upgrade' == $_GET['action'] ) || // page access
			( strpos( $action, 'upgrade-theme_' ) === 0 ) ||
			( 'bulk-update-themes' == $action && // form validation
			( isset( $_POST['action'] ) && 'update-selected-themes' == $_POST['action'] ) || 
			( isset( $_POST['action2'] ) && 'update-selected' == $_POST['action2'] ) )
		) {
			secupress_die( __( 'You do not have sufficient permissions to update themes on this site.' ) );
		}
	}

	add_action( 'load-update-core.php', 'secupress_add_js_to_update_themes_bulk_action', 100 );
	function secupress_add_js_to_update_themes_bulk_action() {
		add_filter( 'map_meta_cap', 'secupress_remove_upgrade_theme_capa', 100, 2 );
	}

	function secupress_remove_upgrade_theme_capa( $caps, $cap ) {
	    if ( $cap == 'update_themes' ) {
	        return array( time() );
	    }
	    return $caps;
	}

	add_filter( 'site_transient_update_themes', 'secupress_remove_themes_packages_from_tr' );
	function secupress_remove_themes_packages_from_tr( $value ) {
		if ( $value && isset( $value->response ) ) {
			foreach ( $value->response as $k => $response ) {
				if ( isset( $response['package'] ) ) {
					unset( $value->response[ $k ]['package'] );
				}
			}
		}
		return $value;
	}

}