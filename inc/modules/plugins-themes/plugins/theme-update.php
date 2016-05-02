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
	/**
	 * Forbid plugin update.
	 *
	 * @since 1.0
	 *
	 * @param (string) $action The nonce action.
	 */
	function secupress_avoid_update_theme( $action ) {
		global $pagenow;

		if ( ( 'update.php' === $pagenow && isset( $_GET['action'] ) && 'upgrade-theme' === $_GET['action'] ) || // Page access.
			( 'update-core.php' === $pagenow && isset( $_GET['action'] ) && 'do-theme-upgrade' === $_GET['action'] ) || // Page access.
			( strpos( $action, 'upgrade-theme_' ) === 0 ) ||
			( 'bulk-update-themes' === $action && // Form validation.
			( isset( $_POST['action'] ) && 'update-selected-themes' === $_POST['action'] ) || // WPCS: CSRF ok.
			( isset( $_POST['action2'] ) && 'update-selected' === $_POST['action2'] ) ) // WPCS: CSRF ok.
		) {
			secupress_die( __( 'You do not have sufficient permissions to update themes on this site.' ) );
		}
	}


	add_action( 'load-update-core.php', 'secupress_add_js_to_update_themes_bulk_action', 100 );
	/**
	 * On update pages, launch a filter that will bloat the user capability `update_themes`.
	 *
	 * @since 1.0
	 */
	function secupress_add_js_to_update_themes_bulk_action() {
		add_filter( 'map_meta_cap', 'secupress_remove_upgrade_theme_capa', 100, 2 );
	}


	/**
	 * Filter a user's capabilities depending on specific context and/or privilege.
	 * User cap filter that bloats the capability `update_themes`.
	 *
	 * @since 1.0
	 *
	 * @param (array)  $caps Returns the user's actual capabilities.
	 * @param (string) $cap  Capability name.
	 *
	 * @return (array)
	 */
	function secupress_remove_upgrade_theme_capa( $caps, $cap ) {
		if ( 'update_themes' === $cap ) {
			return array( time() );
		}
		return $caps;
	}

	add_filter( 'site_transient_update_themes', 'secupress_remove_themes_packages_from_tr' );
	/**
	 * Remove theme packages from the transient `update_themes`.
	 *
	 * @since 1.0
	 *
	 * @param (mixed) $value The transient value.
	 *
	 * @return (mixed)
	 */
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
