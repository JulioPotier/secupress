<?php
/*
Module Name: No Plugin Deactivation
Description: Disabled the plugin deactivation
Main Module: plugins_themes
Author: SecuPress
Version: 1.0
*/
defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

if ( is_admin() ) {

	add_filter( 'network_admin_plugin_action_links', 'secupress_no_plugin_deactivation', PHP_INT_MAX );
	add_filter( 'plugin_action_links', 'secupress_no_plugin_deactivation', PHP_INT_MAX );

	function secupress_no_plugin_deactivation( $actions ) {
		if ( isset( $actions['deactivate'] ) ) {
			global $current_screen;
			if ( $current_screen->in_admin( 'network' ) ) {
				$actions['deactivate'] = '<del>' . __( 'Network Deactivate' ) . '</del>';
			} else {
				$actions['deactivate'] = '<del>' . __( 'Deactivate' ) . '</del>';
			}
		}
		return $actions;
	}

	add_action( 'check_admin_referer', 'secupress_avoid_deactivate_plugin' );
	function secupress_avoid_deactivate_plugin( $action ) {
		global $pagenow;
		if ( ( 'plugins.php' == $pagenow && isset( $_GET['action'] ) && 'deactivate' == $_GET['action'] ) || // page access
			( 'bulk-plugins' == $action && // form validation
			( isset( $_POST['action'] ) && 'deactivate-selected' == $_POST['action'] ) || 
			( isset( $_POST['action2'] ) && 'deactivate-selected' == $_POST['action2'] ) )
		) {
			secupress_die( __( 'You do not have sufficient permissions to deactivate plugins on this site.' ) );
		}
	}

	add_action( 'admin_footer-plugins.php', 'secupress_add_js_to_deactivate_bulk_action', 100 );
	function secupress_add_js_to_deactivate_bulk_action() {
	?>
	<script>
		jQuery( 'option[value="deactivate-selected"]' ).remove();
		if ( 1 == jQuery( '#bulk-action-selector-top option' ).length ) {
			jQuery( '#bulk-action-selector-top' ).remove();
		}
		if ( 1 == jQuery( '#bulk-action-selector-bottom option' ).length ) {
			jQuery( '#bulk-action-selector-bottom' ).remove();
		}
		jQuery( document ).ready( function() {
			if ( 0 == jQuery( 'div.bulkactions select' ).length ) {
				jQuery( 'div.bulkactions' ).remove();
			}
		});	</script>
	<?php
	}

}