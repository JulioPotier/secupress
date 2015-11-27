<?php
/*
Module Name: No Plugin Activation
Description: Disabled the plugin activation
Main Module: plugins_themes
Author: SecuPress
Version: 1.0
*/
defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

if ( is_admin() ) {

	add_filter( 'network_admin_plugin_action_links', 'secupress_no_plugin_activation', PHP_INT_MAX );
	add_filter( 'plugin_action_links', 'secupress_no_plugin_activation', PHP_INT_MAX );

	function secupress_no_plugin_activation( $actions ) {
		if ( isset( $actions['activate'] ) ) {
			global $current_screen;
			if ( $current_screen->in_admin( 'network' ) ) {
				$actions['activate'] = '<del>' . __( 'Network Activate' ) . '</del>';
			} else {
				$actions['activate'] = '<del>' . __( 'Activate' ) . '</del>';
			}
		}
		return $actions;
	}

	add_action( 'check_admin_referer', 'secupress_avoid_activate_plugin' );
	function secupress_avoid_activate_plugin( $action ) {
		global $pagenow;
		if ( ( 'plugins.php' == $pagenow && isset( $_GET['action'] ) && 'activate' == $_GET['action'] ) || // page access
			( 'bulk-plugins' == $action && // form validation
			( isset( $_POST['action'] ) && 'activate-selected' == $_POST['action'] ) || 
			( isset( $_POST['action2'] ) && 'activate-selected' == $_POST['action2'] ) )
		) {
			secupress_die( __( 'You do not have sufficient permissions to install plugins on this site.' ) );
		}
	}

	add_action( 'admin_footer-plugins.php', 'secupress_add_js_to_activate_bulk_action', 100 );
	function secupress_add_js_to_activate_bulk_action() {
	?>
	<script>
		jQuery( 'option[value="activate-selected"]' ).remove();
	</script>
	<?php
	}

}