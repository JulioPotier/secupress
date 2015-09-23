<?php
/*
Module Name: No Plugin Updates
Description: Disabled the plugin updates
Main Module: plugins_themes
Author: SecuPress
Version: 1.0
*/
defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

if ( is_admin() ) {

	add_action( 'check_admin_referer', 'secupress_avoid_update_plugin' );
	function secupress_avoid_update_plugin( $action ) {
		global $pagenow;
		if ( ( 'update.php' == $pagenow && isset( $_GET['action'] ) && 'upgrade-plugin' == $_GET['action'] ) || // page access
			( 'update-core.php' == $pagenow && isset( $_GET['action'] ) && 'do-upgrade-plugin' == $_GET['action'] ) || // page access
			( 'bulk-plugins' == $action && // form validation
			( isset( $_POST['action'] ) && 'update-selected' == $_POST['action'] ) || 
			( isset( $_POST['action2'] ) && 'update-selected' == $_POST['action2'] ) )
		) {
			secupress_die( __( 'You do not have sufficient permissions to update plugins on this site.' ) );
		}
	}

	add_action( 'check_ajax_referer', 'secupress_avoid_update_plugin_ajax' );
	function secupress_avoid_update_plugin_ajax( $action ) {
		if ( defined( 'DOING_AJAX' ) && DOING_AJAX && 'updates' == $action && isset( $_POST['action'], $_POST['slug'], $_POST['plugin'] ) && 'update-plugin' == $_POST['action'] ) {
			wp_send_json_error( array( 'slug' => $_POST['slug'], 'plugin' => $_POST['plugin'], 'error' => __( 'You do not have sufficient permissions to update plugins on this site.' ) ) );
		}
	}

	add_action( 'admin_footer-plugins.php', 'secupress_add_js_to_update_plugin_bulk_action', 100 );
	function secupress_add_js_to_update_plugin_bulk_action() {
	?>
	<script>
		jQuery( 'option[value="update-selected"]' ).remove();
		if ( 1 == jQuery( '#bulk-action-selector-top option' ).length ) {
			jQuery( '#bulk-action-selector-top' ).remove();
		}
		if ( 1 == jQuery( '#bulk-action-selector-bottom option' ).length ) {
			jQuery( '#bulk-action-selector-bottom' ).remove();
		}
		jQuery( document ).ready( function() {
			if ( 0 == jQuery( 'div.bulkactions select' ).length ) {
				jQuery( 'div.bulkactions,table.plugins thead tr th:first,table.plugins tbody tr th,table.plugins tfoot tr th:first' ).remove();
			}
		});
	</script>
	<?php
	}

	add_action( 'load-update-core.php', 'secupress_add_metacap_to_update_plugins_bulk_action', 100 );
	add_action( 'load-update.php', 'secupress_add_metacap_to_update_plugins_bulk_action', 100 );
	function secupress_add_metacap_to_update_plugins_bulk_action() {
		add_filter( 'map_meta_cap', 'secupress_remove_upgrade_plugin_capa', 100, 2 );
	}

	function secupress_remove_upgrade_plugin_capa( $caps, $cap ) {
	    if ( $cap == 'update_plugins' ) {
	        return array( time() );
	    }
	    return $caps;
	}

	add_filter( 'site_transient_update_plugins', 'secupress_remove_plugin_packages_from_tr' );
	function secupress_remove_plugin_packages_from_tr( $value ) {
		if ( $value && isset( $value->response ) ) {
			foreach ( $value->response as $response ) {
				if ( isset( $response->package ) ) {
					unset( $response->package );
				}
			}
		}
		return $value;
	}

}