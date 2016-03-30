<?php
/*
Module Name: Detect Bad Plugins
Description: Detect if a plugin you're using is known as vulnerable
Main Module: plugins_themes
Author: SecuPress
Version: 1.0
*/
defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

add_action( 'admin_footer', 'secupress_detect_bad_plugins_async_get_infos' );
function secupress_detect_bad_plugins_async_get_infos() {
	if ( false === get_site_transient( 'secupress-detect-bad-plugins' ) ) {
		$args = array(
			'timeout'   => 0.01,
			'blocking'  => false,
			'cookies'   => $_COOKIE,
			'sslverify' => apply_filters( 'https_local_ssl_verify', false ),
		);
		wp_remote_get( admin_url( 'admin-post.php' ) . '?action=secupress_refresh_bad_plugins&_wpnonce=' . wp_create_nonce( 'detect-bad-plugins' ), $args );
		set_site_transient( 'secupress-detect-bad-plugins', 1, 6 * HOUR_IN_SECONDS );
	}
}

add_action( 'admin_post_secupress_refresh_bad_plugins', '__secupress_refresh_bad_plugins_ajax_post_cb' );
function __secupress_refresh_bad_plugins_ajax_post_cb() {
	if ( ! isset( $_GET['_wpnonce'] ) || ! wp_verify_nonce( $_GET['_wpnonce'], 'detect-bad-plugins' ) ) {
		secupress_admin_die();
	}
	secupress_refresh_vulnerable_plugins();
}

add_action( 'after_plugin_row', 'secupress_detect_bad_plugins_after_plugin_row', 10, 3 );
function secupress_detect_bad_plugins_after_plugin_row( $plugin_file, $plugin_data, $context ) {
	if ( ( is_network_admin() || ! is_multisite() ) && ! current_user_can('update_plugins') && ! current_user_can('delete_plugins') && ! current_user_can('activate_plugins') ) { // ie. Administrator
		return; 
	}

	$plugins = array( 
					'vulns'      => secupress_get_vulnerable_plugins(), 
					'removed'    => secupress_get_removed_plugins(),
					'notupdated' => secupress_get_notupdated_plugins()
					);

	$plugin_name      = dirname( $plugin_file );
	$is_removed       = isset( $plugins['removed'][ $plugin_name ] );
	$is_notupdated    = isset( $plugins['notupdated'][ $plugin_name ] );
	$is_vuln          = isset( $plugins['vulns'][ $plugin_name ] );
	$plugin_vuln      = $is_vuln ? $plugins['vulns'][ $plugin_name ] : false;

	if ( ! $is_removed && ! $is_vuln && ! $is_notupdated ) {
		return;
	}

	if ( $is_vuln && version_compare( $plugin_data['Version'], $plugin_vuln->fixed_in ) == 1 && $plugin_vuln->fixed_in != '' ) {
		return;
	}

	$wp_list_table = _get_list_table( 'WP_Plugins_List_Table' ); 
	$current       = get_site_transient( 'update_plugins' );
	$page          = get_query_var( 'paged' );
	$s             = isset( $_REQUEST['s'] ) ? esc_attr( stripslashes( $_REQUEST['s'] ) ) : '';
	$r             = isset( $current->response[ $plugin_file ] ) ? $current->response[ $plugin_file ] : null;
	// HTML OUTPUT
	?>
<tr style="background-color: #f88;" class="sppc">
	<td colspan="<?php echo $wp_list_table->get_column_count(); ?>">
	<?php
	if ( $is_vuln ) {

		$plugin_vuln->flaws = unserialize( $plugin_vuln->flaws );
		$plugin_vuln->refs  = unserialize( $plugin_vuln->refs );

		foreach( $plugin_vuln->refs as $k => $link ) {
			$plugin_vuln->refs[ $k ] = sprintf( '<a href="%1$s" target="_blank">%1$s</a>', $link );
		}

		$flaws = wp_sprintf( '%l', $plugin_vuln->refs );
		printf( _n(	__( '<strong>%1$s %2$s</strong> is known to contain this vulnerability: %3$s.', 'secupress' ), 
					__( '<strong>%1$s %2$s</strong> is known to contain these vulnerabilities: %3$s.', 'secupress' ), 
					count( $plugin_vuln->flaws ), 'secupress' ), 
					$plugin_data['Name'],
					$plugin_vuln->fixed_in != '' ? sprintf( __( 'version %s (or lower)', 'secupress' ), $plugin_vuln->fixed_in ) : __( 'all versions', 'secupress' ), 
					'<strong>' . wp_sprintf( '%l', $plugin_vuln->flaws ) . '</strong>'
				); 
		
		echo ' ';
		printf( __( 'More information: %s', 'secupress' ), $flaws );

		if ( $plugin_vuln->fixed_in && current_user_can( 'update_plugins' ) ) {
			
			echo '<p>';
			if ( ! empty( $r->package ) ) {
				printf( '<span class="dashicons dashicons-update"></span> ' . __( 'We invite you to <a href="%1$s">Update</a> this plugin to in version %2$s.', 'secupress' ), 
					wp_nonce_url( admin_url('update.php?action=upgrade-plugin&plugin=') . $plugin_file, 'upgrade-plugin_' . $plugin_file ),
					'<strong>' . ( isset( $r->new_version ) ? $r->new_version : $plugin_vuln->fixed_in ) . '</strong>'
				);
			} else {
				'<span class="dashicons dashicons-update"></span> ' . __( 'We invite you to Update this plugin <em>(Automatic update is unavailable for this plugin.)</em>.', 'secupress' );
			}
			echo '</p>';
 
		} 

	} elseif ( $is_notupdated ) {
		printf( __(	'<strong>%s</strong> have not been updated on official repository for more than 2 years now. It can be dangerous.', 'secupress' ), $plugin_data['Name'] ); 
	} else { // removed
		printf( __(	'<strong>%s</strong> have been removed from official repository for one of these reasons: Security Flaw, on Author\'s demand, Not GPL compatible, this plugin is under investigation.', 'secupress' ), $plugin_data['Name'] ); 
	}
			
	if ( ! $is_vuln ) {
		echo '<p>';
		if ( is_plugin_active( $plugin_file ) && current_user_can( 'activate_plugins' ) ) {
			printf( '<span class="dashicons dashicons-admin-plugins"></span> ' . __( 'We invite you to <a href="%s">Deactivate</a> this plugin, then delete it.', 'secupress' ), 
					wp_nonce_url( admin_url( 'plugins.php?action=deactivate&plugin=' . $plugin_file . '&plugin_status=' . $context . '&paged=' . $page . '&s=' . $s ), 'deactivate-plugin_' . $plugin_file )
				);
		}

		if ( ! is_plugin_active( $plugin_file ) && current_user_can( 'delete_plugins' ) ) {
			printf( '<span class="dashicons dashicons-trash"></span> ' . __( 'We invite you to <a href="%s">Delete</a> this plugin, no patch has been made by its author.', 'secupress' ), 
					wp_nonce_url( admin_url( 'plugins.php?action=delete-selected&amp;checked[]=' . $plugin_file . '&amp;plugin_status=' . $context . '&amp;paged=' . $page . '&amp;s=' . $s ), 'bulk-plugins' )
				);
		}
		echo '</p>';
	}

	?>
	</td>
</tr>
<?php
}

add_action( 'admin_head', 'secupress_detect_bad_plugins_add_notices' );
function secupress_detect_bad_plugins_add_notices() {
	global $pagenow;

	// don't display the notice yet, next reload.
	if ( false === get_site_transient( 'secupress-detect-bad-plugins' ) || 'plugins.php' == $pagenow ||
	( is_network_admin() || ! is_multisite() ) && ! current_user_can('update_plugins') && ! current_user_can('delete_plugins') && ! current_user_can('activate_plugins') ) { // ie. Administrator
		return; 
	}

	$plugins = array( 
				'vulns'      => secupress_get_vulnerable_plugins(), 
				'removed'    => secupress_get_removed_plugins(),
				'notupdated' => secupress_get_notupdated_plugins()
				);

	if ( $plugins['vulns'] || $plugins['removed'] || $plugins['notupdated'] ) {
		$counter  = count( $plugins['vulns'] ) + count( $plugins['removed'] ) + count( $plugins['notupdated'] );
		$url      = admin_url( 'plugins.php' );
		$message  = sprintf( 
						_n( 'Your installation contains %1$s plugin considered as <em>bad</em>, check the details in <a href="%2$s">the plugins page</a>.', 
							'Your installation contains %1$s plugins considered as <em>bad</em>, check the details in <a href="%2$s">the plugins page</a>.', 
							'<strong>' . $counter . '</strong>', 'secupress' ), 
					$counter, $url );
		secupress_add_notice( $message, 'error', 'badplugins' );
	}
}