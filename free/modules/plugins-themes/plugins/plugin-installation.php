<?php
/**
 * Module Name: No Plugin Actions
 * Description: Disable the plugin actions: Installation, Activation, Deactivation, Deletion. Update and rollback are still possible.
 * Main Module: plugins_themes
 * Author: SecuPress
 * Version: 2.2.6
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );

if ( ! secupress_wp_version_is( '6.3' ) ) { // 6.3 because of the needed filter "plugins_list"
	secupress_add_notice( sprintf( __( 'WordPress <b>v%1$s</b> is required to use the module <em>%2$s</em>.', 'secupress' ), '6.3', __( 'Plugin Actions', 'secupress' ) ), 'error', __FILE__ );
	return;
}

// Installation
defined( 'SECUPRESS_INSTALLED_PLUGINS' )   || define( 'SECUPRESS_INSTALLED_PLUGINS'     , '_secupress_installed_plugins' );
defined( 'SECUPRESS_INSTALLED_MUPLUGINS' ) || define( 'SECUPRESS_INSTALLED_MUPLUGINS'   , '_secupress_installed_muplugins' );
// (De)Activation
defined( 'SECUPRESS_ACTIVE_PLUGINS' ) || define( 'SECUPRESS_ACTIVE_PLUGINS', '_secupress_active_plugins' );
if ( is_multisite() ) {
	defined( 'SECUPRESS_ACTIVE_PLUGINS_NETWORK' ) || define( 'SECUPRESS_ACTIVE_PLUGINS_NETWORK', '_secupress_active_sitewide_plugins' );
}

add_action( 'secupress.pro.plugins.activation',                                     'secupress_no_plugin_actions__activation' );
add_action( 'secupress.modules.activate_submodule_' . basename( __FILE__, '.php' ), 'secupress_no_plugin_actions__activation' );
/**
 * Add the options and MU on module activation
 *
 * @author Julio Potier
 * @since 2.2.6
 **/
function secupress_no_plugin_actions__activation() {
	$filepart   = 'no_plugins_installation';
	$args       = [
		'{{PLUGIN_NAME}}' => SECUPRESS_PLUGIN_NAME,
	];
	$filesystem = secupress_get_filesystem();
	$contents   = $filesystem->get_contents( SECUPRESS_INC_PATH . "data/{$filepart}.phps" );
	$contents   = str_replace( array_keys( $args ), $args, $contents );

	secupress_create_mu_plugin( $filepart, $contents );
	sleep( 1 ); // let 1s to create the file on disk.

	// (De)Activation
	if ( ! is_multisite() ) {
		add_option( SECUPRESS_ACTIVE_PLUGINS, get_option( 'active_plugins' ) );
	} else {
		add_site_option( SECUPRESS_ACTIVE_PLUGINS_NETWORK, get_site_option( 'active_sitewide_plugins' ) );
		$sites = get_sites();
		foreach ( $sites as $site ) {
			$site_id = $site->blog_id;
			switch_to_blog( $site_id );
			add_option( SECUPRESS_ACTIVE_PLUGINS, get_option( 'active_plugins', [] ) );
			restore_current_blog();
		}
	}
	// Installation
	add_site_option( SECUPRESS_INSTALLED_PLUGINS,   get_plugins() );
	add_site_option( SECUPRESS_INSTALLED_MUPLUGINS, get_mu_plugins() );
}

add_action( 'secupress.pro.plugins.deactivation',                                     'secupress_no_plugin_actions__deactivation' );
add_action( 'secupress.modules.deactivate_submodule_' . basename( __FILE__, '.php' ), 'secupress_no_plugin_actions__deactivation' );
/**
 * Delete the options on deactivation
 *
 * @author Julio Potier
 * @since 2.2.6
 **/
function secupress_no_plugin_actions__deactivation() {
	$filepart = 'no_plugins_installation';
	secupress_delete_mu_plugin( $filepart );
	// Installation
	delete_site_option( SECUPRESS_INSTALLED_PLUGINS );
	delete_site_option( SECUPRESS_INSTALLED_MUPLUGINS );
	// (De)Activation
	if ( ! is_multisite() ) {
		delete_option( SECUPRESS_ACTIVE_PLUGINS );
	} else {
		delete_site_option( SECUPRESS_ACTIVE_PLUGINS_NETWORK );
		$sites = get_sites();
		foreach ( $sites as $site ) {
			$site_id = $site->blog_id;
			switch_to_blog( $site_id );
			delete_option( SECUPRESS_ACTIVE_PLUGINS );
			restore_current_blog();
		}
	}
}

add_filter( 'map_meta_cap', 'secupress_no_plugin_action_caps', 10, 2 );
/**
 * Prevent actions on plugins using capabilities
 * 
 * @since 2.2.6
 * @author Julio Potier
 *
 * @param (array) $caps
 * @param (string) $cap
 * 
 * @return (array) $caps
 **/
function secupress_no_plugin_action_caps( $caps, $cap ) {
	$disallowed_caps = apply_filters( 'secupress.plugins.plugin-installation.disallowed_caps', [ 'delete_plugins' => 1, 'install_plugins' => 1, 'upload_plugin' => 1, 'resume_plugin' => 1, 'activate_plugin' => 1, 'deactivate_plugin' => 1, 'deactivate_plugins' => 1/*, 'activate_plugins' => 1', manage_network_plugins' => 1*/ ] ); // DO NOT UNCOMMENT
	if ( isset( $disallowed_caps[ $cap ] ) ) {
		return ['do_not_allow'];
	}
	return $caps;
}

add_filter( 'network_admin_plugin_action_links', 'secupress_no_plugin_action_links', SECUPRESS_INT_MAX, 2 );
add_filter( 'plugin_action_links',               'secupress_no_plugin_action_links', SECUPRESS_INT_MAX, 2 );
/**
 * Remove plugin deletion link.
 *
 * @since 1.0
 * @author Julio Potier
 *
 * @param (array) $actions The actions (links).
 */
function secupress_no_plugin_action_links( $actions, $plugin_file ) {
	$act = [];
	unset( $actions['delete'] );
	unset( $actions['activate'] );
	unset( $actions['deactivate'] );
	if ( secupress_is_plugin_active( $plugin_file ) ) {
		$act['secupress_deactivate'] = '<del>' . ( is_network_admin() ? _x( 'Network Deactivate', 'verb', 'secupress' ) : _x( 'Deactivate', 'verb', 'secupress' ) ) . '</del>';
	} else {
		$act['secupress_activate']   = '<del>' . ( is_network_admin() ? _x( 'Network Activate', 'verb', 'secupress' ) : _x( 'Activate', 'verb', 'secupress' ) ) . '</del>';
		$act['secupress_delete']     = '<del>' . _x( 'Delete', 'verb', 'secupress' ) . '</del>';
	}
	return $act + $actions;
}

add_action( 'pre_uninstall_plugin', 'secupress_no_plugin_uninstall' );
/**
 * Prevent any plugin to be uninstalled
 *
 * @author Julio Potier
 * @since 2.2.6
 * 
 **/
function secupress_no_plugin_uninstall( $plugin ) {
	$file     = plugin_basename( $plugin );	
	$filename = WP_PLUGIN_DIR . '/' . dirname( $file ) . '/uninstall.php';
	if ( file_exists( $filename ) ) {
		@unlink( $filename );
	}
	if ( file_exists( $filename ) ) {
		rename( $filename, $filename . '_' . time() );
	}
}

add_action( 'deleted_plugin', 'secupress_no_plugin_install_update_option', 10, 2 );
/**
 * Update the option SECUPRESS_INSTALLED_PLUGINS when a plugin is deleted
 *
 * @author Julio Potier
 * @since 2.2.6
 * 
 * @param (string) $plugin_file
 * @param (bool)   $deleted
 **/
function secupress_no_plugin_install_update_option( $plugin_file, $deleted ) {
	if ( ! $deleted ) {
		return;
	}
	$plugins = get_site_option( SECUPRESS_INSTALLED_PLUGINS );
	unset( $plugins[ $plugin_file ] );
	update_site_option( SECUPRESS_INSTALLED_PLUGINS, $plugins );
}

// should not happen
add_action( 'activate_plugin', 'secupress_no_plugin_install_no_activation', 11 );
/**
 * Prevent a not installed plugin to be activated
 *
 * @author Julio Potier
 * @since 2.2.6
 * 
 **/
function secupress_no_plugin_install_no_activation( $plugin ) {
	secupress_die( __( 'Sorry, you are not allowed to activate plugins on this site.', 'secupress' ), '', [ 'force_die' => true, 'attack_type' => 'plugins' ] );
	return;
}

add_action( 'admin_init', 'secupress_no_plugin_install_warning_no_muplugin' );
/**
 * Run secupress_no_plugin_actions__activation() if needed
 *
 * @author Julio Potier
 * @since 2.2.6
 **/
function secupress_no_plugin_install_warning_no_muplugin() {
	if ( ! defined( 'SECUPRESS_NO_PLUGIN_ACTION_RUNNING' ) ) {
		secupress_no_plugin_actions__activation();
	}
}

add_action( 'load-plugins.php', 'secupress_no_plugin_install_add_malware_column' );
/**
 * Add the malware detection column
 *
 * @see secupress_add_malware_detection_column()
 * @author Julio Potier
 * @since 2.2.6
 **/
function secupress_no_plugin_install_add_malware_column() {
	global $current_screen;

	if ( ! isset( $current_screen ) || ! isset( $_GET['plugin_status'] ) || 'secupress_not_installed' !== $_GET['plugin_status'] || empty( array_filter( secupress_get_not_installed_plugins_list() ) ) ) {
		return;
	}
	// @see /free/admin/admin.php
	add_filter( 'manage_plugins_columns', 'secupress_add_malware_detection_column' );
	// Prevent update notices
	add_filter( 'file_mod_allowed', 'secupress_file_mod_not_allowed', 10, 2 );
}

/**
 * Prevent the file modification on update context
 *
 * @author Julio Potier
 * @since 2.2.6
 * 
 * @param (bool) $file_mod_allowed
 * @param (string) $context
 * @return (bool)
 **/
function secupress_file_mod_not_allowed( $file_mod_allowed, $context ) {
	if ( 'capability_update_core' === $context ) {
		return false;
	}
	return $file_mod_allowed;
}

add_action( 'wp_ajax_' . 'delete-plugin'    , 'secupress_no_plugin_install_no_ajax_action_delete', 0 );
/**
 * Shortcut the native plugin install since we cannot unhook theses ajax hooks.
 *
 * @author Julio Potier
 * @since 2.2.6
 * 
 * @return (string) JSON
 **/
function secupress_no_plugin_install_no_ajax_action_delete() {
	if ( empty( $_POST['plugin'] ) ) {
		wp_send_json_error(
			[
				'slug'         => '',
				'errorCode'    => 'no_plugins_specified',
				'errorMessage' => __( 'No plugins specified.' ),
			]
		);
	}
	$not_installed_plugins = secupress_get_not_installed_plugins_list();
	if ( isset( $not_installed_plugins['all'][ $_POST['plugin'] ] ) || isset( $not_installed_plugins['mu'][ $_POST['plugin'] ] ) ) {
		add_filter( 'secupress.plugins.plugin-installation.disallowed_caps', function( $caps ) {
			unset( $caps['delete_plugins'] );
			return $caps;
		} );
	}
	// DO NOT RETURN OR BLOCK ANYTHING
}

add_action( 'wp_ajax_' . 'install-plugin'    , 'secupress_no_plugin_install_no_ajax_action_install', 0 );
/**
 * Shortcut the native plugin install since we cannot unhook theses ajax hooks.
 *
 * @author Julio Potier
 * @since 2.2.6
 * 
 * @return (string) JSON
 **/
function secupress_no_plugin_install_no_ajax_action_install() {
	if ( empty( $_POST['slug'] ) ) {
		wp_send_json_error(
			[
				'slug'         => '',
				'errorCode'    => 'no_plugins_specified',
				'errorMessage' => __( 'No plugins specified.' ),
			]
		);
	}
	$not_deleted_plugins = secupress_get_deleted_plugins_list();
	if ( array_key_exists( $_POST['slug'], array_flip( array_map( 'dirname', array_keys( $not_deleted_plugins ) ) ) ) ) {
		add_filter( 'secupress.plugins.plugin-installation.disallowed_caps', function( $caps ) {
			unset( $caps['install_plugins'] );
			return $caps;
		} );
	}
	// DO NOT RETURN OR BLOCK ANYTHING
}

add_action( 'delete_plugin', 'secupress_no_plugin_install_muplugins_delete_ajax' );
/**
 * Let the possibility to delete a muplugin using native ajax or native URL behavior
 *
 * @author Julio Potier
 * @since 2.2.6
 * 
 * @param (string) $plugin_file
 **/
function secupress_no_plugin_install_muplugins_delete_ajax( $plugin_file ){
	global $wp_filesystem;
	// It's not a mu-plugin
	if ( ! file_exists( WPMU_PLUGIN_DIR . '/'  . $plugin_file ) ) {
		return;
	}
	$status = [
		'delete' => 'plugin',
		'slug'   => $plugin_file,
	];
	$user_ID = get_current_user_id();
	if ( ! current_user_can( 'delete_plugins' ) || validate_file( $plugin_file, array_keys( secupress_get_not_installed_plugins_list( 'mu' ) ) ) ) {
		$status['errorMessage'] = __( 'Sorry, you are not allowed to delete plugins for this site.' );
		if ( wp_doing_ajax() ) {
			wp_send_json_error( $status );
		} else {
			update_option( 'plugins_delete_result_' . $user_ID, $status['errorMessage'], false );
			wp_redirect( self_admin_url( 'plugins.php?deleted=1&plugin_status=secupress_not_installed' ) );
			exit;
		}
	}
	$plugin_data          = get_plugin_data( WPMU_PLUGIN_DIR . '/'  . $plugin_file );
	$status['plugin']     = $plugin_file;
	$status['pluginName'] = ! empty( $plugin_data['Name'] ) ? esc_html( $plugin_data['Name'] ) : $plugin_file;

	$deleted = $wp_filesystem->delete( WPMU_PLUGIN_DIR . '/'  . $plugin_file );

	if ( ! $deleted ) {
		$status['errorMessage'] = __( 'Plugin could not be deleted.', 'secupress' );
		if ( wp_doing_ajax() ) {
			wp_send_json_error( $status );
		} else {
			update_option( 'plugins_delete_result_' . $user_ID, $status['errorMessage'], false );
			wp_redirect( self_admin_url( 'plugins.php?deleted=1&plugin_status=secupress_not_installed' ) );
			exit;
		}
		wp_send_json_error( $status );
	}
	if ( wp_doing_ajax() ) {
		wp_send_json_success( $status );
	} else {
		update_option( 'plugins_delete_result_' . $user_ID, 1, false );
		wp_redirect( self_admin_url( 'plugins.php?deleted=1&plugin_status=secupress_not_installed' ) );
		exit;
	}
}

add_filter( 'manage_plugins_columns', 'secupress_no_plugin_install_plugin_columns' );
/**
 * Only keep the "name" and "description" columns on our view.
 *
 * @author Julio Potier
 * @since 2.2.6
 * 
 * @param (array) $columns
 * @return (array) $columns
 **/
function secupress_no_plugin_install_plugin_columns( $columns ) {
	global $current_screen;

	if ( ! isset( $current_screen ) || ! isset( $_GET['plugin_status'] ) ) {
		return $columns;
	}
	switch( $_GET['plugin_status'] ) {
		case 'secupress_not_installed';
			if ( empty( array_filter( secupress_get_not_installed_plugins_list() ) ) ) {
				return $columns;
			}
		 break;
		case 'secupress_deleted';
			if ( empty( array_filter( secupress_get_deleted_plugins_list() ) ) ) {
				return $columns;
			}
		 break;
		case 'secupress_not_activated';
		case 'secupress_not_deactivated';
			if ( empty( array_filter( secupress_get_not_activated_plugins_list() ) ) ) {
				return $columns;
			}
		 break;
		 default:
		 	return $columns;
		 break;
	}
	$cols                = [];
	$cols['cb']          = $columns['cb'];
	$cols['plugin-title column-primary'] = __( 'Plugin', 'secupress' );
	$cols['description'] = $columns['description'];
	return $cols;
}

add_filter( 'manage_plugins_custom_column', 'secupress_no_plugin_install_name_col', 10, 3 );
/**
 * Display some infos on the plugin as the "name" column
 * (our real key is "plugin-title column-primary" so it's used as is as CSS class #hacktrick)
 *
 * @author Julio Potier
 * @since 2.2.6
 * 
 * @param  (string) $column_name
 * @param  (string) $plugin_file
 * @param  (array)  $plugin_data
 **/
function secupress_no_plugin_install_name_col( $column_name, $plugin_file, $plugin_data ) {
	global $status;
	if ( 'plugin-title column-primary' !== $column_name ) {
		return;
	}
	switch( $status ) {
		case 'secupress_deleted':
			$actions     = [];
			$plugin_file = preg_replace( '/\.php_\d{14}/', '.php', $plugin_file );
			$actions['secupress_not_activated__info'] = _x( 'Deleted', 'plugin', 'secupress' );
			$actions['secupress_reinstall']           = isset( $plugin_data['muplugin'] ) ? '<span>' . __( 'Reinstalling a mu-plugin is not possible' ) . '</span>' : '<span>' . __( 'Reinstalling a premium or custom plugin is not possible' ) . '</span>';
			if ( ! isset( $plugin_data['muplugin'] ) ) {
				$plugin      = dirname( $plugin_file );
				$api         = secupress_plugins_api( $plugin );
				if ( $api === 'plugin_found' ) {  // DO NOT TRANSLATE
					$actions['secupress_reinstall'] = '<span class="plugin-card-' . esc_attr( $plugin ) . '"><a data-slug="' . esc_attr( $plugin ) . '"  data-name="' . esc_attr( $plugin_data['Name'] ) . '" class="install-now">' . __( 'Reinstall the plugin from wp.org' ) . '</a></span>';
				}
			}
			$plugin_name = isset( $plugin_data['Name'] ) && ! isset( $plugin_data['muplugin'] ) ? esc_html( $plugin_data['Name'] ) : $plugin_file;
			$plugin_loc  = isset( $plugin_data['muplugin'] ) ? '' : $plugin_file;
			$format_msg  = '<br>' . __( 'Type: <i><abbr title="%1$s">%2$s</<abbr></i>', 'secupress' );
			echo '<b>' . $plugin_name  .'</b>';
			if ( isset( $plugin_data['muplugin'] ) ) {
				echo sprintf( $format_msg, MUPLUGINDIR, __( 'Must-Use Plugin', 'secupress' ) );
			} else {
				echo sprintf( $format_msg, str_replace ( ABSPATH, '', WP_PLUGIN_DIR ), __( 'Plugin', 'secupress' ) );
			}
			echo '<div class="row-actions visible">';
			
			$i            = 0;
			$action_count = count( $actions );
			foreach ( $actions as $action => $link ) {
				++$i;
				$separator = ( $i < $action_count ) ? ' | ' : '';
				echo "<span class='$action'>{$link}{$separator}</span>";
			}

			echo '</div>';
		break;
		case 'secupress_not_installed':
			$actions     = [];
			$delete_url  = wp_nonce_url( 'plugins.php?action=delete-selected&verify-delete=1&checked[]=' . $plugin_file, 'bulk-plugins' );
			$plugin_file = preg_replace( '/\.php_\d{14}/', '.php', $plugin_file );
			$actions['secupress_not_installed__info']      = __( 'Installation not allowed', 'secupress' );
			$actions['secupress_not_installed__delete_it'] = '<a class="delete" href="' . $delete_url . '">' . _x( 'Delete', 'verb', 'secupress' ) . '<a>';
			$plugin_name = isset( $plugin_data['Name'] ) && ! isset( $plugin_data['muplugin'] ) ? esc_html( $plugin_data['Name'] ) : $plugin_file;
			$plugin_loc  = isset( $plugin_data['muplugin'] ) ? '' : $plugin_file;
			$format_msg  = '<br>' . __( 'Type: <i><abbr title="%1$s">%2$s</<abbr></i>', 'secupress' );
			echo '<b>' . $plugin_name  .'</b>';
			if ( isset( $plugin_data['muplugin'] ) ) {
				echo sprintf( $format_msg, MUPLUGINDIR, __( 'Must-Use Plugin', 'secupress' ) );
			} else {
				echo sprintf( $format_msg, str_replace ( ABSPATH, '', WP_PLUGIN_DIR ), __( 'Plugin', 'secupress' ) );
			}
			echo '<div class="row-actions visible">';
			
			$i            = 0;
			$action_count = count( $actions );
			foreach ( $actions as $action => $link ) {
				++$i;
				$separator = ( $i < $action_count ) ? ' | ' : '';
				echo "<span class='$action'>{$link}{$separator}</span>";
			}

			echo '</div>';
		break;

		case 'secupress_not_activated':
		case 'secupress_not_deactivated':
			$actions     = [];
			$delete_url  = wp_nonce_url( 'plugins.php?action=delete-selected&verify-delete=1&checked[]=' . $plugin_file, 'bulk-plugins' );
			$plugin_file = preg_replace( '/\.php_\d{14}/', '.php', $plugin_file );
			$actions['secupress_not_activated__info']      = __( 'Activation not allowed', 'secupress' );
			// $actions['secupress_not_activated__delete_it'] = '<a class="delete" href="' . $delete_url . '">' . __( 'Delete', 'secupress' ) . '<a>';
			$plugin_name = isset( $plugin_data['Name'] ) && ! isset( $plugin_data['muplugin'] ) ? esc_html( $plugin_data['Name'] ) : $plugin_file;
			$plugin_loc  = isset( $plugin_data['muplugin'] ) ? '' : $plugin_file;
			$format_msg  = '<br>' . __( 'Type: <i><abbr title="%1$s">%2$s</<abbr></i>', 'secupress' );
			echo '<b>' . $plugin_name  .'</b>';
			if ( isset( $plugin_data['muplugin'] ) ) {
				echo sprintf( $format_msg, MUPLUGINDIR, __( 'Must-Use Plugin', 'secupress' ) );
			} else {
				echo sprintf( $format_msg, str_replace ( ABSPATH, '', WP_PLUGIN_DIR ), __( 'Plugin', 'secupress' ) );
			}
			echo '<div class="row-actions visible">';
			
			$i            = 0;
			$action_count = count( $actions );
			foreach ( $actions as $action => $link ) {
				++$i;
				$separator = ( $i < $action_count ) ? ' | ' : '';
				echo "<span class='$action'>{$link}{$separator}</span>";
			}

			echo '</div>';
		break;
	}
}

add_filter( 'plugin_row_meta', 'secupress_no_plugin_row_meta', SECUPRESS_INT_MAX );
/**
 * Remove any links in the meta in our plugins list
 *
 * @author Julio Potier
 * @since 2.2.6
 * 
 * @param (array) $plugin_meta
 * 
 * @return (array) $plugin_meta
 **/
function secupress_no_plugin_row_meta( $plugin_meta ) {
	global $current_screen;

	if ( empty( $plugin_meta ) || ! isset( $current_screen ) || ! isset( $_GET['plugin_status'] ) || strpos( $_GET['plugin_status'], 'secupress_' ) !== 0 ) {
		return $plugin_meta;
	}
	$plugin_meta = array_map( 'wp_strip_all_tags', $plugin_meta );

	return $plugin_meta;
}

add_filter( 'plugin_row_meta', 'secupress_no_plugin_install_meta', SECUPRESS_INT_MAX );
/**
 * Remove any links in the meta in our not installed plugins list
 *
 * @author Julio Potier
 * @since 2.2.6
 * 
 * @param (array) $plugin_meta
 * @return (array) $plugin_meta
 **/
function secupress_no_plugin_install_meta( $plugin_meta ) {
	global $current_screen;

	if ( empty( $plugin_meta ) || ! isset( $current_screen ) || ! isset( $_GET['plugin_status'] ) || 'secupress_not_installed' !== $_GET['plugin_status'] || empty( array_filter( secupress_get_not_installed_plugins_list() ) ) ) {
		return $plugin_meta;
	}
	$plugin_meta = array_map( 'wp_strip_all_tags', $plugin_meta );

	return $plugin_meta;
}

add_filter( 'all_plugins', 'secupress_no_plugin_filter_all_plugins', 1 );
function secupress_no_plugin_filter_all_plugins( $plugins ) {
	if ( is_multisite() && ! is_network_admin() ) {
		$deleted = secupress_get_not_installed_plugins_list( 'all' );
		$plugins = array_diff_key( $plugins, $deleted );
	}
	return $plugins;
}

add_filter( 'plugins_list', 'secupress_no_plugin_filter_plugins_list', SECUPRESS_INT_MAX );
/**
 * Add a tab with our plugins
 *
 * @author Julio Potier
 * @since 2.2.6
 * 
 * @param (array) $plugins_list
 * @return (array) $plugins_list
 **/
function secupress_no_plugin_filter_plugins_list( $plugins_list ) {
	if ( is_multisite() && ! is_network_admin() ) {
		return $plugins_list;
	}
	// activated or not
	$not_installed_plugins      = secupress_get_not_activated_plugins_list();
	$plugins_list['secupress_not_activated']   = $not_installed_plugins;
	$plugins_list['secupress_not_deactivated'] = secupress_get_not_deactivated_plugins_list();
	// not installed
	$not_installed_plugins      = secupress_get_not_installed_plugins_list( 'all' );
	foreach ( $plugins_list as $type => $list ) {
		$plugins_list[ $type ]  = array_diff_key( $list, $not_installed_plugins );
	}
	$plugins_list['secupress_not_installed']  = $not_installed_plugins;
	$plugins_list['secupress_not_installed'] += secupress_get_not_installed_plugins_list( 'mu' );
	// Deleted
	$deleted_plugins            = secupress_get_deleted_plugins_list( 'all' );
	$deleted_muplugins          = secupress_get_deleted_plugins_list( 'mu' );
	foreach ( $plugins_list as $type => $list ) {
		$plugins_list[ $type ]  = array_diff_key( $list, $deleted_plugins );
	} 
	$plugins_list['mustuse']    = array_diff_key( get_mu_plugins(), $deleted_muplugins );
	$plugins_list['secupress_deleted'] = $deleted_plugins + $deleted_muplugins;

	return $plugins_list;
}

// add_filter( 'plugins_list_status_text', 'secupress_no_plugin_install_plugins_tab_label', 10, 3 );
/**
 * Filter the default name for our link (maybe in the future) ////
 *
 * @author Julio Potier
 * @since 2.2.6
 * 
 * @param (string) $text
 * @param (int) $count
 * @param (string) $type
 * @return (string) $string
 **/
function secupress_no_plugin_install_plugins_tab_label( $text, $count, $type ) {
	switch ( $type ) {
		case 'secupress_deleted':
			$text = _nx( 'Attempted Deletion', 'Attempted Deletions', $count, 'plugins', 'secupress' );
		break;
		case 'secupress_not_activated':
			$text = _nx( 'Attempted Activation', 'Attempted Activations', $count, 'plugins', 'secupress' );
		break;
		case 'secupress_not_deactivated':
			$text = _nx( 'Attempted Deactivation', 'Attempted Deactivations', $count, 'plugins', 'secupress' );
		break;
		case 'secupress_not_installed':
        	$text = _nx( 'Attempted Installation', 'Attempted Installation', $count, 'plugins', 'domain' );
		break;
	}
    return $text;
}

add_action( 'admin_head-plugins.php', 'secupress_no_plugin_action_add_class_SP_Plugins_List_Table_Add_Status' );
/**
 * Add class to hack the allowed status, to be delete (future) ////
 *
 * @author Julio Potier
 * @since 2.2.6
 * 
 * @param (array) $update_plugins
 * @return (array) $update_plugins
 **/
function secupress_no_plugin_action_add_class_SP_Plugins_List_Table_Add_Status() {

	foreach ( secupress_get_not_installed_plugins_list( 'all' ) as $file => $dummy ) {
		remove_all_filters( 'in_plugin_update_message-' . $file );
	}
	
	secupress_plugin_page_add_class_SP_Plugins_List_Table_status_free();
}


add_action( 'in_admin_header', 'secupress_no_plugin_deletion_admin' );
add_action( 'admin_footer', 'secupress_no_plugin_deletion_admin' );
/**
 * Wrap the whole page with "#plugin-filter" so allow reinstall ajax link to work natively
 *
 * @since 2.2.6
 * @author Julio Potier
 **/
function secupress_no_plugin_deletion_admin() {
	global $status, $pagenow;
	if ( 'plugins.php' === $pagenow && 'secupress_deleted' === $status ) {
		if ( 'in_admin_header' === current_action() ) {
			echo '<div id="plugin-filter">';
		} else {
			echo '</div>';
		}
	}
}

add_filter( 'admin_body_class', 'secupress_no_plugin_action_add_css_body_class' );
/**
 * Add the plugin_status as css class
 *
 * @author Julio Potier
 * @since 2.2.6
 * 
 * @param (string) $classes
 * @return (string) $classes
 **/
	function secupress_no_plugin_action_add_css_body_class( $classes ) {
	global $pagenow;
	if ( 'plugins.php' !== $pagenow || ! isset( $_GET['plugin_status'] ) || strpos( $_GET['plugin_status'], 'secupress_' ) !== 0 ) {
		return $classes;
	}
	$function_name = 'secupress_get_' . str_replace( 'secupress_', '', $_GET['plugin_status'] ) . '_plugins_list';
	if ( function_exists( $function_name ) && is_callable( $function_name ) && ! empty( array_filter( $function_name() ) ) ) {
		$classes .= sanitize_html_class( $_GET['plugin_status'] );
	}

	return $classes;
}

add_action( 'admin_footer-plugins.php', 'secupress_no_plugin_install_tab_css_js', 100 );
/**
 * Hide the "Add new plugin" link next to the page title.
 * Change the label ot our tab (to be deleted, future) ////
 * Remove the actions but delete in bulk select
 *
 * @author Julio Potier
 * @since 1.0
 * @since 2.2.6 Add the scripts
 */
function secupress_no_plugin_install_tab_css_js() {
	?>
	<style type="text/css">
		/* red color for sensible tabs */
		.secupress_not_installed > a, .secupress_deleted > a{ color: #b32d2e}
		/* better width for plugin col */
		table.plugins th:nth-child(2) { min-width:230px; }
		/* add a cursor on "reinstall" link */
		.install-now{ cursor: pointer;}
		/* hide the "add new" button */
		.wrap .page-title-action,a.add-new-h2{display:none}
		/* Add some background on not installed plugins */
        .secupress_not_installed #the-list tr.inactive {
            background-image: linear-gradient(130deg, rgba(170, 170, 170, 0.07) 25%, transparent 25%, transparent 50%, rgba(170, 170, 170, 0.07) 50%, rgba(170, 170, 170, 0.07) 75%, transparent 75%, transparent 100%);
            background-size: 12px 15px;
        }
        .secupress_not_installed #the-list tr.inactive:nth-child(even) {
            background-image: linear-gradient(130deg, rgba(170, 170, 170, 0.13) 25%, transparent 25%, transparent 50%, rgba(170, 170, 170, 0.13) 50%, rgba(170, 170, 170, 0.13) 75%, transparent 75%, transparent 100%);
            background-size: 12px 15px;
        }
		/* Add some background on deleted plugins */
		.secupress_deleted #the-list tr.inactive {
			background-image: linear-gradient(130deg, rgba(170, 170, 170, 0.07) 25%, transparent 25%, transparent 50%, rgba(170, 170, 170, 0.07) 50%, rgba(170, 170, 170, 0.07) 75%, transparent 75%, transparent 100%);
			background-size: 12px 15px;
		}
		.secupress_deleted #the-list tr.inactive:nth-child(even) {
			background-image: linear-gradient(130deg, rgba(170, 170, 170, 0.13) 25%, transparent 25%, transparent 50%, rgba(170, 170, 170, 0.13) 50%, rgba(170, 170, 170, 0.13) 75%, transparent 75%, transparent 100%);
			background-size: 12px 15px;
		}
		/* Add some background on not activated plugins */
		.secupress_not_activated #the-list tr.inactive {
			background-image: linear-gradient(130deg, rgba(170, 170, 170, 0.07) 25%, transparent 25%, transparent 50%, rgba(170, 170, 170, 0.07) 50%, rgba(170, 170, 170, 0.07) 75%, transparent 75%, transparent 100%);
			background-size: 12px 15px;
		}
		.secupress_not_activated #the-list tr.inactive:nth-child(even) {
			background-image: linear-gradient(130deg, rgba(170, 170, 170, 0.13) 25%, transparent 25%, transparent 50%, rgba(170, 170, 170, 0.13) 50%, rgba(170, 170, 170, 0.13) 75%, transparent 75%, transparent 100%);
			background-size: 12px 15px;
		}
	</style>
	<script>
	jQuery(document).ready(function($) {
		$(document).on('wp-plugin-install-success', function(event, data) {
			setTimeout(function() {
				$('a[data-slug="'+data.slug+'"]').parent().parent().parent().parent().parent().hide('fast');
			}, 1500);
		});
		$( 'div.bulkactions' ).remove();
		// Rename the label because of a bug in WP, @see #60495
		if ( $('li.secupress_not_installed a').length ) {
			$('li.secupress_not_installed a').html(function(index, oldText) {
				var textBeforeSpan = oldText.split('<span')[0];
				var theSpan        = oldText.split('<span')[1];
				return '<?php echo esc_js( _x( 'Attempted Installation', 'plugin', 'secupress' ) ); ?> <span' + theSpan;
			});
		}
		if ( $('li.secupress_not_activated a').length ) {
			$('li.secupress_not_activated a').html(function(index, oldText) {
				var textBeforeSpan = oldText.split('<span')[0];
				var theSpan        = oldText.split('<span')[1];
				return '<?php echo esc_js( _x( 'Attempted Activation', 'plugin', 'secupress' ) ); ?> <span' + theSpan;
			});
		}
		if ( $('li.secupress_not_deactivated a').length ) {
			$('li.secupress_not_deactivated a').html(function(index, oldText) {
				var textBeforeSpan = oldText.split('<span')[0];
				var theSpan        = oldText.split('<span')[1];
				return '<?php echo esc_js( _x( 'Attempted Deactivation', 'plugin', 'secupress' ) ); ?> <span' + theSpan;
			});
		}
		if ( $('li.secupress_deleted a').length ) {
			$('li.secupress_deleted a').html(function(index, oldText) {
				var textBeforeSpan = oldText.split('<span')[0];
				var theSpan        = oldText.split('<span')[1];
				return '<?php echo esc_js( _x( 'Attempted Deletion', 'plugin', 'secupress' ) ); ?> <span' + theSpan;
			});
		}
	});
	</script>
	<?php 
	if ( empty( array_filter( secupress_get_not_installed_plugins_list() ) ) && ( isset( $_GET['plugin_status'] ) && 'secupress_not_installed' !== $_GET['plugin_status'] ) ) {
		return;
	}
	?>
	<script type="text/javascript">
	jQuery(document).ready(function($) {
		$('.secupress-dashicon.dashicons-editor-expand').on('click', function(){
			$(this).toggleClass(['dashicons-editor-expand', 'dashicons-editor-contract']);
			if ( $(this).hasClass('dashicons-editor-contract') ) {
				$('.secupress-dashicon.dashicons-arrow-right-alt2').toggleClass('dashicons-arrow-right-alt2 dashicons-arrow-down-alt2');
				$('.secupress-toggle-me').show('fast');
			} else {
				$('.secupress-dashicon.dashicons-arrow-down-alt2').toggleClass('dashicons-arrow-right-alt2 dashicons-arrow-down-alt2');
				$('.secupress-toggle-me').hide('fast');
			}
		});
		$('.secupress-dashicon.dashicons-arrow-right-alt2').on('click', function(){
			$(this).toggleClass('dashicons-arrow-right-alt2 dashicons-arrow-down-alt2').nextAll('div').first().toggle('fast');
		});
	} );
	// bulk actions
	jQuery(document).ready(function($) {
		// Remove the links in the "dependancies" meta
		let links        = document.querySelectorAll('a.thickbox.open-plugin-details-modal');
		links.forEach(function(link) {
			let textNode = document.createTextNode(link.textContent);
			link.parentNode.replaceChild(textNode, link);
		});
		// Remove the action in the bulk select but "delete" and default
	    if ( $('.bulkactions select option[value="delete-selected"]').length > 0 ) {
	        $('.bulkactions select').children('option').each(function() {
	            if ($(this).val() !== 'delete-selected' && $(this).val() !== '-1' ) {
	                $(this).remove();
	            }
	        });
	    } else {
	    	// Or remove all if "delete" is not present
	        $('.bulkactions').remove();
	    }
	});
	// Ajax
	jQuery(document).ready(function($) {
		var ajaxQueue = [];

		function performAjaxRequest(elem) {
			let _ajax_nonce = '<?php echo esc_js( wp_create_nonce( 'secupress_check_malware_plugin' ) ); ?>';
			let plugin      = elem.data('plugin');
			let muplugin    = elem.data('muplugin');
			if (elem.prop("tagName").toLowerCase() === "span") {
				elem.find('span').css({ '-webkit-transform': 'scaleX(-1)', 'transform': 'scaleX(-1)' });
			} else { // button
				let spinnerSpan = $('<span><span class="spinner is-active" style="float:left"></span></span>');
				elem.parent().parent().html( spinnerSpan );
				elem = spinnerSpan;
			}

			$.ajax({
				url     : ajaxurl,
				type    : 'POST',
				dataType: 'json',
				data: {
					action     : 'secupress_check_malware_plugin',
					_ajax_nonce: _ajax_nonce,
					plugin     : plugin,
					muplugin   : muplugin,
				},
				success: function(response) {
					elem.html(response.data);
				},
				error: function(xhr, status, error) {
					elem.html(xhr.statusText + ' ' + xhr.status);
				},
				complete: function() {
					nextAjaxRequest();
				}
			});
		}

		$('table tr span[data-plugin]:visible').each(function(index) {
			var span = $(this);
			ajaxQueue.push(function() {
				performAjaxRequest(span);
			});
		});

		var nextAjaxRequest = function() {
			if (ajaxQueue.length > 0) {
				var nextRequest = ajaxQueue.shift();
				nextRequest();
			}
		};

		$('button.refreshscan').on('click', function() {
			performAjaxRequest($(this));
		});

		nextAjaxRequest();
	});
	</script>
	<?php
}


add_action( 'load-plugin-install.php', 'secupress_no_plugin_install_page_redirect' );
/**
 * Forbid access to the plugin installation page.
 *
 * @author Julio Potier
 * @since 1.0
 */
function secupress_no_plugin_install_page_redirect() {
	if ( ! isset( $_GET['tab'] ) || 'plugin-information' !== $_GET['tab'] ) {
		secupress_die( __( 'You do not have sufficient permissions to install plugins on this site.', 'secupress' ), '', [ 'force_die' => true, 'attack_type' => 'plugins' ] );
	}
}


add_action( 'check_admin_referer', 'secupress_no_plugin_install_avoid_install_plugin' );
/**
 * Forbid plugin installation.
 *
 * @author Julio Potier
 * @since 1.0
 *
 * @param (string) $action
 */
function secupress_no_plugin_install_avoid_install_plugin( $action ) {
	if ( 'plugin-upload' === $action || 0 === strpos( $action, 'install-plugin_' ) ) {
		secupress_die( __( 'You do not have sufficient permissions to install plugins on this site.', 'secupress' ), '', [ 'force_die' => true, 'attack_type' => 'plugins' ] );
	}
}


add_action( 'admin_menu', 'secupress_no_plugin_install_remove_new_plugins_link', 100 );
/**
 * Remove the "Add new plugin" item from the admin menu.
 *
 * @author Julio Potier
 * @since 1.0
 */
function secupress_no_plugin_install_remove_new_plugins_link() {
	global $submenu;
	unset( $submenu['plugins.php'][10] );
}

/**
 * Prevent the upload of plugin files
 *
 * @since 1.0
 * @author Julio Potier
 */
if ( isset( $_FILES['pluginzip'] ) ) {
	secupress_die( __( 'You do not have sufficient permissions to install plugins on this site.', 'secupress' ), '', [ 'force_die' => true, 'attack_type' => 'plugins' ] );
}

add_filter( 'pre_option_active_plugins', 'secupress_no_plugin_uninstall_check_plugin_active', PHP_INT_MAX );
/**
 * Remove the possibly deleted plugins from active plugins but without updating our option
 *
 * @since 2.2.6
 * @author Julio Potier
 * 
 * @param (array) $plugins
 * 
 * @return (array) $plugins
 */
function secupress_no_plugin_uninstall_check_plugin_active( $plugins ) {
	remove_filter( 'pre_option_active_plugins', 'secupress_no_plugin_uninstall_check_plugin_active', PHP_INT_MAX );
	if ( ! function_exists( 'validate_active_plugins' ) ) {
		require_once( ABSPATH . 'wp-admin/includes/plugin.php' );
	}
	$not_valid   = array_keys( validate_active_plugins() );
	if ( $not_valid ) {
		$plugins = array_diff( $plugins, $not_valid );
	}
	add_filter( 'pre_option_active_plugins', 'secupress_no_plugin_uninstall_check_plugin_active', PHP_INT_MAX );
	return $plugins;
}