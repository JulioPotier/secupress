<?php
/**
 * Module Name: No Plugin Actions on Back-end
 * Description: Disable the plugin actions: Installation, Activation, Deactivation, Deletion on back-end. Update and rollback are still possible.
 * Main Module: plugins_themes
 * Author: SecuPress
 * Version: 2.3.17
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );

/**
 * Prevent the upload of plugin files
 *
 * @since 1.0
 * @author Julio Potier
 */
if ( isset( $_FILES['pluginzip'] ) ) {
	secupress_die( __( 'You do not have sufficient permissions to install plugins on this site.', 'secupress' ), '', [ 'force_die' => true, 'attack_type' => 'plugins' ] );
}

// Installation
defined( 'SECUPRESS_INSTALLED_PLUGINS' )   || define( 'SECUPRESS_INSTALLED_PLUGINS'     , '_secupress_installed_plugins' );
defined( 'SECUPRESS_INSTALLED_MUPLUGINS' ) || define( 'SECUPRESS_INSTALLED_MUPLUGINS'   , '_secupress_installed_muplugins' );
// (De)Activation
defined( 'SECUPRESS_ACTIVE_PLUGINS' ) || define( 'SECUPRESS_ACTIVE_PLUGINS', '_secupress_active_plugins' );
if ( is_multisite() ) {
	defined( 'SECUPRESS_ACTIVE_PLUGINS_NETWORK' ) || define( 'SECUPRESS_ACTIVE_PLUGINS_NETWORK', '_secupress_active_sitewide_plugins' );
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
	$disallowed_caps = apply_filters( 'secupress.plugins.plugin-installation.disallowed_caps', [ 'delete_plugins' => 1, 'install_plugins' => 1, 'upload_plugin' => 1, 'resume_plugin' => 1, 'activate_plugin' => 1, 'deactivate_plugin' => 1, 'deactivate_plugins' => 1/*, 'activate_plugins' => 1', manage_network_plugins' => 1*/ ] );
	
	if ( ! isset( $disallowed_caps[ $cap ] ) ) {
		return $caps;
	}
	
	if ( 'install_plugins' === $cap && secupress_is_readonly_plugin_info_request() ) {
		return $caps;
	}
	
	return ['do_not_allow'];
}

/**
 * Check if the request is a read-only consultation (changelog, description, etc.)
 * 
 * @since 2.4.1
 * @author Julio Potier
 * 
 * @return bool True if it's a read-only consultation request
 */
function secupress_is_readonly_plugin_info_request() {
	if ( ! isset( $_SERVER['REQUEST_METHOD'] ) || 'GET' !== $_SERVER['REQUEST_METHOD'] ) {
		return false;
	}
	
	if ( ! isset( $_GET['tab'] ) || 'plugin-information' !== $_GET['tab'] ) {
		return false;
	}
	
	$readonly_sections = [ 'changelog', 'description', 'faq', 'screenshots', 'reviews', 'other_notes' ];
	if ( ! isset( $_GET['section'] ) || ! in_array( $_GET['section'], $readonly_sections, true ) ) {
		return false;
	}
	
	$install_actions = [ 'install', 'upload', 'activate', 'activate-selected', 'deactivate-selected' ];
	foreach ( $install_actions as $action ) {
		if ( isset( $_GET[ $action ] ) || isset( $_POST[ $action ] ) ) {
			return false;
		}
	}
	
	if ( isset( $_GET['plugin'] ) ) {
		$plugin_slug = sanitize_text_field( $_GET['plugin'] );
		if ( secupress_is_plugin_installed( $plugin_slug ) ) {
			return true;
		}
	}
	
	$referer = wp_get_referer();
	if ( $referer && false !== strpos( $referer, 'plugins.php' ) ) {
		return true;
	}
	
	if ( isset( $_GET['TB_iframe'] ) && 'true' === $_GET['TB_iframe'] ) {
		return true;
	}
	
	return false;
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

// add_action( 'secupress.plugins.loaded', 'secupress_no_plugin_install_warning_no_muplugin' );
/**
 * Run secupress_no_plugin_actions__activation() if needed and require pro version of the module
 *
 * @since 2.3.17 Change hook from 'admin_init' + require pro version here
 * @since 2.2.6
 * @author Julio Potier
 **/
function secupress_no_plugin_install_warning_no_muplugin() {
	if ( secupress_get_module_option( 'plugins-installation-pro', false, 'plugins-themes') ) {
		require_once( SECUPRESS_PRO_MODULES_PATH . 'plugins-themes/plugins/plugin-installation-pro.php' );
	}
	// if ( ! defined( 'SECUPRESS_NO_PLUGIN_ACTION_RUNNING' ) &&  ) {
		// secupress_no_plugin_actions__activation();
	// } elseif ( defined( 'SECUPRESS_NO_PLUGIN_ACTION_RUNNING' ) && secupress_get_module_option( 'plugins-installation-pro', false, 'plugins-themes') ) {
	// }
}
