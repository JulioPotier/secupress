<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/* PLUGINS */

/**
 * Wrapper for the 3 next plugins functions
 *
 * @since 2.2.6
 * @author Julio Potier
 * 
 * @param (string) $type
 * 
 * @return (array|false) False on error on $type param
 **/
function secupress_get_bad_plugins( $type ) {
	switch( $type ) {
		case 'v':
		case 'vuln':
		case 'vulns':
		case 'vulnerable':
		case 'vulnerables':
			return secupress_get_vulnerable_plugins();
		break;

		case 'c':
		case 'close':
		case 'closed':
		case 'r':
		case 'remove':
		case 'removed':
			return secupress_get_removed_plugins();
		break;
		
		case 'o':
		case 'old':
		case 'olds':
		case 'n':
		case 'nu':
		case 'not-update':
		case 'no-update':
		case 'not-updated':
			return secupress_get_notupdated_plugins();
		break;
	}
	return false;
}

/**
 * Get the plugins closed on repo
 *
 * @since 2.2.6 Get from our option
 * @author Julio Potier
 * @since 1.0
 * @author Grégory Viguier
 *
 * @return (array|bool) The plugins removed from the repository: dirname as array keys and plugin path as values. Return false if the file is not readable.
 */
function secupress_get_removed_plugins() {
	$plugins = get_site_option( SECUPRESS_CLOSED_PLUGINS );
	return $plugins ?? [];
}

/**
 * Get the plugins not update since 2 years from repo
 *
 * @since 2.2.6 Get from our option
 * @author Julio Potier
 * @since 1.0
 * @author Grégory Viguier
 *
 * @return (array|bool) The plugins from the repository not updated for 2 years
 */
function secupress_get_notupdated_plugins() {
	$plugins = get_site_option( SECUPRESS_OLD_PLUGINS );
	return $plugins ?? [];
}


/**
 * Get the vulnerable plugins
 *
 * @since 2.2.6 Get from our option
 * @author Julio Potier
 * @since 1.0
 * @author Grégory Viguier
 *
 * @return (array)
 */
function secupress_get_vulnerable_plugins() {
	$vulnerable_plugins = get_site_option( SECUPRESS_BAD_PLUGINS );
	return $vulnerable_plugins ? (array) json_decode( $vulnerable_plugins, true ) : [];
}


/**
 * Returns the list of installed plugin that should not be, all and mus
 *
 * @author Julio Potier 
 * @since 2.2.6
 * 
 * @param (string) $type 'all' or 'mu' or ''
 * @return (array) $plugins or []
 **/
function secupress_get_not_installed_plugins_list( $type = '' ) {
	if ( ! defined( 'SECUPRESS_INSTALLED_PLUGINS' ) ) {
		return [];
	}

	$ins_plugins    = get_site_option( SECUPRESS_INSTALLED_PLUGINS );
	$mus_plugins    = _secupress_get_not_installed_muplugins_list();
	if ( ! $ins_plugins && ! $mus_plugins ) {
		return [];
	}
	$plugins        = [];
	$get_plugins    = get_plugins();
	$plugins['all'] = array_diff_key( $get_plugins, $ins_plugins );

	$plugins['mu']  = $mus_plugins;

	if ( isset( $plugins[ $type ] ) ) {
		return $plugins[ $type ];
	}

	return $plugins;
}


/**
 * Returns the list of activated plugin that should not be
 *
 * @author Julio Potier 
 * @since 2.2.6
 * 
 * @return (array) $wp_plugins or []
 **/
function secupress_get_not_activated_plugins_list() {
	static $wp_plugins;

	if ( ! defined( 'SECUPRESS_ACTIVE_PLUGINS' ) ) {
		return [];
	}

	if ( isset( $wp_plugins ) ) {
		return $wp_plugins;
	}

	$our_plugins  = get_option( SECUPRESS_ACTIVE_PLUGINS, false );
	if ( false === $our_plugins ) {
		return [];
	}
	require_once( ABSPATH . '/wp-admin/includes/upgrade.php' );
	$difs_plugins = array_flip( array_diff( __get_option( 'active_plugins' ), $our_plugins ) );
	$wp_plugins   = array_intersect_key( get_plugins(), $difs_plugins );
	return $wp_plugins;
}

/**
 *
 * @author Julio Potier 
 * @since 2.2.6
 * 
 * @return (array) $wp_plugins or []
 **/
function secupress_get_not_deactivated_plugins_list() {
	static $wp_plugins;

	if ( ! defined( 'SECUPRESS_ACTIVE_PLUGINS' ) ) {
		return [];
	}

	if ( isset( $wp_plugins ) ) {
		return $wp_plugins;
	}

	$our_plugins  = get_option( SECUPRESS_ACTIVE_PLUGINS, false );
	if ( false === $our_plugins ) {
		return [];
	}
	require_once( ABSPATH . '/wp-admin/includes/upgrade.php' );
	$difs_plugins = array_flip( array_diff( $our_plugins, __get_option( 'active_plugins' ) ) );
	$wp_plugins   = array_intersect_key( get_plugins(), $difs_plugins );
	return $wp_plugins;
}

/**
 * Get deleted mu plugins list
 *
 * @author Julio Potier 
 * @since 2.2.6
 * 
 * @return (array) $wp_plugins or []
 **/
function _secupress_get_deleted_mu_plugins_list() {
	static $wp_plugins;

	if ( ! defined( 'SECUPRESS_ALL_MUPLUGINS' ) ) {
		return [];
	}

	if ( isset( $wp_plugins ) ) {
		return $wp_plugins;
	}

	$all_plugins  = get_option( SECUPRESS_ALL_MUPLUGINS, false );
	if ( false === $all_plugins ) {
		return [];
	}
	$difs_plugins = array_diff_key( $all_plugins, get_mu_plugins() );
	
	array_walk($difs_plugins, function( &$item ) {
		$item['muplugin'] = 1;
	});

	return $difs_plugins;
}

/**
 * Get deleted plugins list
 *
 * @author Julio Potier 
 * @since 2.2.6
 * 
 * @param (string) $type 'all' or 'mu' or ''
 * @return (array) $wp_plugins or []
 **/
function secupress_get_deleted_plugins_list( $type = 'all' ) {
	static $wp_plugins;

	if ( ! defined( 'SECUPRESS_INSTALLED_PLUGINS' ) ) {
		return [];
	}

	if ( isset( $wp_plugins[ $type ] ) ) {
		return $wp_plugins[ $type ];
	}

	$all_plugins  = get_site_option( SECUPRESS_INSTALLED_PLUGINS, false );
	if ( false === $all_plugins ) {
		return [];
	}
	$wp_plugins = [];
	if ( 'all' === $type || ! $type ) {
		$wp_plugins = array_diff_key( $all_plugins, get_plugins() );
	}
	if ( 'mu' === $type || ! $type ) {
		$wp_plugins += _secupress_get_deleted_mu_plugins_list();
	}

	return $wp_plugins;
}

/**
 * Returns the list of installed mu plugin that should not be, from WPMU path
 *
 * @author Julio Potier
 * @since 2.2.6
 * 
 * @return (array) plugins or muplugins or both
 **/
function _secupress_get_not_installed_muplugins_list() {
	static $wp_plugins;

	if ( ! is_dir( WPMU_PLUGIN_DIR ) ) {
		return [];
	}

	if ( isset( $wp_plugins ) ) {
		return $wp_plugins;
	}

	$plugin_files = [];
	// Files in wp-content/mu-plugins directory.
	$plugins = glob( WPMU_PLUGIN_DIR . '/*.php_' . str_repeat( '[0-9]', 14 ) );
	if ( $plugins ) {
		foreach ( $plugins as $file ) {
			$plugin_files[] = basename( $file );
		}
	} else {
		return [];
	}
	$plugin_files = array_flip( array_flip( $plugin_files ) );
	if ( empty( $plugin_files ) ) {
		return [];
	}

	$wp_plugins = [];
	foreach ( $plugin_files as $plugin_file ) {
		$plugin_data                = get_plugin_data( WPMU_PLUGIN_DIR . "/$plugin_file", false, false );
		$plugin_data['muplugin']    = 1; // Custom data.
		$plugin_data['filepath']    = $plugin_file; // Custom data.

		if ( empty( $plugin_data['Name'] ) ) {
			$plugin_data['Name']    = $plugin_file;
		}
		$wp_plugins[ $plugin_file ] = $plugin_data;
	}

	uasort( $wp_plugins, '_sort_uname_callback' );

	return $wp_plugins;
}

/* THEMES */

/**
 * Wrapper for the 3 next themes functions
 *
 * @since 2.2.6
 * @author Julio Potier
 * 
 * @param (string) $type
 * 
 * @return (array|false) False on error on $type param
 **/
function secupress_get_bad_themes( $type ) {
	switch( $type ) {
		case 'v':
		case 'vuln':
		case 'vulnerable':
		case 'vulnerables':
			return secupress_get_vulnerable_themes();
		break;

		case 'c':
		case 'close':
		case 'closed':
		case 'r':
		case 'remove':
		case 'removed':
			return secupress_get_removed_themes();
		break;
		
		case 'o':
		case 'old':
		case 'olds':
		case 'not-update':
		case 'no-update':
		case 'not-updated':
			return secupress_get_notupdated_themes();
		break;
	}
	return false;
}

/**
 * Get the vulnerable themes
 *
 * @since 1.0
 * @author Grégory Viguier
 *
 * @return (array)
 */
function secupress_get_vulnerable_themes() {
	$themes = get_site_option( SECUPRESS_BAD_THEMES );
	return $themes ? (array) json_decode( $themes, true ) : array();
}


/**
 * Get the themes not update since 2 years from repo
 *
 * @since 2.2.6
 * @author Julio Potier
 *
 * @return (array|bool) The themes from the repository not updated for 2 years
 */
function secupress_get_notupdated_themes() {
	$themes = get_site_option( SECUPRESS_OLD_THEMES );
	return $themes ?? [];
}


/**
 * Get the vulnerable plugins
 *
 * @since 2.2.6
 * @author Julio Potier
 *
 * @return (array)
 */
function secupress_get_removed_themes() {
	$themes = get_site_option( SECUPRESS_CLOSED_THEMES );
	return $themes ? (array) json_decode( $themes, true ) : [];
}

/** FTP **/

/**
 * Mimic the WP behaviour without "direct" as result, we need to know which kind of FTP is available.
 *
 * @see get_filesystem_method()
 * @author Julio Potier
 * @since 2.2
 * 
 * @return (string) $method
 **/
function secupress_get_ftp_fs_method() {

	$method = false;

	if ( ! $method && extension_loaded( 'ssh2' ) ) {
		$method = 'ssh2';
	}
	if ( ! $method && extension_loaded( 'ftp' ) ) {
		$method = 'ftpext';
	}
	if ( ! $method && ( extension_loaded( 'sockets' ) || function_exists( 'fsockopen' ) ) ) {
		$method = 'ftpsockets';
	}

	return $method;
}

/**
 * Returns a verbosed version of the FS method
 *
 * @author Julio Potier
 * @since 2.2 
 * 
 * @param (string) $method
 * @return (string) $method
 **/
function secupress_verbose_ftp_fs_method( $method ) {
	if ( secupress_is_submodule_active( 'plugins-themes', 'uploads' ) ) {
		return __( 'Themes & Plugins Upload Disabled', 'secupress' );
	}
	$methods = [ 	
					'direct'     => __( 'Direct File Writing (direct)', 'secupress' ),
					'ssh2'       => __( 'Secure Shell 2 (ssh2)', 'secupress' ),
					'ftpext'     => __( 'File Transfert Protocol Extension (ftpext)', 'secupress' ),
					'ftpsockets' => __( 'File Transfert Protocol with Sockets (ftpsockets)', 'secupress' ),
				];
	return isset( $methods[ $method ] ) ? $methods[ $method ] : $method;
}

/** OTHER **/
/**
 * Darken a color by a percentage
 *
 * @author Julio Potier
 * @since 2.2.6
 * 
 * @param (string) The color to be darkened
 * @param (int) $pervent Integer between 0 & 100
 * 
 * @return (string) $darken_color
 **/
function secupress_darken_color( $color_hex, $percent ) {
	$r = hexdec( substr( $color_hex, 1, 2 ) );
	$g = hexdec( substr( $color_hex, 3, 2 ) );
	$b = hexdec( substr( $color_hex, 5, 2 ) );
	
	$r = max( 0, $r - round( 2.55 * $percent ) );
	$g = max( 0, $g - round( 2.55 * $percent ) );
	$b = max( 0, $b - round( 2.55 * $percent ) );
	
	$darkened_color = sprintf( "#%02X%02X%02X", $r, $g, $b );
	
	return $darkened_color;
}

/**
 * Sanitize a hex color
 *
 * @author Julio Potier
 * @since 2.2.6
 * 
 * @param (string) The color to be sanitized
 * @param (string) The default value is the sanitizatiion failed
 * 
 * @return (string) $color_hex
 **/
function secupress_sanitize_hex_color( $color_hex, $default = '' ) {
    $color_hex = preg_replace('/[^a-fA-F0-9]/', '', $color_hex);
    if ( mb_strlen( $color_hex ) !== 6 ) {
        return $default;
    }
    
    return '#' . $color_hex;
}

/** PLUGINS (to be deletes in future) **////
// add_action( 'admin_head-plugins.php', 'secupress_plugin_page_add_class_SP_Plugins_List_Table_status_free' ); // do not uncomment
/**
 * Add class to hack the allowed status, to be delete (future)
 *
 * @author Julio Potier
 * @since 2.2.6
 * 
 * @param (array) $update_plugins
 * @return (array) $update_plugins
 **/
function secupress_plugin_page_add_class_SP_Plugins_List_Table_status_free() {

	if ( class_exists( 'SP_Plugins_List_Table' ) ) {
		return;
	}

	class SP_Plugins_List_Table extends WP_Plugins_List_Table {

		function __construct( $args = array() ) {
			global $status, $page;

			parent::__construct( array(
				'plural' => 'plugins',
				'screen' => isset( $args['screen'] ) ? $args['screen'] : null,
			) );


			$status = 'all';
			if ( isset( $_REQUEST['plugin_status'] ) ) {
				$status = $_REQUEST['plugin_status'];
			}

			if ( isset( $_REQUEST['s'] ) ) {
				$_SERVER['REQUEST_URI'] = add_query_arg( 's', wp_unslash( $_REQUEST['s'] ) );
			}

			$page = $this->get_pagenum();

			$this->show_autoupdates = wp_is_auto_update_enabled_for_type( 'plugin' )
				&& current_user_can( 'update_plugins' )
				&& ( ! is_multisite() || $this->screen->in_admin( 'network' ) );
		}

		protected function extra_tablenav( $which ) {
			global $status;
			if ( 'secupress_not_activated' === $status || 'secupress_not_deactivated' === $status ) {
				$label = __( 'Clear (de)activation attempts', 'secupress' );
			}
			if ( 'secupress_deleted' === $status ) {
				$label = __( 'Clear deleted plugins', 'secupress' );
			}
			if ( ! isset( $label ) ) {
				return;
			}
			?>
			<button class="button button-secondary" name="action" value="clear_<?php echo esc_attr( $status ); ?>"><?php echo esc_html( $label ); ?></button>
			<?php
		} 
	}

	if ( ! isset( $_REQUEST['action'] ) ) {
		global $wp_list_table;
		$wp_list_table = new SP_Plugins_List_Table;
		$wp_list_table->prepare_items();
	}
}

add_filter( 'handle_bulk_actions-plugins', 'secupress_handle_bulk_actions_on_plugins_page', 10, 2 );
/**
 * Let clear the plugin status from us
 *
 * @since 2.2.6
 * @author Julio Potier
 * 
 * @param ($string) $sendback
 * @param (string) $action  
 * 
 * @return ($string) $sendback
 */
function secupress_handle_bulk_actions_on_plugins_page( $sendback, $action ) {
	$sendback = wp_validate_redirect( $sendback ) ? $sendback : admin_url( 'plugins.php' );
	if ( strpos( $action, 'clear_secupress' ) === false ) {
		return $sendback;
	}
	if ( strpos( $action, 'clear_secupress_not' ) === 0 ) {
		remove_all_filters( 'map_meta_cap' );
		$our_plugins = get_option( SECUPRESS_ACTIVE_PLUGINS );
		if ( ! is_multisite() || ! is_network_admin() ) {
			remove_all_filters( 'pre_update_option_active_plugins' );
			remove_all_filters( 'pre_option_active_plugins' );
			update_option( 'active_plugins', $our_plugins );
		} else {
			remove_all_filters( 'pre_update_option_active_sitewide_plugins' );
			remove_all_filters( 'pre_option_active_sitewide_plugins' );
			update_site_option( 'active_sitewide_plugins', $our_plugins );
		}
	} elseif ( strpos( $action, 'clear_secupress_deleted' ) === 0 ) {
		if ( ! is_multisite() ) {
			update_option( SECUPRESS_INSTALLED_PLUGINS, get_plugins() );
			update_option( SECUPRESS_INSTALLED_MUPLUGINS, get_mu_plugins() );
		} else {
			update_site_option( SECUPRESS_INSTALLED_PLUGINS, get_plugins() );
			update_site_option( SECUPRESS_INSTALLED_MUPLUGINS, get_mu_plugins() );
			remove_all_filters( 'pre_site_update_option_active_sitewide_plugins' );
			remove_all_filters( 'pre_site_option_active_sitewide_plugins' );
			update_site_option( SECUPRESS_ACTIVE_PLUGINS_NETWORK, get_site_option( 'active_sitewide_plugins' ) );
		}
	}

	return $sendback;
}

add_action( 'load-plugins.php', 'secupress_handle_bulk_actions_on_plugins_page_hack' );
/**
 * Add $_POST['checked'] = 1 because WP will verify it to handle bulk, but we don't check any plugin, it's a button.
 *
 * @since 2.2.6
 * @author Julio Potier
 */
function secupress_handle_bulk_actions_on_plugins_page_hack(){
	// "clear_secupress_not_activated" "clear_secupress_not_deactivated" "clear_secupress_deleted"
	if ( isset( $_POST['action'] ) && strpos( $_POST['action'], 'clear_secupress' ) === 0 ) {
		$_POST['checked'] = 1; // Hack !
	}
}

/**
 * Reinstall the free plugins on the website
 *
 * @author Julio Potier
 * @since 2.2.6
 **/
function secupress_reinstall_plugins( $plugins = [] ) {
	if ( ! $get_plugins = secupress_cache_data( 'get_plugins' ) ) {
		$get_plugins = get_plugins();
		unset( $get_plugins[ 'secupress-pro/secupress-pro.php' ] );
		secupress_cache_data( 'get_plugins', $get_plugins );
	}
	$reinstalled = [];
	if ( wp_doing_ajax() && ! $plugins ) {
		return wp_list_pluck( $get_plugins, 'Name' );
	}
	$plugins   = ! empty( $plugins ) ? $plugins : $get_plugins;
	$plugins   = apply_filters( 'secupress.reinstall_plugins.list', $plugins );
	$dl_fail   = [ 'icon' => 'info', 'text' => __( 'Download Failed from wp.org', 'secupress' ) ];
	$repo_fail = [ 'icon' => 'info', 'text' => __( 'Plugin Error on wp.org', 'secupress' ) ];
	$not_repo  = [ 'icon' => 'info', 'text' => __( 'Plugin Not Found on wp.org', 'secupress' ) ];

	foreach ( $plugins as $plugin_path => $plugin_infos ) {
	
		list( $plugin_folder, $plugin_file ) = explode( '/', $plugin_path );

		$plugin_data = get_plugin_data( WP_PLUGIN_DIR . '/' . $plugin_path, false, false );
	
		$reinstalled[ $plugin_path ] = sprintf( '<li class="secupress-status-%1$s">%2$s <abbr class="secupress-status-info" title="%1$s"><span class="dashicons dashicons-%1$s"></span></abbr></li>', '%s', $plugin_data['Name'] . '%s' );
		$plugin_api = secupress_plugins_api( $plugin_folder );
		if ( ! is_wp_error( $plugin_api ) && isset( $plugin_api->version, $plugin_api->download_link ) ) {
			if ( ! class_exists( '\Plugin_Upgrader' ) ) {
				require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
			}
			$skin     = new WP_Ajax_Upgrader_Skin();
			$upgrader = new Plugin_Upgrader( $skin );
			$download = $upgrader->download_package( $plugin_api->download_link, false, [] );
			if ( is_wp_error( $download ) ) {
				$reinstalled[ $plugin_path ] = sprintf( $reinstalled[ $plugin_path ], 'fail', '', $dl_fail['text'], $dl_fail['icon'] );
			} else {
				$result   = $upgrader->install( $download,
					[
						'overwrite_package' => true,  
						'is_multi'          => true,
					] );
				@unlink( $download );
				if ( $result ) {
					$reinstalled[ $plugin_path ] = sprintf( $reinstalled[ $plugin_path ], 'success', ' v' . $plugin_api->version, '', '' );
				} else {
					$reinstalled[ $plugin_path ] = sprintf( $reinstalled[ $plugin_path ], 'fail', '', $repo_fail['text'], $repo_fail['icon'] );
				}
			}
		} else {
			$reinstalled[ $plugin_path ] = sprintf( $reinstalled[ $plugin_path ], 'fail', '', $not_repo['text'], $not_repo['icon'] );
		}
		// 1 iteration of foreach, we do not send more than 1 in the ajax req.
		if ( wp_doing_ajax() ) {
			return $reinstalled[ $plugin_path ];
		}
	}
	$count = count( $reinstalled );
	$list  = sprintf( '<ul>%s</ul>', implode( '', $reinstalled ) );
	secupress_add_transient_notice( sprintf( __( 'Plugin reinstallation results: %s', 'secupress' ), $list ) );
}

add_action( 'wp_ajax_secupress_reinstall_plugins', 'secupress_reinstall_plugins_admin_ajax_cb' );
/**
 * Handle the ajax plugin reinstallation
 *
 * @author Julio Potier
 * @since 2.2.6
 **/
function secupress_reinstall_plugins_admin_ajax_cb() {
	if ( ! isset( $_GET['action'] ) || ! check_ajax_referer( $_GET['action'] ) ) {
		wp_die( -1, 403 );
	}
	$plugins = [];
	if ( isset( $_GET['plugins'] ) ) {
		if ( is_array( $_GET['plugins'] ) ) {
			$plugins = $_GET['plugins'];
		} else {
			$plugins[] = $_GET['plugins'];
		}
	}
	$plugins = array_flip( $plugins );
	wp_send_json_success( secupress_reinstall_plugins( $plugins ) );
}

