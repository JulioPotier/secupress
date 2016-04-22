<?php
defined( 'ABSPATH' ) or die( 'Cheatin\' uh?' );

add_action( 'admin_init', 'secupress_plugins_to_deactivate' );
/**
 * This warning is displayed when some plugins may conflict with SecuPress.
 *
 * @since 1.0
 */
function secupress_plugins_to_deactivate() {
	if ( ! current_user_can( secupress_get_capability() ) ) {
		return;
	}

	$plugins = array(
		'wordfence/wordfence.php'
	);

	$plugins_to_deactivate = array_filter( $plugins, 'is_plugin_active' );

	if ( ! $plugins_to_deactivate ) {
		return;
	}

	$message  = '<p>' . sprintf( __( '%s: ', 'secupress' ), '<strong>' . SECUPRESS_PLUGIN_NAME . '</strong>' );
	$message .= __( 'The following plugins are not compatible with this plugin and may cause unexpected results:', 'secupress' );
	$message .= '</p><ul>';
	foreach ( $plugins_to_deactivate as $plugin ) {
		$plugin_data = get_plugin_data( WP_PLUGIN_DIR . DIRECTORY_SEPARATOR . $plugin );
		$message .= '<li>' . $plugin_data['Name'] . '</span> <a href="' . esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=deactivate_plugin&plugin=' . urlencode( $plugin ) ), 'deactivate_plugin' ) ) . '" class="button-secondary alignright">' . __( 'Deactivate' ) . '</a></li>';
	}
	$message .= '</ul>';

	secupress_add_notice( $message, 'error', 'deactivate-plugin' );
}


add_action( 'admin_init', 'secupress_add_packed_plugins_notice' );
/**
 * Display a notice if the standalone version of a plugin packed in SecuPress is used.
 *
 * @since 1.0
 */
function secupress_add_packed_plugins_notice() {
	if ( ! current_user_can( secupress_get_capability() ) ) {
		return;
	}

	/**
	 * Filter the list of plugins packed in SecuPress.
	 *
	 * @since 1.0
	 *
	 * @param (array) A list of plugin paths, relative to the plugins folder. The "file name" of the packed plugin is used as key.
	 *                Example: array( 'move-login' => 'sf-move-login/sf-move-login.php' )
	 */
	$plugins = apply_filters( 'secupress.plugins.packed-plugins', array() );
	$plugins = array_filter( $plugins, 'is_plugin_active' );

	if ( ! $plugins || secupress_notice_is_dismissed( 'deactivate-packed-plugins' ) ) {
		return;
	}

	$message  = '<p>';
	$message .= sprintf(
		/* translators: 1 is the plugin name */
		__( 'The features of the following plugins are included into %1$s. You can deactivate the plugins now and enable these features later in %1$s:', 'secupress' ),
		'<strong>' . SECUPRESS_PLUGIN_NAME . '</strong>'
	);
	$message .= '</p><ul>';
	foreach ( $plugins as $plugin ) {
		$plugin_data = get_plugin_data( WP_PLUGIN_DIR . DIRECTORY_SEPARATOR . $plugin );
		$message .= '<li>' . $plugin_data['Name'] . '</span> <a href="' . esc_url( wp_nonce_url( admin_url( 'plugins.php?action=deactivate&plugin=' . urlencode( $plugin ) ), 'deactivate-plugin_' . $plugin ) ) . '" class="button-secondary alignright">' . __( 'Deactivate' ) . '</a></li>';
	}
	$message .= '</ul>';

	secupress_add_notice( $message, 'error', 'deactivate-packed-plugins' );
}


add_action( 'activate_plugin', 'secupress_reset_packed_plugins_notice_on_plugins_activation' );
/**
 * When the standalone version of a plugin packed in SecuPress is activated, reinit the notice.
 *
 * @since 1.0
 *
 * @param (string) $plugin The plugin path, relative to the plugins folder.
 */
function secupress_reset_packed_plugins_notice_on_plugins_activation( $plugin ) {
	if ( ! current_user_can( secupress_get_capability() ) ) {
		return;
	}

	/** This action is documented in inc/admin/notices.php */
	$plugins = apply_filters( 'secupress.plugins.packed-plugins', array() );

	if ( ! $plugins ) {
		return;
	}

	$plugins = array_flip( $plugins );

	if ( isset( $plugins[ $plugin ] ) ) {
		secupress_reinit_notice( 'deactivate-packed-plugins' );
	}
}


add_action( 'secupress_activate_plugin', 'secupress_deactivate_standalone_plugin_on_packed_plugin_activation' );
/**
 * When a plugin packed in SecuPress is activated, deactivate the standalone version.
 *
 * @since 1.0
 *
 * @param (string) $plugin The name of the packed plugin.
 */
function secupress_deactivate_standalone_plugin_on_packed_plugin_activation( $plugin ) {
	/** This action is documented in inc/admin/notices.php */
	$plugins = apply_filters( 'secupress.plugins.packed-plugins', array() );

	if ( isset( $plugins[ $plugin ] ) && is_plugin_active( $plugins[ $plugin ] ) ) {
		deactivate_plugins( $plugins[ $plugin ] );
	}
}


add_action( 'admin_init', 'secupress_warning_wp_config_permissions' );
/**
 * This warning is displayed when the wp-config.php file isn't writable.
 *
 * @since 1.0
 */
function secupress_warning_wp_config_permissions() {
	global $pagenow;

	if ( 'plugins.php' === $pagenow && isset( $_GET['activate'] ) ) {
		return;
	}

	if ( ! current_user_can( secupress_get_capability() ) || wp_is_writable( secupress_find_wpconfig_path() ) ) {
		return;
	}

	$message  = sprintf( __( '%s: ', 'secupress' ), '<strong>' . SECUPRESS_PLUGIN_NAME . '</strong>' );
	$message .= sprintf( __( 'It seems we don\'t have <a href="%1$s" target="_blank">writing permissions</a> on %2$s file.', 'secupress' ), 'http://codex.wordpress.org/Changing_File_Permissions', '<code>wp-config.php</code>' );

	secupress_add_notice( $message, 'error', 'wpconfig-not-writable' );
}


add_action( 'admin_init', 'secupress_warning_htaccess_permissions' );
/**
 * This warning is displayed when the .htaccess file or the web.config file doesn't exist or isn't writable.
 *
 * @since 1.0
 */
function secupress_warning_htaccess_permissions() {
	global $is_apache, $is_iis7;

	if ( ! current_user_can( secupress_get_capability() ) ) {
		return;
	}

	if ( $is_apache ) {
		$file = '.htaccess';
		$htaccess_file = secupress_get_home_path() . $file;

		if ( is_writable( $htaccess_file ) ) {
			return;
		}
	} elseif ( $is_iis7 ) {
		$file = 'web.config';
		$web_config_file = secupress_get_home_path() . $file;

		if ( wp_is_writable( $web_config_file ) ) {
			return;
		}
	} else {
		return;
	}

	$message  = sprintf( __( '%s: ', 'secupress' ), '<strong>' . SECUPRESS_PLUGIN_NAME . '</strong>' );
	$message .= sprintf( __( 'If you had <a href="%1$s" target="_blank">writing permissions</a> on %2$s file, %3$s could do more things automatically.', 'secupress' ), 'http://codex.wordpress.org/Changing_File_Permissions', '<code>' . $file . '</code>', '<strong>' . SECUPRESS_PLUGIN_NAME . '</strong>' );

	secupress_add_notice( $message, 'error', 'htaccess-not-writable' );
}


add_action( 'admin_init', 'secupress_warning_module_activity' );
/**
 * These warnings are displayed when a module has been activated/deactivated.
 *
 * @since 1.0
 */
function secupress_warning_module_activity() {
	$current_user_id = get_current_user_id();

	if ( ! current_user_can( secupress_get_capability() ) ) {
		return;
	}

	$activated_modules   = secupress_get_site_transient( 'secupress_module_activation_' . $current_user_id );
	$deactivated_modules = secupress_get_site_transient( 'secupress_module_deactivation_' . $current_user_id );

	if ( false !== $activated_modules ) {
		$message  = '<p>' . sprintf( __( '%s: ', 'secupress' ), '<strong>' . SECUPRESS_PLUGIN_NAME . '</strong>' );
		$message .= _n( 'This module has been activated:', 'These modules have been activated:', count( $activated_modules ), 'secupress' );
		$message .= sprintf( '</p><ul><li>%s</li></ul>', implode( '</li><li>', $activated_modules ) );

		secupress_add_notice( $message );
		secupress_delete_site_transient( 'secupress_module_activation_' . $current_user_id );
	}

	if ( false !== $deactivated_modules ) {
		$message  = '<p>' . sprintf( __( '%s: ', 'secupress' ), '<strong>' . SECUPRESS_PLUGIN_NAME . '</strong>' );
		$message .= _n( 'This module has been deactivated:', 'These modules have been deactivated:', count( $deactivated_modules ), 'secupress' );
		$message .= sprintf( '</p><ul><li>%s</li></ul>', implode( '</li><li>', $deactivated_modules ) );

		secupress_add_notice( $message );
		secupress_delete_site_transient( 'secupress_module_deactivation_' . $current_user_id );
	}
}


add_action( 'admin_init', 'secupress_warning_no_backup_email' );
/**
 * This warning is displayed when the backup email is not set.
 *
 * @since 1.0
 */
function secupress_warning_no_backup_email() {
	if ( get_user_meta( get_current_user_id(), 'backup_email', true ) ) {
		return;
	}

	$message  = sprintf( __( '%s: ', 'secupress' ), '<strong>' . SECUPRESS_PLUGIN_NAME . '</strong>' );
	$message .= sprintf( __( 'Your <a href="%s">Backup E-mail</a> isn\'t yet set. Please do it.', 'secupress' ), get_edit_profile_url( get_current_user_id() ) . '#secupress_backup_email' );

	secupress_add_notice( $message, 'error', false );
}


add_action( 'all_admin_notices', 'secupress_warning_no_oneclick_scan_yet', 50 );
/**
 * This warning is displayed if no "One-Click Scan" has been performed yet.
 *
 * @since 1.0
 */
function secupress_warning_no_oneclick_scan_yet() {
	$screen_id = get_current_screen();
	$screen_id = $screen_id && ! empty( $screen_id->id ) ? $screen_id->id : false;

	if ( 'toplevel_page_secupress_scanners' === $screen_id || ! current_user_can( secupress_get_capability() ) ) {
		return;
	}

	$times = array_filter( (array) get_site_option( SECUPRESS_SCAN_TIMES ) );

	if ( $times ) {
		return;
	}

	echo '<div class="secupress-no-oneclick-scan-yet-notice hide-if-no-js">';
	printf( __( '%s: ', 'secupress' ), '<strong>' . SECUPRESS_PLUGIN_NAME . '</strong>' );
	printf(
		/* Translators: %s is "One Click Scan". */
		__( 'Why not run your first %s now?', 'secupress' ), // ////.
		'<a href="' . esc_url( secupress_admin_url( 'scanners' ) ) . '&oneclick-scan=1">' . __( 'One Click Scan', 'secupress' ) . '</a>'
	);
	echo "</div>\n";
}


add_action( 'admin_menu', 'secupress_display_transient_notices' );
/**
 * Will lately add admin notices added by `secupress_add_transient_notice()`.
 *
 * @since 1.0
 */
function secupress_display_transient_notices() {
	$notices = secupress_get_transient( 'secupress-notices-' . get_current_user_id() );

	if ( ! $notices ) {
		return;
	}

	foreach ( $notices as $notice ) {
		secupress_add_notice( $notice['message'], $notice['error_code'], false );
	}

	delete_transient( 'secupress-notices-' . get_current_user_id() );
}


/**
 * Add a notice with the SecuPress_Admin_Notices class.
 *
 * @since 1.0
 *
 * @param (string)      $message    The message to display in the notice.
 * @param (string)      $error_code Like WordPress notices: "error" or "updated". Default is "updated".
 * @param (string|bool) $notice_id  A unique identifier to tell if the notice is dismissible.
 *                                  false: the notice is not dismissible.
 *                                  string: the notice is dismissible and send an ajax call to store the "dismissed" state into a user meta to prevent it to popup again.
 *                                  enpty string: meant for a one-shot use. The notice is dismissible but the "dismissed" state is not stored, it will popup again. This is the exact same behavior than the WordPress dismissible notices.
 */
function secupress_add_notice( $message, $error_code = null, $notice_id = '' ) {
	SecuPress_Admin_Notices::get_instance()->add( $message, $error_code, $notice_id );
}

/**
 * Add a temporary notice with the SecuPress_Admin_Notices class.
 *
 * @since 1.0
 *
 * @param (string) $message    The message to display in the notice.
 * @param (string) $error_code Like WordPress notices: "error" or "updated". Default is "updated".
 */
function secupress_add_transient_notice( $message, $error_code = null ) {
	SecuPress_Admin_Notices::get_instance()->add_temporary( $message, $error_code );
}


/**
 * Dismiss a notice added with the SecuPress_Admin_Notices class.
 *
 * @since 1.0
 *
 * @param (string) $notice_id The notice identifier.
 * @param (int)    $user_id   User ID. If not set, fallback to the current user ID.
 *
 * @return (bool) true on success.
 */
function secupress_dismiss_notice( $notice_id, $user_id = 0 ) {
	return SecuPress_Admin_Notices::dismiss( $notice_id, $user_id );
}


/**
 * "Undismiss" a notice added with the SecuPress_Admin_Notices class.
 *
 * @since 1.0
 *
 * @param (string) $notice_id The notice identifier.
 * @param (int)    $user_id   User ID. If not set, fallback to the current user ID.
 *
 * @return (bool) true on success.
 */
function secupress_reinit_notice( $notice_id, $user_id = 0 ) {
	return SecuPress_Admin_Notices::reinit( $notice_id, $user_id );
}


/**
 * Test if a notice added with the SecuPress_Admin_Notices class is dismissed.
 *
 * @since 1.0
 *
 * @param (string) $notice_id The notice identifier.
 *
 * @return (bool|null) true if dismissed, false if not, null if the notice is not dismissible.
 */
function secupress_notice_is_dismissed( $notice_id ) {
	return SecuPress_Admin_Notices::is_dismissed( $notice_id );
}
