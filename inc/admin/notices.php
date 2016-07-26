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
		'wordfence/wordfence.php',
		'better-wp-security/better-wp-security.php',
		'all-in-one-wp-security-and-firewall/wp-security.php',
		'bulletproof-security/bulletproof-security.php',
		'sucuri-scanner/sucuri.php',
	);

	$plugins_to_deactivate = array_filter( $plugins, 'is_plugin_active' );

	if ( ! $plugins_to_deactivate ) {
		return;
	}

	$message  = '<p>' . sprintf( __( '%s: ', 'secupress' ), '<strong>' . SECUPRESS_PLUGIN_NAME . '</strong>' );
	$message .= __( 'The following plugins are not recommended with this plugin and may cause unexpected results:', 'secupress' );
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
	 * @param (array) $plugins A list of plugin paths, relative to the plugins folder. The "file name" of the packed plugin is used as key.
	 *                         Example: array( 'move-login' => 'sf-move-login/sf-move-login.php' )
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


add_action( 'secupress.modules.activate_submodule', 'secupress_deactivate_standalone_plugin_on_packed_plugin_activation' );
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


add_action( 'admin_init', 'secupress_warning_no_recovery_email' );
/**
 * This warning is displayed when the recovery email is not set.
 *
 * @since 1.0
 */
function secupress_warning_no_recovery_email() {
	if ( get_user_meta( get_current_user_id(), 'secupress_recovery_email', true ) ) {
		return;
	}

	$message  = sprintf( __( '%s: ', 'secupress' ), '<strong>' . SECUPRESS_PLUGIN_NAME . '</strong>' );
	$message .= sprintf( __( 'Your <a href="%s">Recovery E-mail</a> isn\'t yet set. Please do it.', 'secupress' ), get_edit_profile_url( get_current_user_id() ) . '#secupress_recovery_email' );

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

	if ( ! ( 'secupress_page_' . SECUPRESS_PLUGIN_SLUG . '_settings' === $screen_id || ( 'plugins' === $screen_id && ! is_multisite() ) || 'plugins-network' === $screen_id ) ) {
		return;
	}

	if ( secupress_notice_is_dismissed( 'oneclick-scan' ) || ! current_user_can( secupress_get_capability() ) ) {
		return;
	}

	$times   = array_filter( (array) get_site_option( SECUPRESS_SCAN_TIMES ) );
	$referer = urlencode( esc_url_raw( secupress_get_current_url( 'raw' ) ) );

	if ( $times ) {
		return;
	}
	?>
	<div class="secupress-section-dark secupress-notice secupress-flex">
		<div class="secupress-col-1-4 secupress-col-logo secupress-text-center">
			<div class="secupress-logo-block">
				<div class="secupress-lb-logo">
					<?php echo secupress_get_logo( array( 'width' => '84' ) ); ?>
				</div>
			</div>
		</div>
		<div class="secupress-col-2-4 secupress-col-text">
			<p class="secupress-text-medium"><?php printf( __( '%s is activated, let\'s improve the security of your website!', 'secupress' ), SECUPRESS_PLUGIN_NAME ); ?></p>
			<p><?php esc_html_e( 'Scan every security points for the first time in your website, right now.', 'secupress' ); ?></p>
		</div>
		<div class="secupress-col-1-4 secupress-col-cta">
			<a class="secupress-button secupress-button-primary secupress-button-scan" href="<?php echo esc_url( wp_nonce_url( secupress_admin_url( 'scanners' ), 'first_oneclick-scan' ) ) . '&oneclick-scan=1'; ?>">
				<span class="icon">
					<i class="icon-radar" aria-hidden="true"></i>
				</span>
				<span class="text">
					<?php esc_html_e( 'Scan my website', 'secupress' ); ?>
				</span>
			</a>
			<a class="secupress-close-notice" href="<?php echo wp_nonce_url( admin_url( 'admin-post.php?action=secupress_dismiss-notice&notice_id=oneclick-scan&_wp_http_referer=' . $referer ), 'secupress-notices' ); ?>">
				<i class="icon-squared-cross" aria-hidden="true"></i>
				<span class="screen-reader-text"><?php esc_html_e( 'Close' ); ?></span>
			</a>
		</div>
	</div><!-- .secupress-section-dark -->
	<?php
	secupress_enqueue_notices_styles();
}


add_action( 'all_admin_notices', 'secupress_warning_no_api_key', 50 );
/**
 * This warning is displayed if consumer email and key are unknown.
 *
 * @since 1.0
 * @author Geoffrey
 */
function secupress_warning_no_api_key() {
	$screen_id = get_current_screen();
	$screen_id = $screen_id && ! empty( $screen_id->id ) ? $screen_id->id : false;

	$allowed_screen_ids = array(
		'toplevel_page_' . SECUPRESS_PLUGIN_SLUG . '_scanners'  => 1,
		'secupress_page_' . SECUPRESS_PLUGIN_SLUG . '_modules'  => 1,
		'secupress_page_' . SECUPRESS_PLUGIN_SLUG . '_settings' => 1,
		'secupress_page_' . SECUPRESS_PLUGIN_SLUG . '_logs'     => 1,
	); // //// Add Get Pro page later.

	if ( secupress_notice_is_dismissed( 'get-api-key' ) || ! isset( $allowed_screen_ids[ $screen_id ] ) || ! current_user_can( secupress_get_capability() ) ) {
		return;
	}

	$times = array_filter( (array) get_site_option( SECUPRESS_SCAN_TIMES ) );

	// Don't display the API key banner yet, wait the first OCS.
	if ( secupress_get_consumer_key() || ! $times ) {
		return;
	}

	$referer = urlencode( esc_url_raw( secupress_get_current_url( 'raw' ) ) );
	?>
	<div class="secupress-section-dark secupress-notice mini secupress-flex">
		<div class="secupress-col-1-4 secupress-col-logo mini">
			<div class="secupress-logo-block">
				<div class="secupress-lb-logo">
					<?php echo secupress_get_logo( array( 'width' => '46' ) ); ?>
				</div>
			</div>
		</div>
		<div class="secupress-col-2-4 secupress-col-text">
			<p class="secupress-text-medium"><?php esc_html_e( 'Go further to get more security features!', 'secupress' ); ?></p>
			<p><?php esc_html_e( 'The API Key will allow you to secure more deeply your website by activating new modules.', 'secupress' ); ?></p>
		</div>
		<div class="secupress-col-1-4 secupress-col-cta">
			<a href="<?php echo esc_url( secupress_admin_url( 'settings' ) ); ?>" class="secupress-button secupress-button-primary button-secupress-get-api-key">
				<span class="icon">
					<i class="icon-key" aria-hidden="true"></i>
				</span>
				<span class="text">
					<?php _e( 'Add API Key', 'secupress' ); ?>
				</span>
			</a>
			<a class="secupress-close-notice" href="<?php echo wp_nonce_url( admin_url( 'admin-post.php?action=secupress_dismiss-notice&notice_id=get-api-key&_wp_http_referer=' . $referer ), 'secupress-notices' ); ?>">
				<i class="icon-squared-cross" aria-hidden="true"></i>
				<span class="screen-reader-text"><?php esc_html_e( 'Close' ); ?></span>
			</a>
		</div>
	</div><!-- .secupress-section-medium -->
	<?php
	secupress_enqueue_notices_styles();
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
 * Enqueue styles for not generic SP notices (OCS, Key API)
 *
 * @author Geoffrey
 *
 * @since 1.0
 */
function secupress_enqueue_notices_styles() {
	$suffix    = defined( 'SCRIPT_DEBUG' ) && SCRIPT_DEBUG ? '' : '.min';
	$version   = $suffix ? SECUPRESS_VERSION : time();

	wp_enqueue_style( 'secupress-notices', SECUPRESS_ADMIN_CSS_URL . 'secupress-notices' . $suffix . '.css', array(), $version );
}
