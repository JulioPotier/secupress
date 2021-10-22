<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

add_action( 'current_screen', 'secupress_http_block_external_notice' );
/**
 * This notice is displayed when external HTTP requests are blocked via the WP_HTTP_BLOCK_EXTERNAL constant
 *
 * @since 1.0
 * @author Julio Potier
 */
function secupress_http_block_external_notice() {
	global $current_screen;

	if ( ! current_user_can( secupress_get_capability() ) ) {
		return;
	}

	$is_accessible = defined( 'WP_ACCESSIBLE_HOSTS' ) && strpos( WP_ACCESSIBLE_HOSTS, '*.secupress.me' ) !== false;

	if ( $is_accessible || ! defined( 'WP_HTTP_BLOCK_EXTERNAL' ) || ( isset( $current_screen )
		&& 'toplevel_page_' . SECUPRESS_PLUGIN_SLUG . '_scanners' !== $current_screen->base
		&& SECUPRESS_PLUGIN_SLUG . '_page_' . SECUPRESS_PLUGIN_SLUG . '_modules' !== $current_screen->base
		&& SECUPRESS_PLUGIN_SLUG . '_page_' . SECUPRESS_PLUGIN_SLUG . '_settings' !== $current_screen->base
		&& SECUPRESS_PLUGIN_SLUG . '_page_' . SECUPRESS_PLUGIN_SLUG . '_logs' !== $current_screen->base )
		|| SecuPress_Admin_Notices::is_dismissed( 'http-block-external' )
		) {
		return;
	}

	$message  = '<div>';
		$message .= '<p><strong>' . sprintf( __( '%s: External HTTP requests are blocked!', 'secupress' ), SECUPRESS_PLUGIN_NAME ) . '</strong></p>';
		$message .= '<p>' . sprintf( __( 'You defined the <code>WP_HTTP_BLOCK_EXTERNAL</code> constant in the <code>%s</code> to block all external HTTP requests.', 'secupress' ), secupress_get_wpconfig_filename() ) . '</p>';
		$message .= '<p>';
			$message .= sprintf( __( 'To make %s work well, you have to either remove the PHP constant, or add the following code in your <code>%s</code> file.', 'secupress' ), SECUPRESS_PLUGIN_NAME, secupress_get_wpconfig_filename() ) . '<br/>';
			$message .= __( 'Click on the field and press Ctrl+A or Cmd+A to select all.', 'secupress' );
		$message .= '</p>';
		$message .= '<p><textarea readonly="readonly" class="large-text readonly" rows="1">define( \'WP_ACCESSIBLE_HOSTS\', \'*.secupress.me\' );</textarea></p>';
	$message .= '</div>';

	secupress_add_notice( $message, 'error', 'http-block-external' );
}


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

	$plugins_to_deactivate = [ // Forced deactivation
		'o2s-wp-tiger/o2s-wp-tiger.php' => true, // 2.0.1
	];

	add_filter( 'all_plugins', function( $all_plugins ) use ( $plugins_to_deactivate ) {
		$all_plugins = array_diff_key( $all_plugins, $plugins_to_deactivate );
		return $all_plugins;
	});

	$plugins_to_deactivate = array_filter( array_keys( $plugins_to_deactivate ), 'is_plugin_active' );

	if ( $plugins_to_deactivate ) {
		$message = '<p>' . sprintf( __( '%s:', 'secupress' ), '<strong>' . SECUPRESS_PLUGIN_NAME . '</strong>' ) . ' ';
		$message .= _n( 'The following plugin has been deactivated because we already included its features:', 'The following plugins has been deactivated because we already included its features:', count( $plugins_to_deactivate ), 'secupress' );
		$message .= '</p><ul>';
		foreach ( $plugins_to_deactivate as $plugin ) {
			$plugin_data = get_plugin_data( WP_PLUGIN_DIR . DIRECTORY_SEPARATOR . $plugin );
			$context     = isset( $_GET['plugin_status'] ) ? '&amp;plugin_status=' . $_GET['plugin_status'] : '';
			$page        = isset( $_GET['pages'] ) ? '&amp;paged=' . $_GET['paged'] : '';
			$search      = isset( $_GET['s'] ) ? '&amp;s=' . $_GET['s'] : '';
			$url         = wp_nonce_url( 'plugins.php?action=deactivate&amp;plugin=' . $plugin . $context . $page . $search, 'deactivate-plugin_' . $plugin );
			$message    .= '<li>• ' . $plugin_data['Name'] . '</span></li>';
			deactivate_plugins( $plugin, true );
		}
		$message .= '</ul>';

		secupress_add_notice( $message, 'error', 'deactivate-plugin' );
	}

	$plugins_to_warn = [ // deactivation not mandatory, dismissable
		'all-in-one-wp-security-and-firewall/wp-security.php', // repo
		'better-wp-security/better-wp-security.php', // iTheme Security Free repo
		'bulletproof-security/bulletproof-security.php', // repo
		'getastra/astra-security.php', // repo
		'gotmls/index.php', // repo
		'ithemes-security-pro/ithemes-security-pro.php',
		'ninjafirewall/ninjafirewall.php', // repo
		'malcare-security/malcare.php', // repo
		'security-ninja/security-ninja.php', // repo
		'security-ninja-pro/security-ninja.php', // not sure
		'security-ninja-pro/security-ninja-pro.php', // not sure
		'sucuri-scanner/sucuri.php', // repo
		'wordfence/wordfence.php', // repo
		'wp-cerber/wp-cerber.php', // repo
		'wp-defender/wp-defender.php', // repo
		'wp-simple-firewall/icwp-wpsf.php', // repo
	];

	$plugins_to_warn = array_filter( $plugins_to_warn, 'is_plugin_active' );

	if ( $plugins_to_warn ) {

		$hash = md5( serialize( $plugins_to_warn ) );
		if ( secupress_notice_is_dismissed( 'warn-plugin-' . $hash ) ) {
			return;
		}

		$message = '<p>' . sprintf( __( '%s:', 'secupress' ), '<strong>' . SECUPRESS_PLUGIN_NAME . '</strong>' ) . ' ';
		$message .= _n( 'The following plugin is not compatible with us and will lead to conflicts:', 'The following plugins are not compatible with us and will lead to conflicts:', count( $plugins_to_warn ), 'secupress' );
		$message .= '</p><ul>';
		foreach ( $plugins_to_warn as $plugin ) {
			$plugin_data = get_plugin_data( WP_PLUGIN_DIR . DIRECTORY_SEPARATOR . $plugin );
			$context     = isset( $_GET['plugin_status'] ) ? '&amp;plugin_status=' . $_GET['plugin_status'] : '';
			$page        = isset( $_GET['pages'] ) ? '&amp;paged=' . $_GET['paged'] : '';
			$search      = isset( $_GET['s'] ) ? '&amp;s=' . $_GET['s'] : '';
			$url         = wp_nonce_url( 'plugins.php?action=deactivate&amp;plugin=' . $plugin . $context . $page . $search, 'deactivate-plugin_' . $plugin );
			$message    .= '<li>• ' . $plugin_data['Name'] . '</span> <a href="' . esc_url( $url ) . '" class="button-secondary alignright">' . __( 'Deactivate' ) . '</a></li>';
		}
		$message .= '</ul>';

		secupress_add_transient_notice( $message, 'error', SECUPRESS_MAJOR_VERSION . '-warn-plugin-' . $hash );
	}

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
		/** Translators: 1 is the plugin name */
		__( 'The features of the following plugins are included in %1$s. You can deactivate the plugins now and enable these features later in %1$s:', 'secupress' ),
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

add_action( 'admin_init', 'secupress_warning_module_activity' );
/**
 * These warnings are displayed when a module has been activated/deactivated.
 *
 * @since 1.0
 */
function secupress_warning_module_activity() {
	if ( defined( 'DOING_AJAX' ) ) {
		return;
	}

	$current_user_id = get_current_user_id();

	if ( ! current_user_can( secupress_get_capability() ) ) {
		return;
	}

	$activated_modules   = secupress_get_site_transient( 'secupress_module_activation_' . $current_user_id );
	$deactivated_modules = secupress_get_site_transient( 'secupress_module_deactivation_' . $current_user_id );

	if ( false !== $activated_modules ) {
		$message  = '<p>' . sprintf( __( '%s:', 'secupress' ), '<strong>' . SECUPRESS_PLUGIN_NAME . '</strong>' ) . ' ';
		$message .= _n( 'This module has been activated:', 'These modules have been activated:', count( $activated_modules ), 'secupress' );
		$message .= sprintf( '</p><ul><li>%s</li></ul>', implode( '</li><li>', $activated_modules ) );

		secupress_add_notice( $message );
		secupress_delete_site_transient( 'secupress_module_activation_' . $current_user_id );
	}

	if ( false !== $deactivated_modules ) {
		$message  = '<p>' . sprintf( __( '%s:', 'secupress' ), '<strong>' . SECUPRESS_PLUGIN_NAME . '</strong>' ) . ' ';
		$message .= _n( 'This module has been deactivated:', 'These modules have been deactivated:', count( $deactivated_modules ), 'secupress' );
		$message .= sprintf( '</p><ul><li>%s</li></ul>', implode( '</li><li>', $deactivated_modules ) );

		secupress_add_notice( $message );
		secupress_delete_site_transient( 'secupress_module_deactivation_' . $current_user_id );
	}
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

	if ( ! ( SECUPRESS_PLUGIN_SLUG . '_page_' . SECUPRESS_PLUGIN_SLUG . '_settings' === $screen_id || ( 'plugins' === $screen_id && ! is_multisite() ) || 'plugins-network' === $screen_id ) ) {
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
			<p class="secupress-text-medium"><?php printf( __( '%s is activated, let’s improve the security of your website!', 'secupress' ), SECUPRESS_PLUGIN_NAME ); ?></p>
			<p><?php esc_html_e( 'Scan your website for security issues, right now.', 'secupress' ); ?></p>
		</div>
		<div class="secupress-col-1-4 secupress-col-cta">
			<a class="secupress-button secupress-button-primary secupress-button-scan" href="<?php echo esc_url( wp_nonce_url( secupress_admin_url( 'scanners' ), 'first_oneclick-scan' ) ) . '&oneclick-scan=1'; ?>">
				<span class="icon">
					<i class="secupress-icon-radar" aria-hidden="true"></i>
				</span>
				<span class="text">
					<?php _e( 'Scan my website', 'secupress' ); ?>
				</span>
			</a>
			<a class="secupress-close-notice" href="<?php echo wp_nonce_url( admin_url( 'admin-post.php?action=secupress_dismiss-notice&notice_id=oneclick-scan&_wp_http_referer=' . $referer ), 'secupress-notices' ); ?>">
				<i class="secupress-icon-squared-cross" aria-hidden="true"></i>
				<span class="screen-reader-text"><?php _e( 'Close' ); ?></span>
			</a>
		</div>
	</div><!-- .secupress-section-dark -->
	<?php
	secupress_enqueue_notices_styles();
}


add_action( 'in_plugin_update_message-' . plugin_basename( SECUPRESS_FILE ), 'secupress_updates_message', 10, 2 );
/**
 * Display a message below our plugins to display the next update information if needed
 *
 * @since 1.1.1
 * @author Julio Potier
 *
 * @param (array) $plugin_data Contains the old plugin data from EDD or repository.
 * @param (array) $new_plugin_data Contains the new plugin data from EDD or repository.
 */
function secupress_updates_message( $plugin_data, $new_plugin_data ) {
	// Get next version.
	if ( isset( $new_plugin_data->new_version ) ) {
		$remote_version = $new_plugin_data->new_version;
	}

	if ( ! isset( $remote_version ) ) {
		return;
	}

	$body = get_transient( 'secupress_updates_message' );

	if ( ! isset( $body[ $remote_version ] ) ) {
		$url = 'https://plugins.svn.wordpress.org/secupress/trunk/readme.txt';
		$response = wp_remote_get( $url );

		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return;
		}

		$body = wp_remote_retrieve_body( $response );

		set_transient( 'secupress_updates_message' , array( $remote_version => $body ) );
	} else {
		$body = $body[ $remote_version ];
	}

	// Find the Notes for this version.
	$regexp = '#== Upgrade Notice ==.*= ' . preg_quote( $remote_version ) . ' =(.*)=#Us';

	if ( preg_match( $regexp, $body, $matches ) ) {

		$notes = (array) preg_split( '#[\r\n]+#', trim( $matches[1] ) );
		$date  = str_replace( '* ', '', wp_kses_post( array_shift( $notes ) ) );

		echo '<div>';
		/** Translators: %1$s is the version number, %2$s is a date. */
		echo '<strong>' . sprintf( __( 'Please read these special notes for this update, version %1$s - %2$s', 'secupress' ), $remote_version, $date ) . '</strong>';
		echo '<ul style="list-style:square;margin-left:20px;line-height:1em">';
		foreach ( $notes as $note ) {
			echo '<li>' . str_replace( '* ', '', wp_kses_post( $note ) ) . '</li>';
		}
		echo '</ul>';
		echo '</div>';
	}
}
