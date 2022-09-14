<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/** --------------------------------------------------------------------------------------------- */
/** MIGRATE / UPGRADE =========================================================================== */
/** --------------------------------------------------------------------------------------------- */

/**
 * Tell WP what to do when admin is loaded aka upgrader
 *
 * @since 1.0
 */
function secupress_upgrader() {
	$actual_version = secupress_get_option( 'version' );

	// You can hook the upgrader to trigger any action when SecuPress is upgraded.
	// First install.
	if ( ! $actual_version ) {
		/**
		 * Allow to prevent plugin first install hooks to fire.
		 *
		 * @since 1.0
		 *
		 * @param (bool) $prevent True to prevent triggering first install hooks. False otherwise.
		 */
		if ( ! apply_filters( 'secupress.prevent_first_install', false ) ) {
			/**
			 * Fires on the plugin first install.
			 *
			 * @since 1.0
			 *
			 * @param (string) $module The module to reset. "all" means all modules at once.
			 */
			do_action( 'secupress.first_install', 'all' );
		}

	}
	// Already installed but got updated.
	elseif ( SECUPRESS_VERSION !== $actual_version ) {
		$new_version = SECUPRESS_VERSION;
		/**
		 * Fires when SecuPress is upgraded.
		 *
		 * @since 1.0
		 *
		 * @param (string) $new_version    The version being upgraded to.
		 * @param (string) $actual_version The previous version.
		 */
		do_action( 'secupress.upgrade', $new_version, $actual_version );
	}

	if ( defined( 'SECUPRESS_PRO_VERSION' ) && ( ! defined( 'SECUPRESS_PRO_SECUPRESS_MIN' ) || version_compare( SECUPRESS_VERSION, SECUPRESS_PRO_SECUPRESS_MIN ) >= 0 ) ) {
		$actual_pro_version = secupress_get_option( 'pro_version' );

		// You can hook the upgrader to trigger any action when SecuPress Pro is upgraded.
		// First install.
		if ( ! $actual_pro_version ) {
			/**
			 * Allow to prevent SecuPress Pro first install hooks to fire.
			 *
			 * @since 1.1.4
			 *
			 * @param (bool) $prevent True to prevent triggering first install hooks. False otherwise.
			 */
			if ( ! apply_filters( 'secupress_pro.prevent_first_install', false ) ) {
				/**
				 * Fires on SecuPress Pro first install.
				 *
				 * @since 1.1.4
				 *
				 * @param (string) $module The module to reset. "all" means all modules at once.
				 */
				do_action( 'secupress_pro.first_install', 'all' );
			}

		}
		// Already installed but got updated.
		elseif ( SECUPRESS_PRO_VERSION !== $actual_pro_version ) {
			$new_pro_version = SECUPRESS_PRO_VERSION;
			/**
			 * Fires when SecuPress Pro is upgraded.
			 *
			 * @since 1.0
			 *
			 * @param (string) $new_pro_version    The version being upgraded to.
			 * @param (string) $actual_pro_version The previous version.
			 */
			do_action( 'secupress_pro.upgrade', $new_pro_version, $actual_pro_version );
		}
	}

	// If any upgrade has been done, we flush and update version.
	if ( did_action( 'secupress.first_install' ) || did_action( 'secupress.upgrade' ) || did_action( 'secupress_pro.first_install' ) || did_action( 'secupress_pro.upgrade' ) ) {

		// Do not use secupress_get_option() here.
		$options = get_site_option( SECUPRESS_SETTINGS_SLUG );
		$options = is_array( $options ) ? $options : array();

		// Free version.
		$options['version'] = SECUPRESS_VERSION;

		// Pro version.
		if ( did_action( 'secupress_pro.first_install' ) || did_action( 'secupress_pro.upgrade' ) ) {
			$options['pro_version'] = SECUPRESS_PRO_VERSION;
		}

		// First install.
		if ( did_action( 'secupress.first_install' ) ) {
			$options['hash_key']     = secupress_generate_key( 64 );
			$options['install_time'] = time();
		}
		secupress_update_options( $options );

		/**
		* Fires when an updated has been done.
		*
		* @since 2.0
		* @author Julio Potier
		*
		* @param (string) $actual_version
		* @param (string) $new_version
		* @param (array)  $options
		*/
		do_action( 'secupress.did_upgrade', $actual_version, SECUPRESS_VERSION, $options );
	}
}

add_action( 'secupress.first_install', 'secupress_install_users_login_module' );
/**
 * Create default option on install and reset.
 *
 * @since 1.0
 *
 * @param (string) $module The module(s) that will be reset to default. `all` means "all modules".
 */
function secupress_install_users_login_module( $module ) {
	// First install.
	if ( 'all' === $module ) {
		// Activate "Ask for old password" submodule.
		// secupress_activate_submodule_silently( 'users-login', 'ask-old-password' );
	}

}

add_action( 'secupress_pro.upgrade', 'secupress_new_pro_upgrade', 10, 2 );
/**
 * What to do when SecuPress Pro is updated, depending on versions.
 *
 * @since 2.0
 *
 * @param (string) $secupress_version The version being upgraded to.
 * @param (string) $actual_version    The previous version.
 */
function secupress_new_pro_upgrade( $secupress_version, $actual_pro_version ) {
	global $wpdb;

	// < 2.0
	if ( version_compare( $actual_pro_version, '2.0', '<' ) ) {
		secupress_remove_old_plugin_file( SECUPRESS_PRO_MODULES_PATH . 'services/callbacks.php' );
		delete_site_option( SECUPRESS_FULL_FILETREE );
	}
}

add_action( 'secupress.upgrade', 'secupress_new_upgrade', 10, 2 );
/**
 * What to do when SecuPress is updated, depending on versions.
 *
 * @since 1.0
 *
 * @param (string) $secupress_version The version being upgraded to.
 * @param (string) $actual_version    The previous version.
 */
function secupress_new_upgrade( $secupress_version, $actual_version ) {
	global $wpdb, $current_user;

	// < 1.4.3
	if ( version_compare( $actual_version, '1.4.3', '<' ) ) {

		secupress_deactivate_submodule( 'file-system', 'directory-index' );
		secupress_remove_old_plugin_file( SECUPRESS_MODULES_PATH . 'file-system/plugins/directory-index.php' );

		secupress_deactivate_submodule( 'wordpress-core', 'wp-config-constant-unfiltered-html' );
		secupress_remove_old_plugin_file( SECUPRESS_MODULES_PATH . 'wordpress-core/plugins/wp-config-constant-unfiltered-html.php' );

		secupress_deactivate_submodule( 'sensitive-data', 'restapi' );
		secupress_remove_old_plugin_file( SECUPRESS_MODULES_PATH . 'sensitive-data/plugins/restapi.php' );

		set_site_transient( 'secupress-common', time(), 2 * DAY_IN_SECONDS );
	}

	// < 1.4.4
	if ( version_compare( $actual_version, '1.4.4', '<' ) ) {
		$value = secupress_get_module_option( 'bbq-headers_user-agents-list', secupress_firewall_bbq_headers_user_agents_list_default(), 'firewall' );
		$value = str_replace( 'Wget, ', '', $value );
		secupress_update_module_option( 'bbq-headers_user-agents-list', $value, 'firewall' );
	}

	// < 1.4.9
	if ( version_compare( $actual_version, '1.4.9', '<' ) ) {
		secupress_remove_old_plugin_file( SECUPRESS_MODULES_PATH . 'users-login/plugins/inc/php/move-login/deprecated.php' );
		secupress_remove_old_plugin_file( SECUPRESS_MODULES_PATH . 'users-login/plugins/inc/php/move-login/redirections-and-dies.php' );
		secupress_remove_old_plugin_file( SECUPRESS_MODULES_PATH . 'users-login/plugins/inc/php/move-login/admin.php' );
		secupress_remove_old_plugin_file( SECUPRESS_MODULES_PATH . 'users-login/plugins/inc/php/move-login/url-filters.php' );
	}

	// < 2.0
	if ( version_compare( $actual_version, '2.0', '<' ) ) {
		// Cannot use secupress_is_submodule_active() here because these are not modules yet (< 2.0...)
		if ( defined( 'SECUPRESS_SALT_KEYS_ACTIVE' ) ) {
			secupress_set_site_transient( 'secupress-add-salt-muplugin', array( 'ID' => $current_user->ID ) );
		}
		if ( defined( 'COOKIEHASH' ) && COOKIEHASH !== md5( get_site_option( 'siteurl' ) ) ) {
			secupress_set_site_transient( 'secupress-add-cookiehash-muplugin', array( 'ID' => $current_user->ID, 'username' => $current_user->user_login ) );
		}

		secupress_remove_old_plugin_file( SECUPRESS_MODULES_PATH . 'firewall/plugins/bad-sqli-scan.php' );
		secupress_remove_old_plugin_file( SECUPRESS_MODULES_PATH . 'users-login/plugins/ask-old-password.php' );
		secupress_remove_old_plugin_file( SECUPRESS_CLASSES_PATH . 'class-secupress-admin-support.php.php' );
		delete_site_option( 'secupress_scan_wp_config' );
	}
}


add_action( 'admin_init', 'secupress_better_changelog' );
/**
 * If the plugin is secupress free or pro, let's add our changlog content
 *
 * @since 1.4.3
 * @author Julio Potier
 **/
function secupress_better_changelog() {
	if ( isset( $_GET['tab'], $_GET['plugin'], $_GET['section'] )
	&& ( 'secupress' === $_GET['plugin'] || 'secupress-pro' === $_GET['plugin'] )
	&& 'changelog' === $_GET['section'] && 'plugin-information' === $_GET['tab'] ) {
		remove_action( 'install_plugins_pre_plugin-information', 'install_plugin_information' );
		add_action( 'install_plugins_pre_plugin-information', 'secupress_hack_changelog' );
	}
}

/**
 * Will display our changelog content wiht our CSS
 *
 * @since 1.4.3
 * @author Julio Potier
 **/
function secupress_hack_changelog() {
	global $admin_body_class;

	$api = plugins_api( 'plugin_information', array(
		'slug' => 'secupress',
		'is_ssl' => is_ssl(),
		'fields' => [ 'short_description' => false,
					'reviews' => false,
					'downloaded' => false,
					'downloadlink' => false,
					'last_updated' => false,
					'added' => false,
					'tags' => false,
					'homepage' => false,
					'donate_link' => false,
					'ratings' => false,
					'active_installs' => true,
					'banners' => true,
					'sections' => true,
				]
	) );

	if ( is_wp_error( $api ) ) {
		wp_die( $api );
	}

	$changelog_content = $api->sections['changelog'];
	$changelog_content = explode( "\n", $changelog_content );
	$changelog_content = array_slice( $changelog_content, 0, array_search( '</ul>', $changelog_content, true ) );
	$changelog_content = array_map( 'strip_tags', $changelog_content );
	$changelog_version = array_shift( $changelog_content );
	$changelog_content = array_filter( $changelog_content );
	$changelog_date    = array_shift( $changelog_content );
	$pro_suffix        = secupress_has_pro() ? 'Pro ' : 'Free ';
	$banner            = secupress_has_pro() ? 'banner-secupress-pro.jpg' : 'banner-1544x500.png';

	iframe_header( __( 'Plugin Installation' ) );
	?>
	<style type="text/css">
		body {
			color: #333;
			font-family: Helvetica, Arial, sans-serif;
			margin: 0;
			padding: 0;
			background-color: #fff
		}

		section {
			margin: 20px 25px;
			max-width: 830px
		}

		header {
			position: relative;
			margin-bottom: 20px;
			width: 100%;
			max-width: 830px;
			height: 276px;
			color: #fff;
		}

		#plugin-information-title.with-banner div.vignette {
			background-image: url( 'https://plugins.svn.wordpress.org/secupress/assets/<?php echo $banner; ?>' );
			background-size: contain;
		}

		header h1,
		header h2 {
			font-family: "HelveticaNeue-Light", "Helvetica Neue Light", "Helvetica Neue", sans-serif;
			font-size: 2em;
			font-weight: normal;
			margin: 0;
			color: #fff;
			line-height: 1em
		}

		header h2 {
			font-size: 1.4em;
			margin-bottom: 3px
		}

		hgroup {
			float: right;
			padding-right: 50px
		}

		h2 {
			font-size: 1.2em
		}

		ul {
			margin-bottom: 30px
		}

		li {
			margin-bottom: 0.5em
		}

		.changelog tr {
			line-height: 1.5em;
		}

		.changelog td {
			padding: 3px;
			font-size: 15px;
			vertical-align: middle;
		}

		.changelog .type {
			font-size: 12px;
			text-transform: uppercase;
			padding-right: 15px;
			padding-top: 5px;
			padding-left: 0;
			text-align: left;
			color: #999;
			min-width: 100px;
			border-right: 2px solid #eee;
		}

		.changelog .type, .changelog .description {
			vertical-align: top;
		}

		code {
			background-color: #EEE;
			padding: 2px
		}

		.star-rating {
			display: inline;
		}

		#plugin-information-footer {
			text-align: center;
			line-height: 1.7em;
		}

	</style>
</head>

<body class="$admin_body_class">

<header id="plugin-information-title" class="with-banner">
	<div class="vignette"></div>
	<h2>SecuPress <?php echo $pro_suffix; ?> <?php echo esc_html( $changelog_version ); ?> – <?php echo esc_html( $changelog_date ); ?></h2>
</header>

<section id="plugin-information-scrollable">
	<table class="changelog">
	<?php
	foreach ( $changelog_content as $content ) {
		if ( ! $content ) {
			continue;
		}
		$content = explode( ' ', $content, 2 );
		?>
		<tr>
			<td class="type"><?php echo wp_kses_post( '<strong>' . str_replace( '#', '</strong>&nbsp;#', reset( $content ) ) ); ?></td>
			<td class="description"><?php echo wp_kses_post( end( $content ) ); ?></td>
		</tr>
		<?php
	}
	?>
		<tr>
			<td class="type"><strong><?php _e( 'Full Changelog', 'secupress' ); ?></strong></td>
			<td class="description"><a href="<?php echo SECUPRESS_WEB_MAIN; ?>changelog/" target="_blank"><?php echo SECUPRESS_WEB_MAIN; ?>changelog/</a></td>
		</tr>
	</table>
	<hr>
	<?php
	$status = install_plugin_install_status( $api );
	if ( $status['url'] ) {
		echo '<p><a data-slug="' . esc_attr( $api->slug ) . '" data-plugin="' . esc_attr( $status['file'] ) . '" id="plugin_update_from_iframe" class="button button-primary right" href="' . esc_url( $status['url'] ) . '" target="_parent">' . __( 'Install Update Now' ) . '</a></p>';
	}
	if ( ! secupress_has_pro() ) {
	?>
	<p><a href="<?php echo SECUPRESS_WEB_MAIN; ?>pricing/" class="button button-secondary"><?php _e( 'Get SecuPress Pro Now!', 'secupress' ); ?></a></p>
	<?php
	}
	?>
</section>

<div id="plugin-information-footer">
	<strong><?php _e( 'Requires WordPress Version:' ); ?></strong>
	<?php
	printf( __( '%s or higher' ), $api->requires );

	if ( ! empty( $api->requires_php ) ) {
		echo '& PHP ' . printf( __( '%s or higher' ), $api->requires );
	}
	?> |
	<strong><?php _e( 'Compatible up to:' ); ?></strong>
	<?php echo $api->tested; ?>
	<br>
	<strong><?php _e( 'Active Installations:' ); ?></strong>
	<?php
	if ( $api->active_installs >= 1000000 ) {
		_ex( '1+ Million', 'Active plugin installations' );
	} elseif ( 0 === $api->active_installs ) {
		_ex( 'Less Than 10', 'Active plugin installations' );
	} else {
		echo number_format_i18n( $api->active_installs ) . '+';
	}
	?> |
	<strong><?php _e( 'Average Rating' ); ?>:</strong>
	<?php wp_star_rating( [ 'type' => 'percent', 'rating' => $api->rating, 'number' => $api->num_ratings ] ); ?>
	<p aria-hidden="true" class="fyi-description"><?php printf( _n( '(based on %s rating)', '(based on %s ratings)', $api->num_ratings ), number_format_i18n( $api->num_ratings ) ); ?></p>
	<br>
</div>
<?php
iframe_footer();
exit;
}

if ( ! secupress_is_white_label() ) {
	// add_action( 'admin_notices', 'secupress_display_whats_new' );
	/**
	 * Display a "what's new" notice when not in WhiteLabel and user has the correct capa
	 *
	 * @since 2.0 secupress_add_transient_notice + SECUPRESS_MAJOR_VERSION
	 * @since 1.4.10
	 * @author Julio Potier
	 *
	 * @hook admin_notices
	 * @return (void)
	 **/
	function secupress_display_whats_new() {
		$notice_id = 'new-' . sanitize_key( SECUPRESS_MAJOR_VERSION );
		if ( ! current_user_can( secupress_get_capability() ) || secupress_notice_is_dismissed( $notice_id ) ) {
			return;
		}

		$title    = sprintf( '<strong>' . __( 'What’s new in SecuPress %s', 'secupress' ) . '</strong>', SECUPRESS_MAJOR_VERSION );
		$readmore = '<a href="https://secupress.me/changelog" target="_blank"><em>' . __( 'Or read full changelog on secupress.me', 'secupress' ) . '</em></a>';
		$newitems = [ 	//__( 'New HTTP Logs Module', 'secupress' ),
						// __( 'New Vulnerable Themes and Plugins API', 'secupress' ),
						// __( 'New GeoIP API', 'secupress' ),
						// __( 'New Sessions Details', 'secupress' ),
					];
		if ( ! empty( $newitems ) ) {
			$newitems = '<ul><li>• ' . implode( '</li><li>• ', $newitems ) . '</li></ul>';
			secupress_add_transient_notice( $title . $newitems . $readmore, 'updated', $notice_id );
		}
	}
}
