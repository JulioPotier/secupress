<?php
/*
Module Name: Detect Bad Themes
Description: Detect if a theme you're using is known as vulnerable
Main Module: plugins_themes
Author: SecuPress
Version: 1.0
*/
defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

/**
 * 4 times a day, launch an async call to refresh the vulnerable themes
 *
 * @return void
 * @since 1.0
 **/
add_action( 'admin_footer', 'secupress_detect_bad_themes_async_get_infos' );
function secupress_detect_bad_themes_async_get_infos() {
	if ( false === get_site_transient( 'secupress-detect-bad-themes' ) ) {
		$args = array(
			'timeout'   => 0.01,
			'blocking'  => false,
			'cookies'   => $_COOKIE,
			'sslverify' => apply_filters( 'https_local_ssl_verify', false ),
		);
		wp_remote_get( admin_url( 'admin-post.php' ) . '?action=secupress_refresh_bad_themes&_wpnonce=' . wp_create_nonce( 'detect-bad-themes' ), $args );
		set_site_transient( 'secupress-detect-bad-themes', 1, 6 * HOUR_IN_SECONDS );
	}
}

/**
 * Call the refresh of the vulnerable themes
 *
 * @return void
 * @since 1.0
 **/
add_action( 'admin_post_secupress_refresh_bad_themes', '__secupress_refresh_bad_themes_ajax_post_cb' );
function __secupress_refresh_bad_themes_ajax_post_cb() {
	if ( ! isset( $_GET['_wpnonce'] ) || ! wp_verify_nonce( $_GET['_wpnonce'], 'detect-bad-themes' ) ) {
		secupress_admin_die();
	}
	secupress_refresh_vulnerable_themes();
}
/**
 * Add a red banner on each "bad" theme on themes page
 *
 * @return void
 * @since 1.0
 **/
add_action( 'admin_footer-themes.php', 'secupress_detect_bad_themes_after_theme_row' );
function secupress_detect_bad_themes_after_theme_row() {
	if ( ( is_network_admin() || ! is_multisite() ) && ! current_user_can( 'update_themes' ) && ! current_user_can( 'delete_themes' ) && ! current_user_can( 'switch_themes' ) ) { // ie. Administrator
		return; 
	}
	$themes = array( 
					'vulns'      => secupress_get_vulnerable_themes(), 
					);
	$all_themes = wp_get_themes();
	foreach ( $all_themes as $theme_name => $theme_data ) {

		$is_vuln         = isset( $themes['vulns'][ $theme_name ] );
		$theme_vuln      = $is_vuln ? $themes['vulns'][ $theme_name ] : false;

		if ( ! $is_vuln ) {
			return;
		}

		if ( $is_vuln && version_compare( $theme_data['Version'], $theme_vuln->fixed_in ) == 1 && $theme_vuln->fixed_in != '' ) {
			return;
		}

		$current_theme = wp_get_theme();
		$current       = get_site_transient( 'update_themes' );
		$r             = isset( $current->response[ $theme_name ] ) ? (object) $current->response[ $theme_name ] : null;

		// HTML OUTPUT
		if ( $is_vuln ) {

			$theme_vuln->flaws = unserialize( $theme_vuln->flaws );

			echo '<div class="theme-update secupress-bad-theme" data-theme="' . esc_attr( $theme_name ) . '">';

			printf( _n(	__( '<strong>%1$s %2$s</strong> is known to contain this vulnerability: %3$s.', 'secupress' ), 
						__( '<strong>%1$s %2$s</strong> is known to contain these vulnerabilities: %3$s.', 'secupress' ), 
						count( $theme_vuln->flaws ), 'secupress' ), 
						$theme_data['Name'],
						$theme_vuln->fixed_in != '' ? sprintf( __( 'version %s (or lower)', 'secupress' ), $theme_vuln->fixed_in ) : __( 'all versions', 'secupress' ), 
						'<strong>' . wp_sprintf( '%l', $theme_vuln->flaws ) . '</strong>'
					); 
			
			echo '<br>';
			printf( __( '<a href="%s" target="_blank">More information</a>', 'secupress' ), $theme_vuln->refs );
			if ( $theme_vuln->fixed_in && current_user_can( 'update_themes' ) ) {
				
				echo '<p>';
				if ( ! empty( $r->package ) ) {
					printf( '<span class="dashicons dashicons-update"></span> ' . __( 'We invite you to <a href="%1$s">Update</a> this theme in version %2$s.', 'secupress' ), 
						wp_nonce_url( admin_url('update.php?action=upgrade-theme&theme=') . $theme_name, 'upgrade-theme_' . $theme_name ),
						'<strong>' . ( isset( $r->new_version ) ? $r->new_version : $theme_vuln->fixed_in ) . '</strong>'
					);
				} else {
					'<span class="dashicons dashicons-update"></span> ' . __( 'We invite you to Update this theme <em>(Automatic update is unavailable for this theme.)</em>.', 'secupress' );
				}
				echo '</p>';
				if ( $theme_name == $current_theme->stylesheet || $theme_name == $current_theme->template ) {
					echo '<span class="dashicons dashicons-admin-appearance"></span> ' . __( 'We invite you to switch theme, then delete it.', 'secupress' );
				} else {
					$delete_url = wp_nonce_url( admin_url( 'themes.php?action=delete&stylesheet=' . $theme_name ), 'delete-theme_' . $theme_name );
					printf( '<span class="dashicons dashicons-admin-appearance"></span> ' . __( 'We invite you to <a href="%s">delete it</a>.', 'secupress' ), $delete_url );
				}
			}

		}
				
		echo '</div>';
		?>
		</td>
	</tr>
	<?php
	}
}

/**
 * Add a notice if a theme is considered as "bad"
 *
 * @return void
 * @since 1.0
 **/

add_action( 'admin_head', 'secupress_detect_bad_themes_add_notices' );
function secupress_detect_bad_themes_add_notices() {
	global $pagenow;

	// don't display the notice yet, next reload.
	if ( false === get_site_transient( 'secupress-detect-bad-themes' ) || 'themes.php' == $pagenow ||
	( is_network_admin() || ! is_multisite() ) && ! current_user_can( 'update_plugins' ) && ! current_user_can( 'delete_plugins' ) && ! current_user_can( 'activate_plugins' ) ) { // ie. Administrator
		return; 
	}

	$themes = array( 
				'vulns'      => secupress_get_vulnerable_themes(), 
				);

	if ( $themes['vulns'] ) {
		$counter  = count( $themes['vulns'] );
		$url      = admin_url( 'themes.php' );
		$message  = sprintf( 
						_n( 'Your installation contains %1$s theme considered as <em>bad</em>, check the details in <a href="%2$s">the themes page</a>.', 
							'Your installation contains %1$s themes considered as <em>bad</em>, check the details in <a href="%2$s">the themes page</a>.', 
							$counter, 'secupress' ), 
					'<strong>' . $counter . '</strong>', $url );
		secupress_add_notice( $message, 'error', 'bad-themes' );
	}
}