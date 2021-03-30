<?php
/**
 * Plugin Name: {{PLUGIN_NAME}} Notice ({{PLUGIN_ID}})
 * Description: This plugin purpose is only to display a message after {{PLUGIN_NAME}} is deactivated. It will be deleted once the message is dismissed.
 * Version: 1.0.2
 * License: GPLv2
 * License URI: http://www.gnu.org/licenses/gpl-2.0.html
 *
 * Copyright 2012-2016 SecuPress
 */

defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/**
 * Print the notice.
 *
 * @since 1.0
 */
add_action( 'all_admin_notices', 'secupress_mup_notice_{{PLUGIN_ID}}' );

function secupress_mup_notice_{{PLUGIN_ID}}() {
	$capa = is_multisite() ? 'manage_network_options' : 'administrator';

	if ( get_current_user_id() !== {{USER_ID}} || ! current_user_can( $capa ) ) {
		return;
	}

	$port = (int) $_SERVER['SERVER_PORT'];
	$port = 80 !== $port && 443 !== $port ? ( ':' . $port ) : '';
	$url  = ! empty( $GLOBALS['HTTP_SERVER_VARS']['REQUEST_URI'] ) ? $GLOBALS['HTTP_SERVER_VARS']['REQUEST_URI'] : ( ! empty( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : '' );
	$url  = 'http' . ( is_ssl() ? 's' : '' ) . '://' . $_SERVER['HTTP_HOST'] . $port . $url;
	$url  = urlencode( esc_url_raw( $url ) );
	$url  = admin_url( 'admin-post.php?action=secupress_kill_mu_notice_{{PLUGIN_ID}}&_wp_http_referer=' . $url );
	$url  = wp_nonce_url( $url, 'secupress-mup-notice-{{PLUGIN_ID}}-{{USER_ID}}' );
	?>
	<div class="updated notice secupress-mup-notice"><p>
		{{MESSAGE}}
		<a href="<?php echo esc_url( $url ); ?>" class="button button-primary" style="float:right;margin-top:-.35em">{{BUTTON_TEXT}}</a>
	</p></div>
	<?php
}


/**
 * Delete this file.
 *
 * @since 1.0
 */
add_action( 'admin_post_secupress_kill_mu_notice_{{PLUGIN_ID}}', 'secupress_mup_kill_notice_{{PLUGIN_ID}}' );

function secupress_mup_kill_notice_{{PLUGIN_ID}}() {
	$capa = is_multisite() ? 'manage_network_options' : 'administrator';

	if ( get_current_user_id() !== {{USER_ID}} || ! current_user_can( $capa ) ) {
		return;
	}

	check_admin_referer( 'secupress-mup-notice-{{PLUGIN_ID}}-{{USER_ID}}' );
	unlink( __FILE__ );
	wp_safe_redirect( wp_get_referer() );
	die();
}
