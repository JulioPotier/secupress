<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/** --------------------------------------------------------------------------------------------- */
/** MOVE LOGIN MIGRATION ======================================================================== */
/** --------------------------------------------------------------------------------------------- */

if ( secupress_is_plugin_active( 'sf-move-login/sf-move-login.php' ) ) {
	if ( ! secupress_is_submodule_active( 'users-login', 'move-login' ) ) {
		$sfml_settings   = get_option( 'sfml' );
		if ( isset( $sfml_settings['slugs.login'] ) ) { // Move Login <2.6
			$login_slug = $sfml_settings['slugs.login'];
			delete_option( 'sfml' );
			delete_option( 'sfml_version' );
			secupress_activate_submodule( 'users-login', 'move-login' );
			secupress_update_module_option( 'move-login_slug-login', $login_slug, 'users-login' );
		}
		$movelogin_settings   = get_option( 'movelogin_users-login_settings' );
		if ( isset( $movelogin_settings['move-login_slug-login'] ) ) { // Move Login 2.6+
			$login_slug = $movelogin_settings['move-login_slug-login'];
			delete_option( 'movelogin_settings' );
			delete_option( 'movelogin_users-login_settings' );
			delete_option( 'movelogin_active_submodule_move-login' );
			secupress_activate_submodule( 'users-login', 'move-login' );
			secupress_update_module_option( 'move-login_slug-login', $login_slug, 'users-login' );
		}
	}
	deactivate_plugins( 'sf-move-login/sf-move-login.php' );
	secupress_add_notice( sprintf( __( 'The plugin "Move Login" has been deactivated because it is no longer needed. This feature is now included in %s. You can <a href="%s">delete</a> it now.', 'secupress' ), SECUPRESS_PLUGIN_NAME, wp_nonce_url( admin_url( 'plugins.php?action=delete&plugin=sf-move-login/sf-move-login.php' ), 'delete-plugin_sf-move-login/sf-move-login.php' ) ), 'success' );
}