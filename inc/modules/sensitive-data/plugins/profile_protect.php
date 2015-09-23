<?php
/*
Module Name: Profile Protect
Description: Ask the user's password to enter in their profile page (need page_protect)
Main Module: sensitive_data
Author: SecuPress
Version: 1.0
*/
add_action( 'load-profile.php', 'secupress_shortcut_settings', 0 );

add_action( 'admin_init', 'secupress_shortcut_profile_hooks' );
function secupress_shortcut_profile_hooks() {

	add_action( 'load-profile.php', 'secupress_shortcut_settings', 0 );
	add_action( 'current_screen', '__secupress_shortcut_profile_hooks' );
	function __secupress_shortcut_profile_hooks() {
		global $pagenow;
		if ( 'profile.php' == $pagenow && 'POST' == $_SERVER['REQUEST_METHOD'] && ! empty( $_POST ) &&
			false === get_site_transient( 'secupress_check_password_' . get_current_user_id() ) ) {
				wp_safe_redirect( add_query_arg( 'error', '1', wp_get_referer() ) );
				die();
		}
	}

}