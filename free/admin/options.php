<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/** --------------------------------------------------------------------------------------------- */
/** MODULES OPTIONS ============================================================================= */
/** --------------------------------------------------------------------------------------------- */

add_action( 'admin_init', 'secupress_register_all_settings' );
/**
 * Register all modules settings.
 *
 * @since 1.0
 */
function secupress_register_all_settings() {
	$modules = secupress_get_modules();

	if ( $modules ) {
		foreach ( $modules as $key => $module_data ) {
			secupress_register_setting( $key );
		}
	}
}

add_action( 'update_option_home', 'secupress_scan_https_on_option_update', 10, 2 );
add_action( 'update_option_siteurl', 'secupress_scan_https_on_option_update', 10, 2 );
/**
 * Runs the HTTPS scanner on URL update
 *
 * @since 2.0
 * @author Julio Potier
 **/
function secupress_scan_https_on_option_update( $old_value, $new_value ) {
	$old_value = parse_url( $old_value, PHP_URL_SCHEME );
	$new_value = parse_url( $new_value, PHP_URL_SCHEME );
	if ( $old_value !== $new_value ) {
		secupress_scanit( 'HTTPS' );
	}
}

add_action( 'update_option_default_role', 'secupress_scan_subscription_on_option_update', 10, 2 );
/**
 * Runs the HTTPS scanner on URL update
 *
 * @since 2.0
 * @author Julio Potier
 **/
function secupress_scan_subscription_on_option_update() {
	secupress_scanit( 'Subscription' );
}

add_action( 'upgrader_process_complete', 'secupress_scan_update_plugins_themes_core', 10, 2 );
/**
 * Runs the update scanner on plugin, theme or core update
 *
 * @since 2.0
 * @author Julio Potier
 **/
function secupress_scan_update_plugins_themes_core( $dummy, $hook_extra ) {
	if ( ! isset( $hook_extra['type'] ) ) {
		return;
	}
	switch ( $hook_extra['type'] ) {
		case 'plugin':
			secupress_scanit( 'Plugins_Update' );
		break;

		case 'theme':
			secupress_scanit( 'Themes_Update' );
		break;

		case 'core':
			secupress_scanit( 'Core_Update' );
		break;
	}
}

register_activation_hook( 'woocommerce/woocommerce.php', 'secupress_scan_woocommerce_on_activation' );
/**
 * Runs the update scanner on Woocommerce activation
 *
 * @since 2.0
 * @author Julio Potier
 **/
function secupress_scan_woocommerce_on_activation() {
	secupress_scanit( 'Woocommerce_Discloses' );
}

register_activation_hook( 'sitepress-multilingual-cms/sitepress.php', 'secupress_scan_wpml_on_activation' );
/**
 * Runs the update scanner on WPML activation
 *
 * @since 2.0
 * @author Julio Potier
 **/
function secupress_scan_wpml_on_activation() {
	secupress_scanit( 'Wpml_Discloses' );
}
