<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

if ( secupress_is_pro() && defined( 'WP_SWL' ) && WP_SWL ) {
	$this->load_plugin_settings( 'wl' );
}
if ( ! secupress_is_white_label() && ( ! defined( 'SECUPRESS_HIDE_API_KEY' ) || ! SECUPRESS_HIDE_API_KEY ) ) {
	$this->load_plugin_settings( 'api-key' );
}
if ( ! defined( 'SECUPRESS_HIDE_ADVANCED_SETTINGS' ) || ! SECUPRESS_HIDE_ADVANCED_SETTINGS ) {
	$this->load_plugin_settings( 'advanced-settings' );
}
$this->load_plugin_settings( 'settings-manager' );
