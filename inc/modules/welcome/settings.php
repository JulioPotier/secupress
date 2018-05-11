<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

if ( defined( 'WP_SWL' ) && WP_SWL ) {
	$this->load_plugin_settings( 'wl' );
}
$this->load_plugin_settings( 'api-key' );
$this->load_plugin_settings( 'settings-manager' );
