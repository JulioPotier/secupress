<?php
/**
 * Plugin Name: {{PLUGIN_NAME}} COOKIEHASH
 * Description: Change the default COOKIEHASH constant value to prevent easy guessing.
 * Version: 2.3.16
 * License: GPLv2
 * License URI: http://www.gnu.org/licenses/gpl-2.0.html
 *
 * Copyright 2012-2025 SecuPress
 */

defined( 'ABSPATH' ) or die( 'Something went wrong.' );

if ( defined( 'SECUPRESS_COOKIEHASH_MODULE_ACTIVE' ) ) {
	@unlink( __FILE__ ); // We are in a duplicated file, should not happen, delete us!
	return;
}

if ( ! get_site_option( 'secupress_active_submodule_wp-config-constant-cookiehash' ) || defined( 'COOKIEHASH' ) ) {
	return;
}

define( 'SECUPRESS_COOKIEHASH_MODULE_ACTIVE', true );

define( 'COOKIEHASH', md5( __FILE__ . '{{HASH}}' ) );
