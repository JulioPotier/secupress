<?php
/**
 * Module Name: Major Updates
 * Description: Allow Auto Updates for Major Versions
 * Main Module: wordpress_core
 * Author: SecuPress
 * Version: 1.0
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );

// Fix using filters auto_update_core, allow_major_auto_core_updates.
add_filter( 'auto_update_core',              '__return_true', PHP_INT_MAX );
add_filter( 'allow_major_auto_core_updates', '__return_true', PHP_INT_MAX );
