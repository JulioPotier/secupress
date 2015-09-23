<?php
/*
Module Name: Major Updates
Description: Allow Auto Updates for Major Versions
Main Module: wordpress_core
Author: SecuPress
Version: 1.0
*/
defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

// Try via constant AUTOMATIC_UPDATER_DISABLED
defined( 'AUTOMATIC_UPDATER_DISABLED' ) or define( 'AUTOMATIC_UPDATER_DISABLED', false );

// Try via constant WP_AUTO_UPDATE_CORE
defined( 'WP_AUTO_UPDATE_CORE' ) or define( 'WP_AUTO_UPDATE_CORE', true );

// and filters auto_update_core, allow_major_auto_core_updates
add_filter( 'auto_update_core', '__return_true', PHP_INT_MAX );
add_filter( 'allow_major_auto_core_updates', '__return_true', PHP_INT_MAX );