<?php
/*
Module Name: Minor Updates
Description: Allow Auto Updates for Minor Versions
Main Module: wordpress_core
Author: SecuPress
Version: 1.0
*/
defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

// Try via constant AUTOMATIC_UPDATER_DISABLED
defined( 'AUTOMATIC_UPDATER_DISABLED' ) or define( 'AUTOMATIC_UPDATER_DISABLED', false );

// or filter automatic_updater_disabled
add_filter( 'automatic_updater_disabled', '__return_false', PHP_INT_MAX );