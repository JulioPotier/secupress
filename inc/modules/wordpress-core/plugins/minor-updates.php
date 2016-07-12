<?php
/*
Module Name: Minor Updates
Description: Allow Auto Updates for Minor Versions
Main Module: wordpress_core
Author: SecuPress
Version: 1.0
*/
defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

// Fix using filters automatic_updater_disabled, automatic_updater_disabled.
add_filter( 'automatic_updater_disabled',    '__return_false', PHP_INT_MAX );
add_filter( 'allow_minor_auto_core_updates', '__return_true',  PHP_INT_MAX );
