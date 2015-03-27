<?php

// If uninstall not called from WordPress exit
defined( 'WP_UNINSTALL_PLUGIN' ) or die( 'Cheatin&#8217; uh?' );

// delete_transient( '' ); ////

// Delete WP Rocket options
delete_option( 'secupress_settings' );