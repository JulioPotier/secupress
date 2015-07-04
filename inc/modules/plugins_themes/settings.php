<?php
defined( 'ABSPATH' ) or	die( 'Cheatin&#8217; uh?' );

global $modulenow, $sectionnow, $pluginnow, $current_user;

secupress_load_settings( $modulenow, 'plugins' );

secupress_load_settings( $modulenow, 'themes' );