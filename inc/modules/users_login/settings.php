<?php
defined( 'ABSPATH' ) or	die( 'Cheatin&#8217; uh?' );

global $modulenow, $sectionnow, $pluginnow, $current_user;

secupress_load_settings( $modulenow, 'double_auth' );

secupress_load_settings( $modulenow, 'bad_logins' );