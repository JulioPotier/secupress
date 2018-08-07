<?php
/**
 * Module Name: Expert Mode
 * Description: Hide descriptions and helpers
 * Main Module: users_login
 * Author: SecuPress
 * Version: 1.0
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

add_filter( 'secupress.settings.help', '__return_empty_string' );
add_filter( 'secupress.settings.description', '__return_empty_string' );