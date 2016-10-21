<?php
/**
 * Plugin Name: SecuPress COOKIEHASH
 * Plugin URI: https://secupress.me
 * Description: Change the default COOKIEHASH constant value to prevent easy guessing.
 * Author: WP Media
 * Author URI: http://wp-media.me
 * Version: 1.0
 * License: GPLv2
 * License URI: http://www.gnu.org/licenses/gpl-2.0.html
 *
 * Copyright 2012-2016 SecuPress
 */

define( 'COOKIEHASH', md5( __FILE__ . '{{HASH}}' ) );
