<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Launch the Robot
 *
 * @since 1.0
 *
 * @param string $spider (default: 'cache-preload') The spider name: cache-preload or cache-json
 * @param string $lang (default: '') The language code to preload
 * @return void
 */
function run_secupress_bot( $spider = '', $lang = '' ) {
	/**
	 * Filter to manage the bot job
	 *
	 * @since 1.0
	 *
	 * @param bool           Do the job or not
	 * @param string $spider The spider name
	 * @param string $lang   The language code to preload
	*/
	if ( ! apply_filters( 'do_run_secupress_bot', true, $spider, $lang ) ) {
		return false;
	}
	////
}
