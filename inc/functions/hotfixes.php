<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

add_filter( 'wp_update_attachment_metadata', 'secupress_fix_wp_496_1' );
/**
 * Fix the vulnerability discovered on thumb meta data on june 2018, not patched in WP core
 *
 * @param (array) $data Meta data from a media.
 * @return (array) $data Meta data from a media.
 * @author Julio Potier
 * @since 1.4.5.1
 * @source https://blog.ripstech.com/2018/wordpress-file-delete-to-code-execution/
 **/
function secupress_fix_wp_496_1( $data ) {
	if ( isset( $data['thumb'] ) ) {
		$data['thumb'] = basename( $data['thumb'] );
	}

	return $data;
}
