<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Will handle the deletion for non core WordPress files
 *
 * @return void
 * @since 1.0
 **/
add_action( 'wp_ajax_secupress_delete_scanned_files',    '__secupress_delete_scanned_files_ajax_post_cb' );
add_action( 'admin_post_secupress_delete_scanned_files', '__secupress_delete_scanned_files_ajax_post_cb' );

function __secupress_delete_scanned_files_ajax_post_cb() {
	global $wp_version;
	if ( ! isset( $_GET['_wpnonce'] ) || ! isset( $_POST['files'] ) || ! wp_verify_nonce( $_GET['_wpnonce'], 'secupress_delete_scanned_files' ) ) {
		secupress_admin_die();
	}


	$diff_from_root_core = array();

	if ( false !== ( $full_filetree = get_option( SECUPRESS_FULL_FILETREE ) ) && false !== ( $wp_core_files_hashes = get_option( SECUPRESS_WP_CORE_FILES_HASHES ) ) &&
		isset( $wp_core_files_hashes[ $wp_version ]['checksums'], $full_filetree[ $wp_version ] )
	) {
		$orig_self_filetree   = $full_filetree;
		$wp_content_dir       = str_replace( realpath( ABSPATH ) . DIRECTORY_SEPARATOR, '/' , WP_CONTENT_DIR );
		$wp_core_files_hashes = $wp_core_files_hashes[ $wp_version ]['checksums'];
		$wp_core_files_hashes[ 'wp-config.php' ] = 'wp-config.php'; // add this since it's not in the zip but depends from WordPress

		if ( is_multisite() ) {
			$wp_core_files_hashes[ $wp_content_dir . '/sunrise.php' ] = '/sunrise.php'; // add this since it's not in the zip but depends from WordPress MS
		}

		if ( defined( 'WP_CACHE' ) && WP_CACHE ) {
			$wp_core_files_hashes[ $wp_content_dir . '/advanced-cache.php' ] = '/advanced-cache.php'; // add this since it's not in the zip but depends from WordPress Cache
		}
		$wp_core_files_hashes = apply_filters( 'secupress.wp_core_files_hashes', $wp_core_files_hashes );
		$full_filetree        = $full_filetree[ $wp_version ];
		$diff_from_root_core  = array_flip( array_diff( $full_filetree, array_flip( $wp_core_files_hashes ) ) );
	}

	if ( ! $diff_from_root_core ) {
		secupress_admin_die();
	}

	$files = array_intersect( $_POST['files'], $diff_from_root_core );

	foreach ( $files as $file ) {
		if ( unlink( ABSPATH . $file ) ) {
			unset( $orig_self_filetree[ $wp_version ][ $file ] );
		}
	}

	update_option( SECUPRESS_FULL_FILETREE, $orig_self_filetree );

	secupress_admin_send_response_or_redirect( 1 );
}

/**
 * Will display the differences between 2 files from WP Core, using WP core classes
 *
 * @return void
 * @since 1.0
 **/
add_action( 'wp_ajax_secupress_diff_file',    '__secupress_diff_file_ajax_post_cb' );
add_action( 'admin_post_secupress_diff_file', '__secupress_diff_file_ajax_post_cb' );

function __secupress_diff_file_ajax_post_cb() {
	global $wp_version;

	if ( ! current_user_can( 'administrator' ) || ! isset( $_GET['_wpnonce'] ) || ! isset( $_GET['file'] ) || ! wp_verify_nonce( $_GET['_wpnonce'], 'secupress_diff_file-' . $_GET['file'] ) ) {
		secupress_admin_die();
	}

	$file    = $_GET['file'];
	$content = '';

	$response = wp_remote_get( esc_url( "https://core.svn.wordpress.org/tags/$wp_version/$file")  );
	if ( ! is_wp_error( $response ) && 200 == wp_remote_retrieve_response_code( $response ) ) {
		$text = secupress_text_diff( wp_remote_retrieve_body( $response ), file_get_contents( ABSPATH . $file ), array( 'title' => $file ) );
		$content = $text ? $text : $content;
	}

	if ( $content ) {
		secupress_action_page( __( 'File Differences', 'secupress' ), $content, array( 'head' => '<link rel="stylesheet" type="text/css" href="' . admin_url( 'css/revisions.css' ) . '">' ) );
	} else {
		secupress_die( sprintf( __( 'Error while loading %s', 'secupress' ), esc_html( "https://core.svn.wordpress.org/tags/$wp_version/$file" ) ) );
	}

}

/**
 * Will download WP Core files that are different from the original
 *
 * @return void
 * @since 1.0
 **/
add_action( 'wp_ajax_secupress_recover_diff_files',    '__secupress_recover_diff_files_ajax_post_cb' );
add_action( 'admin_post_secupress_recover_diff_files', '__secupress_recover_diff_files_ajax_post_cb' );
function __secupress_recover_diff_files_ajax_post_cb() { //// async
	global $wp_version;

	$full_filetree        = get_option( SECUPRESS_FULL_FILETREE, false );
	$wp_core_files_hashes = get_option( SECUPRESS_WP_CORE_FILES_HASHES, false );

	if ( ! $full_filetree || ! $wp_core_files_hashes || ! current_user_can( 'administrator' ) ||
		! isset( $_GET['_wpnonce'] ) || empty( $_POST['files'] ) || ! wp_verify_nonce( $_GET['_wpnonce'], 'secupress_recover_diff_files' )
 	) {
		secupress_admin_die();
	}

	foreach ( $_POST['files'] as $file ) {
		if ( ! file_exists( ABSPATH . $file ) && isset( $wp_core_files_hashes[ $file ] ) ) {
			continue;
		}
		$response = wp_remote_get( "https://core.svn.wordpress.org/tags/$wp_version/$file" );
		if ( ! is_wp_error( $response ) && 200 == wp_remote_retrieve_response_code( $response ) ) {
			$content = wp_remote_retrieve_body( $response );
			file_put_contents( ABSPATH . $file, $content );
			$full_filetree[ $wp_version ][ $file ] = md5( $content );
		}
	}

	update_option( SECUPRESS_FULL_FILETREE, $full_filetree );

	secupress_admin_send_response_or_redirect( 1 );

}

/**
 * Will download missing files from WP Core
 *
 * @return void
 * @since 1.0
 **/

add_action( 'wp_ajax_secupress_recover_missing_files',    '__secupress_recover_missing_files_ajax_post_cb' );
add_action( 'admin_post_secupress_recover_missing_files', '__secupress_recover_missing_files_ajax_post_cb' );
function __secupress_recover_missing_files_ajax_post_cb() { //// async
	global $wp_version;

	$full_filetree        = get_option( SECUPRESS_FULL_FILETREE, false );
	$wp_core_files_hashes = get_option( SECUPRESS_WP_CORE_FILES_HASHES, false );


	if ( ! $full_filetree || ! $wp_core_files_hashes || ! current_user_can( 'administrator' ) ||
		! isset( $_GET['_wpnonce'] ) || empty( $_POST['files'] ) || ! wp_verify_nonce( $_GET['_wpnonce'], 'secupress_recover_missing_files' )
 	) {
		secupress_admin_die();
	}

	$wp_core_files_hashes = array_flip( array_filter( array_flip( $wp_core_files_hashes[ $wp_version ]['checksums'] ), 'secupress_filter_no_content' ) );
	$missing_from_root_core = array_diff_key( $wp_core_files_hashes, $full_filetree[ $wp_version ] );

	foreach ( $_POST['files'] as $file ) {
		if ( file_exists( ABSPATH . $file ) && ! isset( $missing_from_root_core[ $file ] ) ) {
			continue;
		}
		$response = wp_remote_get( "https://core.svn.wordpress.org/tags/$wp_version/$file" );
		if ( ! is_wp_error( $response ) && 200 == wp_remote_retrieve_response_code( $response ) ) {
			$content = wp_remote_retrieve_body( $response );
			file_put_contents( ABSPATH . $file, $content );
			$full_filetree[ $wp_version ][ $file ] = md5( $content );
		}
	}

	update_option( SECUPRESS_FULL_FILETREE, $full_filetree );

	secupress_admin_send_response_or_redirect( 1 );

}

/**
 * Will delete old WP core files still present in this installation
 *
 * @return void
 * @since 1.0
 **/

add_action( 'wp_ajax_secupress_old_files',    '__secupress_old_files_ajax_post_cb' );
add_action( 'admin_post_secupress_old_files', '__secupress_old_files_ajax_post_cb' );
function __secupress_old_files_ajax_post_cb() {
	global $wp_version;

	$full_filetree        = get_option( SECUPRESS_FULL_FILETREE, false );

	require_once( ABSPATH . 'wp-admin/includes/update-core.php' );
	global $_old_files;
	$wp_old_files = array();
	foreach ( $_old_files as $file ) {
		if ( file_exists( ABSPATH . $file ) ) {
			$wp_old_files[ $file ] = $file;
		}
	}

	if ( ! $wp_old_files || ! current_user_can( 'administrator' ) ||
		! isset( $_GET['_wpnonce'] ) || empty( $_POST['files'] ) || ! wp_verify_nonce( $_GET['_wpnonce'], 'secupress_old_files' )
 	) {
		secupress_admin_die();
	}

	foreach ( $_POST['files'] as $file ) {
		if ( ! file_exists( ABSPATH . $file ) || ! isset( $wp_old_files[ $file ] ) ) {
			continue;
		}
		if ( @unlink( ABSPATH . $file ) ) {
			unset( $full_filetree[ $wp_version ][ $file ] );
		}
	}

	update_option( SECUPRESS_FULL_FILETREE, $full_filetree );

	secupress_admin_send_response_or_redirect( 1 );

}
