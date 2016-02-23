<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/*------------------------------------------------------------------------------------------------*/
/* ON MODULE SETTINGS SAVE ====================================================================== */
/*------------------------------------------------------------------------------------------------*/

/**
 * Callback to filter, sanitize.
 *
 * @since 1.0
 * @return array $settings
 */
function __secupress_backups_settings_callback( $settings ) {
	$locations = secupress_backups_storage_labels();

	if ( ! isset( $settings['backups-storage_location'] ) || ! secupress_is_pro() || ! isset( $locations[ $settings['backups-storage_location'] ] ) ) {
		$settings['backups-storage_location'] = 'local';
	}

	return $settings;
}


add_action( 'wp_ajax_secupress_backup_db',    '__secupress_do_backup_db' );
add_action( 'admin_post_secupress_backup_db', '__secupress_do_backup_db' );

function __secupress_do_backup_db() {

	if ( ! isset( $_GET['_wpnonce'] ) || ! wp_verify_nonce( $_GET['_wpnonce'], 'secupress_backup_db' ) ) {
		secupress_admin_die();
	}

	$wp_tables      = secupress_get_wp_tables();
	$other_tables   = secupress_get_non_wp_tables();
	$backup_storage = secupress_get_module_option( 'backups-storage_location', 'local', 'backups' );
	$backup_file    = '';

	if ( 'local' == $backup_storage ) {
		$backup_file  = secupress_get_hashed_folder_name( 'backup', WP_CONTENT_DIR . '/backups/' ) . secupress_get_db_backup_filename();

		if ( secupress_pre_backup() ) {
			file_put_contents( $backup_file, secupress_get_db_tables_content( array_merge( $wp_tables, $other_tables ) ) );
			$backup_file = secupress_zip_backup_file( $backup_file );
		}
	} elseif ( secupress_is_pro() ) {
		$backup_file = apply_filters( 'secupress.do_backup.file', $backup_file, $backup_storage );
	}

	if ( ! $backup_file ) {
		secupress_admin_die();
	}

	if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
		wp_send_json_success( secupress_print_backup_file_formated( $backup_file, false ) );
	} else {
		wp_redirect( wp_get_referer() );
		die();
	}
}


// No AJAX support needed here
add_action( 'admin_post_secupress_download_backup', '__secupress_download_backup_ajax_post_cb' );

function __secupress_download_backup_ajax_post_cb() {

	if ( ! isset( $_GET['_wpnonce'], $_GET['file'] ) || ! wp_verify_nonce( $_GET['_wpnonce'], 'secupress_download_backup-' . $_GET['file'] ) ) {
		wp_nonce_ays( '' );
	}

	$file = glob( secupress_get_hashed_folder_name( 'backup', WP_CONTENT_DIR . '/backups/' ) . '*' . $_GET['file'] . '*.{zip,sql}', GLOB_BRACE );

	if ( $file ) {
		$file = reset( $file );
	} else {
		wp_nonce_ays( '' );
	}

	if ( ini_get( 'zlib.output_compression' ) ) {
		ini_set( 'zlib.output_compression', 'Off' );
	}

	header( 'Pragma: public' );
	header( 'Expires: 0' );
	header( 'Cache-Control: must-revalidate, post-check=0, pre-check=0');
	header( 'Last-Modified: ' . gmdate ( 'D, d M Y H:i:s', filemtime( $file ) ) . ' GMT' );
	header( 'Cache-Control: private', false );
	header( 'Content-Type: application/force-download' );
	header( 'Content-Disposition: attachment; filename="' . basename( $file ) . '"' );
	header( 'Content-Transfer-Encoding: binary' );
	header( 'Content-Length: ' . filesize( $file ) );
	header( 'Connection: close' );
	readfile($file);
	die();
}


add_action( 'wp_ajax_secupress_delete_backup',    '__secupress_delete_backup_ajax_post_cb' );
add_action( 'admin_post_secupress_delete_backup', '__secupress_delete_backup_ajax_post_cb' );

function __secupress_delete_backup_ajax_post_cb() {

	if ( ! isset( $_GET['_wpnonce'] ) || ! isset( $_GET['file'] ) || ! wp_verify_nonce( $_GET['_wpnonce'], 'secupress_delete_backup-' . $_GET['file'] ) ) {
		secupress_admin_die();
	}

	$files = glob( secupress_get_hashed_folder_name( 'backup', WP_CONTENT_DIR . '/backups/' ) . '*' . $_GET['file'] . '*.{zip,sql}', GLOB_BRACE );

	if ( ! $files ) {
		secupress_admin_die();
	}

	@array_map( 'unlink', $files );

	secupress_admin_send_response_or_redirect( $_GET['file'] );
}


add_action( 'wp_ajax_secupress_delete_backups',    '__secupress_delete_backups_ajax_post_cb' );
add_action( 'admin_post_secupress_delete_backups', '__secupress_delete_backups_ajax_post_cb' );

function __secupress_delete_backups_ajax_post_cb() {

	if ( ! isset( $_GET['_wpnonce'] ) || ! wp_verify_nonce( $_GET['_wpnonce'], 'secupress_delete_backups' ) ) {
		secupress_admin_die();
	}

	$files = glob( secupress_get_hashed_folder_name( 'backup', WP_CONTENT_DIR . '/backups/' ) . '*.{zip,sql}', GLOB_BRACE );

	if ( ! $files ) {
		secupress_admin_die();
	}

	@array_map( 'unlink', $files );

	secupress_admin_send_response_or_redirect( 1 );
}


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


add_action( 'wp_ajax_secupress_diff_file',    '__secupress_diff_file_ajax_post_cb' );
add_action( 'admin_post_secupress_diff_file', '__secupress_diff_file_ajax_post_cb' );

function __secupress_diff_file_ajax_post_cb() {
	global $wp_version;

	if ( ! current_user_can( 'administrator' ) || ! isset( $_GET['_wpnonce'] ) || ! isset( $_GET['file'] ) || ! wp_verify_nonce( $_GET['_wpnonce'], 'secupress_diff_file-' . $_GET['file'] ) ) {
		secupress_admin_die();
	}

	$file    = $_GET['file'];
	$content = '';

	$response = wp_remote_get( esc_url( "http://core.svn.wordpress.org/tags/$wp_version/$file")  );
	if ( ! is_wp_error( $response ) && 200 == wp_remote_retrieve_response_code( $response ) ) {
		$text = secupress_text_diff( wp_remote_retrieve_body( $response ), file_get_contents( ABSPATH . $file ), array( 'title' => $file ), 'wp-includes/version.php' == $file );
		$content = $text ? $text : $content;
	}

	if ( $content ) {
		secupress_action_page( __( 'File Differences', 'secupress' ), $content, array( 'head' => '<link rel="stylesheet" type="text/css" href="' . admin_url( 'css/revisions.css' ) . '">' ) );
	} else {
		secupress_die( sprintf( __( 'Error while loading %s', 'secupress' ), esc_html( "http://core.svn.wordpress.org/tags/$wp_version/$file" ) ) );
	}

}


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
		$response = wp_remote_get( "http://core.svn.wordpress.org/tags/$wp_version/$file" );
		if ( ! is_wp_error( $response ) && 200 == wp_remote_retrieve_response_code( $response ) ) {
			$content = wp_remote_retrieve_body( $response );
			file_put_contents( ABSPATH . $file, $content );
			$full_filetree[ $wp_version ][ $file ] = md5( $content );
		}
	}
	
	update_option( SECUPRESS_FULL_FILETREE, $full_filetree );

	secupress_admin_send_response_or_redirect( 1 );

}

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
		$response = wp_remote_get( "http://core.svn.wordpress.org/tags/$wp_version/$file" );
		if ( ! is_wp_error( $response ) && 200 == wp_remote_retrieve_response_code( $response ) ) {
			$content = wp_remote_retrieve_body( $response );
			file_put_contents( ABSPATH . $file, $content );
			$full_filetree[ $wp_version ][ $file ] = md5( $content );
		}
	}
	
	update_option( SECUPRESS_FULL_FILETREE, $full_filetree );

	secupress_admin_send_response_or_redirect( 1 );

}


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



/*------------------------------------------------------------------------------------------------*/
/* TOOLS ======================================================================================== */
/*------------------------------------------------------------------------------------------------*/

/**
 * Return the values/labels used for the backups storage setting.
 *
 * @since 1.0
 *
 * @return (array) An array with back types as keys and labels as values.
 */
function secupress_backups_storage_labels() {
	return array(
		'local'     => __( 'Local', 'secupress' ),
		'ftp'       => __( 'FTP', 'secupress' ),
		'amazons3'  => __( 'Amazon S3', 'secupress' ),
		'dropbox'   => __( 'Dropbox', 'secupress' ),
		'rackspace' => __( 'Rackspace Cloud', 'secupress' ),
	);
}
