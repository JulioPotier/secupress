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
	if ( ! isset( $settings['backups-storage_location'] ) || ! in_array( $settings['backups-storage_location'], array( 'local', 'ftp', 'amazons3', 'dropbox', 'rackspace' ) ) ) {
		$settings['backups-storage_location'] = 'local';
	}
	return $settings;
}

add_action( 'wp_ajax_secupress_backup_db', '__secupress_do_backup_db' );
add_action( 'admin_post_secupress_backup_db', '__secupress_do_backup_db' );
function __secupress_do_backup_db() {
	
	if ( ! isset( $_GET['_wpnonce'] ) || ! wp_verify_nonce( $_GET['_wpnonce'], 'secupress_backup_db' ) ) {
		if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
			wp_send_json_error();
		} else {
			wp_nonce_ays( '' );
		}
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
	} else {
		$backup_file = apply_filters( 'secupress.do_backup.file', $backup_file, $backup_storage );
	}

	if ( ! $backup_file ) {
		if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
			wp_send_json_error();
		} else {
			wp_nonce_ays( '' );
		}
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

	if( ini_get( 'zlib.output_compression' ) ) { 
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


add_action( 'wp_ajax_secupress_delete_backup', '__secupress_delete_backup_ajax_post_cb' );
add_action( 'admin_post_secupress_delete_backup', '__secupress_delete_backup_ajax_post_cb' );
function __secupress_delete_backup_ajax_post_cb() {
	
	if ( ! isset( $_GET['_wpnonce'], $_GET['file'] ) || ! wp_verify_nonce( $_GET['_wpnonce'], 'secupress_delete_backup-' . $_GET['file'] ) ) {
		if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
			wp_send_json_error();
		} else {
			wp_nonce_ays( '' );
		}
	}

	$files = glob( secupress_get_hashed_folder_name( 'backup', WP_CONTENT_DIR . '/backups/' ) . '*' . $_GET['file'] . '*.{zip,sql}', GLOB_BRACE );
	if ( ! $files ) {
		if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
			wp_send_json_error();
		} else {
			wp_nonce_ays( '' );
		}
	}

	@array_map( 'unlink', $files );

	if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
		wp_send_json_success( $_GET['file'] );
	} else {
		wp_redirect( wp_get_referer() );
		die();
	}

}

add_action( 'wp_ajax_secupress_delete_backups', '__secupress_delete_backups_ajax_post_cb' );
add_action( 'admin_post_secupress_delete_backups', '__secupress_delete_backups_ajax_post_cb' );
function __secupress_delete_backups_ajax_post_cb() {
	
	if ( ! isset( $_GET['_wpnonce'] ) || ! wp_verify_nonce( $_GET['_wpnonce'], 'secupress_delete_backups' ) ) {
		if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
			wp_send_json_error();
		} else {
			wp_nonce_ays( '' );
		}
	}

	$files = glob( secupress_get_hashed_folder_name( 'backup', WP_CONTENT_DIR . '/backups/' ) . '*.{zip,sql}', GLOB_BRACE );
	if ( ! $files ) {
		if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
			wp_send_json_error();
		} else {
			wp_nonce_ays( '' );
		}
	}

	@array_map( 'unlink', $files );

	if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
		wp_send_json_success();
	} else {
		wp_redirect( wp_get_referer() );
		die();
	}

}