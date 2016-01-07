<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 *
 */
function secupress_pre_backup() {
	$backup_dir    = secupress_get_backup_path();
	$htaccess_file = dirname( $backup_dir ) . '/.htaccess';
	$fs_chmod_dir  = defined( 'FS_CHMOD_DIR' ) ? FS_CHMOD_DIR : 0755;

	if ( ! is_dir( $backup_dir ) ) {
		mkdir( $backup_dir, $fs_chmod_dir, true );
	}

	if ( ! file_exists( $htaccess_file ) ) {
		$htaccess_file_content  = "Order Allow, Deny\n";
		$htaccess_file_content .= "Deny from all";
		file_put_contents( $htaccess_file, $htaccess_file_content );
	}

	return is_writable( $backup_dir ) && file_exists( $htaccess_file );
}


/**
 *
 */
function secupress_get_backup_path() {
	return WP_CONTENT_DIR . '/backups/secupress-' . substr( sha1( wp_salt( 'nonce' ) ), 2, 8 ) . '/';
}


/**
 *
 */
function secupress_zip_backup_file( $filename ) {

	if ( ! file_exists( $filename ) || ! class_exists( 'ZipArchive' ) ) {
		return false;
	}

	$zip = new ZipArchive();

	if ( $zip->open( $filename . '.zip', ZipArchive::CREATE ) === true ) {
		$zip->addFile( $filename, basename( $filename ) );
		$zip->close();
		unlink( $filename );
		return $filename . '.zip';
	}

	return false;
}


/**
 *
 */
function secupress_get_backup_file_list() {
	return glob( secupress_get_backup_path() . '*.{zip,sql}', GLOB_BRACE );
}


/**
 *
 */
function secupress_print_backup_file_formated( $file, $echo = true ) {

	list( $_date, $_type, $_prefix, $file_uniqid ) = explode( '.', basename( $file ) );

	$_date        = date_i18n( __( 'M jS Y', 'secupress' ) . ' ' . __( 'G:i', 'secupress' ), strtotime( substr_replace( $_date, ':', 13, 1 ) ), true );

	$download_url = wp_nonce_url( admin_url( 'admin-post.php?action=secupress_download_backup&file=' . $file_uniqid ), 'secupress_download_backup-' . $file_uniqid );
	$delete_url   = wp_nonce_url( admin_url( 'admin-post.php?action=secupress_delete_backup&file=' . $file_uniqid ), 'secupress_delete_backup-' . $file_uniqid );

	$file_format  = sprintf( '<p class="db-backup-row">%s <strong>%s</strong> <em>(%s)</em>', ucwords( $_type ), $_prefix, $_date );
	$file_format .= sprintf( '<span><a href="%s">%s</a> | <a href="%s" class="a-delete-backup" data-file-uniqid="%s">%s</a></span></p>', $download_url, _x( 'Download', 'verb', 'secupress' ), $delete_url, $file_uniqid, __( 'Delete', 'secupress' ) );

	if ( $echo ) {
		echo $file_format;
	}

	return $file_format;
}
