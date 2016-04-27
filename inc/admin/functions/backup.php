<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Prepare the backups folder: create the folder if it doesn't exist and place a `.htaccess` file inside, denying access to.
 *
 * @since 1.0
 *
 * @return (bool) True if the folder is writable and the `.htaccess` file exists.
 */
function secupress_pre_backup() {
	global $is_apache, $is_nginx, $is_iis7;

	$backups_dir  = WP_CONTENT_DIR . '/backups/';
	$backup_dir   = secupress_get_hashed_folder_name( 'backup', $backups_dir );
	$fs_chmod_dir = defined( 'FS_CHMOD_DIR' ) ? FS_CHMOD_DIR : 0755;

	if ( ! is_dir( $backup_dir ) ) {
		mkdir( $backup_dir, $fs_chmod_dir, true );
	}

	if ( $is_apache ) {
		$file          = '.htaccess';
		$file_content  = "Order allow,deny\n";
		$file_content .= 'Deny from all';
	} elseif ( $is_iis7 ) {
		// - https://www.iis.net/configreference/system.webserver/security/authorization
		// - https://technet.microsoft.com/en-us/library/cc772441%28v=ws.10%29.aspx
		$file          = 'web.config';
		$file_content  = '<?xml version="1.0" encoding="utf-8" ?>
<configuration>
  <system.webServer>
    <security>
      <authorization>
        <remove users="*" roles="" verbs="" />
        <add accessType="Deny" users="*" roles="" verbs="" />
      </authorization>
    </security>
  </system.webServer>
</configuration>';
	} elseif ( $is_nginx ) {
		return is_writable( $backup_dir );
	}

	if ( ! $file ) {
		return false;
	}

	$file = $backups_dir . $file;

	if ( file_exists( $file ) ) {
		return is_writable( $backup_dir );
	}

	file_put_contents( $file, $file_content );

	return is_writable( $backup_dir ) && file_exists( $file );
}


/**
 * Zip a file in the same folder.
 *
 * @since 1.0
 *
 * @param (string) $filename The file path.
 *
 * @return (string|bool) The file path on success. False otherwise.
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
 * List the existing backup files (`.zip`, `.sql`).
 *
 * @since 1.0
 *
 * @return (array|bool) An array of file paths. False on error.
 */
function secupress_get_backup_file_list() {
	return glob( secupress_get_hashed_folder_name( 'backup', WP_CONTENT_DIR . '/backups/' ) . '*.{zip,sql}', GLOB_BRACE );
}


/**
 * Print an HTML markup for a backup: creation date, download link, deletion link, etc.
 *
 * @since 1.0
 *
 * @param (string) $file The file path.
 * @param (bool)   $echo Return or echo the markup.
 *
 * @return (string)
 */
function secupress_print_backup_file_formated( $file, $echo = true ) {

	list( $_date, $_type, $_prefix, $file_uniqid ) = explode( '.', basename( $file ) );

	$_date        = date_i18n( __( 'M jS Y', 'secupress' ) . ' ' . __( 'G:i', 'secupress' ), strtotime( substr_replace( $_date, ':', 13, 1 ) ), true );

	$download_url = esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=secupress_download_backup&file=' . $file_uniqid ), 'secupress_download_backup-' . $file_uniqid ) );
	$delete_url   = esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=secupress_delete_backup&file=' . $file_uniqid ), 'secupress_delete_backup-' . $file_uniqid ) );

	$file_format  = sprintf( '<p class="secupress-large-row">%s <strong>%s</strong> <em>(%s)</em>', ucwords( $_type ), $_prefix, $_date );
	$file_format .= sprintf( '<span><a href="%s">%s</a> | <a href="%s" class="a-delete-backup" data-file-uniqid="%s">%s</a></span></p>', $download_url, _x( 'Download', 'verb', 'secupress' ), $delete_url, $file_uniqid, __( 'Delete', 'secupress' ) );

	if ( ! $echo ) {
		return $file_format;
	}

	echo $file_format;
}
