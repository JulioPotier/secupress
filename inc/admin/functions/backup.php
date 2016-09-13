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
	$tmp_dir      = $backups_dir . 'secupress-' . secupress_generate_hash( 'backups-tmp', 8, 8 ) . '-tmp/';
	$fs_chmod_dir = defined( 'FS_CHMOD_DIR' ) ? FS_CHMOD_DIR : 0755;

	if ( ! is_dir( $backup_dir ) ) {
		mkdir( $backup_dir, $fs_chmod_dir, true );
	}

	if ( ! is_dir( $tmp_dir ) ) {
		mkdir( $tmp_dir, $fs_chmod_dir, true );
	}

	if ( $is_apache ) {
		$file = '.htaccess';
	} elseif ( $is_iis7 ) {
		$file = 'web.config';
	} elseif ( $is_nginx ) {
		return is_writable( $backup_dir ) && is_writable( $tmp_dir );
	} else {
		return false;
	}

	$file = $backups_dir . $file;

	if ( file_exists( $file ) ) {
		return is_writable( $backup_dir ) && is_writable( $tmp_dir );
	}

	file_put_contents( $file, secupress_backup_get_protection_content() );

	return is_writable( $backup_dir ) && is_writable( $tmp_dir ) && file_exists( $file );
}


/**
 * Get rules to be added to a `.htaccess`/`nginx.conf`/`web.config` file to protect the backups folder.
 *
 * @since 1.0
 *
 * @return (string) The rules to insert.
 */
function secupress_backup_get_protection_content() {
	global $is_apache, $is_nginx, $is_iis7;

	$file_content = '';

	if ( $is_apache ) {
		// Apache.
		$file_content = "Order allow,deny\nDeny from all";
	} elseif ( $is_iis7 ) {
		/*
		 * IIS7.
		 * https://www.iis.net/configreference/system.webserver/security/authorization
		 * https://technet.microsoft.com/en-us/library/cc772441%28v=ws.10%29.aspx
		 */
		$file_content = '<?xml version="1.0" encoding="utf-8" ?>
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
		// Nginx.
		$backup_dir   = secupress_get_hashed_folder_name( 'backup', WP_CONTENT_DIR . '/backups/' );
		$backup_dir   = str_replace( rtrim( wp_normalize_path( ABSPATH ), '/' ), '', wp_normalize_path( $backup_dir ) );
		$path         = secupress_get_rewrite_bases();
		$path         = $path['home_from'] . rtrim( dirname( $backup_dir ), '/' );
		$file_content = "
server {
	location ~* $path {
		deny all;
	}
}";
	}

	return $file_content;
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

	list( $_date, $_type, $_prefix, $file_uniqid ) = explode( '.', esc_html( basename( $file ) ) );

	$_date   = strtotime( substr_replace( $_date, ':', 13, 1 ) ) + ( get_option( 'gmt_offset' ) * HOUR_IN_SECONDS );
	$_date   = date_i18n( __( 'M jS Y', 'secupress' ) . ' ' . __( 'G:i', 'secupress' ), $_date, true );
	$_prefix = str_replace( array( '@', '#' ), array( '.', '/' ), $_prefix );

	switch ( $_type ) :
		case 'database' :
			$_type = __( 'Database', 'secupress' );
		break;

		case 'files' :
			$_type = __( 'Files', 'secupress' );
		break;

		default :
			$_type = ucwords( $_type );
	endswitch;

	$download_url = esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=secupress_download_backup&file=' . $file_uniqid ), 'secupress_download_backup-' . $file_uniqid ) );
	$delete_url   = esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=secupress_delete_backup&file=' . $file_uniqid ), 'secupress_delete_backup-' . $file_uniqid ) );

	$file_format  = sprintf( '<p class="secupress-large-row">%s <strong>%s</strong> <em>(%s)</em>', $_type, $_prefix, $_date );
	$file_format .= sprintf( '<span><a href="%s">%s</a> | <a href="%s" class="a-delete-backup" data-file-uniqid="%s">%s</a></span></p>', $download_url, _x( 'Download', 'verb', 'secupress' ), $delete_url, $file_uniqid, __( 'Delete', 'secupress' ) );

	if ( ! $echo ) {
		return $file_format;
	}

	echo $file_format;
}
