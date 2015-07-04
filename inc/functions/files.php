<?php
defined( 'ABSPATH' ) or	die( 'Cheatin&#8217; uh?' );

/**
 * Remove a single file or a folder recursively
 *
 * @since 1.0
 *
 * @param string $dir File/Directory to delete
 * @param array $dirs_to_preserve (default: array()) Dirs that should not be deleted
 * @return void
 */
function secupress_rrmdir( $dir, $dirs_to_preserve = array() )
{
	$dir = rtrim( $dir, '/' );

	/**
	 * Fires after a file/directory cache was deleted
	 *
	 * @since 1.0
	 *
	 * @param string $dir File/Directory to delete
	 * @param array $dirs_to_preserve Directories that should not be deleted
	 */
	do_action( 'before_secupress_rrmdir', $dir, $dirs_to_preserve );

	if ( ! is_dir( $dir ) ) {
		@unlink( $dir );
		return;
	};

	if ( $dirs = glob( $dir . '/*', GLOB_NOSORT ) ) {

		$keys = array();
		foreach( $dirs_to_preserve as $dir_to_preserve ) {
			$matches = preg_grep( "#^$dir_to_preserve$#" , $dirs );
			$keys[] = reset( $matches );
		}

		$dirs = array_diff( $dirs, array_filter( $keys ) );
		foreach ( $dirs as $dir ) {
			if ( is_dir( $dir ) ) {
				secupress_rrmdir( $dir, $dirs_to_preserve );
			} else {
				@unlink( $dir );
			}
		}
	}

	@rmdir($dir);

	/**
	 * Fires before a file/directory cache was deleted
	 *
	 * @since 1.0
	 *
	 * @param string $dir File/Directory to delete
	 * @param array $dirs_to_preserve Dirs that should not be deleted
	 */
	do_action( 'after_secupress_rrmdir', $dir, $dirs_to_preserve );
}

/**
 * Directory creation based on WordPress Filesystem
 *
 * @since 1.0
 *
 * @param string $dir The path of directory will be created
 * @return bool
 */
function secupress_mkdir( $dir )
{
	global $wp_filesystem;
	if ( ! $wp_filesystem ) {
		require_once( ABSPATH . 'wp-admin/includes/class-wp-filesystem-base.php' );
		require_once( ABSPATH . 'wp-admin/includes/class-wp-filesystem-direct.php' );
		$wp_filesystem = new WP_Filesystem_Direct( new StdClass() );
	}

	$chmod = defined( 'FS_CHMOD_DIR' ) ? FS_CHMOD_DIR : ( fileperms( WP_CONTENT_DIR ) & 0777 | 0755 );
	return $wp_filesystem->mkdir( $dir, $chmod );
}

/**
 * Recursive directory creation based on full path.
 *
 * @since 1.0
 *
 * @source wp_mkdir_p() in /wp-includes/functions.php
 */
function secupress_mkdir_p( $target )
{
	// from php.net/mkdir user contributed notes
	$target = str_replace( '//', '/', $target );

	// safe mode fails with a trailing slash under certain PHP versions.
	$target = rtrim($target, '/'); // Use rtrim() instead of untrailingslashit to avoid formatting.php dependency.
	if ( empty($target) ) {
		$target = '/';
	}

	if ( file_exists( $target ) ) {
		return @is_dir( $target );
	}

	// Attempting to create the directory may clutter up our display.
	if ( secupress_mkdir( $target ) ) {
		return true;
	} elseif ( is_dir( dirname( $target ) ) ) {
		return false;
	}

	// If the above failed, attempt to create the parent node, then try again.
	if ( ( $target != '/' ) && ( secupress_mkdir_p( dirname( $target ) ) ) ) {
		return secupress_mkdir_p( $target );
	}

	return false;
}

/**
 * File creation based on WordPress Filesystem
 *
 * @since 1.0
 *
 * @param string $file 	  The path of file will be created
 * @param string $new_content The content that will be added on top of the file
 * @param string $file_content The content that will already exists in the file
 * @return bool
 */
function secupress_put_content( $file, $marker, $new_content )
{
	global $wp_filesystem;
	if ( ! $wp_filesystem ) {
		require_once( ABSPATH . 'wp-admin/includes/class-wp-filesystem-base.php' );
		require_once( ABSPATH . 'wp-admin/includes/class-wp-filesystem-direct.php' );
		$wp_filesystem = new WP_Filesystem_Direct( new StdClass() );
	}
	// Get content of file
	$ftmp = file_get_contents( $file );
	$file_content = preg_replace( '/# BEGIN SecuPress ' . $marker . '(.*)# END SecuPress/isU', '', $ftmp );
	if ( ! empty( $new_content ) ) {
		$content = '# BEGIN SecuPress ' . $marker . PHP_EOL;
		$content .= trim( $new_content ) . PHP_EOL;
		$content .= '# END SecuPress' . PHP_EOL;
		$content .= $file_content;
		$file_content = $content;
	}
	$chmod = defined( 'FS_CHMOD_FILE' ) ? FS_CHMOD_FILE : 0644;
	return $wp_filesystem->put_contents( $file, $file_content, $chmod );
}


/**
 * File creation based on WordPress Filesystem
 *
 * @since 1.0
 *
 * @param string $file 	  The path of file will be created
 * @param string $new_content The content that will be removed from the file
 * @param string $file_content The content that will already exists in the file
 * @return bool
 */
function secupress_remove_content( $file, $marker, $file_content )
{
	global $wp_filesystem;
	if ( ! $wp_filesystem ) {
		require_once( ABSPATH . 'wp-admin/includes/class-wp-filesystem-base.php' );
		require_once( ABSPATH . 'wp-admin/includes/class-wp-filesystem-direct.php' );
		$wp_filesystem = new WP_Filesystem_Direct( new StdClass() );
	}

	$chmod = defined( 'FS_CHMOD_FILE' ) ? FS_CHMOD_FILE : 0644;
	$file_content = str_replace( $new_content, '', $file_content );
	return $wp_filesystem->put_contents( $file, $file_content, $chmod );
}


/**
 * File creation based on WordPress Filesystem
 *
 * @since 1.0
 *
 * @param string $file 	  The path of file will be created
 * @param string $new_content The content that will be replaced on top from the file
 * @param string $file_content The content that will already exists in the file
 * @return bool
 */
function secupress_replace_content( $file, $marker, $new_content, $file_content )
{
	secupress_remove_content( $file, $marker, $file_content );
	secupress_add_content( $file, $new_content, $file_content );
}


/**
 * Try to find the correct wp-config.php file, support one level up in filetree
 *
 * @since 1.0
 *
 * @return string|bool The path of wp-config.php file or false
 */
function secupress_find_wpconfig_path()
{
	$config_file = get_home_path() . 'wp-config.php';
	$config_file_alt = dirname( get_home_path() ) . '/wp-config.php';

	if ( file_exists( $config_file ) ) {
		return $config_file;
	} elseif ( @file_exists( $config_file_alt ) && ! file_exists( dirname( get_home_path() ) . '/wp-settings.php' ) ) {
		return $config_file_alt;
	}

	// No writable file found
	return false;
}