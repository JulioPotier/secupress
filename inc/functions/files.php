<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Remove a single file or a folder recursively
 *
 * @since 1.0
 *
 * @param string $dir File/Directory to delete
 * @param array $dirs_to_preserve (default: array()) Dirs that should not be deleted
 * @return void
 */
function secupress_rrmdir( $dir, $dirs_to_preserve = array() ) {
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
		foreach ( $dirs_to_preserve as $dir_to_preserve ) {
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

	@rmdir( $dir );

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
function secupress_mkdir( $dir ) {
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
function secupress_mkdir_p( $target ) {
	// from php.net/mkdir user contributed notes
	$target = str_replace( '//', '/', $target );

	// safe mode fails with a trailing slash under certain PHP versions.
	$target = rtrim( $target, '/' );

	if ( empty( $target ) ) {
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
	if ( ( $target !== '/' ) && ( secupress_mkdir_p( dirname( $target ) ) ) ) {
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
 * @param array  $args (optional) 
 *				 marker (string): An additional suffix string adde the the "SecuPress" marker, Default ''
 *				 put (string) (prepend|append|replace): Prepend of append content in the file, Default 'Prepend'
 *				 text (string) When (prepend|append)is used for "put", you can speficy a text to find, it will be pre/append around this text
 * @return bool
 */
function secupress_put_contents( $file, $new_content, $args ) {

	$defaults = array( 'marker' =>'', 'put' => 'prepend', 'text' => '' );
	$args = wp_parse_args( $args, $defaults );

	global $wp_filesystem;

	if ( ! $wp_filesystem ) {
		require_once( ABSPATH . 'wp-admin/includes/class-wp-filesystem-base.php' );
		require_once( ABSPATH . 'wp-admin/includes/class-wp-filesystem-direct.php' );

		$wp_filesystem = new WP_Filesystem_Direct( new StdClass() );
	}

	$comment_char = 'php.ini' != basename( $file ) ? '#' : ';';
	// Get content of file
	$file_content = '';
	if ( file_exists( $file ) ) {
		$ftmp         = file_get_contents( $file );
		$file_content = preg_replace( '/' . $comment_char . ' BEGIN SecuPress ' . $args['marker'] . '(.*)' . $comment_char . ' END SecuPress\s*?/isU', '', $ftmp );
	}

	// Remove empty spacings
	$ftmp = str_replace( "\n\n" , "\n" , $ftmp );

	if ( ! empty( $new_content ) ) {

		$content  = $comment_char . ' BEGIN SecuPress ' . $marker . PHP_EOL;
		$content .= trim( $new_content ) . PHP_EOL;
		$content .= $comment_char . ' END SecuPress' . PHP_EOL . PHP_EOL;


		if ( '' != $args['text'] && strpos( $file_content, $args['text'] ) !== false ) {
			if ( 'append' == $args['put'] ) {
				$content = str_replace( $args['text'], $args['text'] . PHP_EOL . $content, $file_content );
			} elseif ( 'prepend' == $args['put'] ) {
				$content = str_replace( $args['text'], $content . PHP_EOL . $args['text'], $file_content );
			}
		} else {
			if ( 'append' == $args['put'] ) {
				$content = $content . $file_content;
			} elseif ( 'prepend' == $args['put'] ) {
				$content = $file_content . $content;
			}
		}

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
 * @param string $old_content The content to be replaced from the file (preg_replace)
 * @param string $new_content The new content (preg_replace)
 * @return bool
 */
function secupress_replace_content( $file, $old_content, $new_content ) {

	if ( ! file_exists( $file ) ) {
		return false;
	}

	global $wp_filesystem;

	if ( ! $wp_filesystem ) {
		require_once( ABSPATH . 'wp-admin/includes/class-wp-filesystem-base.php' );
		require_once( ABSPATH . 'wp-admin/includes/class-wp-filesystem-direct.php' );

		$wp_filesystem = new WP_Filesystem_Direct( new StdClass() );
	}

	$file_content = $wp_filesystem->get_contents( $file );

	$chmod        = defined( 'FS_CHMOD_FILE' ) ? FS_CHMOD_FILE : 0644;
	$new_content  = preg_replace( $old_content, $new_content, $file_content );
	$replaced     =  $new_content != null && $new_content != $file_content;
	$put_contents = $wp_filesystem->put_contents( $file, $new_content, $chmod );
	
	return $put_contents && $replaced;
}


/**
 * Try to find the correct wp-config.php file, support one level up in filetree
 *
 * @since 1.0
 *
 * @return string|bool The path of wp-config.php file or false
 */
function secupress_find_wpconfig_path() {
	$config_file     = ABSPATH . 'wp-config.php';
	$config_file_alt = dirname( ABSPATH ) . '/wp-config.php';

	if ( file_exists( $config_file ) ) {
		return $config_file;
	} elseif ( @file_exists( $config_file_alt ) && ! file_exists( dirname( ABSPATH ) . '/wp-settings.php' ) ) {
		return $config_file_alt;
	}

	// No writable file found
	return false;
}

/**
 * From WP Core async_upgrade() but using Automatic_Upgrader_Skin instead of Language_Pack_Upgrader_Skin to have a silent upgrade
 *
 * @since 1.0
 * @return void
 **/
function secupress_async_upgrades() {
	// Nothing to do?
	$language_updates = wp_get_translation_updates();
	// war_dump( $language_updates );
	if ( ! $language_updates ) {
		return;
	}

	// Avoid messing with VCS installs, at least for now.
	// Noted: this is not the ideal way to accomplish this.
	$check_vcs = new WP_Automatic_Updater;
	if ( $check_vcs->is_vcs_checkout( WP_CONTENT_DIR ) ) {
		return;
	}

	foreach ( $language_updates as $key => $language_update ) {
		$update = ! empty( $language_update->autoupdate );

		/**
		 * Filter whether to asynchronously update translation for core, a plugin, or a theme.
		 *
		 * @since 4.0.0
		 *
		 * @param bool   $update          Whether to update.
		 * @param object $language_update The update offer.
		 */
		$update = apply_filters( 'async_update_translation', $update, $language_update );

		if ( ! $update ) {
			unset( $language_updates[ $key ] );
		}
	}

	if ( empty( $language_updates ) ) {
		return;
	}

	$skin = new Automatic_Upgrader_Skin();

	$lp_upgrader = new Language_Pack_Upgrader( $skin );
	$lp_upgrader->bulk_upgrade( $language_updates );
}

/**
 * Create a MU-PLUGIN
 *
 * @since 1.0
 * @return bool
 **/
function secupress_create_mu_plugin( $filename_part, $contents ) {
	
	global $wp_filesystem;

	if ( ! $wp_filesystem ) {
		require_once( ABSPATH . 'wp-admin/includes/class-wp-filesystem-base.php' );
		require_once( ABSPATH . 'wp-admin/includes/class-wp-filesystem-direct.php' );

		$wp_filesystem = new WP_Filesystem_Direct( new StdClass() );
	}

	$filename = WPMU_PLUGIN_DIR . "/_secupress_{$filename_part}.php";
	if ( file_exists( $filename ) ) {
		$wp_filesystem->delete( $filename );
	}
	if ( ! file_exists( WPMU_PLUGIN_DIR ) ) {
		$wp_filesystem->mkdir( WPMU_PLUGIN_DIR );
	}
	if ( file_exists( $filename ) || ! file_exists( WPMU_PLUGIN_DIR ) ) {
		return false;
	}

	return $wp_filesystem->put_contents( $filename, $contents );

}