<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/**
 * Get WP Direct filesystem object.
 *
 * @author Grégory Viguier
 * @since 1.3 Don't use the global Filesystem anymore, to make sure to use "direct" (some things don't work over "ftp").
 * @since 1.0
 *
 * @return `$wp_filesystem` object.
 */
function secupress_get_filesystem() {
	static $filesystem;

	if ( $filesystem ) {
		return $filesystem;
	}

	require_once( ABSPATH . 'wp-admin/includes/class-wp-filesystem-base.php' );
	require_once( ABSPATH . 'wp-admin/includes/class-wp-filesystem-direct.php' );

	$filesystem = new WP_Filesystem_Direct( new StdClass() ); // WPCS: override ok.

	// Set the permission constants if not already set.
	if ( ! defined( 'FS_CHMOD_DIR' ) ) {
		define( 'FS_CHMOD_DIR', ( @fileperms( ABSPATH ) & 0777 | 0755 ) );
	}
	if ( ! defined( 'FS_CHMOD_FILE' ) ) {
		define( 'FS_CHMOD_FILE', ( @fileperms( ABSPATH . 'index.php' ) & 0777 | 0644 ) );
	}

	return $filesystem;
}


/**
 * Remove a single file or a folder recursively.
 *
 * @since 1.0
 *
 * @param (string) $dir              File/Directory to delete.
 * @param (array)  $dirs_to_preserve Dirs that should not be deleted. Default: array().
 */
function secupress_rrmdir( $dir, $dirs_to_preserve = array() ) {
	$dir = rtrim( $dir, '/' );

	/**
	 * Fires after a file/directory cache was deleted.
	 *
	 * @since 1.0
	 *
	 * @param (string) $dir              File/Directory to delete.
	 * @param (array)  $dirs_to_preserve Directories that should not be deleted.
	 */
	do_action( 'secupress.before_rrmdir', $dir, $dirs_to_preserve );

	$filesystem = secupress_get_filesystem();

	if ( ! $filesystem->is_dir( $dir ) ) {
		$filesystem->delete( $dir );
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
			if ( $filesystem->is_dir( $dir ) ) {
				secupress_rrmdir( $dir, $dirs_to_preserve );
			} else {
				$filesystem->delete( $dir );
			}
		}
	}

	$filesystem->delete( $dir );

	/**
	 * Fires before a file/directory cache was deleted.
	 *
	 * @since 1.0
	 *
	 * @param (string) $dir              File/Directory to delete.
	 * @param (array)  $dirs_to_preserve Dirs that should not be deleted.
	 */
	do_action( 'secupress.after_rrmdir', $dir, $dirs_to_preserve );
}


/**
 * Directory creation based on WordPress Filesystem.
 *
 * @since 1.0
 *
 * @param (string) $dir The path of directory will be created.
 *
 * @return (bool)
 */
function secupress_mkdir( $dir ) {
	$filesystem = secupress_get_filesystem();
	return $filesystem->mkdir( $dir );
}


/**
 * Recursive directory creation based on full path.
 *
 * @since 1.0
 * @source wp_mkdir_p() in `/wp-includes/functions.php`.
 *
 * @param (string) $target A folder path.
 *
 * @return True on success.
 */
function secupress_mkdir_p( $target ) {
	$target     = wp_normalize_path( $target );
	$filesystem = secupress_get_filesystem();

	// Safe mode fails with a trailing slash under certain PHP versions.
	$target = rtrim( $target, '/' );

	if ( empty( $target ) ) {
		$target = '/';
	}

	if ( $filesystem->exists( $target ) ) {
		return $filesystem->is_dir( $target );
	}

	// Attempting to create the directory may clutter up our display.
	if ( $filesystem->mkdir( $target ) ) {
		return true;
	} elseif ( $filesystem->is_dir( dirname( $target ) ) ) {
		return false;
	}

	// If the above failed, attempt to create the parent node, then try again.
	if ( '/' !== $target && secupress_mkdir_p( dirname( $target ) ) ) {
		return secupress_mkdir_p( $target );
	}

	return false;
}


/**
 * Tell if a file located in the home folder is writable.
 * If the file does not exist, tell if the home folder is writable.
 *
 * @since 1.0
 *
 * @param (string) $file File name.
 *
 * @return (bool)
 */
function secupress_root_file_is_writable( $file ) {
	static $home_path;

	if ( ! isset( $home_path ) ) {
		$home_path = secupress_get_home_path();
	}

	return wp_is_writable( $home_path . $file ) || ! file_exists( $home_path . $file ) && wp_is_writable( $home_path );
}


/**
 * Try to find the correct `wp-config.php` file, support one level up in filetree.
 *
 * @since 2.0 Add filter secupress.wpconfig_path to target another file with your constants
 * @since 1.0
 *
 * @hook secupress.wpconfig_filename
 * @param (string) $context Can be use for filtering
 * @return (string|bool) The path of `wp-config.php` file or false.
 */
function secupress_find_wpconfig_path( $context = '' ) {
	$config_file     = ABSPATH . 'wp-config.php';
	$config_file_alt = dirname( ABSPATH ) . '/wp-config.php';

	if ( file_exists( $config_file ) ) {
		/**
		* Filter the wp-config.php file path
		*
		* @param (string) The default file path for wp-config.php
		* @since 2.0
		* @author Julio Potier
		*/
		return apply_filters( 'secupress.wpconfig_path', $config_file, 'main', $context );
	}
	if ( @file_exists( $config_file_alt ) && ! file_exists( dirname( ABSPATH ) . '/wp-settings.php' ) ) {
		/**
		* Filter the wp-config.php file path
		*
		* @param (string) The default file path for wp-config.php
		* @since 2.0
		* @author Julio Potier
		*/
		return apply_filters( 'secupress.wpconfig_path', $config_file_alt, 'alt', $context );
	}

	// No writable file found.
	return false;
}

/**
 * Allow interface to display a custom filename for wp-config.php
 *
 * @since 2.0
 * @author Julio Potier
 *
 * @see secupress_find_wpconfig_path()
 *
 * @hook secupress.wpconfig_filename
 * @return (string) The custom wpconfig.php
 **/
function secupress_get_wpconfig_filename( $context = 'filename' ) {
	$filename = str_replace( ABSPATH, '', secupress_find_wpconfig_path( $context ) );
	/**
	* Filter the wp-config.php filename (custom or not)
	*
	* @param (string) The default filename from the real file path
	* @since 2.0
	* @author Julio Potier
	*/
	return apply_filters( 'secupress.wpconfig_filename', $filename, $context );
}


/**
 * Tell if the `wp-config.php` file is writable.
 *
 * @since 1.2.4 Return null if the file can't be located.
 * @since 1.2.2
 * @author Grégory Viguier
 *
 * @return (string|bool|null) The path of `wp-config.php` file if writable, false if not writable, null if the file doesn't exist.
 */
function secupress_is_wpconfig_writable( $context = '' ) {
	$wpconfig_filepath = secupress_find_wpconfig_path( $context );

	if ( ! $wpconfig_filepath ) {
		return null;
	}

	return wp_is_writable( $wpconfig_filepath ) ? $wpconfig_filepath : false;
}


/**
 * Comment a constant definition in the `wp-config.php` file (or any other file).
 * If `$marker` is provided, our definition will be also removed.
 *
 * @since 2.0 Julio Potier Change the return values to let a possible TRUE if these are WP defaults + remove $new_value param (unused and not the purpose)
 * @since 1.2.2
 * @author Grégory Viguier
 *
 * @param (string) $constant          Name of the constant.
 * @param (string) $wpconfig_filepath Path to the `wp-config.php` file.
 * @param (string) $marker            Name of the marker used to define the constant ourself.
 *
 * @return (bool)
 */
function secupress_comment_constant( $constant, $wpconfig_filepath = false, $marker = false ) {
	static $file_content = '';
	if ( ! $wpconfig_filepath ) {
		$wpconfig_filepath = secupress_is_wpconfig_writable();

		if ( ! $wpconfig_filepath ) {
			return false;
		}
	}

	$filesystem   = secupress_get_filesystem();
	if ( ! $file_content ) {
		$file_content = $filesystem->get_contents( $wpconfig_filepath );
	}

	if ( $marker && preg_match( "@[\t ]*?# BEGIN SecuPress {$marker}\s.*# END SecuPress\s*?@sU", $file_content ) ) {
		// Remove the constant we could have previously set.
		return secupress_replace_content( $wpconfig_filepath, "@[\t ]*?# BEGIN SecuPress {$marker}\s.*# END SecuPress\s*?@sU", '' );
	}

	// Comment old value.
	if ( preg_match( "@^[\t ]*define\s*\(\s*(?:'{$constant}'|\"{$constant}\")\s*,(?:.*);.*\s*$@mU", $file_content ) ) {
		return secupress_replace_content( $wpconfig_filepath, "@^[\t ]*define\s*\(\s*(?:'{$constant}'|\"{$constant}\")\s*,(?:.*);.*\s*$@mU", '/** Commented by SecuPress. */ /** $0 */' );
	}

	// Nothing has been replaced because there is nothing to replace, aka, these are WordPress default values, still overridable
	// ps: if these constants are set elsewhere… well, my bad :)
	return true;
}


/**
 * Uncomment a constant definition in the `wp-config.php` file (or any other file).
 * If `$marker` is provided, our definition will be also removed.
 *
 * @since 1.2.2
 * @author Grégory Viguier
 *
 * @param (string) $constant          Name of the constant.
 * @param (string) $wpconfig_filepath Path to the `wp-config.php` file.
 * @param (string) $marker            Name of the marker used to define the constant ourself.
 *
 * @return (bool) True if the constant definition has been successfully uncommented. False if:
 *                - the constant is already defined somewhere,
 *                - or the file is not writable,
 *                - or the comment was not found in the file,
 *                - or it couldn't be uncommented.
 *                So basically, this information is totally useless, deal with it.
 */
function secupress_uncomment_constant( $constant, $wpconfig_filepath = false, $marker = false ) {
	if ( ! $wpconfig_filepath ) {
		$wpconfig_filepath = secupress_is_wpconfig_writable();

		if ( ! $wpconfig_filepath ) {
			return false;
		}
	}

	if ( $marker ) {
		// Remove the constant we could have previously set.
		$replaced = secupress_replace_content( $wpconfig_filepath, "@[\t ]*?# BEGIN SecuPress {$marker}\s.*# END SecuPress\s*?@sU", '' );

		if ( defined( $constant ) && ! $replaced ) {
			/**
			 * If the constant is defined and "our" has not been removed (because it didn't exist), that means it's defined somewhere else.
			 * In that case, we must not uncomment the previous value or it will be defined twice.
			 */
			return false;
		}
	}

	// Uncomment old value.
	$constant = "(define\s*\(\s*(?:'$constant'|\"$constant\")\s*,(?:.*))";
	$p = "@^[\t ]*/\*+\s*Commented by SecuPress\.*\s*\*/\s*?(?:/\*+\s*{$constant}\s*\*/|/+\s*{$constant})\s*$@mU";
	return secupress_replace_content( $wpconfig_filepath, $p, '$1' );
}


/**
 * Get plugins dir path.
 *
 * @since 1.0
 *
 * @return (string)
 */
function secupress_get_plugins_path() {
	static $plugins_dir;

	if ( ! isset( $plugins_dir ) ) {
		$plugins_dir = realpath( WP_PLUGIN_DIR ) . DIRECTORY_SEPARATOR;
	}

	return $plugins_dir;
}


/**
 * Get themes dir path.
 *
 * @since 1.0
 *
 * @return (string)
 */
function secupress_get_themes_path() {
	static $themes_dir;

	if ( ! isset( $themes_dir ) ) {
		$wp_filesystem = secupress_get_filesystem(); // WPCS: override ok.
		$themes_dir    = realpath( $wp_filesystem->wp_themes_dir() ) . DIRECTORY_SEPARATOR;
	}

	return $themes_dir;
}


/**
 * Tell if a plugin is symlinked.
 *
 * @since 1.0
 *
 * @param (string) $plugin_file Plugin main file path, relative to the plugins folder.
 *
 * @return (bool) True if the plugin is symlinked.
 */
function secupress_is_plugin_symlinked( $plugin_file ) {
	$plugins_dir = secupress_get_plugins_path();
	$plugin_path = realpath( $plugins_dir . $plugin_file );

	return ! ( $plugin_path && 0 === strpos( $plugin_path, $plugins_dir ) );
}


/**
 * Tell if a theme is symlinked.
 *
 * @since 1.0
 *
 * @param (string) $theme_slug Theme dir name.
 *
 * @return (bool) True if the theme is symlinked.
 */
function secupress_is_theme_symlinked( $theme_slug ) {
	$themes_dir = secupress_get_themes_path();
	$theme_path = realpath( $themes_dir . $theme_slug );

	return ! ( $theme_path && 0 === strpos( $theme_path, $themes_dir ) );
}


/**
 * File creation based on WordPress Filesystem.
 *
 * @since 1.0
 *
 * @param (string) $file The path of file.
 * @param (string) $new_content The content that will be added to the file.
 * @param (array)  $args (optional)
 *                 marker (string): An additional suffix string to add to the "SecuPress" marker, Default ''.
 *                 put    (string): (prepend|append|replace): Prepend or append content in the file, Default 'prepend'.
 *                 text   (string): When (prepend|append) is used for "put", you can speficy a text to find, it will be pre/appended around this text.
 * @return (bool)
 */
function secupress_put_contents( $file, $new_content = '', $args = array() ) {
	static $file_content = '';

	$args = wp_parse_args( $args, array(
		'marker'   => '',
		'put'      => 'prepend',
		'text'     => '',
		'keep_old' => false,
	) );

	$filesystem   = secupress_get_filesystem();
	$comment_char = pathinfo( $file, PATHINFO_EXTENSION ) !== 'ini' ? '#' : ';';

	// Get the whole content of file and remove old marker content.
	if ( file_exists( $file ) ) {
		$pattern      = '/' . $comment_char . ' BEGIN SecuPress ' . $args['marker'] . '(.*)' . $comment_char . ' END SecuPress\s*?/isU';
		if ( ! $file_content ) {
			$file_content = file_get_contents( $file );
		}
		if ( $args['keep_old'] ) {
			preg_match( $pattern, $file_content, $keep_old );
		}
		$file_content = preg_replace( $pattern, '', $file_content );
	}

	if ( ! empty( $new_content ) ) {

		$content  = $comment_char . ' BEGIN SecuPress ' . $args['marker'] . PHP_EOL;
		if ( $args['keep_old'] && isset( $keep_old[1] ) ) {
			$content .= trim( $keep_old[1] ) . "\n";
		}
		$content .= trim( $new_content ) . PHP_EOL;
		$content .= $comment_char . ' END SecuPress' . PHP_EOL . PHP_EOL;

		if ( '' !== $args['text'] && strpos( $file_content, $args['text'] ) !== false ) {
			if ( 'append' === $args['put'] ) {
				$content = str_replace( $args['text'], $args['text'] . PHP_EOL . $content, $file_content );
			} elseif ( 'prepend' === $args['put'] ) {
				$content = str_replace( $args['text'], $content . PHP_EOL . $args['text'], $file_content );
			}
		} else {
			if ( 'append' === $args['put'] ) {
				$content = $file_content . PHP_EOL . $content;
			} elseif ( 'prepend' === $args['put'] ) {
				$content = $content . $file_content;
			}
		}

		$file_content = $content;
	}

	return $filesystem->put_contents( $file, $file_content, FS_CHMOD_FILE );
}


/**
 * File creation based on WordPress Filesystem.
 *
 * @since 1.0
 * @since 1.3 Use a sandbox for the `wp-config.php` file.
 *
 * @param (string) $file        The path of file will be created.
 * @param (string) $old_content The content to be replaced from the file (preg_replace).
 * @param (string) $new_content The new content (preg_replace).
 *
 * @return (bool)
 */
function secupress_replace_content( $file, $old_content, $new_content, $skip_sandbox = false ) {
	static $file_content = '';

	if ( ! file_exists( $file ) ) {
		return false;
	}

	$filesystem = secupress_get_filesystem();
	if ( ! $file_content ) {
		$file_content = $filesystem->get_contents( $file );
	}

	$new_content  = preg_replace( $old_content, $new_content, $file_content );
	if ( null === $new_content || $new_content === $file_content ) {
		return false;
	}

	$file_content = $new_content;
	$filename     = preg_quote( secupress_get_wpconfig_filename() );
	$skip_sandbox = ( ! defined( 'SECUPRESS_NO_SANDBOX' ) || ! SECUPRESS_NO_SANDBOX ) && $skip_sandbox;
	if ( ! $skip_sandbox && false !== preg_match( '@/$filename$@', $file ) && true !== secupress_wpconfig_success_in_sandbox( $new_content ) ) {
		return false;
	}

	return $filesystem->put_contents( $file, $new_content, FS_CHMOD_FILE );
}


/**
 * A sandbox for doing crazy things with `wp-config.php`.
 * Create a folder containing a `index.php` file with the provided content.
 * Then, make a request to the `index.php` file to test if a server error is triggered.
 *
 * @since 2.0 Add secupress.use_sandbox filter
 * @since 1.3
 * @author Grégory Viguier
 * @author Julio Potier
 *
 * @param (string) $content The content to put in the `wp-config.php` file.
 *
 * @return (object|bool) Return true if the server does not trigger an error 500, false otherwise.
 *                       Return a WP_Error object if the sandbox creation fails or if the HTTP request fails.
 */
function secupress_wpconfig_success_in_sandbox( $content ) {
	/**
	* Allows to bypass the sandbox
	* @since 2.0
	* @param (bool) true by default, false to use it.
	* @param (string) A context.
	*/
	if ( false === apply_filters( 'secupress.use_sandbox', true, 'wp-config' ) ) {
		return true;
	}
	$wp_filesystem = secupress_get_filesystem();
	$file_name     = 'index.php';
	$folder_name   = 'secupress-sandbox-' . uniqid();
	$folder_path   = ABSPATH . $folder_name;
	// Remove any `require_once()` and friends.
	$content       = preg_replace( '@(require|include)(_once)?[\s(][^;]+;@', '$foo = "foo";', $content );
	// Define `ABSPATH` and add `error_reporting()`.
	$content       = preg_replace( '@^<\?php@', '<?php error_reporting( -1 );', trim( $content ) );
	// Print a placeholder when the file is requested.
	$content      .= "\necho 'SANDBOX OK';";
	// Create folder.
	if ( ! $wp_filesystem->mkdir( $folder_path ) ) {
		return new WP_Error( 'dir_creation_failed', __( 'The temporary directory could not be created.', 'secupress' ) );
	}

	// Create `index.php` file with our content.
	if ( ! $wp_filesystem->put_contents( $folder_path . '/' . $file_name, $content, FS_CHMOD_FILE ) ) {
		$wp_filesystem->delete( $folder_path, true );
		return new WP_Error( 'file_creation_failed', __( 'The temporary file could not be created.', 'secupress' ) );
	}

	/** This filter is documented in inc/classes/scanners/class-secupress-scan.php. */
	$timeout      = apply_filters( 'secupress.remote_timeout', 30 );
	$origin       = 'wp-config-sandbox';
	$request_args = array(
		'redirection' => 0,
		'timeout'     => $timeout,
		'local'       => true,
		'sslverify'   => false,
		'user-agent'  => SECUPRESS_PLUGIN_NAME . '/' . SECUPRESS_VERSION,
		'cookies'     => $_COOKIE,
		'headers'     => array(
			'X-SecuPress-Origin' => $origin,
		),
	);

	/** This filter is documented in inc/classes/scanners/class-secupress-scan.php. */
	$request_args = apply_filters( 'secupress.scan.default_request_args', $request_args, $origin );

	// Try to reach `index.php`.
	$request_url = $folder_name . '/' . $file_name . '?' . md5( $folder_name . 's' ) . '=' . md5( $folder_name . 'p' );
	$response    = wp_remote_get( site_url( $request_url ), $request_args );

	// Now we can get rid of the files.
	$wp_filesystem->delete( $folder_path, true );

	// HTTP requests are probably blocked.
	if ( is_wp_error( $response ) ) {
		return $response;
	}

	// Finally, the answer we were looking for.
	return 500 !== wp_remote_retrieve_response_code( $response ) && false !== strpos( wp_remote_retrieve_body( $response ), 'SANDBOX OK' );
}


/**
 * From WP Core `async_upgrade()` but using `Automatic_Upgrader_Skin` instead of `Language_Pack_Upgrader_Skin` to have a silent upgrade.
 *
 * @since 1.0
 */
function secupress_async_upgrades() {
	// Nothing to do?
	$language_updates = wp_get_translation_updates();

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

		/** This filter is documented in wp-admin/includes/class-wp-upgrader.php */
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
 * Create a MU-PLUGIN.
 *
 * @since 1.0
 *
 * @param (string) $filename_part The file name part in `_secupress_{$filename_part}.php`.
 * @param (string) $contents      The file content.
 *
 * @return (bool) True on success.
 */
function secupress_create_mu_plugin( $filename_part, $contents ) {

	$filesystem = secupress_get_filesystem();
	$filename   = WPMU_PLUGIN_DIR . "/_secupress_{$filename_part}.php";

	if ( file_exists( $filename ) ) {
		$filesystem->delete( $filename );
	}
	if ( ! file_exists( WPMU_PLUGIN_DIR ) ) {
		$filesystem->mkdir( WPMU_PLUGIN_DIR );
	}
	if ( file_exists( $filename ) || ! file_exists( WPMU_PLUGIN_DIR ) ) {
		return false;
	}

	return $filesystem->put_contents( $filename, $contents );
}


/**
 * Format a path with no heading slash and a trailing slash.
 * If the path is empty, it returns an empty string, not a lonely slash.
 * Example: foo/bar/
 *
 * @since 1.0
 *
 * @param (string) $slug A path.
 *
 * @return (string) The path with no heading slash and a trailing slash.
 */
function secupress_trailingslash_only( $slug ) {
	return ! is_null( $slug ) ? ltrim( trim( $slug, '/' ) . '/', '/' ) : '';
}


/**
 * A better `get_home_path()`, without the bugs on old versions.
 * https://core.trac.wordpress.org/ticket/25767
 *
 * @since 1.0
 *
 * @return (string) The home path.
 */
function secupress_get_home_path() {
	$home    = set_url_scheme( get_option( 'home' ), 'http' );
	$siteurl = set_url_scheme( get_option( 'siteurl' ), 'http' );

	if ( ! empty( $home ) && 0 !== strcasecmp( $home, $siteurl ) ) {
		$wp_path_rel_to_home = str_ireplace( $home, '', $siteurl ); /* $siteurl - $home */
		$pos       = strripos( str_replace( '\\', '/', $_SERVER['SCRIPT_FILENAME'] ), trailingslashit( $wp_path_rel_to_home ) );
		$home_path = substr( $_SERVER['SCRIPT_FILENAME'], 0, $pos );
		$home_path = trailingslashit( $home_path );
	}
	else {
		$home_path = ABSPATH;
	}

	return wp_normalize_path( $home_path );
}


/**
 * Is WP a MultiSite and a subfolder install?
 *
 * @since 1.0
 *
 * @return (bool).
 */
function secupress_is_subfolder_install() {
	global $wpdb;
	static $subfolder_install;

	if ( ! isset( $subfolder_install ) ) {
		if ( is_multisite() ) {
			$subfolder_install = ! is_subdomain_install();
		}
		elseif ( ! is_null( $wpdb->sitemeta ) ) {
			$subfolder_install = ! $wpdb->get_var( "SELECT meta_value FROM $wpdb->sitemeta WHERE site_id = 1 AND meta_key = 'subdomain_install'" );
		}
		else {
			$subfolder_install = false;
		}
	}

	return $subfolder_install;
}


/**
 * Has WP its own directory?
 *
 * @since 1.0
 * @see http://codex.wordpress.org/Giving_WordPress_Its_Own_Directory
 *
 * @return (string) The directory containing WP.
 */
function secupress_get_wp_directory() {
	static $wp_siteurl_subdir;

	if ( isset( $wp_siteurl_subdir ) ) {
		return $wp_siteurl_subdir;
	}

	$wp_siteurl_subdir = '';

	$home    = set_url_scheme( rtrim( get_option( 'home' ), '/' ), 'http' );
	$siteurl = set_url_scheme( rtrim( get_option( 'siteurl' ), '/' ), 'http' );

	if ( ! empty( $home ) && 0 !== strcasecmp( $home, $siteurl ) ) {
		$wp_siteurl_subdir = str_ireplace( $home, '', $siteurl ); /* $siteurl - $home */
		$wp_siteurl_subdir = secupress_trailingslash_only( $wp_siteurl_subdir );
	} else {
		$parsed_url_path   = parse_url( $home, PHP_URL_PATH );
		if ( '/' !== $parsed_url_path ) {
			$wp_siteurl_subdir = secupress_trailingslash_only( $parsed_url_path );
			return $wp_siteurl_subdir;
		}
	}

	return $wp_siteurl_subdir;
}


/**
 * Get infos for the rewrite rules.
 * The main concern is about directories.
 *
 * @since 1.0
 *
 * @return (array) An array containing the following keys:
 *         'base'      => Rewrite base, or "home directory".
 *         'wp_dir'    => WP directory.
 *         'site_dir'  => Directory containing the WordPress files.
 *         'is_sub'    => Is it a subfolder install? (Multisite).
 *         'site_from' => Regex for first part of the rewrite rule (WP files).
 *         'site_to'   => First part of the rewrited address (WP files).
 *                        In case of MultiSite with sub-folders, this is not really where the files are: WP rewrites the admin URL for example, which is based on the "site URL".
 *         'home_from' => Regex for first part of the rewrite rule (home URL).
 *         'home_to'   => First part of the rewrited address (home URL).
 */
function secupress_get_rewrite_bases() {
	global $is_apache, $is_nginx, $is_iis7;
	static $bases;

	if ( isset( $bases ) ) {
		return $bases;
	}

	$base     = wp_parse_url( trailingslashit( get_option( 'home' ) ) );
	$base     = $base['path'];
	$wp_dir   = secupress_get_wp_directory();     // WP in its own directory.
	$is_sub   = secupress_is_subfolder_install(); // MultiSite by sub-folders.
	$site_dir = $base . ltrim( $wp_dir, '/' );

	$bases = array(
		'base'     => $base,     // '/' or '/sub-dir/'.
		'wp_dir'   => $wp_dir,   // '' or '/wp-dir/'.
		'site_dir' => $site_dir, // '/', '/wp-dir/', '/sub-dir/', or '/sub-dir/wp-dir/'.
		'is_sub'   => $is_sub,   // True or false.
	);

	// Apache.
	if ( $is_apache ) {
		/**
		 * In the `*_from` fields, we don't add `$base` because we use `RewriteBase $base` in the rewrite rules.
		 * In the `*_to` fields, `$base` is optional, but WP adds it so we do the same for concistancy.
		 */
		if ( $is_sub ) {
			// MultiSite by sub-folders.
			return ( $bases = array_merge( $bases, array(
				// 'site_from' and 'site_to': no `$wp_dir` here, because it is used only for the main blog.
				'site_from' => $wp_dir ? '([_0-9a-zA-Z-]+/)' : '(([_0-9a-zA-Z-]+/)?)',
				'site_to'   => $base . '$1',
				'home_from' => '([_0-9a-zA-Z-]+/)?',
				'home_to'   => $base . '$1',
			) ) );
		} else {
			// Not MultiSite, or MultiSite by sub-domains.
			return ( $bases = array_merge( $bases, array(
				'site_from' => $wp_dir,
				'site_to'   => $site_dir,
				'home_from' => '',
				'home_to'   => $base,
			) ) );
		}
	}

	// Nginx.
	if ( $is_nginx ) {
		if ( $is_sub ) {
			// MultiSite by sub-folders.
			return ( $bases = array_merge( $bases, array(
				// 'site_from' and 'site_to': no `$wp_dir` here, because it is used only for the main blog.
				'site_from' => $base . '(' . ( $wp_dir ? '[_0-9a-zA-Z-]+/' : '([_0-9a-zA-Z-]+/)?' ) . ')',
				'site_to'   => $base . '$1',
				'home_from' => $base . '([_0-9a-zA-Z-]+/)?',
				'home_to'   => $base . '$1',
			) ) );
		} else {
			// Not MultiSite, or MultiSite by sub-domains.
			return ( $bases = array_merge( $bases, array(
				'site_from' => $site_dir,
				'site_to'   => $site_dir,
				'home_from' => $base,
				'home_to'   => $base,
			) ) );
		}
	}

	// IIS7.
	if ( $is_iis7 ) {
		$base     = ltrim( $base, '/' );     // No heading slash for IIS: '' or 'sub-dir/'.
		$site_dir = ltrim( $site_dir, '/' ); // No heading slash for IIS: '', 'wp-dir/', 'sub-dir/', or 'sub-dir/wp-dir/'.

		if ( $is_sub ) {
			// MultiSite by sub-folders.
			return ( $bases = array_merge( $bases, array(
				'base'      => $base,
				'site_dir'  => $site_dir,
				// 'site_from' and 'site_to': no `$wp_dir` here, because it is used only for the main blog.
				'site_from' => $base . '(' . ( $wp_dir ? '[_0-9a-zA-Z-]+/' : '([_0-9a-zA-Z-]+/)?' ) . ')',
				'site_to'   => $base . '{R:1}',
				'home_from' => $base . '([_0-9a-zA-Z-]+/)?',
				'home_to'   => $base . '{R:1}',
			) ) );
		} else {
			// Not MultiSite, or MultiSite by sub-domains.
			return ( $bases = array_merge( $bases, array(
				'base'      => $base,
				'site_dir'  => $site_dir,
				'site_from' => $site_dir,
				'site_to'   => $site_dir,
				'home_from' => $base,
				'home_to'   => $base,
			) ) );
		}
	}

	return ( $bases = false );
}
