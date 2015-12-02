<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Get WP Direct filesystem object.
 *
 * @since 1.0
 *
 * @return `$wp_filesystem` object.
 */
function secupress_get_filesystem() {
	global $wp_filesystem;

	if ( ! $wp_filesystem ) {
		require_once( ABSPATH . 'wp-admin/includes/class-wp-filesystem-base.php' );
		require_once( ABSPATH . 'wp-admin/includes/class-wp-filesystem-direct.php' );

		$wp_filesystem = new WP_Filesystem_Direct( new StdClass() );
	}

	return $wp_filesystem;
}


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
	$wp_filesystem = secupress_get_filesystem();

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
 * @param string $file The path of file
 * @param string $new_content The content that will be added to the file
 * @param array  $args (optional)
 *               marker (string): An additional suffix string to add to the "SecuPress" marker, Default ''
 *               put    (string): (prepend|append|replace): Prepend or append content in the file, Default 'prepend'
 *               text   (string): When (prepend|append) is used for "put", you can speficy a text to find, it will be pre/appended around this text
 * @return bool
 */
function secupress_put_contents( $file, $new_content, $args ) {

	$args = wp_parse_args( $args, array(
		'marker' => '',
		'put'    => 'prepend',
		'text'   => '',
	) );

	$wp_filesystem = secupress_get_filesystem();
	$file_content  = '';
	$comment_char  = 'php.ini' != basename( $file ) ? '#' : ';';

	// Get content of file
	if ( file_exists( $file ) ) {
		$ftmp         = file_get_contents( $file );
		$file_content = preg_replace( '/' . $comment_char . ' BEGIN SecuPress ' . $args['marker'] . '(.*)' . $comment_char . ' END SecuPress\s*?/isU', '', $ftmp );
	}

	if ( ! empty( $new_content ) ) {

		$content  = $comment_char . ' BEGIN SecuPress ' . $args['marker'] . PHP_EOL;
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
				$content = $file_content . PHP_EOL . $content;
			} elseif ( 'prepend' == $args['put'] ) {
				$content = $content . $file_content;
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
 * @param string $file        The path of file will be created
 * @param string $old_content The content to be replaced from the file (preg_replace)
 * @param string $new_content The new content (preg_replace)
 * @return bool
 */
function secupress_replace_content( $file, $old_content, $new_content ) {

	if ( ! file_exists( $file ) ) {
		return false;
	}

	$wp_filesystem = secupress_get_filesystem();
	$file_content  = $wp_filesystem->get_contents( $file );

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
	}
	if ( @file_exists( $config_file_alt ) && ! file_exists( dirname( ABSPATH ) . '/wp-settings.php' ) ) {
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

	$wp_filesystem = secupress_get_filesystem();
	$filename      = WPMU_PLUGIN_DIR . "/_secupress_{$filename_part}.php";

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


/**
 * Insert content at the beginning of web.config file.
 * Can also be sused to remove content.
 *
 * @since 1.0
 *
 * @param (string)       $marker       An additional suffix string to add to the "SecuPress" marker.
 * @param (array)        $args         An array containing the following arguments:
 *        (array|string) $nodes_string Content to insert in the file.
 *        (array|string) $node_types   Node types: used to removed old nodes. Optional.
 *        (string)       $path         Path where nodes should be created, relative to `/configuration/system.webServer`.
 *
 * @return (bool) true on success.
 **/
function secupress_insert_iis7_nodes( $marker, $args ) {
	static $home_path;

	$args = wp_parse_args( $args, array(
		'nodes_string' => '',
		'node_types'   => false,
		'path'         => '',
		'attribute'    => 'name',
	) );

	$nodes_string = $args['nodes_string'];
	$node_types   = $args['node_types'];
	$path         = $args['path'];
	$attribute    = $args['attribute'];

	if ( ! $marker || ! class_exists( 'DOMDocument' ) ) {
		return false;
	}

	if ( ! isset( $home_path ) ) {
		$home_path = secupress_get_home_path();
	}

	// About the file.
	$web_config_file = $home_path . 'web.config';
	$has_web_config  = file_exists( $web_config_file );
	$is_writable     = $has_web_config && wp_is_writable( $web_config_file );

	// New content
	$marker       = strpos( $marker, 'SecuPress' ) === 0 ? $marker : 'SecuPress ' . $marker;
	$nodes_string = is_array( $nodes_string ) ? implode( "\n", $nodes_string ) : $nodes_string;
	$nodes_string = trim( $nodes_string, "\r\n\t " );

	if ( ! ( $is_writable || ! $has_web_config && wp_is_writable( $home_path ) && $nodes_string ) ) {
		return false;
	}

	// If configuration file does not exist then we create one.
	if ( ! $has_web_config ) {
		$fp = fopen( $web_config_file, 'w' );
		fwrite( $fp, '<configuration/>' );
		fclose( $fp );
	}

	$doc = new DOMDocument();
	$doc->preserveWhiteSpace = false;

	if ( false === $doc->load( $web_config_file ) ) {
		return false;
	}

	$path_end = ! $path && strpos( ltrim( $nodes_string ), '<rule ' ) === 0 ? '/rewrite/rules/rule' : '';
	$path     = '/configuration/system.webServer' . ( $path ? '/' . trim( $path, '/' ) : '' ) . $path_end;

	$xpath = new DOMXPath( $doc );

	// Remove possible nodes not created by us.
	if ( $node_types ) {
		$node_types = (array) $node_types;

		foreach ( $node_types as $node_type ) {
			$old_nodes = $xpath->query( $path . '/' . $node_type );

			if ( $old_nodes->length > 0 ) {
				foreach ( $old_nodes as $old_node ) {
					$old_node->parentNode->removeChild( $old_node );
				}
			}
		}
	}

	// Remove old nodes created by us.
	$old_nodes = $xpath->query( "$path/*[starts-with(@$attribute,'$marker')]" );

	if ( $old_nodes->length > 0 ) {
		foreach ( $old_nodes as $old_node ) {
			$old_node->parentNode->removeChild( $old_node );
		}
	}

	// No new nodes? Stop here.
	if ( ! $nodes_string ) {
		$doc->formatOutput = true;
		saveDomDocument( $doc, $web_config_file );
		return true;
	}

	// Indentation.
	$spaces = ( count( ( explode( '/', trim( $path, '/' ) ) ) ) - 1 ) * 2; // Don't ask, it's magic.
	$spaces = str_repeat( ' ', $spaces );

	// Create fragment.
	$fragment = $doc->createDocumentFragment();
	$fragment->appendXML( "\n$spaces  $nodes_string\n$spaces" );

	// Maybe create child nodes and then, prepend new nodes.
	__secupress_get_iis7_node( $doc, $xpath, $path, $fragment );

	// Save and finish.
	$doc->encoding     = 'UTF-8';
	$doc->formatOutput = true;
	saveDomDocument( $doc, $web_config_file );

	return true;
}


/**
 * A better `get_home_path()`, without the bugs on old versions.
 * https://core.trac.wordpress.org/ticket/25767
 *
 * @since 1.0
 *
 * @return (string) The home path.
 **/
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

	return secupress_normalize_path( $home_path );
}


/**
 * A `wp_normalize_path()`-like, but available for WP < 3.9.0.
 *
 * @since 1.0
 *
 * @param (string) The path to normalize.
 *
 * @return (string) The normalized path.
 **/
function secupress_normalize_path( $path ) {
	if ( function_exists( 'wp_normalize_path' ) ) {
		return wp_normalize_path( $path );
	}
	$path = str_replace( '\\', '/', $path );
	$path = preg_replace( '|/+|','/', $path );
	if ( ':' === substr( $path, 1, 1 ) ) {
		$path = ucfirst( $path );
	}
	return $path;
}


/**
 * Get a DOMNode node.
 * If it does not exist it is created recursively.
 *
 * @since 1.0
 *
 * @param (object) $doc   DOMDocument element.
 * @param (object) $xpath DOMXPath element.
 * @param (string) $path  Path to the desired node.
 * @param (object) $child DOMNode to be prepended.
 *
 * @return (object) The DOMNode node.
 **/
function __secupress_get_iis7_node( $doc, $xpath, $path, $child ) {
	$nodelist = $xpath->query( $path );

	if ( $nodelist->length > 0 ) {
		return secupress_prepend_iis7_node( $nodelist->item( 0 ), $child );
	}

	$path = explode( '/', $path );
	$node = array_pop( $path );
	$path = implode( '/', $path );

	$final_node = $doc->createElement( $node );

	if ( $child ) {
		$final_node->appendChild( $child );
	}

	return __secupress_get_iis7_node( $doc, $xpath, $path, $final_node );
}


/**
 * A shorthand to prepend a DOMNode node.
 *
 * @since 1.0
 *
 * @param (object) $container_node DOMNode that will contain the new node.
 * @param (object) $new_node       DOMNode to be prepended.
 *
 * @return (object) DOMNode containing the new node.
 **/
function secupress_prepend_iis7_node( $container_node, $new_node ) {
	if ( ! $new_node ) {
		return $container_node;
	}

	if ( $container_node->hasChildNodes() ) {
		$container_node->insertBefore( $new_node, $container_node->firstChild );
	} else {
		$container_node->appendChild( $new_node );
	}

	return $container_node;
}


/**
 * Is WP a MultiSite and a subfolder install?
 *
 * @since 1.0
 *
 * @return (bool).
 **/
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
 * Format a path with no heading slash and a trailing slash.
 * If the path is empty, it returns an empty string, not a lonely slash.
 * Example: foo/bar/
 *
 * @since 1.0
 *
 * @param (string) A path.
 *
 * @return (string) The path with no heading slash and a trailing slash.
 **/
function secupress_trailingslash_only( $slug ) {
	return ltrim( trim( $slug, '/' ) . '/', '/' );
}


/**
 * Has WP its own directory?
 *
 * @since 1.0
 * @see http://codex.wordpress.org/Giving_WordPress_Its_Own_Directory
 *
 * @return (string) The directory containing WP.
 **/
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
 *         'base'      => rewrite base,
 *         'wpdir'     => WP directory,
 *         'is_sub'    => Is it a subfolder install? (Multisite),
 *         'site_from' => regex for first part of the rewrite rule (WP files),
 *         'site_to'   => first part of the rewrited address (WP files),
 *         'home_from' => regex for first part of the rewrite rule (home),
 *         'home_to'   => first part of the rewrited address (home).
 **/
function secupress_get_rewrite_bases() {
	global $is_apache, $is_nginx, $is_iis7;
	static $bases;

	if ( isset( $bases ) ) {
		return $bases;
	}

	$base   = parse_url( trailingslashit( get_option( 'home' ) ), PHP_URL_PATH );
	$wp_dir = secupress_get_wp_directory();

	// Apache
	if ( $is_apache ) {
		if ( secupress_is_subfolder_install() ) {
			return ( $bases = array(
				'base'      => $base,
				'wpdir'     => $wp_dir,
				'is_sub'    => true,
				'site_from' => $wp_dir . '([_0-9a-zA-Z-]+/)?',
				'site_to'   => $wp_dir . '$1',
				'home_from' => '([_0-9a-zA-Z-]+/)?',
				'home_to'   => '$1',
			) );
		}
		else {
			return ( $bases = array(
				'base'      => $base,
				'wpdir'     => $wp_dir,
				'is_sub'    => false,
				'site_from' => $wp_dir,
				'site_to'   => $wp_dir,
				'home_from' => '',
				'home_to'   => '',
			) );
		}
	}

	// Nginx
	if ( $is_nginx ) {
		if ( secupress_is_subfolder_install() ) {
			return ( $bases = array(
				'base'      => $base,
				'wpdir'     => $wp_dir,
				'is_sub'    => true,
				'site_from' => $wp_dir . '([_0-9a-zA-Z-]+/)?',
				'site_to'   => $base . $wp_dir . '$1',
				'home_from' => '([_0-9a-zA-Z-]+/)?',
				'home_to'   => $base . '$1',
			) );
		}
		else {
			return ( $bases = array(
				'base'      => $base,
				'wpdir'     => $wp_dir,
				'is_sub'    => false,
				'site_from' => $wp_dir,
				'site_to'   => $base . $wp_dir,
				'home_from' => '',
				'home_to'   => $base,
			) );
		}
	}

	// iis7
	if ( $is_iis7 ) {
		$base = secupress_trailingslash_only( $base );

		if ( secupress_is_subfolder_install() ) {
			return ( $bases = array(
				'base'      => $base,
				'wpdir'     => $wp_dir,
				'is_sub'    => true,
				'site_from' => $base . $wp_dir . '([_0-9a-zA-Z-]+/)?',
				'site_to'   => $base . $wp_dir . '{R:1}',
				'home_from' => $base . '([_0-9a-zA-Z-]+/)?',
				'home_to'   => $base . '{R:1}',
			) );
		}
		else {
			return ( $bases = array(
				'base'      => $base,
				'wpdir'     => $wp_dir,
				'is_sub'    => false,
				'site_from' => $base . $wp_dir,
				'site_to'   => $base . $wp_dir,
				'home_from' => $base,
				'home_to'   => $base,
			) );
		}
	}

	return ( $bases = false );
}
