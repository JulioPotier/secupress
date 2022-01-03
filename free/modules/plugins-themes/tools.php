<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/**
 * Get the plugins removed from repo from our local file.
 *
 * @since 1.0.3 Use the whitelist
 * @since 1.0
 *
 * @return (array|bool) The plugins removed from the repository: dirname as array keys and plugin path as values. Return false if the file is not readable.
 */
function secupress_get_removed_plugins() {
	static $removed_plugins;

	if ( isset( $removed_plugins ) ) {
		return $removed_plugins;
	}

	if ( false !== ( $from_transient = get_site_transient( 'secupress_removed_plugins' ) ) ) {
		return $from_transient;
	}

	$plugins_list_file = SECUPRESS_INC_PATH . 'data/no-longer-in-directory-plugin-list.data';

	if ( ! is_readable( $plugins_list_file ) ) {
		return false;
	}

	$removed_plugins = array_flip( array_map( 'trim', file( $plugins_list_file ) ) );
	$whitelist       = secupress_get_plugins_whitelist();

	if ( $whitelist ) {
		$removed_plugins = array_diff_key( $removed_plugins, $whitelist );
	}

	$all_plugins     = array_keys( get_plugins() );
	$all_plugins     = array_combine( array_map( 'dirname', $all_plugins ), $all_plugins );
	$removed_plugins = array_intersect_key( $all_plugins, $removed_plugins );

	set_site_transient( 'secupress_removed_plugins', $removed_plugins, 6 * HOUR_IN_SECONDS );

	return $removed_plugins;
}


/**
 * Get the plugins not update since 2 years from repo from our local file.
 *
 * @since 1.0
 *
 * @return (array|bool) The plugins from the repository not updated for 2 years: dirname as array keys and plugin path as values. Return false if the file is not readable.
 */
function secupress_get_notupdated_plugins() {
	static $notupdated_plugins;

	if ( isset( $notupdated_plugins ) ) {
		return $notupdated_plugins;
	}

	if ( false !== ( $from_transient = get_site_transient( 'secupress_notupdated_plugins' ) ) ) {
		return $from_transient;
	}

	$plugins_list_file = SECUPRESS_INC_PATH . 'data/not-updated-in-over-two-years-plugin-list.data';

	if ( ! is_readable( $plugins_list_file ) ) {
		return false;
	}

	$notupdated_plugins = array_flip( array_map( 'trim', file( $plugins_list_file ) ) );

	$all_plugins = array_keys( get_plugins() );
	$all_plugins = array_combine( array_map( 'dirname', $all_plugins ), $all_plugins );
	$all_plugins = array_intersect_key( $all_plugins, $notupdated_plugins );

	$notupdated_plugins = $all_plugins;
	set_site_transient( 'secupress_notupdated_plugins', $notupdated_plugins, 6 * HOUR_IN_SECONDS );

	return $notupdated_plugins;
}


/**
 * Get the plugins vulnerable from an option, from our option, set by `secupress_refresh_bad_plugins_list_ajax_post_cb()`.
 *
 * @since 1.0
 *
 * @return (array) The vulnerables plugins.
 */
function secupress_get_vulnerable_plugins() {
	static $vulnerable_plugins;

	if ( isset( $vulnerable_plugins ) ) {
		return $vulnerable_plugins;
	}

	$temp = get_site_option( 'secupress_bad_plugins' );
	$temp = $temp ? (array) json_decode( $temp, true ) : [];

	if ( $temp ) {
		$vulnerable_plugins = $temp;
		return $vulnerable_plugins;
	}

	return [];
}

/**
 * Get the plugins whitelist from our local file.
 *
 * @since 1.0
 *
 * @return (array) The plugins whitelist, with dirname as keys.
 */
function secupress_get_plugins_whitelist() {
	static $whitelist;

	if ( isset( $whitelist ) ) {
		return $whitelist;
	}

	$whitelist_file = SECUPRESS_INC_PATH . 'data/whitelist-plugin-list.data';
	/**
	* Shortcut the list with this filter
	*/
	$whitelist      = apply_filters( 'secupress.allowed.plugins.pre', [] ) ;
	if ( ! empty( $whitelist) ) {
		return $whitelist;
	}

	$whitelist = file( $whitelist_file );
	$whitelist = array_map( 'trim', $whitelist );
	$whitelist = array_flip( $whitelist );

	if ( ! is_readable( $whitelist_file ) ) {
		/**
		* If file is not readable, you can fill it manually
		*/
		return apply_filters( 'secupress.allowed.plugins.file_not_readable', [] ) ;
	}

	/**
	* The list from file, you can filter it
	*/
	$whitelist = apply_filters( 'secupress.allowed.plugins.list', $whitelist ) ;

	return $whitelist;
}


/* THEMES */

/**
 * Get the vulnerable themes from an option, from our option, set by `secupress_refresh_bad_themes_list_ajax_post_cb()`.
 *
 * @since 1.0
 *
 * @return (array) The vulnerables themes.
 */
function secupress_get_vulnerable_themes() {
	static $vulnerable_themes;
	$errors = array( '-1', '-2', '-3', '-99' );

	if ( isset( $vulnerable_themes ) ) {
		return $vulnerable_themes;
	}

	if ( false !== ( $from_transient = get_site_transient( 'secupress_vulnerable_themes' ) ) ) {
		return array_diff( $from_transient, $errors );
	}

	$temp = get_site_option( 'secupress_bad_themes' );
	$temp = $temp ? (array) json_decode( $temp, true ) : array();
	$temp = $temp ? array_diff( $temp, $errors ) : array();

	if ( $temp ) {
		$vulnerable_themes = $temp;
		set_site_transient( 'secupress_vulnerable_themes', $vulnerable_themes, 6 * HOUR_IN_SECONDS );
		return $vulnerable_themes;
	}

	return array();
}

/**
 * Mimic the WP behaviour without "direct" as result, we need to know which kind of FTP is available.
 *
 * @see get_filesystem_method()
 * @author Julio Potier
 * @since 2.2
 * @return (string) $method
 **/
function secupress_get_ftp_fs_method() {

	$method = false;

	if ( ! $method && extension_loaded( 'ssh2' ) ) {
		$method = 'ssh2';
	}
	if ( ! $method && extension_loaded( 'ftp' ) ) {
		$method = 'ftpext';
	}
	if ( ! $method && ( extension_loaded( 'sockets' ) || function_exists( 'fsockopen' ) ) ) {
		$method = 'ftpsockets';
	}

	return $method;
}

/**
 * Returns a verbosed version of the FS method
 *
 * @param (string) $method
 * @author Julio Potier
 * @since 2.2 
 * @return (string) $method
 **/
function secupress_verbose_ftp_fs_method( $method ) {
	if ( secupress_is_submodule_active( 'plugins-themes', 'uploads' ) ) {
		return __( 'Themes & Plugins Upload Disabled', 'secupress' );
	}
	$methods = [ 	
					'direct'     => __( 'Direct File Writing (direct)', 'secupress' ),
					'ssh2'       => __( 'Secure Shell 2 (ssh2)', 'secupress' ),
					'ftpext'     => __( 'File Transfert Protocol Extension (ftpext)', 'secupress' ),
					'ftpsockets' => __( 'File Transfert Protocol with Sockets (ftpsockets)', 'secupress' ),
				];
	return isset( $methods[ $method ] ) ? $methods[ $method ] : $method;
}