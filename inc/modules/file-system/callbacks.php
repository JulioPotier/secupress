<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/*------------------------------------------------------------------------------------------------*/
/* MALWARE SCANNER ============================================================================== */
/*------------------------------------------------------------------------------------------------*/

add_action( 'wp_ajax_secupress_delete_scanned_files',    'secupress_delete_scanned_files_ajax_post_cb' );
add_action( 'admin_post_secupress_delete_scanned_files', 'secupress_delete_scanned_files_ajax_post_cb' );
/**
 * Will handle the deletion for non core WordPress files
 *
 * @since 1.0
 */
function secupress_delete_scanned_files_ajax_post_cb() {
	global $wp_version;

	secupress_check_user_capability();
	secupress_check_admin_referer( 'secupress_delete_scanned_files' );

	if ( ! isset( $_POST['files'] ) ) {
		secupress_admin_die();
	}

	$diff_from_root_core  = array();
	$full_filetree        = get_option( SECUPRESS_FULL_FILETREE );
	$wp_core_files_hashes = get_option( SECUPRESS_WP_CORE_FILES_HASHES );

	if ( false !== $full_filetree && false !== $wp_core_files_hashes && isset( $wp_core_files_hashes[ $wp_version ]['checksums'], $full_filetree[ $wp_version ] ) ) {
		$orig_self_filetree   = $full_filetree;
		$wp_content_dir       = str_replace( realpath( ABSPATH ) . DIRECTORY_SEPARATOR, '/' , WP_CONTENT_DIR );
		$wp_core_files_hashes = $wp_core_files_hashes[ $wp_version ]['checksums'];
		$wp_core_files_hashes['wp-config.php'] = 'wp-config.php'; // Add this since it's not in the zip but depends from WordPress.

		if ( is_multisite() ) {
			$wp_core_files_hashes[ $wp_content_dir . '/sunrise.php' ] = '/sunrise.php'; // Add this since it's not in the zip but depends from WordPress MS.
		}

		if ( defined( 'WP_CACHE' ) && WP_CACHE ) {
			$wp_core_files_hashes[ $wp_content_dir . '/advanced-cache.php' ] = '/advanced-cache.php'; // Add this since it's not in the zip but depends from WordPress Cache.
		}

		$wp_core_files_hashes = array_keys( $wp_core_files_hashes );
		/**
		 * Filter the list of WordPress core file paths.
		 *
		 * @since 1.0
		 *
		 * @param (array) $wp_core_files_hashes The list of WordPress core file paths.
		 */
		$wp_core_files_hashes = apply_filters( 'secupress.wp_core_files_hashes', $wp_core_files_hashes );
		$diff_from_root_core  = array_diff( $full_filetree[ $wp_version ], $wp_core_files_hashes );
		$diff_from_root_core  = array_flip( $diff_from_root_core );
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


add_action( 'wp_ajax_secupress_diff_file',    'secupress_diff_file_ajax_post_cb' );
add_action( 'admin_post_secupress_diff_file', 'secupress_diff_file_ajax_post_cb' );
/**
 * Will display the differences between 2 files from WP Core, using WP core classes
 *
 * @since 1.0
 */
function secupress_diff_file_ajax_post_cb() {
	global $wp_version;

	if ( ! isset( $_GET['file'] ) ) {
		secupress_admin_die();
	}

	$file = $_GET['file'];

	secupress_check_user_capability();
	secupress_check_admin_referer( 'secupress_diff_file-' . $file );

	$content  = '';
	$response = wp_remote_get( esc_url( "https://core.svn.wordpress.org/tags/$wp_version/$file" ) );

	if ( ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response ) ) {
		$text    = secupress_text_diff( wp_remote_retrieve_body( $response ), file_get_contents( ABSPATH . $file ), array( 'title' => $file ) );
		$content = $text ? $text : $content;
	}

	if ( $content ) {
		secupress_action_page( __( 'File Differences', 'secupress' ), $content, array( 'head' => '<link rel="stylesheet" type="text/css" href="' . esc_url( admin_url( 'css/revisions.css' ) ) . '">' ) );
	} else {
		secupress_die( sprintf( __( 'Error while loading %s', 'secupress' ), esc_html( "https://core.svn.wordpress.org/tags/$wp_version/$file" ) ) );
	}
}


add_action( 'wp_ajax_secupress_recover_diff_files',    'secupress_recover_diff_files_ajax_post_cb' );
add_action( 'admin_post_secupress_recover_diff_files', 'secupress_recover_diff_files_ajax_post_cb' );
/**
 * Will download WP Core files that are different from the original
 *
 * @since 1.0
 */
function secupress_recover_diff_files_ajax_post_cb() {
	global $wp_version; // //// Async.

	secupress_check_user_capability();
	secupress_check_admin_referer( 'secupress_recover_diff_files' );

	$full_filetree        = get_option( SECUPRESS_FULL_FILETREE, false );
	$wp_core_files_hashes = get_option( SECUPRESS_WP_CORE_FILES_HASHES, false );

	if ( ! $full_filetree || ! $wp_core_files_hashes || empty( $_POST['files'] ) ) {
		secupress_admin_die();
	}

	foreach ( $_POST['files'] as $file ) {
		if ( ! file_exists( ABSPATH . $file ) && isset( $wp_core_files_hashes[ $file ] ) ) {
			continue;
		}

		$response = wp_remote_get( "https://core.svn.wordpress.org/tags/$wp_version/$file" );

		if ( ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response ) ) {
			$content = wp_remote_retrieve_body( $response );
			file_put_contents( ABSPATH . $file, $content );
			$full_filetree[ $wp_version ][ $file ] = md5( $content );
		}
	}

	update_option( SECUPRESS_FULL_FILETREE, $full_filetree );

	secupress_admin_send_response_or_redirect( 1 );
}


add_action( 'wp_ajax_secupress_recover_missing_files',    'secupress_recover_missing_files_ajax_post_cb' );
add_action( 'admin_post_secupress_recover_missing_files', 'secupress_recover_missing_files_ajax_post_cb' );
/**
 * Will download missing files from WP Core
 *
 * @since 1.0
 */
function secupress_recover_missing_files_ajax_post_cb() {
	global $wp_version; // //// Async.

	secupress_check_user_capability();
	secupress_check_admin_referer( 'secupress_recover_missing_files' );

	$full_filetree        = get_option( SECUPRESS_FULL_FILETREE, false );
	$wp_core_files_hashes = get_option( SECUPRESS_WP_CORE_FILES_HASHES, false );

	if ( ! $full_filetree || ! $wp_core_files_hashes || empty( $_POST['files'] ) ) {
		secupress_admin_die();
	}

	$wp_core_files_hashes = array_flip( array_filter( array_flip( $wp_core_files_hashes[ $wp_version ]['checksums'] ), 'secupress_filter_no_content' ) );
	$missing_from_root_core = array_diff_key( $wp_core_files_hashes, $full_filetree[ $wp_version ] );

	foreach ( $_POST['files'] as $file ) {
		if ( file_exists( ABSPATH . $file ) && ! isset( $missing_from_root_core[ $file ] ) ) {
			continue;
		}

		$response = wp_remote_get( "https://core.svn.wordpress.org/tags/$wp_version/$file" );

		if ( ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response ) ) {
			$content = wp_remote_retrieve_body( $response );
			file_put_contents( ABSPATH . $file, $content );
			$full_filetree[ $wp_version ][ $file ] = md5( $content );
		}
	}

	update_option( SECUPRESS_FULL_FILETREE, $full_filetree );

	secupress_admin_send_response_or_redirect( 1 );
}


add_action( 'wp_ajax_secupress_old_files',    'secupress_old_files_ajax_post_cb' );
add_action( 'admin_post_secupress_old_files', 'secupress_old_files_ajax_post_cb' );
/**
 * Will delete old WP core files still present in this installation
 *
 * @since 1.0
 */
function secupress_old_files_ajax_post_cb() {
	global $wp_version, $_old_files;

	secupress_check_user_capability();
	secupress_check_admin_referer( 'secupress_old_files' );

	$full_filetree = get_option( SECUPRESS_FULL_FILETREE, false );
	$wp_old_files  = array();

	require_once( ABSPATH . 'wp-admin/includes/update-core.php' );

	foreach ( $_old_files as $file ) {
		if ( file_exists( ABSPATH . $file ) ) {
			$wp_old_files[ $file ] = $file;
		}
	}

	if ( ! $wp_old_files || empty( $_POST['files'] ) ) {
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
/* ON MODULE SETTINGS SAVE ====================================================================== */
/*------------------------------------------------------------------------------------------------*/

/**
 * Callback to filter, sanitize.
 *
 * @since 1.0
 *
 * @param (array) $settings The module settings.
 *
 * @return (array) The sanitized and validated settings.
 */
function secupress_file_system_settings_callback( $settings ) {
	$modulenow = 'file-system';
	$settings  = $settings ? $settings : array();
	$activate  = secupress_get_submodule_activations( $modulenow );

	if ( isset( $settings['sanitized'] ) ) {
		return $settings;
	}
	$settings['sanitized'] = 1;

	// Activate/deactivate.
	if ( secupress_is_pro() ) {
		secupress_manage_submodule( $modulenow, 'bad-file-extensions', ! empty( $activate['bad-file-extensions_activated'] ) );
	} else {
		secupress_deactivate_submodule( $modulenow, array( 'bad-file-extensions' ) );
	}

	return $settings;
}
