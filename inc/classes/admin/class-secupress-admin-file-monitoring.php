<?php
defined( 'ABSPATH' ) or die( 'Cheatin\' uh?' );


/**
 * File Monitoring class.
 *
 * @package SecuPress
 * @since 1.0
 */

class SecuPress_File_Monitoring extends SecuPress_Singleton {


	const VERSION   = '1.0';

	/**
	 * @var Singleton The reference to *Singleton* instance of this class
	 */
	protected static $_instance;


	// Public methods ==============================================================================

	/**
	 * Add tasks to queue and dispatch
	 *
	 * @since 1.0
	 */
	public function process_handler() {
		global $wp_version, $wp_local_package;

		secupress_require_class( 'Admin', 'background-process-file-monitoring' );
		$secupress_background_process_file_monitoring = new SecuPress_Background_Process_File_Monitoring;

		if ( get_transient( 'secupress_toggle_queue' ) ) {
			
			delete_transient( 'secupress_toggle_queue' );

			if ( false === ( $wp_core_files_hashes = get_option( SECUPRESS_WP_CORE_FILES_HASHES ) ) || ! isset( $wp_core_files_hashes[ $wp_version ] ) ) {
				$secupress_background_process_file_monitoring->push_to_queue( 'get_wp_hashes' );
			}

			if ( isset( $wp_local_package ) && isset( $wp_core_files_hashes['locale'] ) && $wp_core_files_hashes['locale'] != $wp_local_package &&
				( false === ( $fix_dists = get_option( SECUPRESS_FIX_DISTS ) ) || ! isset( $fix_dists[ $wp_version ] ) )
			) {
				$secupress_background_process_file_monitoring->push_to_queue( 'fix_dists' );
			}

			$secupress_background_process_file_monitoring->push_to_queue( 'get_self_fulltree' );

			$secupress_background_process_file_monitoring->save();
		}
		$secupress_background_process_file_monitoring->dispatch();

	}

	// Private methods =============================================================================

	protected function _init() {
		add_action( 'init', array( $this, 'process_handler' ) );
	}



}