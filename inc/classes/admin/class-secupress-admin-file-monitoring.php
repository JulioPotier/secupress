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
	const WP_CORE_FILES_HASHES = 'secupress_wp_core_files_hashes';

	/**
	 * @var Singleton The reference to *Singleton* instance of this class
	 */
	protected static $_instance;


	// Public methods ==============================================================================


	public function scan_folder( $folder ) {
		return glob( ABSPATH ); //// ok wait for more ... lol
	}

	/**
	 * Add tasks to queue and dispatch
	 *
	 * @since 1.0
	 */
	public function process_handler() {
		global $wp_version;

		secupress_require_class( 'Admin', 'background-process-file-monitoring' );

		$secupress_background_process_file_monitoring = new SecuPress_Background_Process_File_Monitoring;

		if ( false === ( $wp_core_files_hashes = get_option( self::WP_CORE_FILES_HASHES ) ) || ! isset( $wp_core_files_hashes[ $wp_version ] ) ) {
			$secupress_background_process_file_monitoring->push_to_queue( 'get_wp_hashes' );
			$secupress_background_process_file_monitoring->save();
		}
		$secupress_background_process_file_monitoring->dispatch();

	}

	// Private methods =============================================================================

	protected function _init() {
		add_action( 'init', array( $this, 'process_handler' ) );
	}



}