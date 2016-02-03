<?php
defined( 'ABSPATH' ) or die( 'Cheatin\' uh?' );


/**
 * Background File Monitoring class.
 *
 * @package SecuPress
 * @since 1.0
 */

class SecuPress_Background_Process_File_Monitoring extends WP_Background_Process {

	const WP_CORE_FILES_HASHES = 'secupress_wp_core_files_hashes';

	public function get_wp_hashes( $version = false ) {
		global $wp_version, $wp_local_package;

		$version = $version ? $version : $wp_version;

		if ( false !== ( $result = get_option( self::WP_CORE_FILES_HASHES ) ) && isset( $result[ $version ] ) ) {
			return $result[ $version ];
		}

		update_option( self::WP_CORE_FILES_HASHES, array() ); // do this early to act as a lock toa void multiple background process

		$result = array( $version => array() );
		$locale = isset( $wp_local_package ) ? $wp_local_package : 'en_US';
		$urls   = array(
						$locale => 'http://api.wordpress.org/core/checksums/1.0/?locale=' . $locale . '&version=' . $version,
						'en_US' => 'http://api.wordpress.org/core/checksums/1.0/?locale=en_US&version=' . $version,
						);

		foreach ( $urls as $locale => $url ) {

			$response = wp_remote_get( $url );

			if ( ! is_wp_error( $response ) && 200 == wp_remote_retrieve_response_code( $response ) ) {
				$result[ $version ] = json_decode( wp_remote_retrieve_body( $response ), true );
			}

			if ( isset( $result[ $version ]['checksums'] ) && false !== $result[ $version ]['checksums'] ) {
				$result[ $version ]['locale'] = $locale;
				$result[ $version ]['url'] = $url;
				break;
			}
		}

		if ( ! isset( $result[ $version ]['checksums'] ) ) {
			$result[ $version ]['checksums'] = false;
			//// from zip
		} else {
			update_option( self::WP_CORE_FILES_HASHES, $result );
		}

		// return $result;
	}

	/**
	 * @var string
	 */
	protected $action = 'background_process_file_monitoring';
	/**
	 * Task
	 *
	 * Override this method to perform any actions required on each
	 * queue item. Return the modified item for further processing
	 * in the next pass through. Or, return false to remove the
	 * item from the queue.
	 *
	 * @param mixed $item Queue item to iterate over
	 *
	 * @return mixed
	 */
	protected function task( $item ) {
		$this->$item ();
		set_transient( $item, date( get_option( 'time_format' ) ) );
		return false;
	}
	/**
	 * Complete
	 *
	 * Override if applicable, but ensure that the below actions are
	 * performed, or, call parent::complete().
	 */
	protected function complete() {
		parent::complete();
		delete_site_transient( 'secupress_run_file_scan' );
	}
}