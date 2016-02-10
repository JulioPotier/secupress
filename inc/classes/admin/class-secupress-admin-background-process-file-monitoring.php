<?php
defined( 'ABSPATH' ) or die( 'Cheatin\' uh?' );


/**
 * Background 	File Monitoring class.
 *
 * @package SecuPress
 * @since 1.0
 */

class SecuPress_Background_Process_File_Monitoring extends WP_Background_Process {

	const WP_CORE_FILES_HASHES = 'secupress_wp_core_files_hashes';

	public function get_wp_hashes( $version = false ) {
		global $wp_version, $wp_local_package;

		$version = $version ? $version : $wp_version;

		if ( false !== ( $result = get_option( self::WP_CORE_FILES_HASHES ) ) && isset( $result[ $version ]['checksums'] ) ) {
			return $result[ $version ];
		}

		update_option( self::WP_CORE_FILES_HASHES, array() ); // do this early to act as a lock to avoid multiple background processes

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
			$result[ $version ]['foo'] = 'bar';
		}

		if ( ! isset( $result[ $version ]['checksums'] ) || ! $result[ $version ]['checksums'] ) {

			$file = "http://wordpress.org/wordpress-$version-no-content.zip";
			$file_md5 = "http://wordpress.org/wordpress-$version.zip.md5";
			$response = wp_remote_get( $file_md5 );
			if ( ! is_wp_error( $response ) && 200 == wp_remote_retrieve_response_code( $response ) ) {
				$zip_md5 = wp_remote_retrieve_body( $response );
				require_once( ABSPATH . 'wp-admin/includes/file.php' );
				$tmpfname = download_url( $file );
				$result[ $version ]['foo'] = $tmpfname;
				if ( ! is_wp_error( $tmpfname ) && is_readable( $tmpfname ) ) {
					$file = $tmpfname;

					$result[ $version ]['checksums'] = array();
					$zip = zip_open( $file );
					if ( is_resource( $zip ) ) {
						while ( $zip_entry = zip_read( $zip ) ) {
							zip_entry_open( $zip, $zip_entry, "r" );
							$zfile = zip_entry_read( $zip_entry, zip_entry_filesize( $zip_entry ) );
							list( $wp, $filename ) = explode( '/', zip_entry_name( $zip_entry ), 2 );
							if ( $filename ) {
								$md5tmp = md5( $zfile );
								$result[ $version ]['checksums'][ $filename ] = $md5tmp;
							}
							zip_entry_close( $zip_entry );
						}
						zip_close( $zip );
					}
					unlink( $tmpfname );
				}
			} else {
				$result[ $version ]['checksums'] = $response;
			}

		}

		update_option( self::WP_CORE_FILES_HASHES, $result );

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
		delete_site_transient( 'secupress_toggle_file_scan' );
	}
}