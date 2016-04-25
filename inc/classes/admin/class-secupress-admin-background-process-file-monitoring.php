<?php
defined( 'ABSPATH' ) or die( 'Cheatin\' uh?' );


/**
 * Background File Monitoring class.
 *
 * @package SecuPress
 * @since 1.0
 */
class SecuPress_Background_Process_File_Monitoring extends WP_Background_Process {

	const VERSION = '1.0';

	/**
	 * Prefix used to build the global process identifier.
	 *
	 * @var (string)
	 */
	protected $prefix = 'secupress';

	/**
	 * Suffix used to build the global process identifier.
	 *
	 * @var (string)
	 */
	protected $action = 'file_monitoring';


	/**
	 * Task.
	 *
	 * @param (mixed) $item Queue item to iterate over.
	 *
	 * @since 1.0
	 *
	 * @return (mixed)
	 */
	protected function task( $item ) {
		if ( ! $item || ! is_string( $item ) || ! method_exists( $this, $item ) ) {
			return false;
		}
		return $this->$item();
	}


	/**
	 * Complete.
	 *
	 * @since 1.0
	 */
	protected function complete() {
		parent::complete();
		secupress_delete_site_transient( 'secupress_toggle_file_scan' );
	}


	/**
	 * Will store the wp core files hashes (md5), first from the w.org api, then from the .zip from w.org too.
	 *
	 * @since 1.0
	 */
	public function get_wp_hashes() {
		global $wp_version, $wp_local_package;

		if ( false !== ( $result = get_option( SECUPRESS_WP_CORE_FILES_HASHES ) ) && isset( $result[ $wp_version ]['checksums'] ) ) {
			return $result[ $wp_version ];
		}

		update_option( SECUPRESS_WP_CORE_FILES_HASHES, array( $wp_version => array() ), false );

		$result = array( $wp_version => array() );
		$locale = isset( $wp_local_package ) ? $wp_local_package : 'en_US';
		$urls   = array(
			$locale => 'http://api.wordpress.org/core/checksums/1.0/?locale=' . $locale . '&version=' . $wp_version,
		);

		if ( 'en_US' !== $locale ) {
			$urls['en_US'] = 'http://api.wordpress.org/core/checksums/1.0/?locale=en_US&version=' . $wp_version;
		}

		foreach ( $urls as $locale => $url ) {

			$response = wp_remote_get( $url );

			if ( ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response ) ) {
				$result[ $wp_version ] = json_decode( wp_remote_retrieve_body( $response ), true );
			}

			if ( isset( $result[ $wp_version ]['checksums'] ) && false !== $result[ $wp_version ]['checksums'] ) {
				$result[ $wp_version ]['locale'] = $locale;
				$result[ $wp_version ]['url'] = $url;
				break;
			}
		}

		if ( ! isset( $result[ $wp_version ]['checksums'] ) || ! $result[ $wp_version ]['checksums'] ) {

			$file     = "http://wordpress.org/wordpress-$wp_version-no-content.zip";
			$file_md5 = "http://wordpress.org/wordpress-$wp_version.zip.md5";
			$response = wp_remote_get( $file_md5 );

			if ( ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response ) ) {
				require_once( ABSPATH . 'wp-admin/includes/file.php' );

				$zip_md5  = wp_remote_retrieve_body( $response );
				$tmpfname = download_url( $file );

				if ( ! is_wp_error( $tmpfname ) && is_readable( $tmpfname ) ) {
					$file = $tmpfname;
					$zip  = zip_open( $file );

					$result[ $wp_version ]['checksums'] = array();

					if ( is_resource( $zip ) ) {

						while ( $zip_entry = zip_read( $zip ) ) {
							zip_entry_open( $zip, $zip_entry, 'r' );
							$zfile = zip_entry_read( $zip_entry, zip_entry_filesize( $zip_entry ) );
							list( $wp, $filename ) = explode( '/', zip_entry_name( $zip_entry ), 2 );

							if ( $filename ) {
								$md5tmp = md5( $zfile );
								$result[ $wp_version ]['checksums'][ $filename ] = $md5tmp;
							}
							zip_entry_close( $zip_entry );
						}
						zip_close( $zip );
					}
					unlink( $tmpfname );
				}
			} else {
				$result[ $wp_version ]['checksums'] = $response;
			}
		}

		update_option( SECUPRESS_WP_CORE_FILES_HASHES, $result );
	}


	/**
	 * Will store the possible dists file from wp core files hashes (md5), first from the w.org api, then from the .zip from w.org too.
	 *
	 * @since 1.0
	 *
	 * @param (string) $type ////.
	 * @param (string) $path ////.
	 * @param (string) $pre  ////.
	 */
	public function fix_dists( $type = 'branches', $path = '', $pre = '' ) {
		global $wp_version, $wp_local_package;
		static $wp_files_hashes;
		static $flag = false;

		if ( ! isset( $wp_files_hashes ) ) {
			update_option( SECUPRESS_FIX_DISTS, array( $wp_version => array() ), false );
		}

		$branch   = 'branches' === $type ? substr( $wp_version, 0, 3 ) : $wp_version;
		$i18n_url = ! $path ? "http://i18n.svn.wordpress.org/$wp_local_package/$type/$branch/dist/" : $path;
		$response = wp_remote_get( $i18n_url );

		if ( ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response ) ) {

			$links = strip_tags( wp_remote_retrieve_body( $response ), '<a>' );
			preg_match_all( '/>(.*)<\/a>/', $links, $links );

			if ( isset( $links[1] ) ) {

				$links = $links[1];
				unset( $links[0], $links[ count( $links ) ] );

				foreach ( $links as $dist ) {
					set_time_limit( 0 );

					if ( '/' !== substr( $dist, -1 ) ) {

						$response = wp_remote_get( $i18n_url . $dist );

						if ( ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response ) ) {

							$content = wp_remote_retrieve_body( $response );
							$wp_files_hashes[ $wp_version ][ $pre . $dist ] = md5( $content );
						}
					} else {
						self::fix_dists( $type, $i18n_url . $dist, $pre . $dist );
					}
				}
			}
		} elseif ( $flag !== $path  ) {
			$this->fix_dists( 'tags', $path, $pre );
			$flag = $path;
		}

		update_option( SECUPRESS_FIX_DISTS, $wp_files_hashes, false );
	}


	/**
	 * Wrapper for get_self_filetree() with full recursivity
	 *
	 * @since 1.0
	 *
	 * @return 'map_md5_fulltree' (the next queue)
	 */
	public function get_self_fulltree() {
		self::get_self_filetree( array(), array( 'recursive' => true, 'option' => SECUPRESS_FULL_FILETREE ) );

		return 'map_md5_fulltree';
	}


	/**
	 * Undocumented function ////.
	 *
	 * @since 1.0
	 *
	 * @return false ////.
	 */
	public function map_md5_fulltree() {
		global $wp_version;

		$full_filetree = get_option( SECUPRESS_FULL_FILETREE );

		if ( false === $full_filetree || ! isset( $full_filetree[ $wp_version ] ) ) {
			return false;
		}

		$all_done = true;
		$n        = 0;

		foreach ( $full_filetree[ $wp_version ] as $key => $hash_or_file ) {

			if ( strlen( $hash_or_file ) === 32 && strpos( $hash_or_file, '/' ) === false ) {
				$all_done = $all_done || true;
				continue;
			}

			$all_done = false;
			++$n;
			$full_filetree[ $wp_version ][ $key ] = md5_file( $hash_or_file );

			if ( 20 === $n ) {
				update_option( SECUPRESS_FULL_FILETREE, $full_filetree );
				$n = 0;
			}
		}

		if ( $n > 0 ) {
			update_option( SECUPRESS_FULL_FILETREE, $full_filetree );
		}

		return $all_done;
	}


	/**
	 * Will store the wp core files hashes (md5), first from the w.org api, then from the .zip from w.org too.
	 *
	 * @since 1.0
	 *
	 * @param (array) $paths An array of directory paths. Default is `array( ABSPATH )`.
	 * @param (array) $args  An array of arguments. //// Préciser.
	 */
	public static function get_self_filetree( $paths = array(), $args = array() ) {
		global $wp_version, $wp_local_package;
		static $result = array();

		$paths      = ! $paths ? array( ABSPATH ) : array_filter( array_map( 'realpath', array_unique( (array) $paths ) ), 'is_dir' );
		$ext_filter = isset( $args['ext_filter'] ) ? (array) $args['ext_filter'] : array();
		$ignore     = isset( $args['ignore'] )     ? (array) $args['ignore']     : array();
		$recursive  = isset( $args['recursive'] )  ? (bool) $args['recursive']   : true;
		$option     = isset( $args['option'] )     ? $args['option']             : 'secupress_wtf';

		update_option( $option, array( $wp_version => array() ), false );

		foreach ( $paths as $dir ) {

			$root = scandir( $dir );

			if ( ! $root ) {
				continue;
			}

			foreach ( $root as $value ) {

				$current = $dir . DIRECTORY_SEPARATOR . $value;

				if ( '.' === $value || '..' === $value
					|| WP_CONTENT_DIR === ABSPATH . $value
					|| WP_PLUGIN_DIR === ABSPATH . $value
					|| ( defined( 'UPLOADS' ) && UPLOADS === ABSPATH . $value )
					|| in_array( $current, $ignore, true )
					) {
					continue;
				}

				if ( is_file( $dir . DIRECTORY_SEPARATOR . $value ) ) {

					if ( ! $ext_filter || in_array( strtolower( pathinfo( $current, PATHINFO_EXTENSION ) ), $ext_filter, true ) ) {
						$key = ltrim( str_replace( realpath( ABSPATH ), '', $current ), '/' );
						$key = explode( '\\', $key );
						$key = array_filter( $key );
						$key = implode( '/', $key );
						$result[ $wp_version ][ $key ] = realpath( $current );
					}
					continue;
				}

				if ( $recursive ) {
					self::get_self_filetree( $current, $args );
				}
			}
		}

		update_option( $option, $result );
	}
}
