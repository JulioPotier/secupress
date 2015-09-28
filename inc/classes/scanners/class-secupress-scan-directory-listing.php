<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Directory Listing scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */

class SecuPress_Scan_Directory_Listing extends SecuPress_Scan implements iSecuPress_Scan {

	const VERSION = '1.0';

	/**
	 * @var Singleton The reference to *Singleton* instance of this class
	 */
	protected static $_instance;
	public    static $prio = 'high';


	protected static function init() {
		self::$type  = 'WordPress';
		self::$title = __( 'Check if your WordPress site discloses files in directory (known as Directory Listing).', 'secupress' );
		self::$more  = __( 'Without the appropriate protection, anybody could browse your site files. While browsing some of your files might not be a security risk, most of them are sensitive.', 'secupress' );
	}


	public static function get_messages( $message_id = null ) {
		$messages = array(
			// good
			0   => __( 'Your site does not reveal the files list.', 'secupress' ),
			// warning
			100 => __( 'Unable to determine status of %s.', 'secupress' ),
			// bad
			200 => __( '%s (for example) should not be accessible to anyone.', 'secupress' ),
			// cantfix
			300 => sprintf( __( 'Your %1$s file is not writeable. Please delete lines that may contain %2$s and add the following ones to the file: %3$s.', 'secupress' ), '<code>.htaccess</code>', '<code>Options +Indexes</code>', '<code>%s</code>' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	public function scan() {
		$upload_dir = wp_upload_dir();
		$base_url   = user_trailingslashit( $upload_dir['baseurl'] );
		$response   = wp_remote_get( $base_url, array( 'redirection' => 0 ) );

		if ( ! is_wp_error( $response ) ) {

			if ( 200 === wp_remote_retrieve_response_code( $response ) ) {
				// bad
				$this->add_message( 200, array( '<code>' . $base_url . '</code>' ) );
			}

		} else {
			// warning
			$this->add_message( 100, array( '<code>' . $base_url . '</code>' ) );
		}

		// good
		$this->maybe_set_status( 0 );

		return parent::scan();
	}


	public function fix() {
		global $wp_filesystem;

		// If we can add our lines, it means the file is writeable.
		if ( secupress_write_htaccess( 'directory_listing' ) ) {

			// Remove `Options +Indexes`.
			$file_path    = get_home_path() . '.htaccess';
			$chmod        = defined( 'FS_CHMOD_FILE' ) ? FS_CHMOD_FILE : 0644;
			$file_content = $wp_filesystem->get_contents( $file_path );

			if ( preg_match_all( "/Options\s+\+Indexes\s*(?:\n|$)/", $file_content, $matches, PREG_SET_ORDER ) ) {
				foreach ( $matches as $match ) {
					$file_content = str_replace( $match[0], '', $file_content );
				}

				$wp_filesystem->put_contents( $file_path, trim( $file_content ), $chmod );
			}

		} else {
			$code = secupress_get_htaccess_marker( 'directory_listing' );
			$this->add_message( 300, array( "# BEGIN SecuPress directory_listing\n$code\n# END SecuPress" ) );
		}

		return parent::fix();
	}
}
