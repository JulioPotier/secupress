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
	protected static $fix_rules = "<IfModule mod_autoindex.c>\nOptions -Indexes\n</IfModule>";
	public    static $prio      = 'high';


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
			300 => sprintf( __( 'You run a nginx system, I cannot fix the directory listing disclosure but you can do it yourself with the following code: %s.', 'secupress' ), '<code>autoindex off;</code>' ),
			301 => sprintf( __( 'You run an IIS7 system, I cannot fix the directory listing disclosure but you can do it yourself with the following code: %s.', 'secupress' ), '<code>zobbylamouche</code>' ), ////
			302 => __( 'You don\'t run an Apache system, I cannot fix the directory listing disclosure.', 'secupress' ),
			303 => sprintf( __( 'Your %1$s file is not writable. Please delete lines that may contain %2$s and add the following ones to the file: %3$s.', 'secupress' ), '<code>.htaccess</code>', '<code>Options +Indexes</code>', '<code>%s</code>' ),
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
		global $wp_filesystem, $is_apache, $is_nginx, $is_iis7;

		// Not Apache system, bail out.
		if ( ! $is_apache ) {
			if ( ! isset( $is_nginx ) ) {
				$is_nginx = ! empty( $_SERVER['SERVER_SOFTWARE'] ) && strpos( $_SERVER['SERVER_SOFTWARE'], 'nginx' ) !== false;
			}

			if ( $is_nginx ) {
				$this->add_message( 300 );
			} elseif ( $is_iis7 ) {
				$this->add_message( 301 );
			} else {
				$this->add_message( 302 );
			}

			return parent::fix();
		}

		if ( ! function_exists( 'get_home_path' ) ) {
			require_once( ABSPATH . 'wp-admin/includes/file.php' );
		}

		$file_path = get_home_path() . '.htaccess';
		$rules     = static::$fix_rules;
		$rules     = "# BEGIN SecuPress directory_listing\n$rules\n# END SecuPress";

		// `.htaccess` not writable, bail out.
		if ( ! is_writable( $file_path ) ) {
			$this->add_message( 303, array( $rules ) );
			return parent::fix();
		}

		if ( ! $wp_filesystem ) {
			require_once( ABSPATH . 'wp-admin/includes/class-wp-filesystem-base.php' );
			require_once( ABSPATH . 'wp-admin/includes/class-wp-filesystem-direct.php' );

			$wp_filesystem = new WP_Filesystem_Direct( new StdClass() );
		}

		// Get `.htaccess` content.
		$file_content = $wp_filesystem->get_contents( $file_path );

		// Maybe remove `Options +Indexes`.
		if ( preg_match_all( "/Options\s+\+Indexes\s*(?:\n|$)/", $file_content, $matches, PREG_SET_ORDER ) ) {
			foreach ( $matches as $match ) {
				$file_content = str_replace( $match[0], '', $file_content );
			}
		}

		// Maybe remove old rules.
		$file_content = preg_replace( '/# BEGIN SecuPress directory_listing(.*)# END SecuPress\n*/isU', '', $file_content );

		// Add our rules.
		$file_content = $rules . "\n\n" . trim( $file_content );
		$chmod        = defined( 'FS_CHMOD_FILE' ) ? FS_CHMOD_FILE : 0644;

		$fixed = $wp_filesystem->put_contents( $file_path, $file_content, $chmod );

		if ( ! $fixed ) {
			$this->add_message( 303, array( $rules ) );
		}

		return parent::fix();
	}
}
