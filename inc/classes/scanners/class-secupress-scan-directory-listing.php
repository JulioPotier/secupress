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
		global $is_nginx;
		$nginx_rules = '';

		if ( $is_nginx ) {
			$bases       = secupress_get_rewrite_bases();
			$base        = $bases['base'];
			$marker      = 'directory_listing';
			$nginx_rules = "location $base {\n\t\tautoindex off;\n\t}";
			$nginx_rules = "server {\n\t# BEGIN SecuPress $marker\n\t$nginx_rules\n\t# END SecuPress\n}";
		}

		$messages = array(
			// good
			0   => __( 'Your site does not reveal the files list.', 'secupress' ),
			1   => __( 'Your %s file has been successfully edited.', 'secupress' ),
			// warning
			100 => __( 'Unable to determine status of %s.', 'secupress' ),
			// bad
			200 => __( '%s (for example) should not be accessible to anyone.', 'secupress' ),
			// cantfix
			/* translators: 1 is a block name, 2 is a file name, 3 is some code */
			300 => sprintf( __( 'Your server runs a nginx system, the directory listing disclosure cannot be fixed automatically but you can do it yourself by adding the following code inside the %1$s block of your %2$s file: %3$s.', 'secupress' ), '"server"', '<code>nginx.conf</code>', "<pre>$nginx_rules</pre>" ),
			301 => __( 'Your server runs a non recognized system. The directory listing disclosure cannot be fixed automatically.', 'secupress' ),
			/* translators: 1 si a file name, 2 and 3 are some code */
			302 => __( 'Your %1$s file is not writable. Please delete lines that may contain %2$s and add the following ones at the beginning of the file: %3$s', 'secupress' ),
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
		global $is_apache, $is_nginx, $is_iis7;

		if ( $is_apache ) {
			$this->fix_apache();
		} elseif ( $is_iis7 ) {
			$this->fix_iis7();
		} elseif ( $is_nginx ) {
			$this->add_fix_message( 300 );
		} else {
			$this->add_fix_message( 301 );
		}

		return parent::fix();
	}


	protected function fix_apache() {
		$file_path = secupress_get_home_path() . '.htaccess';
		$rules     = "<IfModule mod_autoindex.c>\n    Options -Indexes\n</IfModule>";
		$rules     = "# BEGIN SecuPress directory_listing\n$rules\n# END SecuPress";

		// `.htaccess` not writable, bail out.
		if ( ! is_writable( $file_path ) ) {
			$this->add_fix_message( 302, array( '<code>.htaccess</code>', '<code>Options +Indexes</code>', '<pre>' . $rules . '</pre>' ) );
			return;
		}

		// Get `.htaccess` content.
		$wp_filesystem = static::get_filesystem();
		$file_content  = $wp_filesystem->get_contents( $file_path );

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

		if ( $fixed ) {
			$this->add_fix_message( 1, array( '<code>.htaccess</code>' ) );
		} else {
			$this->add_fix_message( 302, array( '<code>.htaccess</code>', '<code>Options +Indexes</code>', '<pre>' . $rules . '</pre>' ) );
		}
	}


	protected function fix_iis7() {
		$marker    = 'directory_listing';
		$node_type = 'directoryBrowse';
		$node      = '<' . $node_type . ' name="SecuPress ' . $marker . '" enabled="false" showFlags=""/>';

		if ( secupress_insert_iis7_nodes( $marker, array( 'nodes_string' => $node, 'node_types' => $node_type ) ) ) {
			// good
			$this->add_fix_message( 1, array( '<code>web.config</code>' ) );
		} else {
			// cantfix
			$this->add_fix_message( 302, array( '<code>web.config</code>', '<code>&lt;' . $node_type . '/&gt;</code>', '<pre>' . $node . '</pre>' ) );
		}
	}
}
