<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * DirectoryIndex scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */

class SecuPress_Scan_DirectoryIndex extends SecuPress_Scan implements iSecuPress_Scan {

	const VERSION = '1.0';

	/**
	 * @var Singleton The reference to *Singleton* instance of this class
	 */
	protected static $_instance;
	public    static $prio = 'low';


	protected static function init() {
		global $is_apache, $is_nginx, $is_iis7;

		self::$type  = 'WordPress';
		self::$title = __( 'Check if <em>.php</em> files are loaded in priority instead of <em>.html</em> or <em>.htm</em> etc.', 'secupress' );
		self::$more  = sprintf( __( 'If your website is victim of a defacement using the addition of a file like %1$s, this file could be loaded first instead of the one from WordPress. This is why we have to load %2$s first..', 'secupress' ), '<code>index.htm</code>', '<code>index.php</code>' );

		if ( $is_apache ) {
			$config_file = '.htaccess';
		} elseif ( $is_iis7 ) {
			$config_file = 'web.config';
		} else {
			self::$fixable = false;
		}

		if ( self::$fixable ) {
			self::$more_fix = sprintf( __( 'This will add rules in your %s file to avoid attackers to add <code>.html</code>/<code>.htm</code> files to be loaded before the <code>.php</code> one.', 'secupress' ), '<code>' . $config_file . '</code>' );
		} elseif ( $is_nginx ) {
			self::$more_fix = static::get_messages( 300 );
		} else {
			self::$more_fix = static::get_messages( 301 );
		}
	}


	public static function get_messages( $message_id = null ) {
		global $is_nginx;
		$nginx_rules = '';

		if ( $is_nginx ) {
			$marker      = 'DirectoryIndex';
			$nginx_rules = 'index index.php;';
			$nginx_rules = "server {\n\t# BEGIN SecuPress $marker\n\t$nginx_rules\n\t# END SecuPress\n}";
		}

		$messages = array(
			// good
			0   => sprintf( __( '%s is the first file loaded, perfect.', 'secupress' ), '<code>index.php</code>' ),
			1   => __( 'Your %s file has been successfully edited.', 'secupress' ),
			// warning
			100 => __( 'Unable to determine status of the directory index.', 'secupress' ),
			// bad
			200 => __( 'Your website should load %1$s first, actually it loads %2$s first.', 'secupress' ),
			// cantfix
			/* translators: 1 is a block name, 2 is a file name, 3 is some code */
			300 => sprintf( __( 'Your server runs a nginx system, the directory index cannot be fixed automatically but you can do it yourself by adding the following code inside the %1$s block of your %2$s file: %3$s.', 'secupress' ), '"server"', '<code>nginx.conf</code>', "<pre>$nginx_rules</pre>" ),
			301 => __( 'Your server runs a non recognized system. The directory index cannot be fixed automatically.', 'secupress' ),
			/* translators: 1 si a file name, 2 is some code */
			302 => __( 'Your %1$s file is not writable. Please add the following lines at the beginning of the file: %2$s', 'secupress' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	public function scan() {
		global $is_nginx;

		$response = wp_remote_get( SECUPRESS_PLUGIN_URL . 'inc/DirectoryIndex', array( 'redirection' => 1 ) );

		if ( ! is_wp_error( $response ) ) {

			if ( 200 === wp_remote_retrieve_response_code( $response ) ) {
				$response_body = wp_remote_retrieve_body( $response );
				if ( 'index.php' == $response_body ) {
					// good
					$this->add_message( 0 );
				} else {
					// bad
					$this->add_message( 200, array( '<code>index.php</code>', '<code>' . esc_html( $response_body ) . '</code>' ) );

					if ( $is_nginx ) {
						$this->add_pre_fix_message( 300 );
					} elseif ( ! self::$fixable ) {
						$this->add_pre_fix_message( 301 );
					}
				}
			} else {
				// warning
				$this->add_message( 100 );
			}

		} else {
			// warning
			$this->add_message( 100 );
		}

		return parent::scan();
	}


	public function fix() {
		global $is_apache, $is_iis7;

		if ( $is_apache ) {
			$this->fix_apache();
		} elseif ( $is_iis7 ) {
			$this->fix_iis7();
		}

		return parent::fix();
	}


	protected function fix_apache() {
		$marker = 'DirectoryIndex';
		$rules  = "<ifModule mod_dir.c>\n\tDirectoryIndex index.php index.html index.htm index.cgi index.pl index.xhtml\n</ifModule>";

		if ( secupress_write_htaccess( $marker, $rules ) ) {
			// good
			$this->add_fix_message( 1, array( '<code>.htaccess</code>' ) );
		} else {
			// cantfix
			$this->add_fix_message( 302, array( '<code>.htaccess</code>', "<pre># BEGIN SecuPress $marker\n$rules\n# END SecuPress</pre>" ) );
		}

		return parent::fix();
	}


	protected function fix_iis7() {
		$marker = 'DirectoryIndex';
		$spaces = str_repeat( ' ', 10 );

		$node   = "<defaultDocument name=\"SecuPress $marker\">\n";
			$node  .= "$spaces  <files>\n";
			$node  .= "$spaces    <remove value=\"index.php\" />\n";
			$node  .= "$spaces    <add value=\"index.php\" />\n";
			$node  .= "$spaces  </files>\n";
		$node  .= "$spaces</defaultDocument>";

		if ( secupress_insert_iis7_nodes( $marker, array( 'nodes_string' => $node, 'node_types' => 'defaultDocument' ) ) ) {
			// good
			$this->add_fix_message( 1, array( '<code>web.config</code>' ) );
		} else {
			// cantfix
			$this->add_fix_message( 302, array( '<code>web.config</code>', "<pre>$node</pre>" ) );
		}
	}
}
