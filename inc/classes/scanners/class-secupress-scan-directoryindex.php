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
		$messages = array(
			// good
			0   => sprintf( __( '%s is the first file loaded, perfect.', 'secupress' ), '<code>index.php</code>' ),
			1   => __( 'Protection activated', 'secupress' ),
			// warning
			100 => __( 'Unable to determine status of the directory index.', 'secupress' ),
			// bad
			200 => __( 'Your website should load %1$s first, actually it loads %2$s first.', 'secupress' ),
			// cantfix
			300 => __( 'I can not fix this, you have to do it yourself, have fun.', 'secupress' ),////
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

		$rules = "<ifModule mod_dir.c>\n\tDirectoryIndex index.php index.html index.htm index.cgi index.pl index.xhtml\n</ifModule>";
		secupress_write_htaccess( 'DirectoryIndex', $rules );

		$this->add_fix_message( 1 );

		return parent::fix();
	}
}
