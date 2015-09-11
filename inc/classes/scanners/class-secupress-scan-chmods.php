<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Chmods scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */

class SecuPress_Scan_Chmods extends SecuPress_Scan {

	const VERSION = '1.0';

	protected static $name = 'chmods';
	public    static $prio = 'high';


	public function __construct() {
		if ( self::$instance ) {
			return self::$instance;
		}

		self::$type  = __( 'File System', 'secupress' );
		self::$title = __( 'Check if your files and folders have the correct write permissions (chmod).', 'secupress' );
		self::$more  = __( 'CHMOD is a way to give read/write/execute rights to a file or a folder. The bad guy is known as <code>0777</code> and should never be used. This test will check some strategic files and folders.', 'secupress' );
	}


	public static function get_messages( $message_id = null ) {
		$messages = array(
			// good
			0   => __( 'All is ok, permissions are good.', 'secupress' ),
			// warning
			100 => __( 'Unable to determine status of %s.', 'secupress' ),
			// bad
			200 => _x( '%1$s file permissions should be %2$s, NOT %3$s!', '1: file path, 2: chmod required, 3: current chmod', 'secupress' ),
			// cantfix
			300 => __( 'I can not fix this, you have to do it yourself, have fun.', 'secupress' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	public function scan() {

		$warnings       = array();
		$_wp_upload_dir = wp_upload_dir();
		$home_path      = get_home_path();
		$files          = array(
			secupress_find_wpconfig_path()    => 444,
			$home_path                        => 755,
			$home_path . 'wp-admin/'          => 755,
			$home_path . 'wp-includes/'       => 755,
			WP_CONTENT_DIR . '/'              => 755,
			get_theme_root() . '/'            => 755,
			plugin_dir_path( SECUPRESS_FILE ) => 755,
			$_wp_upload_dir['basedir'] . '/'  => 755,
		);

		if ( $GLOBALS['is_apache'] ) {
			$files[ $home_path . '.htaccess' ] = 444;
		}

		foreach ( $files as $file => $chmod ) {
			$current = decoct( fileperms( $file ) & 0777 );

			if ( ! $current ) {
				// warning
				$file       = str_replace( ABSPATH, '', $file );
				$file       = '' === $file ? '/' : $file;
				$warnings[] = sprintf( '<code>%s</code>', $file );

			} elseif ( $current > $chmod ) {
				// bad
				$this->add_message( 200, array(
					sprintf( '<code>%s</code>', str_replace( ABSPATH, '', $file ) ),
					sprintf( '<code>0%s</code>', $chmod ),
					sprintf( '<code>0%s</code>', $current ),
				) );
			}
		}

		if ( $warnings ) {
			// warning
			$this->add_message( 100, array( wp_sprintf_l( '%l', $warnings ) ) );
		}

		// good
		$this->maybe_set_status( 0 );

		return parent::scan();
	}


	public function fix() {

		// include the fix here.

		return parent::fix();
	}
}
