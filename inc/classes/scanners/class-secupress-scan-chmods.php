<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Chmods scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */

class SecuPress_Scan_Chmods extends SecuPress_Scan implements iSecuPress_Scan {

	const VERSION = '1.0';

	/**
	 * @var Singleton The reference to *Singleton* instance of this class
	 */
	protected static $_instance;
	public    static $prio = 'high';


	protected static function init() {
		self::$type  = __( 'File System', 'secupress' );
		self::$title = __( 'Check if your files and folders have the correct write permissions (chmod).', 'secupress' );
		self::$more  = __( 'CHMOD is the way to give read/write/execute rights to a file or a folder. The bad guy is known as <code>0777</code> and should be avoided. This test will check some strategic files and folders.', 'secupress' );
	}


	public static function get_messages( $message_id = null ) {
		$messages = array(
			// good
			0   => __( 'All files permissions are good.', 'secupress' ),
			1   => __( 'All files permissions are fixed.', 'secupress' ),
			// warning
			100 => __( 'Unable to determine status of %s.', 'secupress' ),
			// bad
			200 => _x( 'File permissions for %1$s <strong>should be %2$s</strong>, NOT %3$s!', '1: file path, 2: chmod required, 3: current chmod', 'secupress' ),
			201 => __( 'Unable to apply new file permissions to %s.', 'secupress' ),
			// cantfix
			300 => __( 'I can not fix this, you have to do it yourself, have fun.', 'secupress' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	public function scan() {

		$warnings = array();
		$files    = static::get_file_perms();
		$abspath  = realpath( ABSPATH );

		foreach ( $files as $file => $chmod ) {
			// Current file perm
			$current = (int) decoct( fileperms( $file ) & 0777 );
			$file    = ltrim( str_replace( $abspath, '', realpath( $file ) ), '\\' );
			$file    = '' === $file ? '/' : $file;

			if ( ! $current ) {
				// warning: unable to determine file perm.
				$warnings[] = sprintf( '<code>%s</code>', $file );

			} elseif ( $current > $chmod ) {
				// bad
				$this->add_message( 200, array(
					sprintf( '<code>%s</code>', $file ),
					sprintf( '<code>0%s</code>', $chmod ),
					sprintf( '<code>0%s</code>', $current ),
				) );
			}
		}

		if ( $warnings ) {
			// warning
			$this->add_message( 100, array( $warnings ) );
		}

		// good
		$this->maybe_set_status( 0 );

		return parent::scan();
	}


	public function fix() {

		$warnings  = array();
		$bads      = array();
		$files     = static::get_file_perms();
		$files_tmp = array();
		$abspath   = realpath( ABSPATH );

		foreach ( $files as $file => $chmod ) {
			// Current file perm
			$current = (int) decoct( fileperms( $file ) & 0777 );

			if ( ! $current || $current > $chmod ) {
				// Apply new file perm.
				@chmod( $file, octdec( $chmod ) );
				$files_tmp[ $file ] = $chmod;
			}
		}

		$count = count( $files_tmp );
		clearstatcache();

		foreach ( $files_tmp as $file => $chmod ) {
			// Check if it worked.
			$current = (int) decoct( fileperms( $file ) & 0777 );
			$file    = ltrim( str_replace( $abspath, '', realpath( $file ) ), '\\' );
			$file    = '' === $file ? '/' : $file;

			if ( ! $current ) {
				// warning: unable to determine file perm.
				$warnings[] = sprintf( '<code>%s</code>', $file );
			} elseif ( $current > $chmod ) {
				// bad: unable to apply the file perm.
				$bads[] = sprintf( '<code>%s</code>', $file );
			}
		}

		if ( ! $count ) {
			// good (there was nothing to fix).
			$this->add_fix_message( 0 );
			return parent::fix();
		}

		if ( $bads ) {
			// bad
			$this->add_fix_message( 201, array( $bads ) );
		}

		if ( $warnings ) {
			// warning
			$this->add_fix_message( 100, array( $warnings ) );
		}

		// good
		$this->maybe_set_fix_status( 1 );

		return parent::fix();
	}


	protected static function get_file_perms() {
		global $is_apache;

		$_wp_upload_dir = wp_upload_dir();
		$home_path      = secupress_get_home_path();
		$files          = array(
			secupress_find_wpconfig_path()    => 644,
			$home_path                        => 755,
			$home_path . 'wp-admin/'          => 755,
			$home_path . 'wp-includes/'       => 755,
			WP_CONTENT_DIR . '/'              => 755,
			get_theme_root() . '/'            => 755,
			plugin_dir_path( SECUPRESS_FILE ) => 755,
			$_wp_upload_dir['basedir'] . '/'  => 755,
		);

		if ( $is_apache ) {
			$files[ $home_path . '.htaccess' ] = 644;
		}

		return $files;
	}
}
