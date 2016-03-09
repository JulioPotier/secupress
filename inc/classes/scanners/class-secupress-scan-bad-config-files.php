<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Bad Config Files scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */

class SecuPress_Scan_Bad_Config_Files extends SecuPress_Scan implements iSecuPress_Scan {

	const VERSION = '1.0';

	/**
	 * @var Singleton The reference to *Singleton* instance of this class
	 */
	protected static $_instance;
	public    static $prio = 'high';


	protected static function init() {
		self::$type     = 'WordPress';
		self::$title    = __( 'Check if your installation contains old or backed up <code>wp-config.php</code> files like <code>wp-config.bak</code>, <code>wp-config.old</code> etc.', 'secupress' );
		self::$more     = __( 'Some attackers will try to find some old and backed up config files to try to steal them. Avoid this kind of attack just by removing them.', 'secupress' );
		self::$more_fix = __( 'The fix will rename all these files using a random name and using the .php extension to avoid being downloaded.', 'secupress' );
	}


	public static function get_messages( $message_id = null ) {
		$messages = array(
			// good
			0   => __( 'You don\'t have old <code>wp-config</code> files.', 'secupress' ),
			1   => _n_noop( 'The file was successfully suffixed with %s.', 'All files were successfully suffixed with %s.', 'secupress' ),
			// warning
			100 => _n_noop( '%1$d file was successfully suffixed with %2$s.', '%1$d files were successfully suffixed with %2$s.', 'secupress' ),
			101 => _n_noop( 'Sorry, this file could not be renamed: %s', 'Sorry, those files could not be renamed: %s', 'secupress' ),
			// bad
			200 => _n_noop( 'Your installation should not contain this old or backed up config file: %s.', 'Your installation should not contain these old or backed up config files: %s.', 'secupress' ),
			201 => _n_noop( 'Sorry, the file could not be renamed.', 'Sorry, the files could not be renamed.', 'secupress' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	public function scan() {

		$files = static::get_files();

		if ( $files ) {
			// bad
			$files = self::wrap_in_tag( $files );
			$this->add_message( 200, array( count( $files ), $files ) );
		} else {
			// good
			$this->add_message( 0 );
		}

		return parent::scan();
	}


	public function fix() {
		$files = static::get_files();

		// Should not happen.
		if ( ! $files ) {
			// good
			$this->add_fix_message( 0 );
			return parent::fix();
		}

		$wp_filesystem = secupress_get_filesystem();
		$count_all     = count( $files );
		$renamed       = array();
		$suffix        = '.' . time() . '.secupress.php';

		// Rename the files.
		foreach ( $files as $filename ) {
			$new_file = ABSPATH . $filename . $suffix;

			if ( $wp_filesystem->move( ABSPATH . $filename, $new_file ) ) {
				$wp_filesystem->chmod( $new_file, octdec( 644 ) );
				// Counting the renamed files is safer that counting the not renamed ones.
				$renamed[] = $filename;
			}
		}

		$count_renamed = count( $renamed );

		if ( $count_renamed === $count_all ) {
			// good: all files were renamed.
			$this->add_fix_message( 1, array( $count_all, '<code>' . $suffix . '</code>' ) );
		} elseif ( $count_renamed ) {
			// warning: some files could not be renamed.
			$not_renamed = array_diff( $files, $renamed );
			$not_renamed = static::wrap_in_tag( $not_renamed );

			$this->add_fix_message( 100, array( $count_renamed, $count_renamed, '<code>' . $suffix . '</code>' ) );
			$this->add_fix_message( 101, array( count( $not_renamed ), $not_renamed ) );
		}
		else {
			// bad: no files could not be renamed.
			$this->add_fix_message( 201, array( $count_all ) );
		}

		return parent::fix();
	}


	protected static function get_files() {
		$files = glob( ABSPATH . '*wp-config*.*' );
		$files = array_map( 'basename', $files );

		foreach( $files as $k => $file ) {
			if ( 'php' === pathinfo( $file, PATHINFO_EXTENSION ) ) {
				unset( $files[ $k ] );
			}
		}

		return $files;
	}
}
