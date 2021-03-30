<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/**
 * Class that will clean temporary files and other leftovers periodically.
 *
 * @package SecuPress
 * @since 1.3
 */
class SecuPress_Cleanup_Leftovers extends SecuPress_Singleton {

	const VERSION = '1.0';

	/**
	 * Cron name.
	 *
	 * @var (string)
	 */
	const CRON_NAME = 'secupress_cleanup_leftovers';

	/**
	 * Cron recurrence.
	 *
	 * @var (string)
	 */
	const CRON_RECURRENCE = 'twicedaily';

	/**
	 * The reference to the *Singleton* instance of this class.
	 *
	 * @var (object)
	 */
	protected static $_instance;


	/** Init ==================================================================================== */

	/**
	 * Set the values.
	 *
	 * @since 1.0
	 */
	protected function _init() {
		add_action( 'init',                       array( $this, 'init_cron' ) );
		add_action( static::CRON_NAME,            array( $this, 'do_cron' ) );
		add_action( 'secupress.deactivation',     array( $this, 'do_cron' ) );
		add_action( 'secupress.pro.deactivation', array( $this, 'do_cron' ) );
	}


	/** Public methods ========================================================================== */

	/**
	 * Initiate the cron that will cleanup leftovers twice-daily.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 */
	public function init_cron() {
		if ( ! wp_next_scheduled( static::CRON_NAME ) ) {
			wp_schedule_event( time(), static::CRON_RECURRENCE, static::CRON_NAME );
		}
	}


	/**
	 * Cron that will that will cleanup leftovers.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 */
	public function do_cron() {
		global $wpdb;
		$filesystem = secupress_get_filesystem();

		// `wp-config.php` and `.htaccess` sandbox folders at the site's root.
		$folder = ABSPATH;
		$files  = static::scandir( $folder );

		if ( $files ) {
			foreach ( $files as $file ) {
				$path = $folder . $file;

				if ( $filesystem->is_dir( $path ) && preg_match( '@^secupress-sandbox-@', $file ) ) {
					$filesystem->delete( $path, true );
				}
			}
		}

		// Backup files in the temporary folder.
		if ( function_exists( 'secupress_get_temporary_backups_path' ) ) {
			$folder = secupress_get_temporary_backups_path();
			if ( file_exists( $folder ) ) {
				$files  = static::scandir( $folder );

				if ( $files ) {
					foreach ( $files as $file ) {
						if ( '.htaccess' !== $file ) {
							$filesystem->delete( $folder . $file, true );
						}
					}
				}
			}
		}

		// Files created by the "Bad file extensions" scan.
		$folder = wp_upload_dir( null, false );
		$folder = trailingslashit( wp_normalize_path( $folder['basedir'] ) );
		if ( file_exists( $folder ) ) {
			$files  = static::scandir( $folder );

			if ( $files ) {
				foreach ( $files as $file ) {
					$path = $folder . $file;

					if ( $filesystem->is_file( $path ) && preg_match( '@^secupress-temporary-file-@', $file ) ) {
						$filesystem->delete( $path );
					}
				}
			}
		}

		// Fake users created by the Subscription scan.
		$users = $wpdb->get_col( "SELECT ID FROM {$wpdb->users} WHERE user_email LIKE 'secupress_no_mail_SS@fakemail.%'" );

		if ( $users ) {
			require_once( ABSPATH . 'wp-admin/includes/user.php' );

			foreach ( $users as $user_id ) {
				wp_delete_user( (int) $user_id );
			}
		}
	}


	/** Tools =================================================================================== */

	/**
	 * Like the real `scandir()`, but without '.' and '..'.
	 *
	 * @since 1.3
	 * @author Grégory Viguier
	 *
	 * @param (string) $path Path of the folder to scan.
	 *
	 * @return (array) An array of files.
	 */
	protected static function scandir( $path ) {
		if ( ! file_exists( $path ) ) {
			return array();
		}
		$files = @scandir( $path );

		if ( $files ) {
			$files = array_diff( $files, array( '.', '..' ) );
		}

		return $files ? $files : array();
	}
}
