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
		self::$type  = 'WordPress';
		self::$title = __( 'Check if your installation contains old or backed up <code>wp-config.php</code> files like <code>wp-config.bak</code>, <code>wp-config.old</code> etc.', 'secupress' );
		self::$more  = __( 'Some attackers will try to find old and backed up config files to try to steal them. Avoid this kind of attack by removing them!', 'secupress' );
	}


	public static function get_messages( $message_id = null ) {
		$messages = array(
			// good
			0   => __( 'You don\'t have old <code>wp-config</code> files.', 'secupress' ),
			// warning
			100 => __( 'Some files still need to be deleted.', 'secupress' ),
			101 => __( 'All selected files have been deleted (but some are still there).', 'secupress' ),
			102 => __( 'Sorry, some files could not be deleted.', 'secupress' ),
			103 => __( 'Please select at least one file.', 'secupress' ),
			// bad
			200 => _n_noop( 'Your installation should not contain this old or backed up config file: %s.', 'Your installation should not contain these old or backed up config files: %s.', 'secupress' ),
			201 => _n_noop( 'Sorry, this file could not be deleted.', 'Sorry, those files could not be deleted.', 'secupress' ),
			// cantfix
			300 => __( 'I can\'t delete those files blindly, please make a selection.', 'secupress' ),
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
			$this->add_message( 200, array( count( $files ), wp_sprintf_l( '%l', $files ) ) );
		}

		// good
		$this->maybe_set_status( 0 );

		return parent::scan();
	}


	public function fix() {

		$files = static::get_files();

		// There are files to delete.
		if ( $files ) {
			// This fix requires the user to take action.
			$this->add_fix_message( 300 );
			$this->add_fix_action( 'delete-files' );
		} else {
			// Should not happen.
			$this->add_fix_message( 0 );
		}

		return parent::fix();
	}


	public function manual_fix() {
		if ( ! $this->has_fix_action_part( 'delete-files' ) ) {
			return parent::manual_fix();
		}

		if ( empty( $_POST['secupress-fix-wp-config-files'] ) || ! is_array( $_POST['secupress-fix-wp-config-files'] ) ) {
			// warning
			$this->add_fix_message( 103 );
			$this->add_fix_action( 'delete-files' );
			return parent::manual_fix();
		}

		$bad_files = static::get_files();
		$count_all = count( $bad_files );
		$files     = array_filter( $_POST['secupress-fix-wp-config-files'] );
		$files     = array_intersect( $bad_files, $files );
		$count     = count( $files );
		$deleted   = 0;

		// Should not happen.
		if ( ! $count_all ) {
			// good
			$this->add_fix_message( 0 );
			return parent::manual_fix();
		}

		// If a file was selected, it is not in the list anymore.
		if ( ! $count ) {
			// Let's play dumb and go to "partial": some files still need to be deleted.
			$this->add_fix_message( 100 );
			return parent::manual_fix();
		}

		// Delete the files.
		foreach ( $files as $filename ) {
			if ( is_writable( ABSPATH . $filename ) && @unlink( ABSPATH . $filename ) ) {
				++$deleted;
			}
		}

		// Everything's deleted, no files left.
		if ( $deleted === $count_all ) {
			// good
			$this->add_fix_message( 0 );
		}
		// All selected files deleted.
		elseif ( $deleted === $count ) {
			// "partial": some files still need to be deleted.
			$this->add_fix_message( 101 );
		}
		// No files deleted.
		elseif ( ! $deleted ) {
			// bad
			$this->add_fix_message( 201, array( $count ) );
		}
		// Some files could not be deleted.
		else {
			// partial
			$this->add_fix_message( 102 );
		}

		return parent::manual_fix();
	}


	public function get_fix_action_template_parts() {
		$files = static::get_files();
		$form = '';

		if ( $files ) {

			$form  = '<div class="show-input">';
			$form .= '<h4>' . _n( 'The following file will be deleted:', 'The following files will be deleted:', count( $files ), 'secupress' ) . '</h4>';
			$form .= '<div>';

			foreach ( $files as $file ) {
				$form .= '<input type="checkbox" checked="checked" id="secupress-fix-wp-config-file-' . sanitize_html_class( $file ) . '" name="secupress-fix-wp-config-files[]" value="' . esc_attr( $file ) . '"/> ';
				$form .= '<label for="secupress-fix-wp-config-file-' . sanitize_html_class( $file ) . '"><code>' . esc_html( $file ) . '</code></label><br/>';
			}

			$form .= '</div>';
			$form .= '</div>';
		}

		return array( 'delete-files' => $form );
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
