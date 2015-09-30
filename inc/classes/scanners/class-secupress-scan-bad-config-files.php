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
			// bad
			200 => _n_noop( 'Your installation should not contain this old or backed up config file: %s.', 'Your installation should not contain these old or backed up config files: %s.', 'secupress' ),
			// cantfix
			300 => __( 'I can not fix this, you have to do it yourself, have fun.', 'secupress' ),
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

		// This fix requires the user to take action.
		if ( $files ) {
			$this->add_fix_action( 'delete-files' );
		}

		return parent::fix();
	}


	public function manual_fix() {
		if ( $this->has_fix_action_part( 'delete-files' ) && ! empty( $_POST['secupress-fix-wp-config-files'] ) && is_array( $_POST['secupress-fix-wp-config-files'] ) ) {
			$files = static::get_files();
			$sent  = $_POST['secupress-fix-wp-config-files'];
			$sent  = array_intersect( $files, $sent );

			if ( $sent ) {
				foreach ( $sent as $filename ) {
					if ( is_writable( ABSPATH . $filename ) ) {
						unlink( ABSPATH . $filename );
					}
				}
			}
		}

		return $this->scan();
	}


	public function get_fix_action_template_parts() {
		$form  = '';
		$files = static::get_files();

		if ( count( $files ) === 1 ) {

			$form .= '<h4>' . __( 'The following file will be deleted:', 'secupress' ) . '</h4>';

			$file  = reset( $files );
			$form .= sprintf( _x( 'Delete %s', 'delete a file', 'secupress' ), '<code>' . esc_html( $file ) . '</code>' );
			$form .= '<input type="hidden" name="secupress-fix-wp-config-files[]" value="' . esc_attr( $file ) . '"/> ';

		} elseif ( $files ) {

			$form .= '<h4>' . __( 'Select the files to delete:', 'secupress' ) . '</h4>';

			foreach ( $files as $file ) {
				$form .= '<input type="checkbox" id="secupress-fix-wp-config-file-' . sanitize_html_class( $file ) . '" name="secupress-fix-wp-config-files[]" value="' . esc_attr( $file ) . '"/> ';
				$form .= '<label for="secupress-fix-wp-config-file-' . sanitize_html_class( $file ) . '">' . sprintf( _x( 'Delete %s', 'delete a file', 'secupress' ), '<code>' . esc_html( $file ) . '</code>' ) . '</label><br/>';
			}

		}

		return array( 'delete-files' => $form );
	}


	protected static function get_files() {
		$files = glob( ABSPATH . '*wp-config*.*' );
		$files = array_map( 'basename', $files );
		foreach( $files as $k => $file ) {
			if ( 'php' == pathinfo( $file, PATHINFO_EXTENSION ) ) {
				unset( $files[ $k ] );
			}
		}

		return $files;
	}
}
